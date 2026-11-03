import base64
import logging
import threading
import time
from hashlib import sha256
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWS
from cryptojwt import as_unicode
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory

from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_JSON
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.metadata import get_signing_algs
from idpyoidc.server.client_authn import BearerHeader
from idpyoidc.server.util import CURRENT_ISSUER

logger = logging.getLogger(__name__)

#: Accepted age (seconds) of a proof's iat
DPOP_IAT_WINDOW = 300
#: Accepted clock skew (seconds) of a proof's iat into the future
DPOP_MAX_CLOCK_SKEW = 60
#: JWK members that only a private or symmetric key has
NON_PUBLIC_JWK_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "k"}


class DPoPProof(Message):
    c_param = {
        # header
        "typ": SINGLE_REQUIRED_STRING,
        "alg": SINGLE_REQUIRED_STRING,
        "jwk": SINGLE_REQUIRED_JSON,
        # body
        "jti": SINGLE_REQUIRED_STRING,
        "htm": SINGLE_REQUIRED_STRING,
        "htu": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "ath": SINGLE_OPTIONAL_STRING,
    }
    header_params = {"typ", "alg", "jwk"}
    body_params = {"jti", "htm", "htu", "iat"}

    def __init__(self, set_defaults=True, **kwargs):
        self.key = None
        Message.__init__(self, set_defaults=set_defaults, **kwargs)

        if self.key:
            pass
        elif "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

    def from_dict(self, dictionary, **kwargs):
        Message.from_dict(self, dictionary, **kwargs)

        if "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

        return self

    def verify(self, **kwargs):
        Message.verify(self, **kwargs)
        if self["typ"] != "dpop+jwt":
            raise ValueError("Wrong type")
        if self["alg"] == "none":
            raise ValueError("'none' is not allowed as signing algorithm")

    def create_header(self) -> str:
        payload = {k: self[k] for k in self.body_params}
        _jws = JWS(payload, alg=self["alg"])
        _headers = {k: self[k] for k in self.header_params}
        self.key.kid = ""
        _sjwt = _jws.sign_compact(keys=[self.key], **_headers)
        return _sjwt

    def verify_header(self, dpop_header, allowed_algs=None) -> Optional["DPoPProof"]:
        """Verify the proof's signature with its own (public, asymmetric) jwk.

        :param allowed_algs: the accepted signing algorithms; any asymmetric one if None
        """
        _jws = factory(dpop_header)
        if _jws:
            _jwt = _jws.jwt
            if "jwk" in _jwt.headers:
                _jwk = _jwt.headers["jwk"]
                if not isinstance(_jwk, dict) or _jwk.get("kty") == "oct" or NON_PUBLIC_JWK_MEMBERS & set(_jwk):
                    raise ValueError("DPoP 'jwk' must be a public asymmetric key")
                _alg = _jwt.headers.get("alg")
                if not _alg or _alg == "none" or _alg.startswith("HS"):
                    raise ValueError("DPoP must be signed with an asymmetric algorithm")
                if allowed_algs is not None and _alg not in allowed_algs:
                    raise ValueError(f"DPoP signing algorithm {_alg} is not supported")
                _pub_key = key_from_jwk_dict(_jwk)
                _pub_key.deserialize()
                _info = _jws.verify_compact(keys=[_pub_key], sigalg=_jwt.headers["alg"])
                for k, v in _jwt.headers.items():
                    self[k] = v

                for k, v in _info.items():
                    self[k] = v
            else:
                raise Exception()

            return self
        else:
            return None


class InvalidDPoPProof(ValueError):
    """A DPoP proof that must be refused."""


class DPoPErrorResponse(TokenErrorResponse):
    """Token error response that also allows the RFC 9449 error codes."""

    c_allowed_values = TokenErrorResponse.c_allowed_values.copy()
    c_allowed_values["error"] = list(TokenErrorResponse.c_allowed_values["error"]) + [
        "invalid_dpop_proof",
        "use_dpop_nonce",
    ]


class JtiCache:
    """Seen DPoP proofs (key thumbprint and ``jti``): each proof is accepted once.

    Entries are kept for the acceptance window of ``iat``; an older proof is
    refused for its age. The cache lives in this process: when several
    processes serve the token endpoint, replace
    ``context.add_on["dpop"]["jti_cache"]`` with one backed by a shared store
    (same ``add_once`` method).
    """

    def __init__(self):
        self._entries = {}
        self._lock = threading.Lock()

    def add_once(self, key: str, ttl: float) -> bool:
        """Records ``key``; False when it was already recorded and has not expired."""
        now = time.time()
        with self._lock:
            for _key in [k for k, exp in self._entries.items() if exp < now]:
                del self._entries[_key]
            if key in self._entries:
                return False
            self._entries[key] = now + ttl
            return True


#: Used when the add-on was not configured through add_support (unit tests)
_DEFAULT_JTI_CACHE = JtiCache()


def _dpop_conf(context) -> dict:
    return (getattr(context, "add_on", {}) or {}).get("dpop") or {}


def _allowed_algs(context):
    return _dpop_conf(context).get("algs_supported")


def _strip_query(url: str) -> str:
    return str(url).split("?", 1)[0].split("#", 1)[0]


def _under_current_issuer(urls) -> list:
    """The ``urls`` under the issuer the request is answered as
    (:data:`idpyoidc.server.util.CURRENT_ISSUER`), or all of them when none is set:
    a proof for another issuer of the same server is refused (RFC 9449 section 4.3)."""
    _issuer = CURRENT_ISSUER.get()
    if not _issuer:
        return list(urls)
    _prefix = f"{_issuer.rstrip('/')}/"
    return [u for u in urls if _strip_query(u).startswith(_prefix)]


def _check_iat(dpop, now=None):
    _iat = dpop.get("iat")
    now = time.time() if now is None else now
    if not isinstance(_iat, int) or _iat > now + DPOP_MAX_CLOCK_SKEW or _iat < now - DPOP_IAT_WINDOW:
        raise InvalidDPoPProof("DPoP 'iat' is outside the accepted window")


def access_token_hash(access_token: str) -> str:
    """The ``ath`` of a proof for this access token (base64url SHA-256, RFC 9449 section 4.2)."""
    digest = sha256(access_token.encode("utf8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_proof(dpop_header: str, method: str, allowed_htu, context, access_token: Optional[str] = None):
    """Validates a DPoP proof (RFC 9449 section 4.3).

    Checks the signature with the proof's own public, asymmetric ``jwk`` and an
    allowed ``alg``, ``typ`` = dpop+jwt, ``htm``, ``htu`` (one of
    ``allowed_htu``, query and fragment ignored), the ``iat`` window, ``ath``
    when an access token is given, and that the ``jti`` was not used before.

    :return: (the proof, the RFC 7638 thumbprint of its key)
    :raises InvalidDPoPProof: if any check fails
    """
    try:
        _dpop = DPoPProof().verify_header(dpop_header, _allowed_algs(context))
    except Exception as err:
        raise InvalidDPoPProof(f"DPoP proof not verified: {err}") from err
    if _dpop is None:
        raise InvalidDPoPProof("DPoP proof is not a JWS")
    if _dpop.get("typ") != "dpop+jwt":
        raise InvalidDPoPProof("DPoP proof 'typ' must be dpop+jwt")
    if _dpop.get("htm") != method:
        raise InvalidDPoPProof("htm in DPoP does not match the HTTP method")
    if _strip_query(_dpop.get("htu", "")) not in {_strip_query(u) for u in allowed_htu}:
        raise InvalidDPoPProof("htu in DPoP does not match the HTTP URI")
    _check_iat(_dpop)
    if access_token is not None and _dpop.get("ath") != access_token_hash(access_token):
        raise InvalidDPoPProof("'ath' in DPoP does not match the token hash")
    _jti = _dpop.get("jti")
    if not isinstance(_jti, str) or not _jti:
        raise InvalidDPoPProof("DPoP proof has no 'jti'")

    if not _dpop.key:
        _dpop.key = key_from_jwk_dict(_dpop["jwk"])
    _jkt = as_unicode(_dpop.key.thumbprint("SHA-256"))
    _cache = _dpop_conf(context).get("jti_cache") or _DEFAULT_JTI_CACHE
    # Last, so that a proof refused for another reason does not use up its jti.
    if not _cache.add_once(f"{_jkt}:{_jti}", DPOP_IAT_WINDOW + DPOP_MAX_CLOCK_SKEW):
        raise InvalidDPoPProof("DPoP proof 'jti' already used")
    return _dpop, _jkt


def token_post_parse_request(request, client_id, context, **kwargs):
    """
    Validates the DPoP proof of a token request, if there is one, and records
    its key thumbprint as ``dpop_jkt`` (the grant and its tokens are bound to it).

    Expects ``http_info`` (headers, method, URL) in kwargs. The proof's ``htu``
    must be one of the configured ``allowed_htu`` (the public token endpoint
    URLs) under the current issuer, or the request URL when none are configured.

    :return: the request, or a DPoPErrorResponse (invalid_dpop_proof)
    """

    _http_info = kwargs.get("http_info")
    if not _http_info:
        return request

    _header = (_http_info.get("headers") or {}).get("dpop")
    if not _header:
        return request

    allowed_htu = _dpop_conf(context).get("allowed_htu") or kwargs.get("allowed_htu")
    allowed_htu = _under_current_issuer(allowed_htu) if allowed_htu else [_http_info.get("url", "")]
    try:
        _, _jkt = verify_proof(_header, _http_info.get("method"), allowed_htu, context)
    except InvalidDPoPProof as err:
        logger.warning("DPoP proof refused: %s", err)
        return DPoPErrorResponse(error="invalid_dpop_proof", error_description=str(err))

    # Need something I can add as a reference when minting tokens
    request["dpop_jkt"] = _jkt
    return request


def par_post_parse_request(request, client_id, context, **kwargs):
    """
    Validates the DPoP proof of a pushed authorization request, if there is
    one, and records its key thumbprint as ``dpop_jkt`` (RFC 9449 section
    10.1): the code can then only be redeemed with a proof by that key.

    The proof's ``htu`` must be one of the configured ``par_allowed_htu`` under
    the current issuer, or the request URL when none are configured.

    :return: the request, or a DPoPErrorResponse (invalid_dpop_proof)
    """

    _http_info = kwargs.get("http_info")
    if not _http_info:
        return request

    _header = (_http_info.get("headers") or {}).get("dpop")
    if not _header:
        return request

    allowed_htu = _dpop_conf(context).get("par_allowed_htu")
    allowed_htu = _under_current_issuer(allowed_htu) if allowed_htu else [_http_info.get("url", "")]
    try:
        _, _jkt = verify_proof(_header, _http_info.get("method"), allowed_htu, context)
    except InvalidDPoPProof as err:
        logger.warning("DPoP proof refused: %s", err)
        return DPoPErrorResponse(error="invalid_dpop_proof", error_description=str(err))

    # RFC 9449 section 10.1: both given, they must name the same key.
    if request.get("dpop_jkt") and request["dpop_jkt"] != _jkt:
        return DPoPErrorResponse(
            error="invalid_dpop_proof", error_description="dpop_jkt does not match the DPoP proof key"
        )
    request["dpop_jkt"] = _jkt
    return request


def authorization_request_jkt_error(grant, request) -> Optional[DPoPErrorResponse]:
    """
    A code from an authorization request with ``dpop_jkt`` (RFC 9449 section
    10) is only redeemed with a proof by that key.

    :return: a DPoPErrorResponse (invalid_dpop_proof) if the token request's
        key is missing or another one, else None
    """
    _jkt = (grant.authorization_request or {}).get("dpop_jkt")
    if _jkt and request.get("dpop_jkt") != _jkt:
        return DPoPErrorResponse(
            error="invalid_dpop_proof",
            error_description="DPoP key differs from the key bound in the authorization request",
        )
    return None


def userinfo_post_parse_request(request, client_id, context, auth_info, **kwargs):
    """
    Validates the DPoP proof sent with a DPoP-bound access token (including
    ``ath``) and records its key thumbprint as ``dpop_jkt``.

    :raises InvalidDPoPProof: if the proof is invalid
    """

    _http_info = kwargs.get("http_info")
    if not _http_info:
        return request

    _, _jkt = verify_proof(
        _http_info["headers"]["dpop"],
        _http_info["method"],
        [_http_info["url"]],
        context,
        access_token=auth_info["token"],
    )
    request["dpop_jkt"] = _jkt
    logger.debug("DPoP verified")
    return request


def token_args(context, client_id, token_args: Optional[dict] = None):
    dpop_jkt = context.cdb.get(client_id, {}).get("dpop_jkt")
    if dpop_jkt:
        _jkt = next(iter(dpop_jkt.keys())) if isinstance(dpop_jkt, dict) else dpop_jkt
        if token_args is None:
            token_args = {}
        token_args["cnf"] = {"jkt": _jkt}

    return token_args


def add_support(endpoint: dict, **kwargs):
    # Pick one endpoint
    # _endp_name = list(endpoint.keys())[0]

    token_endpoint = endpoint.get("token")

    token_endpoint.post_parse_request.append(token_post_parse_request)

    # _endp = endpoint[_endp_name]
    # _endp.post_parse_request.append(token_post_parse_request)

    _algs_supported = kwargs.get("dpop_signing_alg_values_supported")
    if not _algs_supported:
        _algs_supported = ["ES256"]
    else:
        _algs_supported = [alg for alg in _algs_supported if alg in get_signing_algs()]

    _context = token_endpoint.upstream_get("context")
    _context.provider_info["dpop_signing_alg_values_supported"] = _algs_supported
    _context.add_on["dpop"] = {
        "algs_supported": _algs_supported,
        # Public URLs of the token endpoint a proof's htu may name
        "allowed_htu": list(kwargs.get("allowed_htu") or []),
        # Public URLs of the pushed authorization endpoint a proof's htu may name
        "par_allowed_htu": list(kwargs.get("par_allowed_htu") or []),
        "jti_cache": JtiCache(),
    }

    _par_endpoint = endpoint.get("pushed_authorization")
    if _par_endpoint:
        _par_endpoint.post_parse_request.append(par_post_parse_request)
    _context.client_authn_methods["dpop"] = DPoPClientAuth(BearerHeader)

    for _dpop_endpoint in kwargs.get("dpop_endpoints", ["userinfo"]):
        _endpoint = endpoint.get(_dpop_endpoint, None)
        if _endpoint:
            _endpoint.post_parse_request.append(userinfo_post_parse_request)


# DPoP-bound access token in the "Authorization" header and the DPoP proof in the "DPoP" header


class DPoPClientAuth(BearerHeader):
    tag = "dpop_client_auth"

    def is_usable(
        self,
        request=None,
        authorization_token=None,
        http_headers=None,
        http_info: Optional[dict] = None,
    ):
        if authorization_token is not None and authorization_token.startswith("DPoP "):
            return True
        return False

    def verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        get_client_id_from_token: Optional[Callable] = None,
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        # info contains token and client_id
        info = BearerHeader._verify(
            self,
            request,
            authorization_token,
            endpoint,
            get_client_id_from_token,
            **kwargs,
        )
        return info
