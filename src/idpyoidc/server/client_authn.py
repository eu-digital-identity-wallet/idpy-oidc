import base64
import json
import logging
import os
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Union

import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptojwt.exception import BadSignature, Invalid, IssuerNotFound, MissingKey
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import JWT, utc_time_sans_frac
from cryptojwt.utils import as_bytes, as_unicode

from idpyoidc.message import Message
from idpyoidc.message.oauth2.device_authorization import WalletInstanceAttestationJWT
from idpyoidc.message.oidc import JsonWebToken, verified_claim_name
from idpyoidc.node import topmost_unit
from idpyoidc.server.constant import JWT_BEARER
from idpyoidc.server.exception import (
    BearerTokenAuthenticationError,
    ClientAuthenticationError,
    InvalidClient,
    InvalidToken,
    ToOld,
    UnknownClient,
)
from idpyoidc.server.util import current_issuer, endpoint_url
from idpyoidc.util import importer, sanitize

logger = logging.getLogger(__name__)

#: client_status of the wallet attestation verified in the current request.
#: Tokens take it from here, not from the client database entry, which
#: concurrent requests of other wallet instances with the same client_id share.
VERIFIED_CLIENT_STATUS: ContextVar = ContextVar("verified_client_status", default=None)

__author__ = "roland hedberg"


class ClientAuthnMethod(object):
    tag = None

    def __init__(self, upstream_get):
        """
        :param upstream_get: A method that can be used to get general server information.
        """
        self.upstream_get = upstream_get

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        """
        Verify authentication information in a request
        :param kwargs:
        :return:
        """
        raise NotImplementedError()

    def verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        get_client_id_from_token: Optional[Callable] = None,
        **kwargs,
    ):
        """
        Verify authentication information in a request
        :param kwargs:
        :return:
        """
        res = self._verify(
            request=request,
            authorization_token=authorization_token,
            endpoint=endpoint,
            get_client_id_from_token=get_client_id_from_token,
            **kwargs,
        )
        res["method"] = self.tag
        return res

    def is_usable(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        http_info: Optional[dict] = None,
    ):
        """
        Verify that this authentication method is applicable.

        :param request: The request
        :param authorization_token: The authorization token
        :return: True/False
        """
        raise NotImplementedError()


def basic_authn(authorization_token: str):
    if not authorization_token.startswith("Basic "):
        raise ClientAuthenticationError("Wrong type of authorization token")

    _tok = as_bytes(authorization_token[6:])
    # Will raise ValueError type exception if not base64 encoded
    _tok = base64.b64decode(_tok)
    part = as_unicode(_tok).split(":", 1)
    if len(part) != 2:
        raise ValueError("Illegal token")

    return dict(zip(["id", "secret"], part))


class NoneAuthn(ClientAuthnMethod):
    """
    Used for testing purposes
    """

    tag = "none"

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        return request is not None

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        return {"client_id": request.get("client_id")}


class PublicAuthn(ClientAuthnMethod):
    """
    Used for public clients, that don't require any form of authentication other
    than their client_id
    """

    tag = "public"

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):

        if http_info is not None:
            _headers = http_info.get("headers", {})
            header_keys = {k.lower() for k in _headers}
            # A request carrying credentials of another method is not public.
            # A DPoP proof is not client authentication (RFC 9449): public
            # clients send one too.
            if any(
                h in header_keys
                for h in (
                    "oauth-client-attestation",
                    "oauth-client-attestation-pop",
                    "authorization",
                )
            ):
                return False

        return request and "client_id" in request

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        return {"client_id": request["client_id"]}


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.
    """

    tag = "client_secret_basic"

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        if authorization_token is not None and authorization_token.startswith("Basic "):
            return True
        return False

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        client_info = basic_authn(authorization_token)
        _context = self.upstream_get("context")
        if _context.cdb[client_info["id"]]["client_secret"] == client_info["secret"]:
            return {"client_id": client_info["id"]}
        else:
            raise ClientAuthenticationError()


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.
    """

    tag = "client_secret_post"

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        if request is None:
            return False
        if "client_id" in request and "client_secret" in request:
            return True
        return False

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        _context = self.upstream_get("context")
        if _context.cdb[request["client_id"]]["client_secret"] == request["client_secret"]:
            return {"client_id": request["client_id"]}
        else:
            raise ClientAuthenticationError("secrets doesn't match")


class BearerHeader(ClientSecretBasic):
    """"""

    tag = "bearer_header"

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        if authorization_token is not None and authorization_token.startswith("Bearer "):
            return True
        return False

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        get_client_id_from_token: Optional[Callable] = None,
        **kwargs,
    ):
        logger.debug(f"Client Auth method: {self.tag}")
        token = authorization_token.split(" ", 1)[1]
        _context = self.upstream_get("context")
        # The client is the one the token was issued to, never a client_id
        # named in the request.
        client_id = ""
        if get_client_id_from_token:
            try:
                client_id = get_client_id_from_token(_context, token, request)
            except ToOld:
                raise BearerTokenAuthenticationError("Expired token")
            except KeyError:
                raise BearerTokenAuthenticationError("Unknown token")
            except Exception:
                logger.debug(f"Exception in {self.tag}")

        return {"token": token, "client_id": client_id, "method": self.tag}


class BearerBody(ClientSecretPost):
    """
    Same as Client Secret Post
    """

    tag = "bearer_body"

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        if request is not None and "access_token" in request:
            return True
        return False

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        get_client_id_from_token: Optional[Callable] = None,
        **kwargs,
    ):
        _token = request.get("access_token")
        if _token is None:
            raise ClientAuthenticationError("No access token")

        res = {"token": _token}
        _context = self.upstream_get("context")
        _client_id = get_client_id_from_token(_context, _token, request)
        if _client_id:
            res["client_id"] = _client_id
        return res


class JWSAuthnMethod(ClientAuthnMethod):

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        if request is None:
            return False
        if "client_assertion" in request:
            return True
        return False

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        key_type: Optional[str] = None,
        **kwargs,
    ):
        _context = self.upstream_get("context")
        _keyjar = self.upstream_get("attribute", "keyjar")
        _jwt = JWT(_keyjar, msg_cls=JsonWebToken)
        try:
            ca_jwt = _jwt.unpack(request["client_assertion"])
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("%s" % sanitize(err))
            raise ClientAuthenticationError("Could not verify client_assertion.")

        _sign_alg = ca_jwt.jws_header.get("alg")
        if _sign_alg and _sign_alg.startswith("HS"):
            if key_type == "private_key":
                raise AttributeError("Wrong key type")
            keys = _keyjar.get("sig", "oct", ca_jwt["iss"], ca_jwt.jws_header.get("kid"))
            _secret = _context.cdb[ca_jwt["iss"]].get("client_secret")
            if _secret and keys[0].key != as_bytes(_secret):
                raise AttributeError("Oct key used for signing not client_secret")
        else:
            if key_type == "client_secret":
                raise AttributeError("Wrong key type")

        authtoken = sanitize(ca_jwt.to_dict())
        logger.debug("authntoken: {}".format(authtoken))

        if endpoint is None or not endpoint:
            if current_issuer(_context) in ca_jwt["aud"]:
                pass
            else:
                raise InvalidToken("Not for me!")
        else:
            if set(ca_jwt["aud"]).intersection(endpoint.allowed_target_uris()):
                pass
            else:
                raise InvalidToken("Not for me!")

        # If there is a jti use it to make sure one-time usage is true
        _jti = ca_jwt.get("jti")
        if _jti:
            _key = "{}:{}".format(ca_jwt["iss"], _jti)
            if _key in _context.jti_db:
                raise InvalidToken("Have seen this token once before")
            else:
                _context.jti_db[_key] = utc_time_sans_frac()

        request[verified_claim_name("client_assertion")] = ca_jwt
        client_id = kwargs.get("client_id") or ca_jwt["iss"]

        return {"client_id": client_id, "jwt": ca_jwt}


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """

    tag = "client_secret_jwt"

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        res = super()._verify(
            request=request, key_type="client_secret", endpoint=endpoint, **kwargs
        )
        # Verify that a HS alg was used
        return res


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key sign a JWT using that key.
    """

    tag = "private_key_jwt"

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        res = super()._verify(
            request=request,
            authorization_token=authorization_token,
            endpoint=endpoint,
            **kwargs,
            key_type="private_key",
        )
        # Verify that an RS or ES alg was used ?
        return res




# AttestationJWTClientAuthentication
class ClientAuthenticationAttestation(ClientAuthnMethod):
    """Attestation-Based Client Authentication with a Wallet Instance Attestation.

    Based on draft-ietf-oauth-attestation-based-client-auth: the client sends
    the attestation (WIA) in ``OAuth-Client-Attestation`` and a proof of
    possession of its ``cnf`` key in ``OAuth-Client-Attestation-PoP``.

    The WIA is trusted when its signature verifies with the ``x5c`` leaf
    certificate and that chain is trusted: by the trust validator
    (``trust_validator_url``), or else by the certificates in
    ``trusted_attesters_path``.
    """

    tag = "attest_jwt_client_auth"
    assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
    attestation_class = {"wallet-attestation+jwt": WalletInstanceAttestationJWT}
    metadata = {}

    ATTESTATION_MAX_AGE = 3600  # seconds: how old (iat) a WIA may be
    POP_TIME_WINDOW = 300  # seconds: the PoP iat must be within +/- this window
    CLOCK_SKEW = 30
    # Registered asymmetric JOSE algorithms accepted for the WIA and the PoP
    ALLOWED_ASYM_ALGS = {"ES256", "ES384", "ES512"}
    REQUIRED_WIA_CLAIMS = (
        "sub",
        "iat",
        "exp",
        "cnf",
        "wallet_name",
        "wallet_version",
        "wallet_solution_certification_information",
        "client_status",
    )
    PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "k"}
    # Status validator context for the status list behind the WIA's client_status
    STATUS_VALIDATION_CONTEXT = "WalletOrKeyStorageStatus"

    def __init__(self, upstream_get):
        super().__init__(upstream_get)
        # PoP jti -> time after which it may be forgotten (replay protection)
        self._seen_pop_jti = {}

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        if not http_info:
            return False
        _headers = {k.lower() for k in http_info.get("headers", {})}
        return {"oauth-client-attestation", "oauth-client-attestation-pop"} <= _headers

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _parse_jws(raw: str, what: str):
        try:
            jws = factory(raw)
        except Exception:
            jws = None
        if not jws:
            raise ClientAuthenticationError(f"{what} is not a well-formed JWS.")
        return jws

    def _check_alg(self, headers: dict, what: str) -> str:
        _alg = headers.get("alg")
        if _alg not in self.ALLOWED_ASYM_ALGS:
            logger.error(f"{what} signature algorithm {_alg!r} is not allowed.")
            raise ClientAuthenticationError(f"{what} uses a disallowed signature algorithm.")
        return _alg

    @staticmethod
    def _key_from_public_key(public_key):
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            key = ECKey()
        elif isinstance(public_key, rsa.RSAPublicKey):
            key = RSAKey()
        else:
            raise ClientAuthenticationError("Unsupported attester key type.")
        key.load_key(public_key)
        return key

    @staticmethod
    def _valid_now(cert: x509.Certificate) -> bool:
        _utc = timezone.utc
        # cryptography < 42 only has the naive (UTC) properties
        _before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=_utc)
        _after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=_utc)
        return _before <= datetime.now(_utc) <= _after

    @staticmethod
    def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
        try:
            cert.verify_directly_issued_by(issuer)
            return True
        except Exception:
            return False

    def _load_x5c(self, x5c) -> list:
        if not isinstance(x5c, list) or not x5c:
            raise ClientAuthenticationError("WIA 'x5c' header must be a non-empty list.")
        try:
            chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in x5c]
        except Exception:
            raise ClientAuthenticationError("WIA 'x5c' header is malformed.")
        for position, cert in enumerate(chain):
            if not self._valid_now(cert):
                raise ClientAuthenticationError(f"WIA certificate {position} is expired or not yet valid.")
            if position + 1 < len(chain) and not self._issued_by(cert, chain[position + 1]):
                raise ClientAuthenticationError(f"WIA certificate {position} is not issued by the next one.")
        return chain

    @staticmethod
    def _accept_header_kid(jws, key):
        """The verification key is fixed by context (x5c leaf, trusted attester or WIA cnf).

        'kid' is only a hint (RFC 7515 section 4.1.4) and the attestation draft puts no
        requirement on it, but cryptojwt drops any key whose kid differs from the header's.
        """
        key.kid = jws.jwt.headers.get("kid") or ""
        return key

    def _verify_with(self, raw: str, key, alg: str) -> bool:
        try:
            jws = factory(raw)
            jws.verify_compact(raw, keys=[self._accept_header_kid(jws, key)], sigalg=alg)
            return True
        except Exception as err:
            logger.debug(f"WIA signature check failed: {err.__class__.__name__}")
            return False

    def _chain_anchored(self, chain: list, trusted_attesters: list) -> bool:
        """The chain contains, or is directly issued by, a trusted attester certificate."""
        for attester_pem in trusted_attesters:
            try:
                attester = x509.load_pem_x509_certificate(attester_pem.encode())
            except Exception as err:
                logger.warning(f"Unreadable trusted attester certificate: {err}")
                continue
            if not self._valid_now(attester):
                continue
            for cert in chain:
                if cert == attester or self._issued_by(cert, attester):
                    return True
        return False

    def verify_wia_signature(self, wia_headers, wia_raw, trusted_attesters=None, trust_validator_url=None):
        """The WIA is signed by its x5c leaf and that chain is trusted."""
        _alg = self._check_alg(wia_headers, "WIA")

        if "x5c" in wia_headers:
            chain = self._load_x5c(wia_headers["x5c"])
            if not self._verify_with(wia_raw, self._key_from_public_key(chain[0].public_key()), _alg):
                raise ClientAuthenticationError("WIA signature does not verify with its x5c certificate.")
            if trust_validator_url:
                try:
                    trusted = self.call_trust_validator(
                        url=trust_validator_url,
                        chain=wia_headers["x5c"],
                        verification_context="WalletInstanceAttestation",
                    )
                except Exception as err:
                    logger.error(f"Error calling trust validator: {err}")
                    raise ClientAuthenticationError("Could not check the WIA certificate chain.")
            else:
                trusted = self._chain_anchored(chain, trusted_attesters or [])
            if not trusted:
                raise ClientAuthenticationError("WIA certificate chain is not trusted.")
            return

        if trust_validator_url:
            raise ClientAuthenticationError("WIA 'x5c' header is required.")

        # No certificate chain: the WIA must verify with a trusted attester's key.
        for idx, attester_pem in enumerate(trusted_attesters or []):
            try:
                attester = x509.load_pem_x509_certificate(attester_pem.encode())
                if not self._valid_now(attester):
                    continue
                key = self._key_from_public_key(attester.public_key())
            except Exception as err:
                logger.debug(f"Attester cert {idx}: {err.__class__.__name__}")
                continue
            if self._verify_with(wia_raw, key, _alg):
                logger.debug(f"WIA signature verified with trusted attester cert {idx}")
                return
        raise ClientAuthenticationError("WIA signature verification failed: no trusted attester matched.")

    def verify_pop(self, _wia, _pop_raw, audiences, POP_TIME_WINDOW=None, CLOCK_SKEW=None, ALLOWED_ASYM_ALGS=None):
        """The PoP is signed by the WIA cnf key, for this server, fresh and not replayed."""
        window = POP_TIME_WINDOW or self.POP_TIME_WINDOW
        skew = CLOCK_SKEW or self.CLOCK_SKEW
        _now = time.time()

        jws = self._parse_jws(_pop_raw, "Client Attestation PoP")
        _pop_headers = jws.jwt.headers
        if _pop_headers.get("typ") != "oauth-client-attestation-pop+jwt":
            raise ClientAuthenticationError("Invalid Client Attestation PoP format: missing or incorrect 'typ'.")
        _alg = self._check_alg(_pop_headers, "PoP")

        try:
            key = key_from_jwk_dict(_wia["cnf"]["jwk"])
        except Exception:
            raise ClientAuthenticationError("Client Attestation 'cnf.jwk' is not a usable public key.")
        try:
            _pop = jws.verify_compact(_pop_raw, keys=[self._accept_header_kid(jws, key)], sigalg=_alg)
        except Exception as err:
            logger.error(f"PoP signature verification failed: {err.__class__.__name__}: {err}")
            raise ClientAuthenticationError("PoP signature verification failed.")

        for claim in ("aud", "jti", "iat"):
            if claim not in _pop:
                raise ClientAuthenticationError(f"Client Attestation PoP missing required claim: {claim}.")

        _aud = _pop["aud"] if isinstance(_pop["aud"], list) else [_pop["aud"]]
        _accepted = {str(a).rstrip("/") for a in audiences if a}
        if not any(str(a).rstrip("/") in _accepted for a in _aud):
            logger.error(f"PoP 'aud' {_aud} is not this server ({sorted(_accepted)}).")
            raise ClientAuthenticationError("Client Attestation PoP 'aud' is not this server.")

        if "iss" in _pop and _pop["iss"] != _wia.get("sub"):
            raise ClientAuthenticationError("Client Attestation PoP 'iss' does not match the WIA 'sub'.")

        _iat = _pop["iat"]
        if not isinstance(_iat, (int, float)) or abs(_now - _iat) > window:
            raise ClientAuthenticationError("PoP 'iat' outside allowed freshness window.")
        _nbf = _pop.get("nbf")
        if _nbf and (_now + skew) <= _nbf:
            raise ClientAuthenticationError("PoP is not yet valid (nbf in the future).")
        _exp = _pop.get("exp")
        if _exp and (_now - skew) >= _exp:
            raise ClientAuthenticationError("PoP has expired.")

        # Replay protection: a PoP is accepted once while it is fresh.
        for jti, forget_at in list(self._seen_pop_jti.items()):
            if forget_at < _now:
                del self._seen_pop_jti[jti]
        _ref = f"{_wia.get('sub')}|{_pop['jti']}"
        if _ref in self._seen_pop_jti:
            logger.error("Client Attestation PoP replayed.")
            raise ClientAuthenticationError("Client Attestation PoP has already been used.")
        self._seen_pop_jti[_ref] = _now + 2 * window + skew

        logger.debug("Verified Client Attestation PoP.")

    def check_wia_revocation(
        self,
        url: str,
        status_idx: int,
        status_uri: str,
        validation_context: str = STATUS_VALIDATION_CONTEXT,
        timeout: int = 10,
    ) -> bool:
        """
        Calls status-list-validator to check whether the status list entry
        referenced by the WIA's client_status.status is revoked.

        Returns True if revoked, False if valid.
        """
        payload = {"idx": status_idx, "uri": status_uri, "validation_context": validation_context}
        headers = {"accept": "application/json", "Content-Type": "application/json"}

        response = requests.post(f"{url}", json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()

        logger.info(f"WIA revocation check response: {data}")
        return data.get("valid") is False

    def call_trust_validator(self, url: str, chain: list, verification_context: str, timeout: int = 10):
        """
        Generic function to call the trust validator.

        Args:
            url: Trust validator endpoint
            chain: certificate chain (list of base64 certs)
            verification_context: Validation context (e.g., WalletUnitAttestation, PID)
            timeout: Request timeout in seconds

        Returns:
            bool: whether the trust validator trusts the chain
        """

        payload = {"chain": chain, "verificationContext": verification_context}

        headers = {"accept": "application/json", "Content-Type": "application/json"}

        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()

        data = response.json()

        logger.info(f"Trust validator response: {data}")

        return bool(data.get("trusted", False))

    def verify_wia_claims(self, _wia, request, skip_client_id_check=False):
        _now = time.time()

        for claim in self.REQUIRED_WIA_CLAIMS:
            if claim not in _wia:
                raise ClientAuthenticationError(f"Client Attestation missing required claim: {claim}.")

        _jwk = _wia["cnf"].get("jwk") if isinstance(_wia["cnf"], dict) else None
        if not _jwk or not isinstance(_jwk, dict):
            raise ClientAuthenticationError("Client Attestation 'cnf' claim is malformed.")
        if self.PRIVATE_JWK_FIELDS.intersection(_jwk):
            raise ClientAuthenticationError("Client Attestation 'jwk' must not contain private key material.")

        # The attested client is the one making the request. The server's own
        # internal calls (pre-authorized code) may skip this; a client cannot.
        request_client_id = request.get("client_id")
        if request_client_id and not skip_client_id_check and _wia["sub"] != request_client_id:
            logger.error(f"WIA 'sub' ({_wia['sub']}) does not match request 'client_id' ({request_client_id}).")
            raise ClientAuthenticationError("Client Attestation subject ('sub') must match the request 'client_id'.")

        try:
            _exp, _iat = float(_wia["exp"]), float(_wia["iat"])
        except (TypeError, ValueError):
            raise ClientAuthenticationError("Client Attestation 'exp' / 'iat' are not numbers.")
        if (_now - self.CLOCK_SKEW) >= _exp:
            raise ClientAuthenticationError("Client Attestation has expired.")
        _nbf = _wia.get("nbf")
        if _nbf and (_now + self.CLOCK_SKEW) <= _nbf:
            raise ClientAuthenticationError("Client Attestation is not yet valid.")
        if (_now - _iat) > self.ATTESTATION_MAX_AGE or _iat > (_now + self.CLOCK_SKEW):
            raise ClientAuthenticationError("Client Attestation is too old or issued in the future.")

        _client_status = _wia["client_status"]
        if not isinstance(_client_status, dict) or "status" not in _client_status or "exp" not in _client_status:
            raise ClientAuthenticationError("Client Attestation 'client_status' is malformed.")
        if not isinstance(_client_status["exp"], (int, float)) or (_now - self.CLOCK_SKEW) >= _client_status["exp"]:
            raise ClientAuthenticationError("Client Attestation 'client_status' has expired.")
        _status_list_ref = (_client_status["status"] or {}).get("status_list") if isinstance(
            _client_status["status"], dict
        ) else None
        if not _status_list_ref or "idx" not in _status_list_ref or "uri" not in _status_list_ref:
            raise ClientAuthenticationError("Client Attestation status list reference is malformed.")
        return _status_list_ref

    def verify_oath_attestation(
        self,
        _wia_headers,
        _wia,
        _wia_raw,
        request,
        trusted_attesters=None,
        trust_validator_url=None,
        status_validator_url=None,
        status_validation_context=None,
        skip_client_id_check=False,
        **kwargs,
    ):
        if _wia_headers.get("typ") != "oauth-client-attestation+jwt":
            raise ClientAuthenticationError("Invalid Client Attestation format: missing or incorrect 'typ'.")

        self.verify_wia_signature(_wia_headers, _wia_raw, trusted_attesters, trust_validator_url)
        _status_list_ref = self.verify_wia_claims(_wia, request, skip_client_id_check)

        if status_validator_url:
            try:
                revoked = self.check_wia_revocation(
                    url=status_validator_url,
                    status_idx=_status_list_ref["idx"],
                    status_uri=_status_list_ref["uri"],
                    validation_context=status_validation_context or self.STATUS_VALIDATION_CONTEXT,
                )
            except Exception as e:
                logger.error(f"Error checking WIA revocation status: {e}")
                raise ClientAuthenticationError("Could not check the WIA revocation status.")
            if revoked:
                raise ClientAuthenticationError("Client Attestation has been revoked.")
        else:
            logger.warning("No status_validator_url configured; skipping WIA revocation check.")

        logger.info(f"Verified WIA for client {_wia.get('sub')!r} ({_wia.get('wallet_name')!r})")

    @staticmethod
    def _load_trusted_attesters(trusted_attesters_path) -> list:
        if not trusted_attesters_path:
            raise ClientAuthenticationError("Missing trusted attesters configuration")
        if not os.path.isdir(trusted_attesters_path):
            logger.error(f"trusted_attesters_path is not a directory: {trusted_attesters_path}")
            raise ClientAuthenticationError("trusted_attesters_path must be a directory")
        trusted_attesters = []
        for filename in sorted(os.listdir(trusted_attesters_path)):
            if filename.endswith(".pem"):
                try:
                    with open(os.path.join(trusted_attesters_path, filename), "r") as f:
                        trusted_attesters.append(f.read())
                except Exception as e:
                    logger.warning(f"Failed to load certificate {filename}: {e}")
        if not trusted_attesters:
            raise ClientAuthenticationError("No trusted attester certificates found")
        return trusted_attesters

    def _audiences(self, endpoint, pop_allowed_aud=None) -> list:
        """What the PoP 'aud' may be: the issuer identifier the request is answered as
        (see :data:`idpyoidc.server.util.CURRENT_ISSUER`), the endpoint URL under it,
        or one of ``pop_allowed_aud``."""
        _context = topmost_unit(self).context
        _aud = [current_issuer(_context)]
        if endpoint is not None:
            _aud.append(endpoint_url(endpoint))
        _aud.extend(pop_allowed_aud or [])
        return [a for a in _aud if a]

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        get_client_id_from_token: Optional[Callable] = None,
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        if not http_info or "headers" not in http_info:
            raise ClientAuthenticationError("Missing http_info or headers")
        if request is None:
            request = {}

        headers = {k.lower(): v for k, v in http_info["headers"].items()}
        wia_raw = headers.get("oauth-client-attestation")
        pop_raw = headers.get("oauth-client-attestation-pop")
        if not wia_raw:
            raise ClientAuthenticationError("Missing OAuth-Client-Attestation header")
        if not pop_raw:
            raise ClientAuthenticationError("Missing OAuth-Client-Attestation-PoP header")
        if "," in wia_raw or "," in pop_raw:
            raise ClientAuthenticationError("Client attestation headers must contain a single value")

        trust_validator_url = kwargs.get("trust_validator_url")
        trusted_attesters = None
        if not trust_validator_url:
            trusted_attesters = self._load_trusted_attesters(kwargs.get("trusted_attesters_path"))

        jws = self._parse_jws(wia_raw, "Client Attestation")
        _wia_headers = jws.jwt.headers
        _wia = jws.jwt.payload()

        self.verify_oath_attestation(
            _wia_headers=_wia_headers,
            _wia=_wia,
            _wia_raw=wia_raw,
            request=request,
            trusted_attesters=trusted_attesters,
            trust_validator_url=trust_validator_url,
            status_validator_url=kwargs.get("status_validator_url"),
            status_validation_context=kwargs.get("status_validation_context"),
            skip_client_id_check=bool(kwargs.get("skip_client_id_check")),
        )
        self.verify_pop(_wia=_wia, _pop_raw=pop_raw, audiences=self._audiences(endpoint, kwargs.get("pop_allowed_aud")))

        client_id = request.get("client_id") or _wia["sub"]

        # Register (or update) the client from the attestation. Merge: other
        # flows of the same client may be using other redirect URIs.
        oas = topmost_unit(self)
        _c_info = dict(oas.context.cdb.get(client_id, {}))
        _uris = list(_c_info.get("redirect_uris") or [])
        _redirect_uri = request.get("redirect_uri")
        if _redirect_uri and _redirect_uri not in [u[0] if isinstance(u, (list, tuple)) else u for u in _uris]:
            _uris.append((_redirect_uri, {}))
        _c_info.update(
            {"client_id": client_id, "redirect_uris": _uris, "client_status": _wia.get("client_status")}
        )
        # Add metadata from the WIA
        for key, val in self.metadata.items():
            _val = _wia.get(key, None)
            if _val:
                _c_info[key] = _val
        oas.context.cdb[client_id] = _c_info
        VERIFIED_CLIENT_STATUS.set(_wia.get("client_status"))

        return {"client_id": client_id, "jwt": _wia}


class RequestParam(ClientAuthnMethod):
    tag = "request_param"

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        if request and "request" in request:
            return True

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        _context = self.upstream_get("context")
        _jwt = JWT(self.upstream_get("attribute", "keyjar"), msg_cls=JsonWebToken)
        try:
            _jwt = _jwt.unpack(request["request"])
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("%s" % sanitize(err))
            raise ClientAuthenticationError("Could not verify client_assertion.")

        # If there is a jti use it to make sure one-time usage is true
        _jti = _jwt.get("jti")
        if _jti:
            _key = "{}:{}".format(_jwt["iss"], _jti)
            if _key in _context.jti_db:
                raise InvalidToken("Have seen this token once before")
            else:
                _context.jti_db[_key] = utc_time_sans_frac()

        request[verified_claim_name("client_assertion")] = _jwt
        client_id = kwargs.get("client_id") or _jwt["iss"]

        return {"client_id": client_id, "jwt": _jwt}


CLIENT_AUTHN_METHOD = dict(
    client_secret_basic=ClientSecretBasic,
    client_secret_post=ClientSecretPost,
    bearer_header=BearerHeader,
    bearer_body=BearerBody,
    client_secret_jwt=ClientSecretJWT,
    private_key_jwt=PrivateKeyJWT,
    request_param=RequestParam,
    wallet_attestation=ClientAuthenticationAttestation,
    public=PublicAuthn,
    none=NoneAuthn,
)

TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)]


def valid_client_secret(cinfo):
    if "client_secret" in cinfo:
        eta = cinfo.get("client_secret_expires_at", 0)
        if eta != 0 and eta < utc_time_sans_frac():
            return False
    return True


def verify_client(
    request: Union[dict, Message],
    http_info: Optional[dict] = None,
    get_client_id_from_token: Optional[Callable] = None,
    endpoint=None,  # Optional[Endpoint]
    also_known_as: Optional[Dict[str, str]] = None,
    **kwargs,
) -> dict:
    """
    Initiated Guessing !

    :param also_known_as:
    :param endpoint: Endpoint instance
    :param context: EndpointContext instance
    :param request: The request
    :param http_info: Client authentication information
    :param get_client_id_from_token: Function that based on a token returns a client id.
    :return: dictionary containing client id, client authentication method and
        possibly access token.
    """
    VERIFIED_CLIENT_STATUS.set(None)

    if http_info and "headers" in http_info:
        authorization_token = http_info["headers"].get("authorization")
        if not authorization_token:
            authorization_token = http_info["headers"].get("Authorization")

        if "dpop" in http_info["headers"]:
            authorization_token = f"DPoP {http_info['headers'].get('dpop')}"
    else:
        authorization_token = None

    auth_info = {}

    _context = endpoint.upstream_get("context")

    methods = getattr(_context, "client_authn_methods", None)

    client_id = None
    allowed_methods = getattr(endpoint, "client_authn_method")
    if not allowed_methods:
        allowed_methods = list(methods.keys())  # If not specific for this endpoint then all

    logger.debug(f"Client authentication methods allowed at {getattr(endpoint, 'name', '?')}: {allowed_methods}")

    _method = None
    _cdb = _cinfo = None
    _tested = []
    for _method in (methods[meth] for meth in allowed_methods):
        if not _method.is_usable(
            request=request,
            authorization_token=authorization_token,
            http_info=http_info,
        ):
            continue
        try:
            logger.info(f"Verifying client authentication using {_method.tag}")
            _tested.append(_method.tag)

            auth_info = _method.verify(
                keyjar=endpoint.upstream_get("attribute", "keyjar"),
                request=request,
                authorization_token=authorization_token,
                endpoint=endpoint,
                get_client_id_from_token=get_client_id_from_token,
                http_info=http_info,
                **kwargs,
            )
        except (BearerTokenAuthenticationError, ClientAuthenticationError):
            raise
        except Exception as err:
            logger.info("Verifying auth using {} failed: {}".format(_method.tag, err))
            continue

        logger.debug(f"Verify returned: {auth_info}")

        if auth_info.get("method") == "none" and auth_info.get("client_id") is None:
            break

        client_id = auth_info.get("client_id")
        if client_id is None:
            raise ClientAuthenticationError("Failed to verify client")

        if also_known_as:
            client_id = also_known_as[client_id]
            auth_info["client_id"] = client_id

        _get_client_info = kwargs.get("get_client_info", None)
        if _get_client_info:
            _cinfo = _get_client_info(client_id, endpoint)
        else:
            _cdb = getattr(_context, "cdb", None)
            try:
                _cinfo = _cdb[client_id]
            except KeyError:
                _auto_reg = getattr(endpoint, "automatic_registration", None)
                if _auto_reg:
                    _cinfo = {"client_id": client_id}
                    _auto_reg.set(client_id, _cinfo)
                else:
                    raise UnknownClient("Unknown Client ID")

        if not _cinfo:
            raise UnknownClient("Unknown Client ID")

        if not valid_client_secret(_cinfo):
            logger.warning("Client secret has expired.")
            raise InvalidClient("Not valid client")

        # Validate that the used method is allowed for this client/endpoint
        client_allowed_methods = _cinfo.get(
            f"{endpoint.endpoint_name}_client_authn_method",
            _cinfo.get("client_authn_method", None),
        )
        if client_allowed_methods is not None and auth_info["method"] not in client_allowed_methods:
            logger.info(
                f"Allowed methods for client: {client_id} at endpoint: {endpoint.name} are: "
                f"`{', '.join(client_allowed_methods)}`"
            )
            auth_info = {}
            continue
        break

    logger.debug("Authn methods applied")
    logger.debug(f"Method tested: {_tested}")

    # store what authn method was used
    if "method" in auth_info and client_id and _cdb:
        _request_type = request.__class__.__name__
        _used_authn_method = _cinfo.get("auth_method")
        if _used_authn_method:
            _cdb[client_id]["auth_method"][_request_type] = auth_info["method"]
        else:
            _cdb[client_id]["auth_method"] = {_request_type: auth_info["method"]}

    return auth_info


def client_auth_setup(upstream_get, auth_set=None):
    if auth_set is None:
        auth_set = CLIENT_AUTHN_METHOD
    else:
        auth_set.update(CLIENT_AUTHN_METHOD)
    res = {}

    for name, cls in auth_set.items():
        if isinstance(cls, str):
            cls = importer(cls)
        res[name] = cls(upstream_get)
    return res


def get_client_authn_methods():
    return list(CLIENT_AUTHN_METHOD.keys())
