import base64
import json
import logging
import time
import os
import requests
from datetime import datetime
from typing import Callable
from typing import Dict
from typing import Optional
from typing import Union

from cryptojwt.exception import BadSignature
from cryptojwt.exception import Invalid
from cryptojwt.exception import MissingKey
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from cryptojwt.jws.jws import factory
from cryptography import x509

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jws.jws import factory

from idpyoidc.message import Message
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.message.oauth2.device_authorization import WalletInstanceAttestationJWT
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.server.constant import JWT_BEARER
from idpyoidc.server.exception import BearerTokenAuthenticationError
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import InvalidClient
from idpyoidc.server.exception import InvalidToken
from idpyoidc.server.exception import ToOld
from idpyoidc.server.exception import UnknownClient
from idpyoidc.util import importer
from idpyoidc.util import sanitize
from idpyoidc.node import topmost_unit
from cryptojwt.exception import IssuerNotFound


logger = logging.getLogger(__name__)

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
            if any(
                h in header_keys
                for h in (
                    "oauth-client-attestation",
                    "oauth-client-attestation-pop",
                    "dpop",
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
        client_id = request["client_id"]
        if get_client_id_from_token:
            try:
                client_id = get_client_id_from_token(_context, token, request)
            except ToOld:
                raise BearerTokenAuthenticationError("Expired token")
            except KeyError:
                raise BearerTokenAuthenticationError("Unknown token")
            except Exception as err:
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
            if _context.issuer in ca_jwt["aud"]:
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


from cryptojwt.jwk.ec import ECKey


# AttestationJWTClientAuthentication
class ClientAuthenticationAttestation(ClientAuthnMethod):
    # based on https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-01.html
    tag = "attest_jwt_client_auth"
    assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
    attestation_class = {"wallet-attestation+jwt": WalletInstanceAttestationJWT}
    metadata = {}

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = None):
        if request is None and http_info is None:
            return False

        _headers = http_info.get("headers", {})
        if {"oauth-client-attestation", "oauth-client-attestation-pop"} <= {
            k.lower() for k in _headers
        }:
            return True

        return False

    def verify_pop(
        self,
        _wia,
        _pop_raw,
        POP_TIME_WINDOW,
        CLOCK_SKEW,
        ALLOWED_ASYM_ALGS,
    ):
        _now = time.time()

        jws = factory(_pop_raw)
        _pop_headers = jws.jwt.headers
        _pop = jws.jwt.payload()

        # 1. Check 'typ' in header
        if _pop_headers.get("typ") != "oauth-client-attestation-pop+jwt":
            logger.error("WIA 'typ' header is missing or incorrect.")
            raise ClientAuthenticationError(
                "Invalid Client Attestation format: missing or incorrect 'typ'."
            )

        # 2. Check 'alg' in header (REQUIRED)
        _alg = _pop_headers.get("alg")
        if not _alg:
            logger.error("PoP header is missing the 'alg' parameter.")
            raise ClientAuthenticationError("PoP must contain a signature algorithm ('alg').")

        if _alg not in ALLOWED_ASYM_ALGS:
            logger.error(f"PoP signature algorithm '{_alg}' is not in the allowed list.")
            raise ClientAuthenticationError("PoP uses a disallowed signature algorithm.")

        _jwk = _wia["cnf"]["jwk"]

        # Verify the PoP JWS signature using the public key
        try:
            key = ECKey(**_jwk)
            pop_jws = factory(_pop_raw)
            pop_jws.verify_compact(_pop_raw, keys=[key])  # verify signature with public key
            logger.info(" PoP signature verified using WIA public key.")
        except (Invalid, MissingKey, BadSignature, IssuerNotFound) as err:
            logger.exception("Failed PoP signature verification.")
            raise ClientAuthenticationError(
                f"PoP signature verification failed: {err.__class__.__name__}"
            )
        except Exception as err:
            logger.exception("Unexpected error verifying PoP.")
            raise ClientAuthenticationError(f"Unexpected error verifying PoP: {err}")

        # 3. REQUIRED Claims
        required_claims = ["iss", "aud", "jti", "iat"]
        for claim in required_claims:
            if claim not in _pop:
                logger.error(f"PoP missing required claim: {claim}")
                raise ClientAuthenticationError(
                    f"Client Attestation PoP missing required claim: {claim}."
                )

        _iss = _pop.get("iss")
        _aud = _pop.get("aud")
        _jti = _pop.get("jti")
        _iat = _pop.get("iat")
        _nbf = _pop.get("nbf")

        wia_sub = _wia.get("sub")
        if _iss != wia_sub:
            logger.error(f"PoP 'iss' ({_iss}) does not match WIA 'sub' ({wia_sub}).")
            raise ClientAuthenticationError(
                "PoP issuer ('iss') must match WIA subject ('sub') / client_id."
            )

        # 6. Check 'iat' freshness
        # Must be within ± POP_TIME_WINDOW of current time
        if abs(_now - _iat) > POP_TIME_WINDOW:
            logger.error(
                f"PoP 'iat' ({datetime.fromtimestamp(_iat)}) not within allowed window ({POP_TIME_WINDOW}s)."
            )
            raise ClientAuthenticationError("PoP 'iat' outside allowed freshness window.")

        # 7. Check 'nbf' (if present)
        if _nbf and (_now + CLOCK_SKEW) <= _nbf:
            logger.error(f"PoP not yet valid (nbf: {datetime.fromtimestamp(_nbf)})")
            raise ClientAuthenticationError("PoP is not yet valid (nbf in the future).")

        logger.info("Verified Client Attestation PoP successfully.", extra={"jti": _jti})

    def call_trust_validator(
        self, url: str, chain: list[str], verification_context: str, timeout: int = 10
    ):
        """
        Generic function to call the trust validator.

        Args:
            url: Trust validator endpoint
            chain: certificate chain (list of base64 certs)
            verification_context: Validation context (e.g., WalletUnitAttestation, PID)
            timeout: Request timeout in seconds

        Returns:
            dict: Parsed JSON response from the trust validator
        """

        payload = {"chain": chain, "verificationContext": verification_context}

        headers = {"accept": "application/json", "Content-Type": "application/json"}

        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()

        data = response.json()

        logger.info(f"Trust validator response: {data}")

        return bool(data.get("trusted", False))

    def verify_oath_attestation(
        self,
        _wia_headers,
        _wia,
        _wia_raw,
        request,
        ATTESTATION_MAX_AGE,
        CLOCK_SKEW,
        ALLOWED_ASYM_ALGS,
        trusted_attesters=None,
        trust_validator_url=None,
    ):
        _now = time.time()

        # 1. Check 'typ' in header
        if _wia_headers.get("typ") != "oauth-client-attestation+jwt":
            logger.error("WIA 'typ' header is missing or incorrect.")
            raise ClientAuthenticationError(
                "Invalid Client Attestation format: missing or incorrect 'typ'."
            )

        _iss = _wia.get("iss")
        if not _iss:
            logger.error("WIA missing 'iss' claim.")
            raise ClientAuthenticationError("WIA missing required 'iss' claim.")

        signature_verified = False
        verification_errors = []

        if trust_validator_url:

            try:
                signature_verified = self.call_trust_validator(
                    url=trust_validator_url,
                    chain=_wia_headers["x5c"],
                    verification_context="WalletInstanceAttestation",
                )
            except Exception as e:
                logger.error(f"Error calling trust validator: {e}")
                raise ClientAuthenticationError(f"Error calling trust validator: {e}")

        else:
            for idx, attester_cert_pem in enumerate(trusted_attesters):
                try:
                    # Load the certificate
                    cert = x509.load_pem_x509_certificate(attester_cert_pem.encode())
                    public_key = cert.public_key()

                    # Convert to JWK format for verification
                    if isinstance(public_key, ec.EllipticCurvePublicKey):
                        numbers = public_key.public_numbers()
                        curve_name = public_key.curve.name

                        # Map curve names to JWK crv values
                        curve_map = {
                            "secp256r1": "P-256",
                            "secp384r1": "P-384",
                            "secp521r1": "P-521",
                        }

                        crv = curve_map.get(curve_name)
                        if not crv:
                            logger.debug(f"Attester cert {idx}: Unsupported curve {curve_name}")
                            continue

                        # Get coordinate byte lengths
                        coord_byte_length = {
                            "P-256": 32,
                            "P-384": 48,
                            "P-521": 66,
                        }[crv]

                        x_bytes = numbers.x.to_bytes(coord_byte_length, "big")
                        y_bytes = numbers.y.to_bytes(coord_byte_length, "big")

                        jwk_dict = {
                            "kty": "EC",
                            "crv": crv,
                            "x": base64.urlsafe_b64encode(x_bytes).decode().rstrip("="),
                            "y": base64.urlsafe_b64encode(y_bytes).decode().rstrip("="),
                        }

                    elif isinstance(public_key, rsa.RSAPublicKey):
                        numbers = public_key.public_numbers()

                        n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                        e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")

                        jwk_dict = {
                            "kty": "RSA",
                            "n": base64.urlsafe_b64encode(n_bytes).decode().rstrip("="),
                            "e": base64.urlsafe_b64encode(e_bytes).decode().rstrip("="),
                        }
                    else:
                        logger.debug(
                            f"Attester cert {idx}: Unsupported key type {type(public_key)}"
                        )
                        continue

                    # Create key and verify
                    if jwk_dict["kty"] == "EC":
                        key = ECKey(**jwk_dict)
                    else:
                        key = RSAKey(**jwk_dict)

                    wia_jws = factory(_wia_raw)

                    try:
                        verified_payload = wia_jws.verify_compact(_wia_raw, keys=[key])
                        logger.info(
                            f"WIA signature verified with trusted attester (cert {idx}): {_iss}"
                        )
                        signature_verified = True
                        break
                    except Exception as verify_error:
                        raise verify_error

                except Exception as e:
                    # Try next certificate
                    error_msg = f"Attester cert {idx}: {type(e).__name__}: {str(e)}"
                    logger.debug(error_msg)
                    verification_errors.append(error_msg)
                    continue

        if not signature_verified:
            logger.error(
                f"WIA signature could not be verified with any trusted attester. Errors: {verification_errors}"
            )
            raise ClientAuthenticationError(
                "WIA signature verification failed: no trusted attester matched."
            )

        # 2. Check REQUIRED Claims: 'iss', 'sub', 'exp', 'cnf'
        required_claims = ["iss", "sub", "exp", "cnf"]
        for claim in required_claims:
            if claim not in _wia:
                logger.error(f"WIA missing required claim: {claim}")
                raise ClientAuthenticationError(
                    f"Client Attestation missing required claim: {claim}."
                )

        # 2. Check 'alg' in header (REQUIRED)
        _alg = _wia_headers.get("alg")
        if not _alg:
            logger.error("WIA header is missing the 'alg' parameter.")
            raise ClientAuthenticationError("WIA must contain a signature algorithm ('alg').")

        if _alg not in ALLOWED_ASYM_ALGS:
            logger.error(f"WIA signature algorithm '{_alg}' is not in the allowed list.")
            raise ClientAuthenticationError("WIA uses a disallowed signature algorithm.")

        try:
            _jwk = _wia["cnf"]["jwk"]
        except KeyError:
            logger.error("WIA missing 'cnf.jwk' for PoP signature verification.")
            raise ClientAuthenticationError("Missing public key in WIA 'cnf' claim.")

        request_client_id = request.get("client_id")
        wia_sub = _wia.get("sub")
        redirect_uri = request.get("redirect_uri")

        if request_client_id is not None and redirect_uri != "preauth":

            if not request_client_id:
                logger.error("Request body is missing the 'client_id' parameter.")
                # Reject if the request context doesn't have the client_id to compare against
                raise ClientAuthenticationError("Missing 'client_id' in request.")

            if wia_sub != request_client_id:
                logger.error(
                    f"WIA 'sub' ({wia_sub}) does not match request 'client_id' ({request_client_id})."
                )
                raise ClientAuthenticationError(
                    "Client Attestation subject ('sub') must match the request 'client_id'."
                )

            logger.info(f"WIA 'sub' matches request 'client_id': {wia_sub} == {request_client_id}")

        else:
            logger.info("No client_id. Skipping 'sub' vs 'client_id' check.")

        # 3. Check 'cnf' structure and 'jwk' existence
        _jwk = _wia["cnf"].get("jwk")
        if not _jwk or not isinstance(_jwk, dict):
            logger.error("WIA 'cnf' claim missing required 'jwk'.")
            raise ClientAuthenticationError("Client Attestation 'cnf' claim is malformed.")

        # 3a. Ensure the JWK is NOT a private key
        private_fields = {"d", "p", "q", "dp", "dq", "qi"}
        found_private_fields = private_fields.intersection(_jwk.keys())
        if found_private_fields:
            logger.error(f"WIA 'jwk' contains private key parameters: {found_private_fields}")
            raise ClientAuthenticationError(
                "Client Attestation 'jwk' must not contain private key material."
            )

        # 4. Check 'exp' (Expiration Time) with clock skew
        # The current time minus the skew must be BEFORE the expiration time.
        if (_now - CLOCK_SKEW) >= _wia["exp"]:
            logger.error(
                f"WIA expired at {datetime.fromtimestamp(_wia['exp'])}, current time is too far past."
            )
            raise ClientAuthenticationError(
                "Client Attestation has expired (expired time is before current time minus skew)."
            )

        # 5. Check 'nbf' (Not Before) - OPTIONAL but must be respected if present
        _nbf = _wia.get("nbf")
        if _nbf and (_now + CLOCK_SKEW) <= _nbf:
            logger.error(f"WIA not yet valid (nbf: {datetime.fromtimestamp(_nbf)})")
            raise ClientAuthenticationError("Client Attestation is not yet valid.")

        # 6. Check 'iat' (Issued At) - OPTIONAL but used for ATTESTATION_MAX_AGE freshness
        _iat = _wia.get("iat")
        if _iat:
            # Check freshness: iat must be within ATTESTATION_MAX_AGE seconds
            if (_now - _iat) > ATTESTATION_MAX_AGE:
                logger.error(f"WIA is too old (iat: {datetime.fromtimestamp(_iat)})")
                raise ClientAuthenticationError("Client Attestation is too old (max age exceeded).")

        # --- End WIA Claim Validity Checks ---

        logger.info(f"Verified WIA: ", _wia)

    def _verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        get_client_id_from_token: Optional[Callable] = None,
        http_info: Optional[dict] = None,
        **kwargs,
    ):

        ATTESTATION_MAX_AGE = 3600  # seconds: how fresh attestation must be
        POP_TIME_WINDOW = 300  # seconds: PoP iat must be within +/- this window
        CLOCK_SKEW = 30
        # Allowed asymmetric signature algorithms (registered asymmetric JOSE algs)
        ALLOWED_ASYM_ALGS = {
            "ES256",
            "ES384",
            "ES512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
        }

        if not http_info or "headers" not in http_info:
            logger.error("Missing http_info or headers")
            raise ClientAuthenticationError("Missing http_info or headers")

        headers = {k.lower(): v for k, v in http_info["headers"].items()}

        if "oauth-client-attestation" not in headers:
            logger.error("Missing OAuth-Client-Attestation header")
            raise ClientAuthenticationError("Missing OAuth-Client-Attestation header")

        if "oauth-client-attestation-pop" not in headers:
            logger.error("Missing OAuth-Client-Attestation-PoP header")
            raise ClientAuthenticationError("Missing OAuth-Client-Attestation-PoP header")

        wia_raw = headers["oauth-client-attestation"]
        pop_raw = headers["oauth-client-attestation-pop"]

        if "," in wia_raw:
            logger.error("OAuth-Client-Attestation header contains multiple values")
            raise ClientAuthenticationError(
                "OAuth-Client-Attestation header contains multiple values"
            )

        if "," in pop_raw:
            logger.error("OAuth-Client-Attestation-PoP header contains multiple values")
            raise ClientAuthenticationError(
                "OAuth-Client-Attestation-PoP header contains multiple values"
            )

        logger.info(f"OAuth-Client-Attestation: {wia_raw}")
        logger.info(f"OAuth-Client-Attestation-PoP: {pop_raw}")

        trust_validator_url = kwargs.get("trust_validator_url")

        trusted_attesters = None

        if trust_validator_url:
            logger.info(f"Using trust validator URL: {trust_validator_url}")

        else:
            trusted_attesters_path = kwargs.get("trusted_attesters_path")
            if not trusted_attesters_path:
                logger.error("No trusted_attesters_path provided in kwargs")
                raise ClientAuthenticationError("Missing trusted attesters configuration")

            if not os.path.isdir(trusted_attesters_path):
                logger.error(f"trusted_attesters_path is not a directory: {trusted_attesters_path}")
                raise ClientAuthenticationError("trusted_attesters_path must be a directory")

            # Load all PEM certificates from directory
            trusted_attesters = []
            for filename in os.listdir(trusted_attesters_path):
                if filename.endswith((".pem")):
                    filepath = os.path.join(trusted_attesters_path, filename)
                    try:
                        with open(filepath, "r") as f:
                            cert_pem = f.read()
                            trusted_attesters.append(cert_pem)
                            logger.debug(f"Loaded attester certificate: {filename}")
                    except Exception as e:
                        logger.warning(f"Failed to load certificate {filename}: {e}")
                        continue

            if not trusted_attesters:
                logger.error(f"No valid certificates found in {trusted_attesters_path}")
                raise ClientAuthenticationError("No trusted attester certificates found")

            logger.info(f"Loaded {len(trusted_attesters)} trusted attester certificate(s)")

        oas = topmost_unit(self)

        logger.info(f"oas: {oas.context.keyjar}")

        jws = factory(wia_raw)

        jws = factory(wia_raw)
        _wia_headers = jws.jwt.headers
        _wia = jws.jwt.payload()

        self.verify_oath_attestation(
            _wia_headers=_wia_headers,
            _wia=_wia,
            _wia_raw=wia_raw,
            request=request,
            ATTESTATION_MAX_AGE=ATTESTATION_MAX_AGE,
            CLOCK_SKEW=CLOCK_SKEW,
            ALLOWED_ASYM_ALGS=ALLOWED_ASYM_ALGS,
            trusted_attesters=trusted_attesters,
            trust_validator_url=trust_validator_url,
        )

        self.verify_pop(
            _wia=_wia,
            _pop_raw=pop_raw,
            POP_TIME_WINDOW=POP_TIME_WINDOW,
            CLOCK_SKEW=CLOCK_SKEW,
            ALLOWED_ASYM_ALGS=ALLOWED_ASYM_ALGS,
        )

        # Get the header
        print("Header:")
        print(json.dumps(jws.jwt.headers, indent=2))

        # Get the payload (decoded but not verified)
        print("\nPayload:")
        print(json.dumps(jws.jwt.payload(), indent=2))

        # Should be a key in there

        _c_info = {
            "client_id": request["client_id"],
            "redirect_uris": [(request["redirect_uri"], {})],
        }

        # Add metadata from the WIE/WIA
        for key, val in self.metadata.items():
            _val = _wia.get(key, None)
            if _val:
                _c_info[key] = _val

        oas.context.cdb[request["client_id"]] = _c_info

        return {"client_id": request["client_id"], "jwt": _wia}


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

    print("\n-------------at client_auth verify_client------------------------")

    if http_info and "headers" in http_info:
        authorization_token = http_info["headers"].get("authorization")
        if not authorization_token:
            authorization_token = http_info["headers"].get("Authorization")

        if "dpop" in http_info["headers"]:
            authorization_token = f"DPoP {http_info['headers'].get('dpop')}"
    else:
        authorization_token = None

    print("\nverify_client authorization_token", authorization_token)

    auth_info = {}

    _context = endpoint.upstream_get("context")

    print("\ncontext client_authn_methods: ", _context.client_authn_methods)

    methods = getattr(_context, "client_authn_methods", None)

    client_id = None
    allowed_methods = getattr(endpoint, "client_authn_method")
    if not allowed_methods:
        allowed_methods = list(methods.keys())  # If not specific for this endpoint then all

    print("\n-------------allowed_methods: ", allowed_methods)
    print("\n-------------http_info: ", http_info)

    _method = None
    _cdb = _cinfo = None
    _tested = []
    for _method in (methods[meth] for meth in allowed_methods):
        print("\n-------------_method: ", _method)
        if not _method.is_usable(
            request=request,
            authorization_token=authorization_token,
            http_info=http_info,
        ):
            print("\n-------------not usable: ", _method)
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

    logger.debug(f"Authn methods applied")
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
