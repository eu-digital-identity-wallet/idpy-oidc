"""Exact OAuth error codes of the token side of the authorization server.

The server is set up like the credential issuer's AS (OpenID4VCI / HAIP): the
OIDC token endpoint with PKCE (S256, essential) and DPoP add-ons, pushed
authorization, introspection and wallet attestation client authentication.

Each test asserts the ``error`` value the governing specification requires,
not only that there is an error. Client authentication failures are raised
(ClientAuthenticationError and subclasses), which the AS answers with 401
invalid_client (RFC 6749 section 5.2).

The pre-authorized code grant (OpenID4VCI) is implemented by the AS, not here;
the jwt-bearer grant is advertised by the AS but has no helper in this library.
"""

import hashlib
import os
import time
import uuid

import pytest
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.utils import b64e

from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.oauth2.add_on.dpop import DPoPProof
from idpyoidc.server.oauth2.introspection import Introspection
from idpyoidc.server.oauth2.pushed_authorization import PushedAuthorization
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

BASEDIR = os.path.abspath(os.path.dirname(__file__))

ISSUER = "https://example.com"
TOKEN_URL = f"{ISSUER}/token"
REDIRECT_URI = "https://example.com/cb"

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
]

CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" * 2
CODE_CHALLENGE = b64e(hashlib.sha256(CODE_VERIFIER.encode()).digest()).decode()

CLIENT_AUTHN = ["client_secret_post", "wallet_attestation"]


def server_conf(trusted_attesters_path=None):
    """Mirrors the AS configuration (config.yaml) as far as this library is concerned."""
    _token_kwargs = {"client_authn_method": CLIENT_AUTHN}
    if trusted_attesters_path:
        _token_kwargs["trusted_attesters_path"] = trusted_attesters_path
    return {
        "issuer": ISSUER,
        "httpc_params": {"verify": False, "timeout": 1},
        "preference": {
            "subject_types_supported": ["public", "pairwise"],
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "refresh_token",
            ],
        },
        "add_ons": {
            "pkce": {
                "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
                "kwargs": {"essential": True, "code_challenge_methods": ["S256"]},
            },
            "dpop": {
                "function": "idpyoidc.server.oauth2.add_on.dpop.add_support",
                "kwargs": {
                    "dpop_signing_alg_values_supported": ["ES256"],
                    "allowed_htu": [TOKEN_URL],
                },
            },
        },
        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
        "token_handler_args": {
            "jwks_def": {
                "private_path": "private/token_jwks.json",
                "read_only": False,
                "key_defs": [
                    {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "code"},
                    {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "refresh"},
                ],
            },
            "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "token": {
                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"]},
            },
            "refresh": {
                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                "kwargs": {"lifetime": 86400, "aud": ["https://example.org/appl"]},
            },
            "id_token": {"class": "idpyoidc.server.token.id_token.IDToken", "kwargs": {}},
        },
        "cookie_handler": {
            "class": CookieHandler,
            "kwargs": {"keys": {"key_defs": COOKIE_KEYDEFS}},
        },
        "endpoint": {
            "provider_config": {
                "path": ".well-known/openid-configuration",
                "class": ProviderConfiguration,
                "kwargs": {"client_authn_method": None},
            },
            "authorization": {
                "path": "authorization",
                "class": Authorization,
                "kwargs": {
                    "client_authn_method": None,
                    "response_types_supported": ["code"],
                    "response_modes_supported": ["query", "fragment", "form_post"],
                },
            },
            "pushed_authorization": {
                "path": "pushed_authorization",
                "class": PushedAuthorization,
                "kwargs": {"client_authn_method": CLIENT_AUTHN},
            },
            "token": {"path": "token", "class": Token, "kwargs": _token_kwargs},
            "introspection": {
                "path": "introspection",
                "class": Introspection,
                "kwargs": {"client_authn_method": None, "release": ["username"]},
            },
        },
        "authentication": {
            "anon": {
                "acr": INTERNETPROTOCOLPASSWORD,
                "class": "idpyoidc.server.user_authn.user.NoAuthn",
                "kwargs": {"user": "diana"},
            }
        },
        "userinfo": {"class": "idpyoidc.server.user_info.UserInfo", "kwargs": {"db": {}}},
        "client_authn": verify_client,
        "template_dir": "template",
        "authz": {
            "class": AuthzHandling,
            "kwargs": {
                "grant_config": {
                    "usage_rules": {
                        "authorization_code": {
                            "supports_minting": ["access_token", "refresh_token"],
                            "max_usage": 1,
                            "expires_in": 600,
                        },
                        "access_token": {"expires_in": 300},
                        "refresh_token": {
                            "supports_minting": ["access_token", "refresh_token"],
                            "expires_in": 604800,
                        },
                    },
                    "expires_in": 2592000,
                }
            },
        },
        "session_params": SESSION_PARAMS,
    }


def make_server(trusted_attesters_path=None):
    server = Server(OPConfiguration(conf=server_conf(trusted_attesters_path), base_path=BASEDIR), cwd=BASEDIR)
    for client_id in ("client_1", "client_2"):
        server.context.cdb[client_id] = {
            "client_id": client_id,
            "client_secret": f"{client_id}-secret",
            "redirect_uris": [(REDIRECT_URI, None)],
            "response_types_supported": ["code"],
            "allowed_scopes": ["openid", "eu.europa.ec.eudi.pid.1"],
        }
    return server


def dpop_proof(key=None, htu=TOKEN_URL, htm="POST", iat=None):
    key = key or new_ec_key(crv="P-256")
    _dpop = DPoPProof(
        typ="dpop+jwt",
        alg="ES256",
        jwk=key.serialize(),
        jti=str(uuid.uuid4()),
        htm=htm,
        htu=htu,
        iat=iat or int(time.time()),
    )
    _dpop.key = key
    return _dpop.create_header()


def http_info(proof=None, **headers):
    _headers = dict(headers)
    if proof:
        _headers["dpop"] = proof
    return {"headers": _headers, "url": TOKEN_URL, "method": "POST"}


AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri=REDIRECT_URI,
    scope=["openid", "eu.europa.ec.eudi.pid.1"],
    state="STATE",
    response_type="code",
    code_challenge=CODE_CHALLENGE,
    code_challenge_method="S256",
)


def assert_error(response, error):
    assert isinstance(response, ResponseMessage), response
    assert response["error"] == error, response.to_dict()


class TestTokenEndpoint:
    """RFC 6749 section 5.2 (and RFC 7636 section 4.6) at the token endpoint."""

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.server = make_server()
        self.context = self.server.context
        self.session_manager = self.context.session_manager
        self.token_endpoint = self.server.get_endpoint("token")
        self.user_id = "diana"

    def _code(self, auth_req=AUTH_REQ):
        ae = create_authn_event(self.user_id)
        session_id = self.session_manager.create_session(
            ae, auth_req, self.user_id, client_id=auth_req["client_id"]
        )
        grant = self.session_manager[session_id]
        usage_rules = grant.usage_rules.get("authorization_code", {})
        code = grant.mint_token(
            session_id=session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=self.session_manager.token_handler["authorization_code"],
            usage_rules=usage_rules,
        )
        code.expires_at = utc_time_sans_frac() + usage_rules.get("expires_in", 600)
        return grant, code

    def _token_request(self, code=None, client_id="client_1", **overrides):
        req = {
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "client_secret": f"{client_id}-secret",
            "code_verifier": CODE_VERIFIER,
        }
        if code is not None:
            req["code"] = code.value if hasattr(code, "value") else code
        req.update(overrides)
        return {k: v for k, v in req.items() if v is not None}

    def _token(self, request, info=None):
        """Parse and, if that passed, process a token request."""
        _req = self.token_endpoint.parse_request(request, http_info=info or http_info())
        if isinstance(_req, ResponseMessage) and "error" in _req:
            return _req
        _resp = self.token_endpoint.process_request(_req)
        if isinstance(_resp, ResponseMessage):
            return _resp
        return _resp["response_args"]

    def _refresh_token(self, key=None):
        _, code = self._code()
        _resp = self._token(self._token_request(code), http_info(dpop_proof(key)))
        return _resp["refresh_token"]

    def test_valid_code_redemption(self):
        _, code = self._code()
        _resp = self._token(self._token_request(code), http_info(dpop_proof()))
        assert "access_token" in _resp
        assert _resp["token_type"] == "DPoP"

    # --- grant_type -------------------------------------------------------

    def test_missing_grant_type_is_invalid_request(self):
        _, code = self._code()
        assert_error(self._token(self._token_request(code, grant_type=None)), "invalid_request")

    def test_unknown_grant_type_is_unsupported_grant_type(self):
        # RFC 6749 section 5.2: "The authorization grant type is not supported
        # by the authorization server."
        _, code = self._code()
        _req = self._token_request(code, grant_type="urn:example:unknown")
        assert_error(self._token(_req), "unsupported_grant_type")

    def test_advertised_grant_type_without_helper_is_unsupported_grant_type(self):
        # jwt-bearer is in grant_types_supported, but nothing here handles it.
        _req = self._token_request(
            grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer", assertion="x.y.z"
        )
        assert_error(self._token(_req), "unsupported_grant_type")

    def test_grant_type_not_allowed_for_client_is_unauthorized_client(self):
        # RFC 6749 section 5.2: "The authenticated client is not authorized to
        # use this authorization grant type."
        self.context.cdb["client_1"]["grant_types_supported"] = ["authorization_code"]
        _req = {
            "grant_type": "refresh_token",
            "refresh_token": "anything",
            "client_id": "client_1",
            "client_secret": "client_1-secret",
        }
        assert_error(self._token(_req), "unauthorized_client")

    # --- authorization_code grant -----------------------------------------

    def test_missing_code_is_invalid_request(self):
        assert_error(self._token(self._token_request()), "invalid_request")

    @pytest.mark.parametrize("value", ["not-a-code", "Zm9vYmFy", "a.b.c"])
    def test_unknown_code_is_invalid_grant(self, value):
        assert_error(self._token(self._token_request(value)), "invalid_grant")

    def test_expired_code_is_invalid_grant(self):
        _, code = self._code()
        code.expires_at = utc_time_sans_frac() - 10
        assert_error(self._token(self._token_request(code)), "invalid_grant")

    def test_reused_code_is_invalid_grant(self):
        _, code = self._code()
        assert "access_token" in self._token(self._token_request(code), http_info(dpop_proof()))
        assert_error(self._token(self._token_request(code)), "invalid_grant")

    def test_revoked_code_is_invalid_grant(self):
        _, code = self._code()
        code.revoke()
        assert_error(self._token(self._token_request(code)), "invalid_grant")

    def test_refresh_token_as_code_is_invalid_grant(self):
        _refresh = self._refresh_token()
        assert_error(self._token(self._token_request(_refresh)), "invalid_grant")

    def test_code_issued_to_another_client_is_invalid_grant(self):
        _, code = self._code()
        _req = self._token_request(code, client_id="client_2")
        assert_error(self._token(_req), "invalid_grant")

    def test_redirect_uri_mismatch_is_invalid_grant(self):
        # RFC 6749 section 5.2: the grant "does not match the redirection URI
        # used in the authorization request".
        _, code = self._code()
        _req = self._token_request(code, redirect_uri="https://example.com/other")
        assert_error(self._token(_req), "invalid_grant")

    def test_missing_redirect_uri_is_invalid_request(self):
        # RFC 6749 section 4.1.3: redirect_uri is REQUIRED when the
        # authorization request had one; a missing required parameter is
        # invalid_request (section 5.2).
        _, code = self._code()
        _req = self._token_request(code, redirect_uri=None)
        assert_error(self._token(_req), "invalid_request")

    # --- PKCE (RFC 7636 section 4.6) --------------------------------------

    def test_pkce_wrong_verifier_is_invalid_grant(self):
        _, code = self._code()
        _req = self._token_request(code, code_verifier="x" * 64)
        assert_error(self._token(_req), "invalid_grant")

    def test_pkce_missing_verifier_is_invalid_grant(self):
        _, code = self._code()
        _req = self._token_request(code, code_verifier=None)
        assert_error(self._token(_req), "invalid_grant")

    # --- refresh_token grant ----------------------------------------------

    def _refresh_request(self, refresh_token, **overrides):
        req = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "client_1",
            "client_secret": "client_1-secret",
        }
        req.update(overrides)
        return {k: v for k, v in req.items() if v is not None}

    def test_valid_refresh(self):
        key = new_ec_key(crv="P-256")
        _refresh = self._refresh_token(key)
        _resp = self._token(self._refresh_request(_refresh), http_info(dpop_proof(key)))
        assert "access_token" in _resp

    def test_missing_refresh_token_is_invalid_request(self):
        _req = self._refresh_request(None)
        assert_error(self._token(_req), "invalid_request")

    @pytest.mark.parametrize("value", ["not-a-token", "a.b.c"])
    def test_unknown_refresh_token_is_invalid_grant(self, value):
        assert_error(self._token(self._refresh_request(value)), "invalid_grant")

    def test_code_as_refresh_token_is_invalid_grant(self):
        _, code = self._code()
        assert_error(self._token(self._refresh_request(code.value)), "invalid_grant")

    def test_refresh_token_of_another_client_is_invalid_grant(self):
        key = new_ec_key(crv="P-256")
        _refresh = self._refresh_token(key)
        _req = self._refresh_request(
            _refresh, client_id="client_2", client_secret="client_2-secret"
        )
        assert_error(self._token(_req, http_info(dpop_proof(key))), "invalid_grant")

    def test_refresh_with_broader_scope_is_invalid_scope(self):
        # RFC 6749 section 6: the scope MUST NOT include any scope not
        # originally granted; section 5.2 invalid_scope.
        key = new_ec_key(crv="P-256")
        _refresh = self._refresh_token(key)
        _req = self._refresh_request(_refresh, scope="openid profile")
        assert_error(self._token(_req, http_info(dpop_proof(key))), "invalid_scope")

    # --- DPoP (RFC 9449) --------------------------------------------------

    def test_invalid_dpop_proof_is_invalid_dpop_proof(self):
        # RFC 9449 section 5: "error" is invalid_dpop_proof.
        _, code = self._code()
        _proof = dpop_proof(htu="https://evil.example.com/token")
        assert_error(self._token(self._token_request(code), http_info(_proof)), "invalid_dpop_proof")

    def test_dpop_proof_wrong_method_is_invalid_dpop_proof(self):
        _, code = self._code()
        _proof = dpop_proof(htm="GET")
        assert_error(self._token(self._token_request(code), http_info(_proof)), "invalid_dpop_proof")

    def test_malformed_dpop_proof_is_invalid_dpop_proof(self):
        _, code = self._code()
        assert_error(
            self._token(self._token_request(code), http_info("not-a-jwt")), "invalid_dpop_proof"
        )

    def test_dpop_error_survives_process_request(self):
        # The parse result is handed to process_request by callers that do not
        # check it first: the DPoP error must not turn into another error.
        _, code = self._code()
        _req = self.token_endpoint.parse_request(
            self._token_request(code), http_info=http_info(dpop_proof(htm="GET"))
        )
        assert_error(self.token_endpoint.process_request(_req), "invalid_dpop_proof")

    def test_refresh_with_other_dpop_key_is_invalid_dpop_proof(self):
        # RFC 9449 section 5: a refresh token of a DPoP-bound grant is used
        # with that key only. The RFC names no code for the mismatch; the
        # proof is the part that is wrong, so invalid_dpop_proof.
        _refresh = self._refresh_token(new_ec_key(crv="P-256"))
        _req = self._refresh_request(_refresh)
        assert_error(self._token(_req, http_info(dpop_proof())), "invalid_dpop_proof")

    def test_refresh_without_dpop_of_bound_grant_is_refused(self):
        _refresh = self._refresh_token(new_ec_key(crv="P-256"))
        assert_error(self._token(self._refresh_request(_refresh)), "invalid_dpop_proof")

    def test_code_bound_with_dpop_jkt_refuses_other_key(self):
        key = new_ec_key(crv="P-256")
        _areq = AUTH_REQ.copy()
        _areq["dpop_jkt"] = key.thumbprint("SHA-256").decode()
        _, code = self._code(_areq)
        assert_error(self._token(self._token_request(code), http_info(dpop_proof())), "invalid_dpop_proof")

    # --- client authentication (RFC 6749 sections 2.3 and 5.2) ------------

    def test_wrong_client_secret_is_client_authentication_error(self):
        _, code = self._code()
        _req = self._token_request(code, client_secret="wrong")
        with pytest.raises(ClientAuthenticationError):
            self.token_endpoint.parse_request(_req, http_info=http_info())

    def test_unknown_client_is_client_authentication_error(self):
        _, code = self._code()
        _req = self._token_request(code, client_id="unknown", client_secret="x")
        with pytest.raises(ClientAuthenticationError):
            self.token_endpoint.parse_request(_req, http_info=http_info())

    def test_no_client_authentication_is_client_authentication_error(self):
        _, code = self._code()
        _req = self._token_request(code, client_secret=None)
        with pytest.raises(ClientAuthenticationError):
            self.token_endpoint.parse_request(_req, http_info=http_info())


class TestIntrospection:
    """RFC 7662 section 2.2: an unusable token is {"active": false} with 200, not an error."""

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.server = make_server()
        self.context = self.server.context
        self.session_manager = self.context.session_manager
        self.endpoint = self.server.get_endpoint("introspection")
        self.user_id = "diana"

    def _access_token(self):
        ae = create_authn_event(self.user_id)
        session_id = self.session_manager.create_session(
            ae, AUTH_REQ, self.user_id, client_id="client_1"
        )
        grant = self.session_manager[session_id]
        grant.resources = ["client_1"]
        token = grant.mint_token(
            session_id=session_id,
            context=self.context,
            token_class="access_token",
            token_handler=self.session_manager.token_handler["access_token"],
            usage_rules=grant.usage_rules.get("access_token", {}),
        )
        token.expires_at = utc_time_sans_frac() + 300
        return session_id, token

    def _introspect(self, token_value):
        _req = self.endpoint.parse_request({"token": token_value})
        _resp = self.endpoint.process_request(_req)
        assert "response_code" not in _resp  # 200
        return _resp["response_args"]

    def test_active_token(self):
        _, token = self._access_token()
        assert self._introspect(token.value)["active"] is True

    @pytest.mark.parametrize("value", ["not-a-token", "a.b.c", "Zm9vYmFy"])
    def test_unknown_token_is_inactive(self, value):
        assert self._introspect(value).to_dict() == {"active": False}

    def test_expired_token_is_inactive(self):
        _, token = self._access_token()
        token.expires_at = utc_time_sans_frac() - 10
        assert self._introspect(token.value).to_dict() == {"active": False}

    def test_jwt_expired_token_is_inactive(self, monkeypatch):
        _, token = self._access_token()
        monkeypatch.setattr("idpyoidc.server.token.jwt_token.is_expired", lambda *a, **k: True)
        assert self._introspect(token.value).to_dict() == {"active": False}

    def test_revoked_token_is_inactive(self):
        session_id, token = self._access_token()
        self.session_manager.revoke_token(session_id, token.value)
        assert self._introspect(token.value).to_dict() == {"active": False}

    def test_missing_token_is_invalid_request(self):
        # RFC 7662 section 2.3: an invalid request is answered as in RFC 6749
        # section 5.2.
        assert_error(self.endpoint.parse_request({}), "invalid_request")


class TestWalletAttestation:
    """Attestation-based client authentication (draft-ietf-oauth-attestation-based-client-auth).

    Every failure is a client authentication error: invalid_client with 401
    (RFC 6749 section 5.2; the draft, section 7.4, allows the more specific
    invalid_client_attestation in addition). Server challenges
    (use_attestation_challenge) are not implemented.
    """

    @pytest.fixture(autouse=True)
    def create_endpoint(self, tmp_path):
        from .test_server_70_wia_client_authn import CLIENT_ID
        from .test_server_70_wia_client_authn import Pki
        from .test_server_70_wia_client_authn import _pem

        self.client_id = CLIENT_ID
        self.pki = Pki()
        (tmp_path / "ca.pem").write_text(_pem(self.pki.ca))
        self.server = make_server(trusted_attesters_path=str(tmp_path))
        self.par_endpoint = self.server.get_endpoint("pushed_authorization")
        self.token_endpoint = self.server.get_endpoint("token")

    def _headers(self, wia=None, pop=None, aud=ISSUER):
        from .test_server_70_wia_client_authn import make_pop
        from .test_server_70_wia_client_authn import make_wia

        return {
            "oauth-client-attestation": wia if wia is not None else make_wia(self.pki),
            "oauth-client-attestation-pop": pop if pop is not None else make_pop(self.pki, aud=aud),
        }

    def _push(self, headers):
        _args = {
            "client_id": self.client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid",
            "code_challenge": CODE_CHALLENGE,
            "code_challenge_method": "S256",
        }
        return self.par_endpoint.parse_request(_args, http_info={"headers": headers})

    def test_valid_attestation(self):
        _req = self._push(self._headers())
        assert "error" not in _req
        assert _req["authenticated"] is True

    def test_pop_for_another_audience(self):
        with pytest.raises(ClientAuthenticationError):
            self._push(self._headers(aud="https://other.example.com"))

    def test_untrusted_attestation(self):
        from .test_server_70_wia_client_authn import Pki
        from .test_server_70_wia_client_authn import make_wia

        with pytest.raises(ClientAuthenticationError):
            self._push(self._headers(wia=make_wia(Pki())))

    def test_malformed_attestation(self):
        with pytest.raises(ClientAuthenticationError):
            self._push(self._headers(wia="not-a-jwt"))

    def test_attestation_without_pop(self):
        _headers = self._headers()
        del _headers["oauth-client-attestation-pop"]
        with pytest.raises(ClientAuthenticationError):
            self._push(_headers)

    def test_token_request_with_bad_attestation(self):
        _req = {
            "grant_type": "authorization_code",
            "code": "anything",
            "redirect_uri": REDIRECT_URI,
            "client_id": self.client_id,
            "code_verifier": CODE_VERIFIER,
        }
        with pytest.raises(ClientAuthenticationError):
            self.token_endpoint.parse_request(
                _req, http_info=http_info(**self._headers(aud="https://other.example.com"))
            )
