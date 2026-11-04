"""Coverage tests for idpyoidc.server.oauth2.add_on.pkce."""

import hashlib
import logging
from types import SimpleNamespace

import pytest
from cryptojwt.utils import b64e

from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import CCAccessTokenRequest
from idpyoidc.message.oauth2 import RefreshAccessTokenRequest
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.oauth2.add_on import pkce
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.server.oauth2.token import Token

ISSUER = "https://example.com/"
CLIENT_ID = "client_1"
VERIFIER = "dBjftJeZ4CVP-mJ92K9qPdrb1eA5DVL2yI3tO8f0sJ"  # 42 unreserved characters

CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}


# ---------------------------------------------------------------------------
# Light-weight context used for start-up and authorization request checks


class _Endpoint:
    def __init__(self, context):
        self.post_parse_request = []
        self._context = context

    def upstream_get(self, what, *args):
        return self._context


def _light_context(client=None):
    prefs = {}
    context = SimpleNamespace(
        cdb={"client": client or {}},
        add_on={},
        set_preference=lambda key, val: prefs.__setitem__(key, val),
        prefs=prefs,
    )
    return context


def _endpoints(context, par=False):
    endpoints = {"authorization": _Endpoint(context), "token": _Endpoint(context)}
    if par:
        endpoints["pushed_authorization"] = _Endpoint(context)
    return endpoints


def _authz_request(**extra):
    return AuthorizationRequest(
        client_id="client", response_type="code", redirect_uri="https://w.example/cb", **extra
    )


def _is_error(result):
    return isinstance(result, AuthorizationErrorResponse)


class TestCodeChallengeMethods:
    def test_plain(self):
        assert pkce.CC_METHOD["plain"]("abc") == "abc"

    @pytest.mark.parametrize(
        "name,hfun",
        [("S256", hashlib.sha256), ("S384", hashlib.sha384), ("S512", hashlib.sha512)],
    )
    def test_hashes(self, name, hfun):
        expected = b64e(hfun(VERIFIER.encode("ascii")).digest()).decode("ascii")
        assert pkce.CC_METHOD[name](VERIFIER) == expected
        assert "=" not in expected

    def test_verify_code_challenge(self):
        challenge = pkce.CC_METHOD["S256"](VERIFIER)
        assert pkce.verify_code_challenge(VERIFIER, challenge) is True
        assert pkce.verify_code_challenge(VERIFIER + "x", challenge) is False
        assert pkce.verify_code_challenge("abc", "abc", "plain") is True
        assert pkce.verify_code_challenge("abc", "abd", "plain") is False


class TestAddSupport:
    def test_default_methods(self):
        context = _light_context()
        endpoints = _endpoints(context)
        pkce.add_support(endpoints)
        assert context.add_on["pkce"]["code_challenge_methods"] is pkce.CC_METHOD
        assert context.add_on["pkce"]["essential"] is False
        assert context.prefs["code_challenge_methods_supported"] == list(pkce.CC_METHOD)
        assert endpoints["authorization"].post_parse_request == [pkce.post_authn_parse]
        assert endpoints["token"].post_parse_request == [pkce.post_token_parse]

    def test_method_list(self):
        context = _light_context()
        pkce.add_support(_endpoints(context), code_challenge_methods=["S256", "S512"])
        methods = context.add_on["pkce"]["code_challenge_methods"]
        assert list(methods) == ["S256", "S512"]
        assert methods["S256"] is pkce.CC_METHOD["S256"]
        assert context.prefs["code_challenge_methods_supported"] == ["S256", "S512"]

    def test_method_tuple(self):
        context = _light_context()
        pkce.add_support(_endpoints(context), code_challenge_methods=("S384",))
        assert list(context.add_on["pkce"]["code_challenge_methods"]) == ["S384"]

    def test_method_string(self):
        context = _light_context()
        pkce.add_support(_endpoints(context), code_challenge_methods="S256 S384")
        assert list(context.add_on["pkce"]["code_challenge_methods"]) == ["S256", "S384"]

    def test_method_dict(self):
        context = _light_context()
        cfg = {"S256": pkce.CC_METHOD["S256"]}
        pkce.add_support(_endpoints(context), code_challenge_methods=cfg, essential=True)
        assert context.add_on["pkce"] == {"code_challenge_methods": cfg, "essential": True}

    @pytest.mark.parametrize("methods", [["S256", "MD5"], {"nope": None}, "S256 S1"])
    def test_unknown_method_refused(self, methods):
        context = _light_context()
        with pytest.raises(ValueError, match="Unsupported method"):
            pkce.add_support(_endpoints(context), code_challenge_methods=methods)
        assert "pkce" not in context.add_on

    def test_misspelt_option(self):
        context = _light_context()
        with pytest.raises(ValueError, match="code_challenge_methods"):
            pkce.add_support(_endpoints(context), code_challenge_method="S256")

    def test_no_authorization_endpoint(self, caplog):
        context = _light_context()
        endpoints = {"token": _Endpoint(context)}
        with caplog.at_level(logging.WARNING):
            assert pkce.add_support(endpoints) is None
        assert "No authorization endpoint" in caplog.text
        assert endpoints["token"].post_parse_request == []
        assert "pkce" not in context.add_on

    def test_no_token_endpoint(self, caplog):
        context = _light_context()
        endpoints = {"authorization": _Endpoint(context)}
        with caplog.at_level(logging.WARNING):
            assert pkce.add_support(endpoints) is None
        assert "No token endpoint" in caplog.text
        assert endpoints["authorization"].post_parse_request == []

    def test_pushed_authorization_endpoint(self):
        context = _light_context()
        endpoints = _endpoints(context, par=True)
        pkce.add_support(endpoints)
        assert endpoints["pushed_authorization"].post_parse_request == [pkce.post_authn_parse]


def _configured(essential=True, methods=("S256",), client=None):
    context = _light_context(client)
    pkce.add_support(_endpoints(context), code_challenge_methods=list(methods), essential=essential)
    return context


class TestPostAuthnParse:
    def test_essential_missing_challenge(self):
        res = pkce.post_authn_parse(_authz_request(), "client", _configured())
        assert _is_error(res)
        assert res["error"] == "invalid_request"
        assert "Missing required code_challenge" in res["error_description"]

    def test_not_essential_missing_challenge(self):
        req = _authz_request()
        res = pkce.post_authn_parse(req, "client", _configured(essential=False))
        assert res is req
        # A default method is filled in, though no challenge was given
        assert res["code_challenge_method"] == "plain"

    def test_client_cannot_relax(self):
        ctx = _configured(essential=True, client={"pkce_essential": False})
        assert _is_error(pkce.post_authn_parse(_authz_request(), "client", ctx))

    def test_client_can_tighten(self):
        ctx = _configured(essential=False, client={"pkce_essential": True})
        assert _is_error(pkce.post_authn_parse(_authz_request(), "client", ctx))

    def test_pre_authorized_code_skips(self):
        req = _authz_request()
        res = pkce.post_authn_parse(req, "client", _configured(), pre_authorized_code=True)
        assert res is req

    def test_plain_refused(self):
        req = _authz_request(code_challenge="abc", code_challenge_method="plain")
        res = pkce.post_authn_parse(req, "client", _configured())
        assert _is_error(res)
        assert "Unsupported code_challenge_method=plain" in res["error_description"]

    def test_missing_method_defaults_to_plain_refused(self):
        req = _authz_request(code_challenge="abc")
        res = pkce.post_authn_parse(req, "client", _configured())
        assert _is_error(res)
        assert "plain" in res["error_description"]

    def test_plain_accepted_when_configured(self):
        req = _authz_request(code_challenge="abc")
        res = pkce.post_authn_parse(req, "client", _configured(methods=("plain", "S256")))
        assert not _is_error(res)
        assert res["code_challenge_method"] == "plain"

    def test_s256_accepted(self):
        req = _authz_request(code_challenge="abc", code_challenge_method="S256")
        res = pkce.post_authn_parse(req, "client", _configured())
        assert res is req
        assert res["code_challenge_method"] == "S256"


# ---------------------------------------------------------------------------
# Token side with a real server/session manager


@pytest.fixture
def server(tmp_path):
    conf = {
        "issuer": ISSUER,
        "httpc_params": {"verify": False},
        "keys": {"key_defs": [{"type": "RSA", "key": "", "use": ["sig"]}], "uri_path": "jwks.json"},
        "endpoint": {
            "authorization": {"path": "authorization", "class": Authorization, "kwargs": {}},
            "token": {
                "path": "token",
                "class": Token,
                "kwargs": {"client_authn_method": ["client_secret_post"]},
            },
        },
        "authentication": {
            "anon": {
                "acr": "http://www.swamid.se/policy/assurance/al1",
                "class": "idpyoidc.server.user_authn.user.NoAuthn",
                "kwargs": {"user": "diana"},
            }
        },
        "add_on": {
            "pkce": {
                "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
                "kwargs": {"essential": True, "code_challenge_methods": ["S256"]},
            }
        },
        "claims_interface": {
            "class": "idpyoidc.server.session.claims.OAuth2ClaimsInterface",
            "kwargs": {},
        },
        "session_params": {"encrypter": CRYPT_CONFIG},
        "token_handler_args": {
            "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "token": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        },
    }
    srv = Server(ASConfiguration(conf=conf, base_path=str(tmp_path)), cwd=str(tmp_path))
    srv.context.cdb[CLIENT_ID] = {
        "client_secret": "hemligt",
        "redirect_uris": [("https://example.com/cb", None)],
        "response_types": ["code"],
    }
    return srv


def _code(server, **authz_extra):
    context = server.context
    authz_req = AuthorizationRequest(
        client_id=CLIENT_ID,
        redirect_uri="https://example.com/cb",
        response_type="code",
        state="STATE",
        **authz_extra,
    )
    mngr = context.session_manager
    sid = mngr.create_session(create_authn_event("diana"), authz_req, "diana", client_id=CLIENT_ID)
    grant = mngr[sid]
    code = grant.mint_token(
        sid,
        context=context,
        token_class="authorization_code",
        token_handler=mngr.token_handler["authorization_code"],
    )
    return code.value


def _token_req(code, **extra):
    return AccessTokenRequest(
        client_id=CLIENT_ID,
        grant_type="authorization_code",
        redirect_uri="https://example.com/cb",
        code=code,
        **extra,
    )


class TestPostTokenParse:
    def test_configured_via_server(self, server):
        assert pkce.post_token_parse in server.get_endpoint("token").post_parse_request
        assert pkce.post_authn_parse in server.get_endpoint("authorization").post_parse_request
        assert list(server.context.add_on["pkce"]["code_challenge_methods"]) == ["S256"]

    @pytest.mark.parametrize(
        "request_obj",
        [
            AuthorizationErrorResponse(error="invalid_request"),
            RefreshAccessTokenRequest(refresh_token="x", grant_type="refresh_token"),
            TokenExchangeRequest(subject_token="x", subject_token_type="y"),
            CCAccessTokenRequest(grant_type="client_credentials"),
        ],
    )
    def test_passthrough_types(self, server, request_obj):
        assert pkce.post_token_parse(request_obj, CLIENT_ID, server.context) is request_obj

    def test_unknown_grant(self, server, monkeypatch):
        def _missing(*args, **kwargs):
            raise KeyError("no such grant")

        monkeypatch.setattr(
            server.context.session_manager, "get_session_info_by_token", _missing
        )
        res = pkce.post_token_parse(_token_req("whatever"), CLIENT_ID, server.context)
        assert isinstance(res, TokenErrorResponse)
        assert res["error"] == "invalid_grant"
        assert res["error_description"] == "Unknown access grant"

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: oauth2/add_on/pkce.py:113 only KeyError is caught; an undecryptable "
        "code raises UnknownToken out of post_token_parse instead of invalid_grant",
    )
    def test_garbage_code_is_invalid_grant(self, server):
        res = pkce.post_token_parse(_token_req("not-a-code"), CLIENT_ID, server.context)
        assert isinstance(res, TokenErrorResponse)
        assert res["error"] == "invalid_grant"

    def test_garbage_code_through_token_endpoint(self, server):
        # In the endpoint the grant-type helper runs first and rejects the code,
        # so the PKCE hook is never reached with it.
        endpoint = server.get_endpoint("token")
        req = _token_req("not-a-code", client_secret="hemligt")
        res = endpoint.parse_request(req.to_dict())
        assert isinstance(res, TokenErrorResponse)
        assert res["error"] == "invalid_grant"

    def test_token_endpoint_pkce_mismatch(self, server):
        code = _code(
            server,
            code_challenge=pkce.CC_METHOD["S256"](VERIFIER),
            code_challenge_method="S256",
        )
        endpoint = server.get_endpoint("token")
        req = _token_req(code, client_secret="hemligt", code_verifier="x" * 43)
        res = endpoint.parse_request(req.to_dict())
        assert isinstance(res, TokenErrorResponse)
        assert res["error_description"] == "PKCE check failed"

    def test_no_challenge_in_authz_request(self, server):
        req = _token_req(_code(server))
        assert pkce.post_token_parse(req, CLIENT_ID, server.context) is req

    def test_missing_verifier(self, server):
        code = _code(
            server,
            code_challenge=pkce.CC_METHOD["S256"](VERIFIER),
            code_challenge_method="S256",
        )
        res = pkce.post_token_parse(_token_req(code), CLIENT_ID, server.context)
        assert isinstance(res, TokenErrorResponse)
        assert res["error_description"] == "Missing code_verifier"

    def test_verifier_mismatch(self, server):
        code = _code(
            server,
            code_challenge=pkce.CC_METHOD["S256"](VERIFIER),
            code_challenge_method="S256",
        )
        req = _token_req(code, code_verifier=VERIFIER + "x")
        res = pkce.post_token_parse(req, CLIENT_ID, server.context)
        assert isinstance(res, TokenErrorResponse)
        assert res["error"] == "invalid_grant"
        assert res["error_description"] == "PKCE check failed"

    def test_verifier_match(self, server):
        code = _code(
            server,
            code_challenge=pkce.CC_METHOD["S256"](VERIFIER),
            code_challenge_method="S256",
        )
        req = _token_req(code, code_verifier=VERIFIER)
        assert pkce.post_token_parse(req, CLIENT_ID, server.context) is req

    def test_authorization_endpoint_rejects_missing_challenge(self, server):
        endpoint = server.get_endpoint("authorization")
        req = AuthorizationRequest(
            client_id=CLIENT_ID,
            redirect_uri="https://example.com/cb",
            response_type="code",
            state="STATE",
        )
        res = endpoint.parse_request(req.to_dict())
        assert isinstance(res, AuthorizationErrorResponse)
        assert res["error"] == "invalid_request"
