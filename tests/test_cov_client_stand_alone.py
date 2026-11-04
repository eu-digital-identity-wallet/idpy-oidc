"""Coverage tests for idpyoidc.client.oauth2.stand_alone_client."""
import json
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
import responses
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.defaults import OIDCONF_PATTERN
from idpyoidc.client.exception import ConfigurationError
from idpyoidc.client.client_auth import ClientSecretBasic
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.exception import Unsupported
from idpyoidc.client.oauth2 import stand_alone_client
from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient
from idpyoidc.client.oauth2.stand_alone_client import backchannel_logout
from idpyoidc.client.oauth2.stand_alone_client import load_registration_response
from idpyoidc.exception import MessageException
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
from idpyoidc.message.oidc import AccessTokenResponse
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationResponse

ISSUER = "https://op.example.com"
TOKEN_EP = "https://op.example.com/token"
USERINFO_EP = "https://op.example.com/user"
ISSUER_KEYS = build_keyjar(DEFAULT_KEY_DEFS, issuer_id=ISSUER)
SECRET = "asdflkjh0987654321"

_services = DEFAULT_OIDC_SERVICES.copy()
_services["end_session"] = {"class": "idpyoidc.client.oidc.end_session.EndSession"}


def _config(**extra):
    conf = {
        "base_url": "https://example.com/cli/",
        "client_id": "Number5",
        "client_type": "oidc",
        "client_secret": SECRET,
        "post_logout_redirect_uri": "https://example.com/cli/logout",
        "services": _services,
        "provider_info": {
            "issuer": ISSUER,
            "authorization_endpoint": "https://op.example.com/authn",
            "token_endpoint": TOKEN_EP,
            "userinfo_endpoint": USERINFO_EP,
            "end_session_endpoint": "https://op.example.com/end_session",
        },
    }
    conf.update(extra)
    return conf


def _state(url):
    return parse_qs(urlsplit(url).query)["state"][0]


def _qs(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def _ready_client(conf=None, **kw):
    client = StandAloneClient(config=conf or _config(), **kw)
    client.do_provider_info()
    client.do_client_registration()
    client.get_attribute("keyjar").import_jwks(ISSUER_KEYS.export_jwks(issuer_id=ISSUER), ISSUER)
    return client


def _id_token(client, state, subject="Subject", **extra):
    _session = client.get_session_information(state)
    idval = {
        "nonce": _session.get("nonce"),
        "sub": subject,
        "iss": ISSUER,
        "aud": client.get_context().get_client_id(),
    }
    idval.update(extra)
    if idval["nonce"] is None:
        del idval["nonce"]
    return IdToken(**idval).to_jwt(
        key=ISSUER_KEYS.get_signing_key("rsa", issuer_id=ISSUER), algorithm="RS256", lifetime=300
    )


def _authz(client, req_args=None):
    url = client.init_authorization(req_args=req_args)
    return url, _state(url)


def _json(rsps, method, url, msg, status=200):
    rsps.add(
        method,
        url,
        body=msg if isinstance(msg, str) else msg.to_json(),
        adding_headers={"Content-Type": "application/json"},
        status=status,
    )


# ---------------------------------------------------------------------------
# Provider info
# ---------------------------------------------------------------------------


class TestDoProviderInfo:
    def test_static_sets_endpoints(self):
        client = StandAloneClient(config=_config())
        assert client.do_provider_info() == ISSUER
        assert client.get_service("accesstoken").endpoint == TOKEN_EP
        assert client.get_service("userinfo").endpoint == USERINFO_EP

    def test_dynamic_when_empty(self):
        conf = _config(provider_info={}, issuer=ISSUER)
        client = StandAloneClient(config=conf)
        pcr = ProviderConfigurationResponse(
            issuer=ISSUER,
            authorization_endpoint="https://op.example.com/authn",
            token_endpoint=TOKEN_EP,
            jwks_uri="https://op.example.com/jwks",
            response_types_supported=["code"],
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
        )
        with responses.RequestsMock() as rsps:
            _json(rsps, "GET", OIDCONF_PATTERN.format(ISSUER), pcr)
            _json(rsps, "GET", "https://op.example.com/jwks", ISSUER_KEYS.export_jwks_as_json(
                issuer_id=ISSUER))
            assert client.do_provider_info() == ISSUER
        assert client.get_context().provider_info["token_endpoint"] == TOKEN_EP

    def test_only_issuer_triggers_discovery(self):
        conf = _config(provider_info={"issuer": ISSUER})
        client = StandAloneClient(config=conf)
        pcr = ProviderConfigurationResponse(
            issuer=ISSUER,
            authorization_endpoint="https://op.example.com/authn",
            token_endpoint=TOKEN_EP,
            jwks_uri="https://op.example.com/jwks",
            response_types_supported=["code"],
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
        )
        with responses.RequestsMock() as rsps:
            _json(rsps, "GET", OIDCONF_PATTERN.format(ISSUER), pcr)
            _json(rsps, "GET", "https://op.example.com/jwks", ISSUER_KEYS.export_jwks_as_json(
                issuer_id=ISSUER))
            assert client.do_provider_info() == ISSUER
        assert client.get_context().issuer == ISSUER
        assert client.get_context().provider_info["token_endpoint"] == TOKEN_EP

    def test_keys_url(self):
        conf = _config()
        conf["provider_info"] = dict(conf["provider_info"],
                                     keys={"url": {ISSUER: "https://op.example.com/jwks"}})
        client = StandAloneClient(config=conf)
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            _json(rsps, "GET", "https://op.example.com/jwks",
                  ISSUER_KEYS.export_jwks_as_json(issuer_id=ISSUER))
            client.do_provider_info()
            _kj = client.get_attribute("keyjar")
            assert ISSUER in _kj.owners()
            assert len(_kj.get_issuer_keys(ISSUER)) == 2

    def test_keys_file(self, tmp_path):
        jwks_file = tmp_path / "op.jwks"
        jwks_file.write_text(ISSUER_KEYS.export_jwks_as_json(issuer_id=ISSUER))
        conf = _config()
        conf["provider_info"] = dict(conf["provider_info"], keys={"file": {"jwks": str(jwks_file)}})
        client = StandAloneClient(config=conf)
        client.do_provider_info()
        assert len(client.get_attribute("keyjar").get_issuer_keys(ISSUER)) == 2

    def test_keys_file_rsa(self, tmp_path, monkeypatch):
        seen = []

        class _KB:
            pass

        def _fake(name, typ, usage):
            seen.append((name, typ, usage))
            return _KB()

        monkeypatch.setattr(stand_alone_client, "keybundle_from_local_file", _fake)
        conf = _config()
        conf["provider_info"] = dict(conf["provider_info"], keys={"file": {"rsa": "op.pem",
                                                                           "other": "x"}})
        client = StandAloneClient(config=conf)
        added = []
        monkeypatch.setattr(client.get_attribute("keyjar"), "add_kb",
                            lambda iss, kb: added.append((iss, kb)))
        client.do_provider_info()
        assert seen == [("op.pem", "der", ["sig"])]
        assert added[0][0] == ISSUER

    def test_keys_unknown_type(self):
        conf = _config()
        conf["provider_info"] = dict(conf["provider_info"], keys={"ftp": {}})
        client = StandAloneClient(config=conf)
        with pytest.raises(ValueError, match="Unknown provider JWKS type"):
            client.do_provider_info()

    def test_no_issuer_in_provider_info(self):
        conf = _config()
        conf["provider_info"] = {"token_endpoint": TOKEN_EP, "authorization_endpoint": "x"}
        conf["issuer"] = "https://other.example.com"
        client = StandAloneClient(config=conf)
        assert client.do_provider_info() == "https://other.example.com"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def _client(self):
        conf = _config()
        del conf["client_id"]
        del conf["client_secret"]
        conf["provider_info"] = dict(conf["provider_info"],
                                     registration_endpoint="https://op.example.com/reg")
        conf["redirect_uris"] = ["https://example.com/cli/authz_cb"]
        client = StandAloneClient(config=conf)
        client.do_provider_info()
        return client

    def test_dynamic_with_behaviour_args(self):
        client = self._client()
        reg = RegistrationResponse(client_id="dyn", redirect_uris=["https://example.com/cb"])
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", "https://op.example.com/reg", reg)
            client.do_client_registration(
                behaviour_args={"client_name": "My RP", "not_a_reg_param": 1}
            )
            sent = json.loads(rsps.calls[0].request.body)
        assert sent["client_name"] == "My RP"
        assert "not_a_reg_param" not in sent
        assert client.get_client_id() == "dyn"

    def test_dynamic_error(self):
        client = self._client()
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", "https://op.example.com/reg",
                  json.dumps({"error": "invalid_client_metadata"}), status=400)
            with pytest.raises(OidcServiceError, match="invalid_client_metadata"):
                client.do_client_registration()

    def test_load_registration_no_service(self):
        client = self._client()
        del client._service["registration"]
        with pytest.raises(ConfigurationError, match="No registration info"):
            load_registration_response(client)

    def test_load_registration_other_exception(self, monkeypatch):
        client = self._client()

        def boom(*a, **k):
            raise RuntimeError("down")

        monkeypatch.setattr(client, "do_request", boom)
        with pytest.raises(RuntimeError):
            load_registration_response(client)

    def test_load_registration_already_registered(self, monkeypatch):
        client = StandAloneClient(config=_config())
        monkeypatch.setattr(client, "do_request", lambda *a, **k: pytest.fail("called"))
        assert load_registration_response(client) is None


# ---------------------------------------------------------------------------
# Authorization request
# ---------------------------------------------------------------------------


class TestInitAuthorization:
    def test_response_mode_requested_non_default(self):
        client = _ready_client(_config(response_modes_supported=["query", "form_post"]))
        url = client.init_authorization(req_args={"response_mode": "form_post"})
        assert _qs(url)["response_mode"] == "form_post"

    @pytest.mark.xfail(
        strict=True,
        raises=ValueError,
        reason="BUG: client/oauth2/utils.py:51 pick_redirect_uri returns the whole list "
        "_redirect_uris[response_mode] (missing [0]) for an explicit non form_post "
        "response_mode, giving 'wrong type of value for redirect_uri'",
    )
    def test_response_mode_requested_default_is_dropped(self):
        client = _ready_client(_config(response_modes_supported=["query", "fragment"]))
        url = client.init_authorization(req_args={"response_mode": "query"})
        assert "response_mode" not in _qs(url)

    def test_response_mode_not_supported(self):
        client = _ready_client(_config(response_modes_supported=["query"]))
        with pytest.raises(ValueError, match="response_mode"):
            client.init_authorization(req_args={"response_mode": "form_post"})

    def test_response_mode_without_supported(self):
        client = _ready_client()
        _context = client.get_context()
        _context.claims.use["response_modes"] = []
        assert client._get_response_mode(_context, "code", {}) is None
        assert client._get_response_mode(_context, "code", {"response_mode": "query"}) is None
        assert (
            client._get_response_mode(_context, "code", {"response_mode": "form_post"})
            == "form_post"
        )

    def test_response_type_from_req_args(self):
        client = _ready_client()
        _context = client.get_context()
        assert client._get_response_type(_context, {"response_type": "id_token"}) == "id_token"
        assert client._get_response_type(_context, {"x": 1}) == "code"
        assert client._get_response_type(_context) == "code"

    def test_config_request_args_with_claims(self):
        client = _ready_client()
        # Configuration.get() only sees attributes, so put it there directly
        client.get_context().config["request_args"] = {
            "claims": {"userinfo": {"email": {"essential": True}}},
            "acr_values": "loa1",
        }
        url, state = _authz(client)
        qs = _qs(url)
        assert qs["acr_values"] == "loa1"
        assert json.loads(qs["claims"]) == {"userinfo": {"email": {"essential": True}}}
        assert qs["scope"] == "openid"
        # nonce bound to state
        _nonce = qs["nonce"]
        assert client.get_context().cstate.get_base_key(_nonce) == state
        assert client.get_session_information(state)["iss"] == ISSUER

    @pytest.mark.xfail(
        strict=True,
        raises=KeyError,
        reason="BUG: client/oauth2/stand_alone_client.py:228 reads request_args with "
        "context.config.get(), but the client Configuration only exposes 'issuer'/'key_conf' "
        "as attributes (the rest lives in config.conf), so configured request_args are ignored",
    )
    def test_configured_request_args_are_used(self):
        client = _ready_client(_config(request_args={"acr_values": "loa1"}))
        url, _ = _authz(client)
        assert _qs(url)["acr_values"] == "loa1"

    def test_oauth2_client_has_no_nonce(self):
        conf = _config(client_type="oauth2")
        conf["services"] = {
            "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
            "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
        }
        client = _ready_client(conf)
        url, _ = _authz(client)
        assert "nonce" not in _qs(url)

    def test_unsupported_redirect_uri(self, monkeypatch):
        client = _ready_client()

        def _fail(*a, **k):
            raise KeyError("form_post")

        monkeypatch.setattr(stand_alone_client, "pick_redirect_uri", _fail)
        with pytest.raises(Unsupported):
            client.init_authorization()

    def test_missing_attribute_propagates(self, monkeypatch):
        client = _ready_client()

        def _fail(*a, **k):
            raise MissingRequiredAttribute("redirect_uri")

        monkeypatch.setattr(stand_alone_client, "pick_redirect_uri", _fail)
        with pytest.raises(MissingRequiredAttribute):
            client.init_authorization()


class TestClientAuthnMethod:
    def test_variants(self, monkeypatch):
        client = _ready_client()
        _context = client.get_context()
        f = StandAloneClient.get_client_authn_method
        assert f(client, "userinfo_endpoint") == ""
        monkeypatch.setattr(_context, "get_usage", lambda *a, **k: "client_secret_post")
        assert f(client, "token_endpoint") == "client_secret_post"
        monkeypatch.setattr(_context, "get_usage", lambda *a, **k: ["private_key_jwt", "x"])
        assert f(client, "token_endpoint") == "private_key_jwt"
        monkeypatch.setattr(_context, "get_usage", lambda *a, **k: None)
        assert f(client, "token_endpoint") == ""


# ---------------------------------------------------------------------------
# After authorization
# ---------------------------------------------------------------------------


class TestPostAuthn:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = _ready_client()
        _, self.state = _authz(self.client)
        self.auth_resp = AuthorizationResponse(
            code=24 * "x", state=self.state, iss=ISSUER, client_id="Number5"
        )

    def _finalize_auth(self):
        return self.client.finalize_auth(self.auth_resp.to_dict())

    def test_finalize_auth_error_response(self):
        res = self.client.finalize_auth({"error": "access_denied", "state": self.state})
        assert res["error"] == "access_denied"

    def test_finalize_auth_parse_error(self):
        with pytest.raises(Exception):
            self.client.finalize_auth({"state": self.state, "iss": "https://evil.example.com",
                                       "code": "x"})

    def test_finalize_auth_impersonator(self, monkeypatch):
        self.client.get_context().cstate.update(self.state, {"iss": "https://other"})
        with pytest.raises(ValueError, match="Impersonator"):
            self._finalize_auth()

    def test_finalize_auth_issuer_from_context(self):
        _context = self.client.get_context()
        del _context.provider_info["issuer"]
        _context.issuer = ISSUER
        res = self._finalize_auth()
        assert res["code"] == 24 * "x"

    def test_get_tokens_error(self):
        self._finalize_auth()
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, json.dumps({"error": "invalid_grant"}), status=400)
            with pytest.raises(OidcServiceError, match="invalid_grant"):
                self.client.get_tokens(self.state)

    def test_get_tokens_exception(self, monkeypatch):
        self._finalize_auth()

        def boom(*a, **k):
            raise ConnectionError("nope")

        monkeypatch.setattr(self.client, "do_request", boom)
        with pytest.raises(ConnectionError):
            self.client.get_tokens(self.state)

    def _store_tokens(self):
        self._finalize_auth()
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, AccessTokenResponse(
                access_token="AT", refresh_token="RT", token_type="Bearer", expires_in=300))
            return self.client.get_tokens(self.state)

    def test_get_tokens_sends_code(self):
        self._finalize_auth()
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, AccessTokenResponse(access_token="AT",
                                                              token_type="Bearer"))
            resp = self.client.get_tokens(self.state)
            body = parse_qs(rsps.calls[0].request.body)
        assert resp["access_token"] == "AT"
        assert body["code"] == [24 * "x"]
        assert body["grant_type"] == ["authorization_code"]

    @pytest.mark.xfail(
        strict=True,
        raises=Unsupported,
        reason="BUG: client/oauth2/stand_alone_client.py:339 forces the token endpoint auth "
        "method (default client_secret_basic) on the refresh_token service, which only knows "
        "client_secret_post -> Unsupported; refresh fails with the default configuration",
    )
    def test_refresh_access_token_default_config(self):
        self._store_tokens()
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            _json(rsps, "POST", TOKEN_EP, AccessTokenResponse(access_token="AT2",
                                                              token_type="Bearer"))
            resp = self.client.refresh_access_token(self.state)
        assert resp["access_token"] == "AT2"

    def _enable_basic_on_context(self):
        self.client.get_context().client_authn_methods["client_secret_basic"] = (
            ClientSecretBasic()
        )

    def test_refresh_access_token(self):
        self._store_tokens()
        self._enable_basic_on_context()
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, AccessTokenResponse(access_token="AT2",
                                                              token_type="Bearer"))
            resp = self.client.refresh_access_token(self.state, scope="openid email")
            body = parse_qs(rsps.calls[0].request.body)
            assert rsps.calls[0].request.headers["Authorization"].startswith("Basic ")
        assert resp["access_token"] == "AT2"
        assert body["grant_type"] == ["refresh_token"]
        assert body["refresh_token"] == ["RT"]
        assert body["scope"] == ["openid email"]

    def test_refresh_access_token_error(self):
        self._store_tokens()
        self._enable_basic_on_context()
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, json.dumps({"error": "invalid_grant"}), status=400)
            with pytest.raises(OidcServiceError):
                self.client.refresh_access_token(self.state)

    def test_refresh_access_token_exception(self, monkeypatch):
        monkeypatch.setattr(self.client, "do_request",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
        with pytest.raises(RuntimeError):
            self.client.refresh_access_token(self.state)

    def test_get_user_info_from_state_and_error(self):
        self._store_tokens()
        with responses.RequestsMock() as rsps:
            _json(rsps, "GET", USERINFO_EP, OpenIDSchema(sub="Subject"))
            resp = self.client.get_user_info(self.state)
            assert rsps.calls[0].request.headers["Authorization"] == "Bearer AT"
        assert resp["sub"] == "Subject"
        with responses.RequestsMock() as rsps:
            _json(rsps, "GET", USERINFO_EP, json.dumps({"error": "invalid_token"}), status=401)
            with pytest.raises(OidcServiceError, match="invalid_token"):
                self.client.get_user_info(self.state, access_token="other")

    def test_userinfo_in_id_token(self):
        idt = IdToken(sub="s", email="e@x", iss=ISSUER, custom="c")
        res = StandAloneClient.userinfo_in_id_token(idt)
        assert res["sub"] == "s" and res["email"] == "e@x" and res["custom"] == "c"
        assert "iss" not in res
        res2 = StandAloneClient.userinfo_in_id_token(idt, user_info_claims=["email"])
        assert set(res2) == {"email", "custom"}

    def test_valid_access_token(self, monkeypatch):
        self._store_tokens()
        token, exp = self.client.get_valid_access_token(self.state)
        assert token == "AT" and exp > 0
        # expired
        monkeypatch.setattr(stand_alone_client, "utc_time_sans_frac", lambda: exp + 10)
        with pytest.raises(OidcServiceError):
            self.client.get_valid_access_token(self.state)

    def test_valid_access_token_indefinite(self):
        self.client.get_context().cstate.update(self.state, {"access_token": "forever"})
        assert self.client.get_valid_access_token(self.state) == ("forever", 0)

    def test_valid_access_token_none(self):
        with pytest.raises(OidcServiceError):
            self.client.get_valid_access_token(self.state)

    def test_has_active_authentication_false(self):
        assert self.client.has_active_authentication(self.state) is False

    def test_close_and_clear_session(self):
        self._finalize_auth()
        info = self.client.close(self.state)
        assert info["url"].startswith("https://op.example.com/end_session")
        assert info["request"]["state"]
        self.client.clear_session(self.state)
        with pytest.raises(KeyError):
            self.client.get_context().cstate.get(self.state)

    @pytest.mark.xfail(
        strict=True,
        raises=AttributeError,
        reason="BUG: client/oauth2/stand_alone_client.py:667-670 expects get_service() to raise "
        "KeyError, but Entity.get_service returns None -> AttributeError instead of "
        "OidcServiceError('Does not know how to logout')",
    )
    def test_logout_without_end_session_service(self):
        del self.client._service["end_session"]
        with pytest.raises(OidcServiceError):
            self.client.logout(self.state)


class TestAccessAndIdToken:
    def _client(self, response_type):
        conf = _config(response_types_supported=[response_type])
        conf["preference"] = {"response_types": [response_type]}
        client = _ready_client(conf)
        _, state = _authz(client, req_args={"response_type": response_type})
        return client, state

    def test_implicit_id_token_token(self):
        client, state = self._client("id_token token")
        resp = AuthorizationResponse(state=state, access_token="AT-implicit", token_type="Bearer")
        resp["__verified_id_token"] = IdToken(sub="s1")
        client.get_context().cstate.update(state, resp)
        res = client.get_access_and_id_token(authorization_response=resp, state=state)
        assert res["access_token"] == "AT-implicit"
        assert res["id_token"]["sub"] == "s1"

    def test_implicit_token_collect_tokens(self):
        client, state = self._client("code token")
        resp = AuthorizationResponse(state=state, access_token="AT-impl", code="C",
                                     token_type="Bearer")
        client.get_context().cstate.update(state, resp)
        client.get_context().cstate.update(state, {"redirect_uri": "https://example.com/cb"})
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, AccessTokenResponse(access_token="AT-coll",
                                                              token_type="Bearer"))
            res = client.get_access_and_id_token(
                authorization_response=resp, behaviour_args={"collect_tokens": True}
            )
        assert res == {"access_token": "AT-coll", "id_token": None}

    def test_implicit_token_no_collect(self):
        client, state = self._client("code token")
        resp = AuthorizationResponse(state=state, access_token="AT-impl", token_type="Bearer")
        res = client.get_access_and_id_token(authorization_response=resp, state=state,
                                             behaviour_args={"other": 1})
        assert res == {"access_token": "AT-impl", "id_token": None}

    def test_request_response_type_as_list(self):
        client, state = self._client("code")
        client.get_context().cstate.update(state, {"response_type": ["id_token"]})
        resp = AuthorizationResponse(state=state)
        resp["__verified_id_token"] = IdToken(sub="s2")
        res = client.get_access_and_id_token(authorization_response=resp, state=state)
        assert res == {"access_token": None, "id_token": resp["__verified_id_token"]}


class TestFinalize:
    def test_error(self):
        client = _ready_client()
        _, state = _authz(client)
        res = client.finalize({"error": "access_denied", "state": state})
        assert res == {"state": state, "error": "access_denied"}

    def _flow(self, conf, with_userinfo=True, idt_extra=None):
        client = _ready_client(conf)
        _, state = _authz(client)
        auth = AuthorizationResponse(code="c" * 24, state=state, iss=ISSUER, client_id="Number5")
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, AccessTokenResponse(
                access_token="AT", token_type="Bearer",
                id_token=_id_token(client, state, **(idt_extra or {}))))
            if with_userinfo:
                _json(rsps, "GET", USERINFO_EP, OpenIDSchema(sub="Subject", email="a@b"))
            res = client.finalize(auth.to_dict())
        return client, state, res

    def test_without_userinfo_service_uses_id_token(self):
        conf = _config()
        conf["services"] = {k: v for k, v in _services.items() if k != "userinfo"}
        conf["provider_info"] = dict(conf["provider_info"], backchannel_logout_session_required=True)
        client, state, res = self._flow(conf, with_userinfo=False,
                                        idt_extra={"sid": "SID-1", "email": "x@y"})
        assert res["userinfo"]["email"] == "x@y"
        assert res["userinfo"]["sub"] == "Subject"
        _cstate = client.get_context().cstate
        assert _cstate.get_base_key("SID-1") == state
        assert _cstate.get_base_key("Subject") == state

    def test_frontchannel_sid_without_sid_claim(self):
        conf = _config()
        conf["provider_info"] = dict(conf["provider_info"],
                                     frontchannel_logout_session_required=True)
        client, state, res = self._flow(conf)
        assert res["userinfo"]["email"] == "a@b"
        assert res["id_token"]["sub"] == "Subject"

    def test_userinfo_error(self):
        client = _ready_client()
        _, state = _authz(client)
        auth = AuthorizationResponse(code="c" * 24, state=state, iss=ISSUER, client_id="Number5")
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, AccessTokenResponse(access_token="AT",
                                                              token_type="Bearer"))
            _json(rsps, "GET", USERINFO_EP, json.dumps({"error": "invalid_token"}), status=401)
            with pytest.raises(OidcServiceError):
                client.finalize(auth.to_dict())

    def test_no_userinfo_no_id_token(self):
        conf = _config()
        conf["services"] = {k: v for k, v in _services.items() if k != "userinfo"}
        client = _ready_client(conf)
        _, state = _authz(client)
        auth = AuthorizationResponse(code="c" * 24, state=state, iss=ISSUER, client_id="Number5")
        with responses.RequestsMock() as rsps:
            _json(rsps, "POST", TOKEN_EP, AccessTokenResponse(access_token="AT",
                                                              token_type="Bearer"))
            # inforesp == {} -> no "sub" to bind
            with pytest.raises(KeyError):
                client.finalize(auth.to_dict())


# ---------------------------------------------------------------------------
# Back-channel logout
# ---------------------------------------------------------------------------


def _logout_token(aud="Number5", **claims):
    payload = {
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "jti": "jti-1",
    }
    payload.update(claims)
    _jwt = JWT(key_jar=ISSUER_KEYS, iss=ISSUER, sign_alg="RS256", lifetime=300)
    return _jwt.pack(payload, aud=aud, issuer_id=ISSUER)


class TestBackchannelLogout:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = _ready_client()
        _, self.state = _authz(self.client)
        self.client.get_context().registration_response = Message()
        _cstate = self.client.get_context().cstate
        _cstate.bind_key("Subject", self.state)
        _cstate.bind_key("SID", self.state)

    def test_by_sub_urlencoded(self):
        req = Message(logout_token=_logout_token(sub="Subject")).to_urlencoded()
        assert backchannel_logout(self.client, request=req) == self.state

    def test_by_sid_request_args(self):
        res = backchannel_logout(self.client, request_args={"logout_token": _logout_token(sid="SID")})
        assert res == self.state

    def test_missing(self):
        with pytest.raises(MissingRequiredAttribute):
            backchannel_logout(self.client)

    def test_bogus(self):
        token = _logout_token(aud="someone-else", sub="Subject")
        with pytest.raises(MessageException, match="Bogus logout request"):
            backchannel_logout(self.client, request_args={"logout_token": token})
