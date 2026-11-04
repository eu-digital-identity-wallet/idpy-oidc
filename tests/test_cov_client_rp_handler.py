"""Coverage tests for idpyoidc.client.rp_handler.RPHandler."""
import copy
import json
import os
import re
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
import responses
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client import defaults
from idpyoidc.client.configure import RPHConfiguration
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient
from idpyoidc.client.rp_handler import RPHandler
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import ProviderConfigurationResponse

BASE_URL = "https://rp.example.com"
ISSUER = "https://op.example.com"
OP_KEYS = build_keyjar(DEFAULT_KEY_DEFS)

STATIC_SERVICES = dict(DEFAULT_OIDC_SERVICES)
STATIC_SERVICES["end_session"] = {"class": "idpyoidc.client.oidc.end_session.EndSession"}
STATIC_SERVICES["webfinger"] = {"class": "idpyoidc.client.oidc.webfinger.WebFinger"}


def _static_client_conf():
    return {
        "client_id": "Number5",
        "client_secret": "asdflkjh0987654321",
        "client_type": "oidc",
        "redirect_uris": [f"{BASE_URL}/cb"],
        "services": STATIC_SERVICES,
        "provider_info": {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authn",
            "token_endpoint": f"{ISSUER}/token",
            "userinfo_endpoint": f"{ISSUER}/user",
            "end_session_endpoint": f"{ISSUER}/end",
        },
    }


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Run in a temp dir (key files are written relative to cwd) and protect the
    module level default client configuration from mutation."""
    monkeypatch.chdir(tmp_path)
    saved = copy.deepcopy(defaults.DEFAULT_CLIENT_CONFIGS)
    yield
    defaults.DEFAULT_CLIENT_CONFIGS.clear()
    defaults.DEFAULT_CLIENT_CONFIGS.update(saved)


def _rph(**kw):
    kw.setdefault("keyjar", build_keyjar(DEFAULT_KEY_DEFS))
    kw.setdefault("client_configs", {ISSUER: _static_client_conf()})
    return RPHandler(BASE_URL, **kw)


def _state(url):
    return parse_qs(urlsplit(url).query)["state"][0]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_keyjar_written_to_disk(self, tmp_path):
        rph = RPHandler(BASE_URL)
        assert os.path.isfile(tmp_path / "private" / "jwks.json")
        assert os.path.isfile(tmp_path / "static" / "jwks.json")
        assert rph.jwks_uri == f"{BASE_URL}/static/jwks.json"
        assert set(rph.keyjar.owners()) == {"", BASE_URL}
        assert rph.client_configs is defaults.DEFAULT_CLIENT_CONFIGS
        assert rph.client_cls is StandAloneClient
        assert rph.services is DEFAULT_OIDC_SERVICES
        assert rph.httpc_params == {"verify": True}
        # an already configured key jar keeps its own HTTP parameters
        assert rph.keyjar.httpc_params
        assert isinstance(rph.hash_seed, bytes) and len(rph.hash_seed) >= 32

    def test_key_conf_with_uri_path(self, tmp_path):
        key_conf = {
            "private_path": "priv.json",
            "key_defs": DEFAULT_KEY_DEFS,
            "public_path": "pub.json",
            "uri_path": "jwks/keys.json",
        }
        rph = RPHandler(BASE_URL, key_conf=key_conf, hash_seed="seed")
        assert rph.jwks_uri == f"{BASE_URL}/jwks/keys.json"
        assert "uri_path" not in key_conf
        assert rph.hash_seed == b"seed"

    def test_given_keyjar_without_jwks_path(self):
        kj = build_keyjar(DEFAULT_KEY_DEFS)
        rph = RPHandler(BASE_URL, keyjar=kj, verify_ssl=False)
        assert rph.jwks_uri == ""
        assert len(rph.jwks["keys"]) == 2
        assert rph.httpc_params == {"verify": False}

    def test_given_empty_keyjar(self):
        kj = KeyJar()
        kj.httpc_params = {}
        rph = RPHandler(BASE_URL, keyjar=kj, httpc_params={"timeout": 3})
        assert rph.jwks == {}
        assert rph.httpc_params == {"timeout": 3}
        # a key jar without HTTP parameters inherits the handler's
        assert kj.httpc_params == {"timeout": 3}

    def test_given_keyjar_with_jwks_path(self):
        rph = _rph(jwks_path="static/keys.json", state_db={"x": 1}, services={"a": {}})
        assert rph.jwks_uri == f"{BASE_URL}/static/keys.json"
        assert rph.state_db == {"x": 1}
        assert rph.services == {"a": {}}

    def test_kwargs_extend_default_client_config(self):
        rph = RPHandler(BASE_URL, keyjar=build_keyjar(DEFAULT_KEY_DEFS), client_type="oauth2",
                        add_ons={"x": {}})
        assert rph.client_configs[""]["client_type"] == "oauth2"
        assert rph.client_configs[""]["add_ons"] == {"x": {}}

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: client/rp_handler.py:92-96 writes client_type/preference/add_ons into the "
        "module level DEFAULT_CLIENT_CONFIGS dict, leaking into every later RPHandler",
    )
    def test_kwargs_do_not_mutate_module_defaults(self):
        RPHandler(BASE_URL, keyjar=build_keyjar(DEFAULT_KEY_DEFS), client_type="oauth2")
        assert defaults.DEFAULT_CLIENT_CONFIGS[""]["client_type"] == "oidc"

    def test_client_class_kwarg(self):
        rph = _rph(client_class="idpyoidc.client.oauth2.stand_alone_client.StandAloneClient")
        assert rph.client_cls is StandAloneClient

        class MyClient(StandAloneClient):
            pass

        assert _rph(client_class=MyClient).client_cls is MyClient

    def test_with_rph_configuration(self):
        conf = RPHConfiguration(
            {
                "base_url": BASE_URL,
                "hash_seed": "conf-seed",
                "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                "clients": {ISSUER: _static_client_conf()},
            }
        )
        rph = RPHandler(BASE_URL, config=conf)
        assert rph.hash_seed == "conf-seed"
        assert rph.client_configs == conf.clients
        assert rph.client_cls is StandAloneClient
        assert len(rph.keyjar.get_issuer_keys("")) == 2

    def test_with_rph_configuration_client_class(self):
        class MyClient(StandAloneClient):
            pass

        conf = RPHConfiguration({"key_conf": {"key_defs": DEFAULT_KEY_DEFS}, "clients": {}})
        conf["client_class"] = "idpyoidc.client.oauth2.stand_alone_client.StandAloneClient"
        assert RPHandler(BASE_URL, config=conf).client_cls is StandAloneClient
        conf2 = RPHConfiguration({"key_conf": {"key_defs": DEFAULT_KEY_DEFS}, "clients": {}})
        conf2["client_class"] = MyClient
        assert RPHandler(BASE_URL, config=conf2).client_cls is MyClient


# ---------------------------------------------------------------------------
# Client handling
# ---------------------------------------------------------------------------


class TestInitClient:
    def test_known_issuer(self):
        rph = _rph(jwks_path="static/jwks.json")
        client = rph.init_client(ISSUER)
        assert isinstance(client, StandAloneClient)
        _context = client.get_context()
        assert _context.base_url == BASE_URL
        assert _context.jwks_uri == f"{BASE_URL}/static/jwks.json"
        # The RPH keys are copied into the client key jar
        assert len(client.keyjar.get_issuer_keys("")) >= 2
        assert "webfinger" in client.get_services()

    def test_unknown_issuer_uses_default(self):
        configs = {"": {"client_type": "oidc", "redirect_uris": [f"{BASE_URL}/cb"]}}
        rph = _rph(client_configs=configs)
        client = rph.init_client("https://other.example.com")
        assert client.get_context().get("issuer") == "https://other.example.com"
        assert set(client.get_services().keys()) >= {"authorization", "accesstoken"}

    def test_init_failure(self):
        class Broken(StandAloneClient):
            def __init__(self, *a, **k):
                raise RuntimeError("cannot")

        rph = _rph(client_class=Broken)
        with pytest.raises(RuntimeError, match="cannot"):
            rph.init_client(ISSUER)

    def test_client_without_keyjar(self):
        class NoKeys(StandAloneClient):
            def __init__(self, *a, **k):
                StandAloneClient.__init__(self, *a, **k)
                self.keyjar = None

        rph = _rph(client_class=NoKeys)
        client = rph.init_client(ISSUER)
        assert isinstance(client.keyjar, KeyJar)
        assert len(client.keyjar.get_issuer_keys("")) == 2

    def test_iss_hash_registered(self, monkeypatch):
        rph = _rph()
        orig = StandAloneClient.__init__

        def _init(self, *a, **k):
            orig(self, *a, **k)
            self.get_context().iss_hash = "HASH"

        monkeypatch.setattr(StandAloneClient, "__init__", _init)
        rph.init_client(ISSUER)
        assert rph.hash2issuer["HASH"] == ISSUER


class TestFlow:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.rph = _rph()
        self.url = self.rph.begin(issuer_id=ISSUER)
        self.state = _state(self.url)
        self.client = self.rph.issuer2rp[ISSUER]

    def test_begin(self):
        p = urlsplit(self.url)
        assert f"{p.scheme}://{p.netloc}{p.path}" == f"{ISSUER}/authn"
        assert parse_qs(p.query)["client_id"] == ["Number5"]

    def test_client_setup_returns_cached(self):
        assert self.rph.client_setup(ISSUER) is self.client

    def test_client_setup_needs_issuer_or_user(self):
        with pytest.raises(ValueError):
            self.rph.client_setup()

    def test_begin_error_is_reraised(self, monkeypatch):
        def boom(**kw):
            raise RuntimeError("authz failed")

        monkeypatch.setattr(self.client, "init_authorization", boom)
        with pytest.raises(RuntimeError, match="authz failed"):
            self.rph.begin(issuer_id=ISSUER)

    def test_state2issuer(self):
        assert self.rph.state2issuer(self.state) == ISSUER
        assert self.rph.state2issuer("unknown") is None
        assert self.rph.get_client_from_session_key(self.state) is self.client

    def test_state2issuer_without_iss(self):
        _cstate = self.client.get_context().cstate
        _key = _cstate.create_key()
        _cstate.set(_key, {"foo": "bar"})
        assert self.rph.state2issuer(_key) is None

    def test_session_information(self):
        info = self.rph.get_session_information(self.state)
        assert info["iss"] == ISSUER
        assert self.rph.get_session_information(self.state, client=self.client) == info

    def test_missing_state_errors(self):
        for meth in (self.rph.do_provider_info, self.rph.do_client_registration,
                     self.rph.init_authorization):
            with pytest.raises(ValueError, match="Missing state"):
                meth()

    def test_methods_via_state(self):
        assert self.rph.do_provider_info(state=self.state) == ISSUER
        self.rph.do_client_registration(state=self.state, iss_id="hash-x")
        assert self.rph.hash2issuer["hash-x"] == ISSUER
        url = self.rph.init_authorization(state=self.state, req_args={"acr_values": "a"})
        assert parse_qs(urlsplit(url).query)["acr_values"] == ["a"]

    def test_get_client_authn_method(self, monkeypatch):
        f = RPHandler.get_client_authn_method
        assert f(self.client, "token_endpoint") == "client_secret_basic"
        assert f(self.client, "userinfo_endpoint") is None
        _context = self.client.get_context()
        monkeypatch.setattr(_context, "get_usage", lambda *a: ["private_key_jwt"])
        assert f(self.client, "token_endpoint") == "private_key_jwt"
        monkeypatch.setattr(_context, "get_usage", lambda *a: "")
        assert f(self.client, "token_endpoint") == ""

    @pytest.mark.xfail(
        strict=True,
        raises=AttributeError,
        reason="BUG: client/rp_handler.py:443 get_response_type uses client.service_context, "
        "which does not exist on the client (should be client.get_context())",
    )
    def test_get_response_type(self):
        assert RPHandler.get_response_type(self.client) == "code"

    def test_get_response_type_helper(self):
        _context = self.client.get_context()
        assert self.rph._get_response_type(_context) == "code"
        assert self.rph._get_response_type(_context, {"response_type": "id_token"}) == "id_token"
        assert self.rph._get_response_type(_context, {"x": 1}) == "code"

    def _record(self, monkeypatch, name, ret="RESULT"):
        calls = []

        def _f(*a, **k):
            calls.append((a, k))
            return ret

        monkeypatch.setattr(self.client, name, _f)
        return calls

    def test_delegations(self, monkeypatch):
        s = self.state
        c = self._record(monkeypatch, "get_tokens")
        assert self.rph.get_tokens(s) == "RESULT"
        assert c == [((s,), {})]

        c = self._record(monkeypatch, "get_user_info")
        assert self.rph.get_user_info(s, access_token="AT", extra=1) == "RESULT"
        assert c == [((s,), {"access_token": "AT", "extra": 1})]

        c = self._record(monkeypatch, "finalize_auth")
        assert self.rph.finalize_auth(None, ISSUER, {"code": "x"}, behaviour_args={"b": 1}) == \
            "RESULT"
        assert c == [(({"code": "x"},), {"behaviour_args": {"b": 1}})]

        c = self._record(monkeypatch, "get_access_and_id_token")
        assert self.rph.get_access_and_id_token(state=s) == "RESULT"
        assert c[0][1]["state"] == s

        c = self._record(monkeypatch, "finalize")
        assert self.rph.finalize(ISSUER, {"code": "x"}) == "RESULT"
        assert c == [(({"code": "x"}, None), {})]

        c = self._record(monkeypatch, "has_active_authentication", ret=False)
        assert self.rph.has_active_authentication(s) is False

        c = self._record(monkeypatch, "get_valid_access_token", ret=("AT", 0))
        assert self.rph.get_valid_access_token(s) == ("AT", 0)

    def test_refresh_access_token_delegation(self, monkeypatch):
        c = self._record(monkeypatch, "refresh_access_token")
        assert self.rph.refresh_access_token(self.state) == "RESULT"
        assert c[0][0] == (self.state,)

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: client/rp_handler.py:495 calls client.refresh_access_token(state, "
        "scope='') and drops the caller's scope argument",
    )
    def test_refresh_access_token_passes_scope(self, monkeypatch):
        c = self._record(monkeypatch, "refresh_access_token")
        self.rph.refresh_access_token(self.state, scope="openid email")
        assert c[0][1]["scope"] == "openid email"

    def test_userinfo_in_id_token(self):
        res = RPHandler.userinfo_in_id_token(IdToken(sub="s", email="e@x", iss=ISSUER))
        assert res == {"sub": "s", "email": "e@x"}

    def test_logout_close_clear(self):
        info = self.rph.logout(self.state, post_logout_redirect_uri=f"{BASE_URL}/out")
        assert info["url"].startswith(f"{ISSUER}/end")
        assert info["request"]["post_logout_redirect_uri"] == f"{BASE_URL}/out"
        info2 = self.rph.close(self.state, issuer=ISSUER)
        assert info2["request"]["state"]
        info3 = self.rph.close(self.state)
        assert info3["url"].startswith(f"{ISSUER}/end")
        self.rph.clear_session(self.state)
        with pytest.raises(KeyError):
            self.client.get_context().cstate.get(self.state)


class TestWebfinger:
    def test_client_setup_with_user(self):
        configs = {
            "": {
                "client_type": "oidc",
                "client_id": "Number5",
                "client_secret": "asdflkjh0987654321",
                "redirect_uris": [f"{BASE_URL}/cb"],
                "services": STATIC_SERVICES,
            }
        }
        rph = _rph(client_configs=configs)
        wf = {
            "subject": "acct:alice@op.example.com",
            "links": [
                {"rel": "http://openid.net/specs/connect/1.0/issuer", "href": ISSUER}
            ],
        }
        pcr = ProviderConfigurationResponse(
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/authn",
            token_endpoint=f"{ISSUER}/token",
            jwks_uri=f"{ISSUER}/jwks",
            response_types_supported=["code"],
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
        )
        with responses.RequestsMock() as rsps:
            rsps.add("GET", re.compile(r"https://op\.example\.com/\.well-known/webfinger.*"),
                     body=json.dumps(wf), adding_headers={"Content-Type": "application/jrd+json"})
            rsps.add("GET", f"{ISSUER}/.well-known/openid-configuration", body=pcr.to_json(),
                     adding_headers={"Content-Type": "application/json"})
            rsps.add("GET", f"{ISSUER}/jwks", body=OP_KEYS.export_jwks_as_json(),
                     adding_headers={"Content-Type": "application/json"})
            client = rph.client_setup(user="acct:alice@op.example.com")
            assert "resource=acct" in rsps.calls[0].request.url
        assert rph.issuer2rp[ISSUER] is client
        assert client.get_context().provider_info["token_endpoint"] == f"{ISSUER}/token"
