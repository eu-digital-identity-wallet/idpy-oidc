"""Coverage tests for idpyoidc.client.http.HTTPLib and the generic OAuth2 Client
(idpyoidc.client.oauth2.Client: request/response plumbing and discovery)."""
import json
from http.cookies import CookieError
from types import SimpleNamespace

import pytest
import requests
import responses
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client import http as http_mod
from idpyoidc.client.configure import Configuration
from idpyoidc.configure import Configuration as GenericConfiguration
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.defaults import OAUTH2_SERVER_METADATA_URL
from idpyoidc.client.exception import ConfigurationError
from idpyoidc.client.exception import NonFatalException
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.exception import ParseError
from idpyoidc.client.http import HTTPLib
from idpyoidc.client.oauth2 import Client
from idpyoidc.client.oauth2 import dynamic_provider_info_discovery
from idpyoidc.message.oauth2 import AccessTokenResponse

URL = "https://server.example.com/path"


# ---------------------------------------------------------------------------
# HTTPLib
# ---------------------------------------------------------------------------


class TestHTTPLib:
    def test_init_defaults_and_params(self):
        assert HTTPLib().request_args == {"allow_redirects": False}
        h = HTTPLib(httpc_params={"verify": False, "timeout": 3})
        assert h.request_args == {"allow_redirects": False, "verify": False, "timeout": 3}
        assert h.events is None and h.req_callback is None

    def test_call_sets_cookie_and_stores_event(self):
        h = HTTPLib(httpc_params={"timeout": 5})
        stored = []
        h.events = SimpleNamespace(store=lambda *a, **k: stored.append((a, k)))
        with responses.RequestsMock() as rsps:
            rsps.add("GET", URL, body="ok", status=200,
                     adding_headers={"Set-Cookie": "sid=abc123; Path=/; Domain=server.example.com"})
            r = h(URL, timeout=1)
        assert r.status_code == 200 and r.text == "ok"
        assert stored[0][0][0] == "HTTP response"
        assert stored[0][1] == {"ref": URL}
        assert h._cookies() == {"sid": "abc123"}
        assert h.add_cookies({}) == {"cookies": {"sid": "abc123"}}

    def test_add_cookies_empty_jar(self):
        h = HTTPLib()
        assert h.add_cookies({"a": 1}) == {"a": 1}

    def test_send_alias_with_method(self):
        h = HTTPLib()
        with responses.RequestsMock() as rsps:
            rsps.add("POST", URL, body="{}", status=201)
            r = h.send(URL, "POST", data="x=1")
            assert rsps.calls[0].request.body == "x=1"
        assert r.status_code == 201

    def test_request_exception_is_reraised(self, caplog):
        h = HTTPLib()
        with responses.RequestsMock() as rsps:
            rsps.add("GET", URL, body=requests.ConnectionError("refused"))
            with pytest.raises(requests.ConnectionError):
                h(URL, headers={"Authorization": "Bearer secret-token"})
        assert "http_request failed" in caplog.text

    def test_req_callback_is_called(self):
        h = HTTPLib()
        seen = []

        def cb(method, url, **kwargs):
            seen.append((method, url, kwargs))
            return kwargs

        h.req_callback = cb
        assert h.run_req_callback(URL, "GET", {"x": 1}) == {"x": 1}
        with responses.RequestsMock() as rsps:
            rsps.add("GET", URL, body="ok")
            h(URL, params={"a": "b"})
        assert seen[0] == ("GET", URL, {"x": 1})
        assert seen[1][0:2] == ("GET", URL)

    def test_run_req_callback_none(self):
        assert HTTPLib().run_req_callback(URL, "GET", {"y": 2}) == {"y": 2}

    def test_set_cookie_no_header(self):
        h = HTTPLib()
        h.set_cookie(SimpleNamespace(headers={}))
        h.set_cookie(object())  # no headers attribute at all
        assert h._cookies() == {}

    def test_set_cookie_error(self, monkeypatch):
        h = HTTPLib()

        def bad(*a, **k):
            raise CookieError("illegal key")

        monkeypatch.setattr(http_mod, "set_cookie", bad)
        resp = SimpleNamespace(headers={"set-cookie": "a=b"})
        with pytest.raises(NonFatalException):
            h.set_cookie(resp)

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: client/http.py:89-97 add_cookies()/run_req_callback() operate on the "
        "caller's kwargs, but the request is sent with the _kwargs copy, so stored "
        "cookies (and callback changes) never reach the outgoing request",
    )
    def test_cookies_are_sent(self):
        h = HTTPLib()
        with responses.RequestsMock() as rsps:
            rsps.add("GET", URL, body="ok",
                     adding_headers={"Set-Cookie": "sid=abc123; Path=/; Domain=server.example.com"})
            rsps.add("GET", URL, body="ok")
            h(URL)
            h(URL)
            assert "sid=abc123" in rsps.calls[1].request.headers.get("Cookie", "")


# ---------------------------------------------------------------------------
# oauth2.Client
# ---------------------------------------------------------------------------

KEYJAR = build_keyjar(DEFAULT_KEY_DEFS)
AS = "https://as.example.com"
TOKEN_EP = "https://as.example.com/token"


def _client(**kw):
    config = {
        "client_id": "client_id",
        "client_secret": "a longesh password, really",
        "redirect_uris": ["https://rp.example.com/cb"],
        "issuer": AS,
    }
    config.update(kw.pop("config_extra", {}))
    client = Client(keyjar=KEYJAR, config=config, services=DEFAULT_OAUTH2_SERVICES, **kw)
    client.get_context().provider_info = {"issuer": AS, "token_endpoint": TOKEN_EP}
    return client


PKCE_CONF = {
    "client_id": "client_id",
    "client_secret": "a longesh password, really",
    "redirect_uris": ["https://rp.example.com/cb"],
    "add_ons": {
        "pkce": {
            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
            "kwargs": {"code_challenge_length": 64, "code_challenge_method": "S256"},
        }
    },
}


class FakeResp:
    def __init__(self, status_code, text="", ctype=None, url=TOKEN_EP):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": ctype} if ctype else {}
        self.url = url

    def json(self):
        return json.loads(self.text)


class TestClientInit:
    def test_client_type_argument(self):
        assert _client(client_type="oidc").client_type == "oidc"

    def test_client_type_from_config(self):
        assert _client(config_extra={"client_type": "oidc"}).client_type == "oidc"

    def test_default_client_type(self):
        assert _client().client_type == "oauth2"

    def test_verify_ssl_false_without_params(self):
        c = _client(verify_ssl=False)
        assert c.httpc_params["verify"] is False

    def test_verify_ssl_false_with_params(self):
        c = _client(verify_ssl=False, httpc_params={"timeout": 5})
        assert c.httpc_params == {"timeout": 5, "verify": False}

    def test_default_httpc_is_requests(self):
        assert _client().httpc is requests.request
        f = lambda *a, **k: None  # noqa: E731
        assert _client(httpc=f).httpc is f

    def test_configuration_object_with_add_ons(self):
        conf = GenericConfiguration(dict(PKCE_CONF))
        c = Client(keyjar=KEYJAR, config=conf, services=DEFAULT_OAUTH2_SERVICES)
        assert c.get_context().add_on["pkce"]["code_challenge_method"] == "S256"

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: client/oauth2/__init__.py:106 checks isinstance(config, "
        "idpyoidc.configure.Configuration); an idpyoidc.client.configure.Configuration is "
        "not one, so config.get('add_ons') (attribute lookup) returns None and the add-ons "
        "are silently ignored",
    )
    def test_client_configuration_object_with_add_ons(self):
        conf = Configuration(dict(PKCE_CONF))
        c = Client(keyjar=KEYJAR, config=conf, services=DEFAULT_OAUTH2_SERVICES)
        assert "pkce" in c.get_context().add_on

    def test_set_client_id(self):
        c = _client()
        c.set_client_id("other")
        assert c.get_context().get("client_id") == "other"


class TestGetResponse:
    def test_redirect_returned_raw(self):
        c = _client(httpc=lambda *a, **k: FakeResp(302, ctype="text/html"))
        srv = c.get_service("accesstoken")
        res = c.get_response(srv, TOKEN_EP)
        assert res["http_response"].status_code == 302

    def test_html(self):
        c = _client(httpc=lambda *a, **k: FakeResp(200, "<html/>", "text/html"))
        assert c.get_response(c.get_service("accesstoken"), TOKEN_EP,
                              response_body_type="html") == "<html/>"

    def test_data_kwarg_used_as_body_and_default_body_type(self):
        sent = []

        def httpc(method, url, data=None, headers=None, **kw):
            sent.append((method, url, data, headers))
            return FakeResp(200, json.dumps({"access_token": "AT", "token_type": "Bearer"}),
                            "application/json")

        c = _client(httpc=httpc)
        res = c.get_response(c.get_service("accesstoken"), TOKEN_EP, method="POST",
                             data="a=b", headers={"X": "1"})
        assert sent == [("POST", TOKEN_EP, "a=b", {"X": "1"})]
        assert isinstance(res, AccessTokenResponse)
        assert res["access_token"] == "AT"

    def test_httpc_exception(self):
        def httpc(*a, **k):
            raise requests.Timeout("slow")

        c = _client(httpc=httpc)
        with pytest.raises(requests.Timeout):
            c.get_response(c.get_service("accesstoken"), TOKEN_EP)

    def test_error_status_parsed(self):
        c = _client(httpc=lambda *a, **k: FakeResp(400, '{"error": "invalid_grant"}',
                                                    "application/json"))
        res = c.get_response(c.get_service("accesstoken"), TOKEN_EP)
        assert res["error"] == "invalid_grant"
        assert res["status_code"] == 400

    def test_service_request_skips_update_on_error(self, monkeypatch):
        c = _client(httpc=lambda *a, **k: FakeResp(400, '{"error": "invalid_grant"}',
                                                    "application/json"))
        srv = c.get_service("accesstoken")
        monkeypatch.setattr(srv, "update_service_context",
                            lambda *a, **k: pytest.fail("should not update"))
        res = c.service_request(srv, TOKEN_EP)
        assert res["error"] == "invalid_grant"

    def test_service_request_uses_get_response_ext(self):
        c = _client()
        calls = []

        def ext(service, url, method, body, response_body_type, headers, **kwargs):
            calls.append((url, method, headers))
            return AccessTokenResponse(access_token="X", token_type="Bearer")

        c.get_response_ext = ext
        res = c.service_request(c.get_service("accesstoken"), TOKEN_EP, method="POST")
        assert calls == [(TOKEN_EP, "POST", {})]
        assert res["access_token"] == "X"


class TestParseRequestResponse:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = _client()
        self.srv = self.client.get_service("accesstoken")

    def test_success_with_unexpected_type(self, caplog):
        text = "access_token=AT&token_type=Bearer"
        res = self.client.parse_request_response(
            self.srv, FakeResp(200, text, "application/x-www-form-urlencoded"), "json"
        )
        assert res["access_token"] == "AT"
        assert "Not the body type I expected" in caplog.text

    def test_success_unknown_ctype_uses_given_type(self):
        text = json.dumps({"access_token": "AT", "token_type": "Bearer"})
        res = self.client.parse_request_response(self.srv, FakeResp(200, text, "text/plain"),
                                                 "json")
        assert res["access_token"] == "AT"

    def test_success_parse_failure(self):
        with pytest.raises(Exception):
            self.client.parse_request_response(
                self.srv, FakeResp(200, "not json", "application/json"), "json"
            )

    def test_redirect(self):
        r = FakeResp(303)
        assert self.client.parse_request_response(self.srv, r) is r

    def test_server_error(self):
        with pytest.raises(ParseError, match="Something went wrong"):
            self.client.parse_request_response(self.srv, FakeResp(500, "boom"))

    def test_client_error_no_ctype_defaults_to_json(self):
        r = FakeResp(401, '{"error": "invalid_client"}')
        res = self.client.parse_request_response(self.srv, r, "json")
        assert res["error"] == "invalid_client"
        assert res["status_code"] == 401

    def test_client_error_fallback_to_expected_type(self):
        r = FakeResp(400, "error=invalid_request", "application/json")
        res = self.client.parse_request_response(self.srv, r, "urlencoded")
        assert res["error"] == "invalid_request"

    def test_client_error_fallback_fails(self):
        r = FakeResp(400, "<<garbage>>", "application/json")
        with pytest.raises(OidcServiceError, match="HTTP ERROR"):
            self.client.parse_request_response(self.srv, r, "urlencoded")

    def test_client_error_same_type_fails(self):
        r = FakeResp(400, "<<garbage>>", "application/json")
        with pytest.raises(OidcServiceError, match=r"\[400\]"):
            self.client.parse_request_response(self.srv, r, "json")

    def test_other_status(self):
        with pytest.raises(OidcServiceError, match=r"\[600\]"):
            self.client.parse_request_response(self.srv, FakeResp(600, "weird"))


class TestDynamicDiscovery:
    def test_oauth2_server_metadata(self):
        c = _client(config_extra={"srv_discovery_url": AS})
        c.get_context().provider_info = {}
        metadata = {
            "issuer": AS,
            "authorization_endpoint": AS + "/authz",
            "token_endpoint": TOKEN_EP,
            "response_types_supported": ["code"],
        }
        with responses.RequestsMock() as rsps:
            rsps.add("GET", OAUTH2_SERVER_METADATA_URL.format(AS), body=json.dumps(metadata),
                     adding_headers={"Content-Type": "application/json"})
            dynamic_provider_info_discovery(c)
        assert c.get_context().get("issuer") == AS
        assert c.get_context().provider_info["token_endpoint"] == TOKEN_EP

    def test_error_response(self):
        c = _client()
        with responses.RequestsMock() as rsps:
            rsps.add("GET", OAUTH2_SERVER_METADATA_URL.format(AS),
                     body=json.dumps({"error": "server_error"}), status=400,
                     adding_headers={"Content-Type": "application/json"})
            with pytest.raises(OidcServiceError, match="server_error"):
                dynamic_provider_info_discovery(c)

    def test_no_discovery_service(self):
        c = Client(keyjar=KEYJAR, config={"client_id": "x", "client_type": "oidc"},
                   services=DEFAULT_OAUTH2_SERVICES)
        with pytest.raises(ConfigurationError):
            dynamic_provider_info_discovery(c)
