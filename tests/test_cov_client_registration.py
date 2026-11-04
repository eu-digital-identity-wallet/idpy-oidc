"""Coverage tests for client side dynamic registration, OIDC provider info
discovery and the CIBA (backchannel authentication) client services."""
import json

import pytest
import responses
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import OIDCONF_PATTERN
from idpyoidc.client.oauth2 import Client
from idpyoidc.client.oauth2.registration import Registration
from idpyoidc.client.oidc.backchannel_authentication import BackChannelAuthentication
from idpyoidc.client.oidc.backchannel_authentication import ClientNotification
from idpyoidc.client.oidc.backchannel_authentication import ClientNotificationAuthn
from idpyoidc.client.oidc.provider_info_discovery import add_redirect_uris
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import OauthClientInformationResponse
from idpyoidc.message.oauth2 import OauthClientMetadata
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationResponse

AS_ISSUER = "https://as.example.com"
REG_ENDPOINT = "https://as.example.com/register"

REG_SERVICES = {
    "registration": {"class": "idpyoidc.client.oauth2.registration.Registration"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
}


def _reg_client(keyjar=True, extra_conf=None, services=None):
    conf = {
        "base_url": "https://rp.example.com",
        "redirect_uris": ["https://rp.example.com/cb"],
        "preference": {
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
        "jwks_uri": "https://rp.example.com/jwks.json",
    }
    if extra_conf:
        conf.update(extra_conf)
    _kj = build_keyjar(DEFAULT_KEY_DEFS) if keyjar else None
    client = Client(keyjar=_kj, config=conf, services=services or REG_SERVICES)
    client.get_context().provider_info = {
        "issuer": AS_ISSUER,
        "registration_endpoint": REG_ENDPOINT,
    }
    return client


class TestRegistrationRequest:
    def test_class_attributes(self):
        assert Registration.msg_type is OauthClientMetadata
        assert Registration.response_cls is OauthClientInformationResponse
        assert Registration.http_method == "POST"
        assert Registration.request_body_type == "json"

    def test_gather_request_args_merges_conf_and_kwargs(self):
        client = _reg_client()
        srv = client.get_service("registration")
        # Service.__init__ moves conf["request_args"] into default_request_args,
        # so set it on the conf afterwards.
        srv.conf["request_args"] = {"client_name": "From conf"}
        args = srv.gather_request_args(contacts=["ops@example.com"])
        assert args["client_name"] == "From conf"
        assert args["contacts"] == ["ops@example.com"]
        assert args["redirect_uris"] == ["https://rp.example.com/cb"]

    def test_request_parameters(self):
        client = _reg_client()
        srv = client.get_service("registration")
        info = srv.get_request_parameters()
        assert info["method"] == "POST"
        assert info["url"] == REG_ENDPOINT
        assert info["headers"]["Content-Type"] == "application/json"
        body = json.loads(info["body"])
        assert body["redirect_uris"] == ["https://rp.example.com/cb"]
        assert body["response_types"] == ["code"]
        # grant_types derived from response_types by the post_construct
        assert body["grant_types"] == ["authorization_code"]
        assert body["jwks_uri"] == "https://rp.example.com/jwks.json"

    def test_add_client_preference(self, monkeypatch):
        client = _reg_client()
        srv = client.get_service("registration")
        _context = client.get_context()
        monkeypatch.setattr(
            _context,
            "map_preferred_to_registered",
            lambda *a, **k: {
                # list value for a list parameter is kept
                "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"],
                # list value for a single valued parameter -> the first one
                "client_name": ["first", "second"],
                # plain value
                "token_endpoint_auth_method": "private_key_jwt",
                # falsy values are ignored
                "client_uri": "",
                # already given in request_args -> untouched
                "scope": "ignored",
            },
        )
        args, extra = srv.add_client_preference(request_args={"scope": "openid"})
        assert extra == {}
        assert args["redirect_uris"] == ["https://a.example.com/cb", "https://b.example.com/cb"]
        assert args["client_name"] == "first"
        assert args["token_endpoint_auth_method"] == "private_key_jwt"
        assert "client_uri" not in args
        assert args["scope"] == "openid"

    def test_post_construct(self):
        srv = _reg_client().get_service("registration")
        req = srv.oauth2_post_construct(
            {
                "response_types": ["code", "code id_token"],
                "jwks_uri": "https://rp.example.com/jwks.json",
                "jwks": {"keys": []},
            }
        )
        assert set(req["grant_types"]) == {"authorization_code", "implicit"}
        # jwks MUST NOT be used if jwks_uri is
        assert "jwks" not in req
        assert req["jwks_uri"] == "https://rp.example.com/jwks.json"

    def test_post_construct_no_response_types(self):
        srv = _reg_client().get_service("registration")
        req = srv.oauth2_post_construct({"jwks": {"keys": []}})
        assert "grant_types" not in req
        assert req["jwks"] == {"keys": []}


class TestRegistrationResponse:
    def test_update_service_context_full(self):
        client = _reg_client()
        srv = client.get_service("registration")
        resp = OauthClientInformationResponse(
            client_id="client-1",
            client_secret="a-very-secret-secret",
            client_secret_expires_at=1999999999,
            registration_access_token="rat-123",
            redirect_uris=["https://rp.example.com/cb"],
        )
        srv.update_service_context(resp)

        _context = client.get_context()
        assert _context.registration_response is resp
        assert _context.client_id == "client-1"
        assert _context.client_secret == "a-very-secret-secret"
        assert _context.get_usage("client_secret_expires_at") == 1999999999
        assert _context.get_usage("registration_access_token") == "rat-123"
        _kj = client.get_attribute("keyjar")
        assert "client-1" in _kj
        # The secret is stored as a symmetric key for both "" and client_id
        assert _kj.get_issuer_keys("client-1")
        assert any(k.kty == "oct" for k in _kj.get_issuer_keys(""))
        assert any(k.kty == "oct" for k in _kj.get_issuer_keys("client-1"))

    def test_update_service_context_no_secret(self):
        client = _reg_client()
        srv = client.get_service("registration")
        resp = OauthClientInformationResponse(client_id="client-2")
        srv.update_service_context(resp)
        _context = client.get_context()
        assert _context.client_id == "client-2"
        assert not _context.get_usage("client_secret")
        assert not _context.get_usage("registration_access_token")

    def test_update_service_context_no_client_id(self):
        client = _reg_client()
        srv = client.get_service("registration")
        resp = Message(registration_access_token="rat-only")
        srv.update_service_context(resp)
        _context = client.get_context()
        assert _context.registration_response is resp
        assert not _context.get_usage("client_id")
        assert _context.get_usage("registration_access_token") == "rat-only"

    def test_update_service_context_without_keyjar(self):
        client = _reg_client()
        # Simulate an entity without a key jar
        client.keyjar = None
        srv = client.get_service("registration")
        srv.upstream_get = _wrap_attr(srv.upstream_get, "keyjar", None)
        resp = OauthClientInformationResponse(client_id="client-3", client_secret="0123456789abcdef0123")
        srv.update_service_context(resp)
        # a fresh key jar has been created on the entity
        assert client.keyjar is not None
        assert any(k.kty == "oct" for k in client.keyjar.get_issuer_keys("client-3"))

    def test_registration_roundtrip_with_http(self):
        client = _reg_client()
        reg_resp = OauthClientInformationResponse(
            client_id="client-http",
            client_secret="xyzxyzxyzxyzxyzxyzxyz",
            client_secret_expires_at=0,
        )
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                REG_ENDPOINT,
                body=reg_resp.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            res = client.do_request("registration")
            sent = json.loads(rsps.calls[0].request.body)
        assert isinstance(res, OauthClientInformationResponse)
        assert sent["redirect_uris"] == ["https://rp.example.com/cb"]
        assert client.get_context().client_id == "client-http"

    def test_registration_error_response(self):
        client = _reg_client()
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                REG_ENDPOINT,
                body=json.dumps({"error": "invalid_redirect_uri"}),
                adding_headers={"Content-Type": "application/json"},
                status=400,
            )
            res = client.do_request("registration")
        assert res["error"] == "invalid_redirect_uri"
        assert res["status_code"] == 400
        # context not updated on error
        assert not client.get_context().get_usage("client_id")


def _wrap_attr(upstream_get, name, value):
    def _get(what, *args):
        if what == "attribute" and args and args[0] == name:
            return value
        return upstream_get(what, *args)

    return _get


# ---------------------------------------------------------------------------
# OIDC provider info discovery
# ---------------------------------------------------------------------------

OIDC_SERVICES = {
    "discovery": {"class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"},
    "registration": {"class": "idpyoidc.client.oidc.registration.Registration"},
}

OP_KEYS = build_keyjar(DEFAULT_KEY_DEFS)

OP_INFO = ProviderConfigurationResponse(
    issuer="https://op.example.com",
    authorization_endpoint="https://op.example.com/authn",
    token_endpoint="https://op.example.com/token",
    jwks_uri="https://op.example.com/jwks.json",
    response_types_supported=["code"],
    subject_types_supported=["public"],
    id_token_signing_alg_values_supported=["RS256"],
)


def _oidc_client(conf_extra=None, services=None):
    conf = {
        "issuer": "https://op.example.com",
        "client_type": "oidc",
        "base_url": "https://rp.example.com",
        "redirect_uris": ["https://rp.example.com/cb"],
    }
    if conf_extra:
        conf.update(conf_extra)
    return Client(
        keyjar=build_keyjar(DEFAULT_KEY_DEFS), config=conf, services=services or OIDC_SERVICES
    )


class TestProviderInfoDiscovery:
    def test_request(self):
        client = _oidc_client()
        srv = client.get_service("provider_info")
        info = srv.get_request_parameters()
        assert info["method"] == "GET"
        assert info["url"] == OIDCONF_PATTERN.format("https://op.example.com")

    def test_fetch_and_update(self):
        client = _oidc_client()
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                OIDCONF_PATTERN.format("https://op.example.com"),
                body=OP_INFO.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            rsps.add(
                "GET",
                OP_INFO["jwks_uri"],
                body=OP_KEYS.export_jwks_as_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            resp = client.do_request("provider_info")
        assert resp["issuer"] == "https://op.example.com"
        _context = client.get_context()
        assert _context.provider_info["token_endpoint"] == "https://op.example.com/token"
        assert client.get_service("accesstoken") is None

    def test_update_service_context_pre_load_keys(self, caplog):
        client = _oidc_client(
            services={
                "discovery": {
                    "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery",
                    "kwargs": {"pre_load_keys": True},
                }
            }
        )
        srv = client.get_service("provider_info")
        assert srv.conf["pre_load_keys"] is True
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                OP_INFO["jwks_uri"],
                body=OP_KEYS.export_jwks_as_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            with caplog.at_level("INFO"):
                srv.update_service_context(ProviderConfigurationResponse(**OP_INFO.to_dict()))
        assert "Preloaded keys for https://op.example.com" in caplog.text
        assert client.get_attribute("keyjar").get_issuer_keys("https://op.example.com")

    def test_match_preferences(self, monkeypatch):
        client = _oidc_client()
        srv = client.get_service("provider_info")
        _context = client.get_context()
        seen = []
        monkeypatch.setattr(
            _context, "map_supported_to_preferred", lambda pcr: seen.append(pcr) or {}
        )
        _context.provider_info = {"issuer": "https://op.example.com"}
        srv.match_preferences()
        srv.match_preferences(pcr={"issuer": "x"})
        assert seen == [{"issuer": "https://op.example.com"}, {"issuer": "x"}]


class _FakeClaims:
    def __init__(self, prefs, supports=None):
        self.prefs = prefs
        self.supports = supports or {}

    def get_preference(self, key, default=None):
        return self.prefs.get(key, default)


class _FakeService:
    def __init__(self, claims):
        self._claims = claims

    def upstream_get(self, what, name):
        assert (what, name) == ("attribute", "claims")
        return self._claims


class TestAddRedirectUris:
    def test_already_present(self):
        srv = _FakeService(_FakeClaims({"callback": {"code": "x"}}))
        args, extra = add_redirect_uris({"redirect_uris": ["https://keep"]}, service=srv)
        assert args == {"redirect_uris": ["https://keep"]}
        assert extra == {}

    def test_from_callback_filters_local(self):
        srv = _FakeService(
            _FakeClaims(
                {"callback": {"code": "https://rp/cb", "__hex": "abc", "implicit": "https://rp/i"}}
            )
        )
        args, _ = add_redirect_uris({}, service=srv)
        assert sorted(args["redirect_uris"]) == ["https://rp/cb", "https://rp/i"]

    def test_from_preference(self):
        srv = _FakeService(_FakeClaims({"redirect_uris": ["https://pref/cb"]}))
        args, _ = add_redirect_uris({}, service=srv)
        assert args["redirect_uris"] == ["https://pref/cb"]

    def test_from_supports_default(self):
        srv = _FakeService(_FakeClaims({}, supports={"redirect_uris": ["https://sup/cb"]}))
        args, _ = add_redirect_uris({}, service=srv)
        assert args["redirect_uris"] == ["https://sup/cb"]


# ---------------------------------------------------------------------------
# CIBA
# ---------------------------------------------------------------------------

CIBA_SERVICES = {
    "backchannel_authentication": {
        "class": "idpyoidc.client.oidc.backchannel_authentication.BackChannelAuthentication"
    },
    "client_notification": {
        "class": "idpyoidc.client.oidc.backchannel_authentication.ClientNotification"
    },
}


class TestBackchannelAuthentication:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = Client(
            keyjar=build_keyjar(DEFAULT_KEY_DEFS),
            config={"client_id": "ciba-client", "client_secret": "s3cr3ts3cr3ts3cr3ts3cr3t",
                    "client_type": "oidc"},
            services=CIBA_SERVICES,
        )
        self.client.get_context().provider_info = {
            "issuer": "https://op.example.com",
            "backchannel_authentication_endpoint": "https://op.example.com/bc-authorize",
            "client_notification_endpoint": "https://rp.example.com/notify",
        }

    def test_services(self):
        bca = self.client.get_service("backchannel_authentication")
        assert isinstance(bca, BackChannelAuthentication)
        assert bca.default_request_args == {"scope": ["openid"]}
        assert bca.pre_construct == [] and bca.post_construct == []
        cn = self.client.get_service("client_notification")
        assert isinstance(cn, ClientNotification)
        assert cn.http_method == "POST"
        assert cn.response_cls is None

    def test_authentication_request(self):
        bca = self.client.get_service("backchannel_authentication")
        info = bca.get_request_parameters(
            request_args={"login_hint": "alice@example.com", "client_id": "ciba-client"}
        )
        assert info["url"].startswith("https://op.example.com/bc-authorize")
        req = info["request"]
        assert req["scope"] == ["openid"]
        assert req["login_hint"] == "alice@example.com"

    def test_authentication_response_parse(self):
        bca = self.client.get_service("backchannel_authentication")
        resp = bca.parse_response(
            json.dumps({"auth_req_id": "1c266114", "expires_in": 120}), sformat="json"
        )
        assert isinstance(resp, AuthenticationResponse)
        assert resp["auth_req_id"] == "1c266114"

    def test_client_notification_request(self):
        cn = self.client.get_service("client_notification")
        info = cn.get_request_parameters(request_args={"auth_req_id": "1c266114"})
        assert info["method"] == "POST"
        assert info["url"] == "https://rp.example.com/notify"
        assert json.loads(info["body"]) == {"auth_req_id": "1c266114"}


class TestClientNotificationAuthn:
    def test_construct_new_http_args(self):
        req = Message(client_notification_token="tok-1", auth_req_id="x")
        http_args = ClientNotificationAuthn().construct(request=req)
        assert http_args == {"headers": {"Authorization": "Bearer tok-1"}}
        # the token is removed from the request
        assert "client_notification_token" not in req

    def test_construct_existing_headers(self):
        req = Message(client_notification_token="tok-2")
        http_args = ClientNotificationAuthn().construct(
            request=req, http_args={"headers": {"X": "y"}}
        )
        assert http_args["headers"] == {"X": "y", "Authorization": "Bearer tok-2"}

    def test_construct_http_args_without_headers(self):
        req = Message(client_notification_token="tok-3")
        http_args = ClientNotificationAuthn().construct(request=req, http_args={"timeout": 2})
        assert http_args == {"timeout": 2, "headers": {"Authorization": "Bearer tok-3"}}

    def test_construct_missing_token(self):
        with pytest.raises(KeyError):
            ClientNotificationAuthn().construct(request=Message(auth_req_id="x"))
