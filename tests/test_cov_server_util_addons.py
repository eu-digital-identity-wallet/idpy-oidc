"""Coverage tests for server.util, extra_args, custom_scopes, ROPC helper and authz."""

import json
import logging
from types import SimpleNamespace

import pytest

from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oauth2 import TokenExchangeResponse
from idpyoidc.message.oauth2 import TokenIntrospectionResponse
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server import Server
from idpyoidc.server import util
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.authz import Implicit
from idpyoidc.server.authz import factory as authz_factory
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.exception import FailedAuthentication as ServerFailedAuthentication
from idpyoidc.server.exception import OidcEndpointError
from idpyoidc.server.oauth2.add_on import extra_args
from idpyoidc.server.oauth2.token_helper import resource_owner_password_credentials as ropc
from idpyoidc.server.oauth2.token_helper.resource_owner_password_credentials import (
    ResourceOwnerPasswordCredentials,
)
from idpyoidc.server.oidc.add_on.custom_scopes import add_custom_scopes
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oauth2.token import Token
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.util import JSONDictDB

ISSUER = "https://example.com/"
CLIENT_ID = "client_1"

KEYDEFS = [{"type": "RSA", "key": "", "use": ["sig"]}]

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


def _passwd(tmp_path):
    fname = tmp_path / "passwd.json"
    fname.write_text(json.dumps({"diana": "krall"}))
    return str(fname)


def _conf(tmp_path, **extra):
    conf = {
        "issuer": ISSUER,
        "httpc_params": {"verify": False},
        "keys": {"key_defs": KEYDEFS, "uri_path": "jwks.json"},
        "endpoint": {
            "provider_config": {
                "path": ".well-known/openid-configuration",
                "class": ProviderConfiguration,
                "kwargs": {},
            },
            "authorization": {"path": "authorization", "class": Authorization, "kwargs": {}},
            "token": {
                "path": "token",
                "class": Token,
                "kwargs": {"client_authn_method": ["client_secret_post"]},
            },
        },
        "authentication": {
            "user": {
                "acr": INTERNETPROTOCOLPASSWORD,
                "class": "idpyoidc.server.user_authn.user.UserPass",
                "kwargs": {
                    "db_conf": {
                        "class": "idpyoidc.server.util.JSONDictDB",
                        "kwargs": {"filename": _passwd(tmp_path)},
                    }
                },
            }
        },
        "userinfo": {"class": "idpyoidc.server.user_info.UserInfo", "kwargs": {"db": {}}},
        "session_params": {"encrypter": CRYPT_CONFIG},
        "token_handler_args": {
            "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "token": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "id_token": {"class": "idpyoidc.server.token.id_token.IDToken", "kwargs": {}},
        },
    }
    conf.update(extra)
    return conf


def _server(tmp_path, **extra):
    srv = Server(
        OPConfiguration(conf=_conf(tmp_path, **extra), base_path=str(tmp_path)),
        cwd=str(tmp_path),
    )
    srv.context.cdb[CLIENT_ID] = {
        "client_secret": "hemligt",
        "redirect_uris": [("https://example.com/cb", None)],
        "response_types": ["code"],
        "allowed_scopes": ["openid", "profile", "resourceA"],
    }
    return srv


@pytest.fixture
def server(tmp_path):
    return _server(tmp_path)


# ---------------------------------------------------------------------------
# server.util


class _Dummy:
    name = "dummy"

    def __init__(self, upstream_get=None, **kwargs):
        self.upstream_get = upstream_get
        self.kwargs = kwargs


class TestBuildEndpoints:
    def test_class_reference_with_path(self):
        conf = {"x": {"class": _Dummy, "path": "dummy", "kwargs": {"a": 1}}}
        upstream = object()
        res = util.build_endpoints(conf, upstream, "https://op.example.org/")
        inst = res["dummy"]
        assert inst.upstream_get is upstream
        assert inst.kwargs == {"a": 1}
        assert inst.endpoint_path == "dummy"
        assert inst.full_path == "https://op.example.org/dummy"

    def test_class_string_without_path(self):
        conf = {
            "pc": {"class": "idpyoidc.server.oidc.provider_config.ProviderConfiguration"},
        }
        res = util.build_endpoints(conf, None, "https://op.example.org")
        inst = res["provider_config"]
        assert isinstance(inst, ProviderConfiguration)
        assert inst.full_path == ""

    def test_issuer_without_slash(self):
        conf = {"x": {"class": _Dummy, "path": "p"}}
        res = util.build_endpoints(conf, None, "https://op.example.org")
        assert res["dummy"].full_path == "https://op.example.org/p"
        assert res["dummy"].kwargs == {}


class TestJSONDictDB:
    def test_lookup(self, tmp_path):
        db = JSONDictDB(_passwd(tmp_path))
        assert db["diana"] == "krall"
        assert "diana" in db
        assert "ghost" not in db
        with pytest.raises(KeyError):
            db["ghost"]


class TestLV:
    def test_pack(self):
        assert util.lv_pack("abc", "", "de:f") == "3:abc0:4:de:f"

    def test_roundtrip(self):
        vals = ["abc", "with:colon", "x" * 12]
        assert util.lv_unpack(util.lv_pack(*vals)) == vals
        packed = util.lv_pack("a:b", "cd")
        assert util.lv_unpack(packed) == ["a:b", "cd"]

    def test_unpack_strips(self):
        assert util.lv_unpack("  2:ab1:c \n") == ["ab", "c"]
        assert util.lv_unpack("") == []


class TestGetHttpParams:
    @pytest.mark.parametrize(
        "config,expected",
        [
            ({}, {}),
            ({"verify": True}, {"verify": True}),
            ({"verify": False}, {"verify": False}),
            ({"verify_ssl": False}, {"verify": False}),
            ({"verify": "maybe"}, {}),
            ({"client_cert": "c.pem"}, {"cert": "c.pem"}),
            ({"client_cert": "c.pem", "client_key": "k.pem"}, {"cert": ("c.pem", "k.pem")}),
            (
                {"verify": True, "client_cert": "c.pem", "client_key": "k.pem"},
                {"verify": True, "cert": ("c.pem", "k.pem")},
            ),
        ],
    )
    def test_params(self, config, expected):
        assert util.get_http_params(config) == expected

    def test_key_without_cert(self):
        with pytest.raises(ValueError):
            util.get_http_params({"client_key": "k.pem"})


def _refresh_context(handler, supported):
    return SimpleNamespace(
        session_manager=SimpleNamespace(
            token_handler=SimpleNamespace(handler={"refresh_token": handler} if handler else {})
        ),
        get_preference=lambda key: supported,
    )


class TestAllowRefreshToken:
    def test_no_handler(self):
        assert util.allow_refresh_token(_refresh_context(None, None)) is False

    def test_handler_and_supported(self):
        ctx = _refresh_context(object(), ["authorization_code", "refresh_token"])
        assert util.allow_refresh_token(ctx) is True

    def test_handler_not_supported(self, caplog):
        ctx = _refresh_context(object(), ["authorization_code"])
        with caplog.at_level(logging.WARNING):
            assert util.allow_refresh_token(ctx) is False
        assert "grant type not supported" in caplog.text

    def test_handler_no_preference(self):
        assert util.allow_refresh_token(_refresh_context(object(), None)) is False

    def test_real_server(self, server):
        # The refresh handler exists; whether it's allowed follows the preference
        supported = server.context.get_preference("grant_types_supported") or []
        assert util.allow_refresh_token(server.context) is ("refresh_token" in supported)

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason="BUG: server/util.py:124 returns False early when there is no refresh "
        "handler, so the 'grant type supported but no handler' error (lines 139-143) is "
        "unreachable",
    )
    def test_supported_without_handler_raises(self):
        ctx = _refresh_context(None, ["refresh_token"])
        try:
            util.allow_refresh_token(ctx)
        except OidcEndpointError:
            return
        raise AssertionError("no error for refresh_token grant without handler")


def _ret_kwargs(**kwargs):
    return kwargs


class TestExecute:
    def test_class_reference(self):
        inst = util.execute({"class": _Dummy, "kwargs": {"b": 2}}, a=1)
        assert isinstance(inst, _Dummy)
        assert inst.kwargs == {"a": 1, "b": 2}

    def test_class_string(self):
        res = util.execute({"class": "types.SimpleNamespace", "kwargs": {"x": 1}}, y=2)
        assert res.x == 1
        assert res.y == 2

    def test_function_reference(self):
        assert util.execute({"func": _ret_kwargs, "kwargs": {"b": 2}}, a=1) == {"a": 1, "b": 2}

    def test_function_string(self):
        assert util.execute({"func": "idpyoidc.server.util.lv_pack"}) == ""

    def test_no_class_nor_function(self):
        assert util.execute({"kwargs": {"b": 2}}, a=1) == {"a": 1, "b": 2}


# ---------------------------------------------------------------------------
# extra_args add-on


class TestExtraArgs:
    CONF = {
        "authorization": {"iss": "issuer"},
        "accesstoken": {"issuer_name": "issuer"},
        "token_exchange": {"te_iss": "issuer"},
        "token_introspection": {"ti_iss": "issuer"},
        "userinfo": {"ui_iss": "issuer", "nothing": "empty"},
    }

    def _context(self, conf=None):
        return SimpleNamespace(add_on={"extra_args": conf or self.CONF}, issuer=ISSUER, empty="")

    @pytest.mark.parametrize(
        "cls,arg",
        [
            (AuthorizationResponse, "iss"),
            (AccessTokenResponse, "issuer_name"),
            (TokenExchangeResponse, "te_iss"),
            (TokenIntrospectionResponse, "ti_iss"),
            (OpenIDSchema, "ui_iss"),
        ],
    )
    def test_pre_construct(self, cls, arg):
        res = extra_args.pre_construct(cls(), {}, self._context())
        assert res[arg] == ISSUER
        assert "nothing" not in res

    def test_other_response_untouched(self):
        resp = ResponseMessage(error="x")
        res = extra_args.pre_construct(resp, {}, self._context())
        assert res.to_dict() == {"error": "x"}

    def test_type_not_configured(self):
        ctx = self._context({"authorization": {"iss": "issuer"}})
        res = extra_args.pre_construct(AccessTokenResponse(), {}, ctx)
        assert res.to_dict() == {}

    def test_no_add_on(self):
        ctx = SimpleNamespace(add_on={}, issuer=ISSUER)
        res = extra_args.pre_construct(AuthorizationResponse(code="c"), {}, ctx)
        assert res.to_dict() == {"code": "c"}

    def test_add_support(self, server):
        endpoints = server.endpoint
        kwargs = {"authorization": {"iss": "issuer"}, "token": {"x": "issuer"}}
        extra_args.add_support(endpoints, **kwargs)
        assert extra_args.pre_construct in endpoints["authorization"].pre_construct
        assert extra_args.pre_construct in endpoints["token"].pre_construct
        assert server.context.add_on["extra_args"] == kwargs

    def test_add_support_unknown_endpoint(self, server):
        with pytest.raises(KeyError):
            extra_args.add_support(server.endpoint, nope={"iss": "issuer"})


# ---------------------------------------------------------------------------
# custom_scopes add-on


class TestCustomScopes:
    def test_add_custom_scopes(self, server, caplog):
        context = server.context
        context.provider_info["scopes_supported"] = ["openid", "profile"]
        context.provider_info["claims_supported"] = ["sub"]
        with caplog.at_level(logging.WARNING):
            add_custom_scopes(
                server.endpoint,
                research_and_scholarship=["name", "eduperson_scoped_affiliation"],
                extra=["foo"],
            )
        assert "deprecated" in caplog.text
        pi = context.provider_info
        assert set(pi["scopes_supported"]) == {
            "openid",
            "profile",
            "research_and_scholarship",
            "extra",
        }
        assert set(pi["claims_supported"]) == {
            "sub",
            "name",
            "eduperson_scoped_affiliation",
            "foo",
        }
        handler = context.scopes_handler
        assert set(handler.allowed_scopes) == set(pi["scopes_supported"])
        mapping = handler.get_scopes_mapping()
        assert mapping["extra"] == ["foo"]
        assert "openid" in mapping  # defaults kept

    def test_without_existing_lists(self, server):
        context = server.context
        context.provider_info.pop("scopes_supported", None)
        context.provider_info.pop("claims_supported", None)
        add_custom_scopes(server.endpoint, extra=["foo"])
        assert context.provider_info["scopes_supported"] == ["extra"]
        assert context.provider_info["claims_supported"] == ["foo"]


# ---------------------------------------------------------------------------
# Resource owner password credentials


def _ropc_req(**extra):
    req = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": "hemligt",
        "username": "diana",
        "password": "krall",
    }
    req.update(extra)
    return req


class TestROPC:
    def _helper(self, server):
        return server.get_endpoint("token").grant_type_helper["password"]

    def test_helper_configured(self, server):
        helper = self._helper(server)
        assert isinstance(helper, ResourceOwnerPasswordCredentials)
        assert helper.user_db == {}
        req = _ropc_req()
        assert helper.post_parse_request(req) is req

    def test_config_with_db(self, server, tmp_path):
        endpoint = server.get_endpoint("token")
        helper = ResourceOwnerPasswordCredentials(
            endpoint,
            config={"db": {"class": JSONDictDB, "kwargs": {"filename": _passwd(tmp_path)}}},
        )
        assert helper.user_db["diana"] == "krall"
        helper2 = ResourceOwnerPasswordCredentials(endpoint, config={"other": 1})
        assert helper2.user_db == {}

    def test_success(self, server):
        res = self._helper(server).process_request(_ropc_req())
        assert res["token_type"] == "access_token"
        assert res["scope"] == ["openid", "profile", "resourceA"]
        assert res["access_token"]
        assert res["expires_in"] > 0
        info = server.context.session_manager.get_session_info_by_token(
            res["access_token"], handler_key="access_token"
        )
        assert info["user_id"] == "diana"
        assert info["client_id"] == CLIENT_ID

    @pytest.mark.xfail(
        strict=True,
        raises=TypeError,
        reason="BUG: token_helper/resource_owner_password_credentials.py:69-70 "
        "session_manager.get([user, client]) returns a ClientSessionInfo, which is then "
        "indexed with ['grant']; a second ROPC request for the same user/client crashes",
    )
    def test_second_request_reuses_session(self, server):
        helper = self._helper(server)
        first = helper.process_request(_ropc_req())
        second = helper.process_request(_ropc_req())
        assert first["access_token"] != second["access_token"]
        mngr = server.context.session_manager
        a = mngr.get_session_info_by_token(first["access_token"], handler_key="access_token")
        b = mngr.get_session_info_by_token(second["access_token"], handler_key="access_token")
        assert a["user_id"] == b["user_id"] == "diana"

    def test_no_expiry(self, server, monkeypatch):
        helper = self._helper(server)
        real_mint = helper._mint_token

        def _mint(**kwargs):
            token = real_mint(**kwargs)
            token.expires_at = 0
            return token

        monkeypatch.setattr(helper, "_mint_token", _mint)
        res = helper.process_request(_ropc_req())
        assert "expires_in" not in res

    def test_unknown_client(self, server):
        res = self._helper(server).process_request(_ropc_req(client_id="ghost"))
        assert isinstance(res, TokenErrorResponse)
        assert res["error"] == "invalid_grant"
        assert res["error_description"] == "Unknown client"

    def test_wrong_client_secret(self, server):
        res = self._helper(server).process_request(_ropc_req(client_secret="nope"))
        assert isinstance(res, TokenErrorResponse)
        assert res["error_description"] == "Wrong client"

    def test_pick_auth_fails(self, server, monkeypatch):
        def _boom(*args, **kwargs):
            raise RuntimeError("broker down")

        monkeypatch.setattr(ropc, "pick_auth", _boom)
        res = self._helper(server).process_request(_ropc_req())
        assert isinstance(res, TokenErrorResponse)
        assert res["error"] == "invalid_request"
        assert res["error_description"] == "Can't authenticate user"

    def test_no_authn_method(self, server):
        broker = server.context.authn_broker
        for key in list(broker.db.keys()):
            del broker[key]
        res = self._helper(server).process_request(_ropc_req())
        assert res["error_description"] == "Can't authenticate user"

    def test_acr_unknown(self, server):
        res = self._helper(server).process_request(_ropc_req(), acr="urn:unknown")
        assert res["error_description"] == "Can't authenticate user"

    @pytest.mark.xfail(
        strict=True,
        raises=TypeError,
        reason="BUG: token_helper/resource_owner_password_credentials.py:48 "
        "authn_broker.pick(acr) returns a list, which is then indexed with ['method']",
    )
    def test_acr_known(self, server):
        res = self._helper(server).process_request(_ropc_req(), acr=INTERNETPROTOCOLPASSWORD)
        assert res["access_token"]

    def test_wrong_user_password_with_matching_exception(self, server, monkeypatch):
        # The helper catches idpyoidc.exception.FailedAuthentication
        method = server.context.authn_broker.default()["method"]

        def _verify(**kwargs):
            raise ropc.FailedAuthentication("bad")

        monkeypatch.setattr(method, "verify", _verify)
        res = self._helper(server).process_request(_ropc_req())
        assert isinstance(res, TokenErrorResponse)
        assert res["error"] == "invalid_grant"
        assert res["error_description"] == "Wrong user"

    @pytest.mark.xfail(
        strict=True,
        raises=ServerFailedAuthentication,
        reason="BUG: token_helper/resource_owner_password_credentials.py:5 imports "
        "idpyoidc.exception.FailedAuthentication, but UserPass raises "
        "idpyoidc.server.exception.FailedAuthentication, so a wrong password escapes",
    )
    def test_wrong_user_password(self, server):
        res = self._helper(server).process_request(_ropc_req(password="wrong"))
        assert res["error_description"] == "Wrong user"


# ---------------------------------------------------------------------------
# authz


def _session(server, scope=None, client_id=CLIENT_ID):
    kwargs = {}
    if scope is not None:
        kwargs["scope"] = scope
    req = AuthorizationRequest(
        client_id=client_id,
        redirect_uri="https://example.com/cb",
        response_type="code",
        state="S",
        **kwargs,
    )
    mngr = server.context.session_manager
    return mngr.create_session(create_authn_event("diana"), req, "diana", client_id=client_id)


RULES = {
    "authorization_code": {"expires_in": 300, "max_usage": 1},
    "access_token": {"expires_in": 600},
    "refresh_token": {"expires_in": 86400},
}


class TestAuthzUsageRules:
    def _authz(self, server, rules=None):
        cfg = {"usage_rules": rules} if rules is not None else {}
        return AuthzHandling(server.unit_get, grant_config=cfg, extra=1)

    def test_kwargs_and_defaults(self, server):
        authz = AuthzHandling(server.unit_get)
        assert authz.grant_config == {}
        assert authz.usage_rules() == {}
        assert self._authz(server).kwargs == {"extra": 1}

    def test_no_client(self, server):
        authz = self._authz(server, RULES)
        res = authz.usage_rules()
        assert res == RULES
        assert res is not RULES  # deep copy
        res["access_token"]["expires_in"] = 1
        assert RULES["access_token"]["expires_in"] == 600

    def test_client_without_rules(self, server):
        assert self._authz(server, RULES).usage_rules(CLIENT_ID) == RULES

    def test_unknown_client(self, server):
        assert self._authz(server, RULES).usage_rules("ghost") == RULES

    def test_client_overrides(self, server):
        server.context.cdb[CLIENT_ID]["token_usage_rules"] = {
            "access_token": {"expires_in": 60},
            "refresh_token": {},
            "id_token": {"expires_in": 5},
        }
        res = self._authz(server, RULES).usage_rules(CLIENT_ID)
        assert res["access_token"] == {"expires_in": 60}
        assert res["refresh_token"] == {}
        assert res["authorization_code"] == RULES["authorization_code"]
        assert res["id_token"] == {"expires_in": 5}

    def test_client_rules_only(self, server):
        per_client = {"access_token": {"expires_in": 60}}
        server.context.cdb[CLIENT_ID]["token_usage_rules"] = per_client
        assert self._authz(server).usage_rules(CLIENT_ID) == per_client

    def test_usage_rules_for(self, server):
        authz = self._authz(server, RULES)
        assert authz.usage_rules_for(CLIENT_ID, "access_token") == {"expires_in": 600}
        assert authz.usage_rules_for(CLIENT_ID, "nope") == {}


class TestAuthzCall:
    def test_grant_config_applied(self, server, monkeypatch):
        sid = _session(server, scope=["openid", "profile", "email"])
        authz = AuthzHandling(
            server.unit_get,
            grant_config={"usage_rules": RULES, "expires_in": 43200, "max_usage": 7},
        )
        grant = authz(sid, {"scope": ["ignored"]})
        assert grant.usage_rules == RULES
        assert grant.expires_at > 0
        assert grant.max_usage == 7
        assert grant.resources == [CLIENT_ID]
        # email is not allowed for this client
        assert grant.scope == ["openid", "profile"]
        assert isinstance(grant.claims, dict)

    def test_explicit_resources(self, server):
        sid = _session(server, scope=["openid"])
        grant = AuthzHandling(server.unit_get)(sid, {}, resources=["https://rs.example.org"])
        assert grant.resources == ["https://rs.example.org"]

    def test_scope_from_request(self, server):
        sid = _session(server)
        grant = server.context.session_manager.get_grant(sid)
        grant.scope = []
        grant = AuthzHandling(server.unit_get)(sid, {"scope": ["openid", "email"]})
        # Not filtered when it comes from the request
        assert grant.scope == ["openid", "email"]

    def test_scope_missing(self, server):
        sid = _session(server)
        grant = server.context.session_manager.get_grant(sid)
        grant.scope = []
        grant = AuthzHandling(server.unit_get)(sid, {})
        assert grant.scope == []


class TestImplicit:
    def test_empty_config(self, server):
        sid = _session(server, scope=["openid"])
        grant = Implicit(server.unit_get)(sid, {})
        assert grant is server.context.session_manager.get_grant(sid)

    @pytest.mark.xfail(
        strict=True,
        raises=ValueError,
        reason="BUG: server/authz/__init__.py:110 iterates the grant_config dict "
        "('for arg, val in args') instead of args.items()",
    )
    def test_config_is_applied(self, server):
        sid = _session(server, scope=["openid"])
        grant = Implicit(server.unit_get, grant_config={"max_usage": 3})(sid, {})
        assert grant.max_usage == 3


class TestAuthzFactory:
    def test_known(self, server):
        authz = authz_factory("AuthzHandling", server.unit_get, grant_config={"a": 1})
        assert type(authz) is AuthzHandling
        assert authz.grant_config == {"a": 1}
        assert isinstance(authz_factory("Implicit", server.unit_get), Implicit)

    def test_unknown(self, server):
        assert authz_factory("Nope", server.unit_get) is None
