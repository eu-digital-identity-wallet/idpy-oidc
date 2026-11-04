"""Coverage-oriented tests for idpyoidc.server.oidc.backchannel_authentication (CIBA)."""

import json
import os
from types import SimpleNamespace

import pytest
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.key_jar import build_keyjar

from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.exception import NoSuchAuthentication
from idpyoidc.server.oidc.backchannel_authentication import DEFAULT_EXPIRES_IN
from idpyoidc.server.oidc.backchannel_authentication import DEFAULT_INTERVAL
from idpyoidc.server.oidc.backchannel_authentication import BackChannelAuthentication
from idpyoidc.server.oidc.backchannel_authentication import CIBATokenHelper
from idpyoidc.server.oidc.backchannel_authentication import ClientNotification
from idpyoidc.server.oidc.backchannel_authentication import ClientNotificationAuthn
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.session.token import MintingNotAllowed
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo

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
SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.com/"
CLIENT_ID = "client_id"
CLIENT_SECRET = "a_longer_client_secret"
CIBA_GRANT = "urn:openid:params:grant-type:ciba"

BASEDIR = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(BASEDIR, "users.json")) as _fp:
    USERINFO_DB = json.loads(_fp.read())


def parse_login_hint_token(keyjar: KeyJar, login_hint_token: str, context=None) -> str:
    _info = JWT(keyjar).unpack(login_hint_token)
    _sub_id = _info.get("sub_id")
    _sub = ""
    if _sub_id:
        if _sub_id["format"] == "phone":
            _sub = "tel:" + _sub_id["phone"]
        elif _sub_id["format"] == "mail":
            _sub = "mail:" + _sub_id["mail"]
        if _sub and context and context.login_hint_lookup:
            _sub = context.login_hint_lookup(_sub)
    return _sub


def make_conf(bca_kwargs=None):
    _kwargs = {
        "client_authn_method": ["client_secret_post"],
        "parse_login_hint_token": {"func": parse_login_hint_token},
    }
    if bca_kwargs is not None:
        _kwargs.update(bca_kwargs)
    return {
        "issuer": ISSUER,
        "httpc_params": {"verify": False, "timeout": 1},
        "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
        "token_handler_args": {
            "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "token": {
                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"]},
            },
            "refresh": {
                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"]},
            },
            "id_token": {"class": "idpyoidc.server.token.id_token.IDToken", "kwargs": {}},
        },
        "endpoint": {
            "backchannel_authentication": {
                "path": "backchannel_authn",
                "class": BackChannelAuthentication,
                "kwargs": _kwargs,
            },
            "token": {"path": "token", "class": Token, "kwargs": {}},
            "client_notification": {
                "path": "notify",
                "class": ClientNotification,
                "kwargs": {"client_authn_method": None},
            },
        },
        "authentication": {
            "anon": {
                "acr": INTERNETPROTOCOLPASSWORD,
                "class": "idpyoidc.server.user_authn.user.NoAuthn",
                "kwargs": {"user": "diana"},
            }
        },
        "login_hint_lookup": {"class": "idpyoidc.server.login_hint.LoginHintLookup"},
        "template_dir": "template",
        "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_DB}},
        "session_params": SESSION_PARAMS,
    }


def make_server(bca_kwargs=None):
    server = Server(OPConfiguration(make_conf(bca_kwargs), base_path=BASEDIR), cwd=BASEDIR)
    server.context.cdb = {
        CLIENT_ID: {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uris": [("https://example.com/cb", None)],
            "token_endpoint_auth_method": "client_secret_post",
            "allowed_scopes": ["openid", "email", "offline_access", "example-scope"],
        }
    }
    return server


class TestBackChannelAuthentication:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.server = make_server()
        self.context = self.server.context
        self.endpoint = self.server.get_endpoint("backchannel_authentication")
        self.token_endpoint = self.server.get_endpoint("token")
        self.session_manager = self.context.session_manager

        self.client_keyjar = build_keyjar(KEYDEFS)
        self.client_keyjar.import_jwks(self.server.keyjar.export_jwks(), ISSUER)
        self.server.keyjar.import_jwks(self.client_keyjar.export_jwks(), CLIENT_ID)

    def _base_request(self, **kwargs):
        req = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid email",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
        }
        req.update(kwargs)
        return req

    def test_defaults(self):
        assert self.endpoint.expires_in == DEFAULT_EXPIRES_IN
        assert self.endpoint.interval == DEFAULT_INTERVAL
        assert self.endpoint.parse_login_hint_token["func"] is parse_login_hint_token

    def test_custom_expires_and_interval(self):
        server = make_server({"expires_in": 300, "interval": 7})
        ep = server.get_endpoint("backchannel_authentication")
        assert ep.expires_in == 300
        assert ep.interval == 7

    def test_allowed_target_uris(self):
        uris = self.endpoint.allowed_target_uris()
        assert uris == {
            ISSUER,
            self.endpoint.full_path,
            self.token_endpoint.full_path,
        }
        assert any(u.endswith("backchannel_authn") for u in uris)
        assert any(u.endswith("token") for u in uris)

    # ------------------------------------------------------------- do_request_user
    def test_do_request_user_login_hint(self):
        req = self.endpoint.parse_request(
            AuthenticationRequest(**self._base_request(login_hint="mail:diana@example.org"))
            .to_urlencoded()
        )
        assert "error" not in req
        assert self.endpoint.do_request_user(req) == "diana"

    def test_do_request_user_login_hint_phone(self):
        req = Message(login_hint="tel:+46907865000")
        assert self.endpoint.do_request_user(req) == "diana"

    def test_do_request_user_login_hint_without_lookup(self):
        self.context.login_hint_lookup = None
        assert self.endpoint.do_request_user(Message(login_hint="mail:diana@example.org")) == ""

    def test_do_request_user_id_token_hint(self):
        req = Message()
        req[verified_claim_name("id_token_hint")] = {"sub": "Anna"}
        assert self.endpoint.do_request_user(req) == "Anna"

    def test_do_request_user_id_token_hint_without_sub(self):
        req = Message()
        req[verified_claim_name("id_token_hint")] = {"iss": ISSUER}
        assert self.endpoint.do_request_user(req) == ""

    def test_do_request_user_login_hint_token(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="ES256")
        token = _jwt.pack({"sub_id": {"format": "phone", "phone": "+46907865000"}}, aud=[ISSUER])
        req = self.endpoint.parse_request(
            AuthenticationRequest(**self._base_request(login_hint_token=token)).to_urlencoded(),
            verify_args={"mode": "ping"},
        )
        assert "error" not in req
        assert self.endpoint.do_request_user(req) == "diana"

    def test_do_request_user_no_hint(self):
        assert self.endpoint.do_request_user(Message(scope="openid")) == ""

    def test_parse_request_two_hints_is_error(self):
        req = self.endpoint.parse_request(
            AuthenticationRequest(
                **self._base_request(login_hint="mail:diana@example.org", login_hint_token="x")
            ).to_urlencoded()
        )
        assert isinstance(req, ResponseMessage)
        assert req["error"] == "invalid_request"

    def test_parse_request_ping_without_notification_token(self):
        _req = self._base_request(login_hint="mail:diana@example.org")
        del _req["client_notification_token"]
        req = self.endpoint.parse_request(
            AuthenticationRequest(**_req).to_urlencoded(), verify_args={"mode": "ping"}
        )
        assert req["error"] == "invalid_request"
        assert "client_notification_token" in req["error_description"]

    # ------------------------------------------------------------- process_request
    def test_process_request_known_user(self):
        req = self.endpoint.parse_request(
            AuthenticationRequest(**self._base_request(login_hint="mail:diana@example.org"))
            .to_urlencoded()
        )
        res = self.endpoint.process_request(req)
        args = res["response_args"]
        assert set(args.keys()) == {"auth_req_id", "expires_in", "interval"}
        assert args["expires_in"] == DEFAULT_EXPIRES_IN
        assert args["interval"] == DEFAULT_INTERVAL
        sid = self.session_manager.auth_req_id_map[args["auth_req_id"]]
        uid, cid, _ = self.session_manager.decrypt_session_id(sid)
        assert (uid, cid) == ("diana", CLIENT_ID)

    def test_process_request_unknown_user_keyerror(self):
        req = Message(client_id=CLIENT_ID, login_hint="mail:nobody@example.org")
        res = self.endpoint.process_request(req)
        assert isinstance(res, ResponseMessage)
        assert res["error"] == "invalid_request"
        assert res["error_description"] == "Login hint didn't lead to a known user"

    def test_process_request_no_user(self):
        res = self.endpoint.process_request(Message(client_id=CLIENT_ID, scope="openid"))
        assert isinstance(res, ResponseMessage)
        assert res["error"] == "invalid_request"
        assert res["error_description"] == "Don't know which user you're looking for"


SUBORDINATE_BUG = (
    "BUG: src/idpyoidc/server/oidc/backchannel_authentication.py:150-154 "
    "CIBATokenHelper.post_parse_request compares the client's subordinate entries (full "
    "branch keys 'user;;client;;grant') with the bare grant_id, so the CIBA request's own "
    "grant is never filtered out: with no authentication it proceeds, with exactly one "
    "authentication it reports 'More then one authentication found'"
)


def _ciba_authn_request(endpoint, scope="openid email", redirect_uri=None):
    req = Message(
        client_id=CLIENT_ID, scope=scope.split(" "), login_hint="mail:diana@example.org"
    )
    if redirect_uri:
        req["redirect_uri"] = redirect_uri
    auth_req_id = endpoint.process_request(req)["response_args"]["auth_req_id"]
    return req, auth_req_id


def _user_authenticates(session_manager, req):
    # The user authenticates on the authentication device
    ae = create_authn_event("diana", authn_info=INTERNETPROTOCOLPASSWORD)
    return session_manager.create_session(ae, req, "diana", client_id=CLIENT_ID)


class TestCIBATokenHelper:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.server = make_server()
        self.context = self.server.context
        self.endpoint = self.server.get_endpoint("backchannel_authentication")
        self.token_endpoint = self.server.get_endpoint("token")
        self.session_manager = self.context.session_manager
        self.helper = self.token_endpoint.grant_type_helper[CIBA_GRANT]

    def _token_request(self, auth_req_id, **kwargs):
        args = {"grant_type": CIBA_GRANT, "auth_req_id": auth_req_id, "client_id": CLIENT_ID}
        args.update(kwargs)
        return Message(**args)

    def _manual_post_parse(self, auth_req_id, sid):
        treq = self._token_request(auth_req_id)
        treq["_session_path"] = list(self.session_manager.decrypt_session_id(sid))
        treq["_session_id"] = self.session_manager.auth_req_id_map[auth_req_id]
        return treq

    def test_helper_is_registered(self):
        assert isinstance(self.helper, CIBATokenHelper)

    def test_unknown_auth_req_id(self):
        with pytest.raises(KeyError):
            self.helper.post_parse_request(self._token_request("unknown"))

    @pytest.mark.xfail(strict=True, reason=SUBORDINATE_BUG)
    def test_post_parse_request_no_authentication(self):
        _, auth_req_id = _ciba_authn_request(self.endpoint)
        res = self.helper.post_parse_request(self._token_request(auth_req_id))
        assert isinstance(res, ResponseMessage)
        assert res["error_description"] == "No authentication found"

    @pytest.mark.xfail(strict=True, reason=SUBORDINATE_BUG)
    def test_post_parse_request_after_one_authentication(self):
        req, auth_req_id = _ciba_authn_request(self.endpoint)
        sid2 = _user_authenticates(self.session_manager, req)
        res = self.helper.post_parse_request(self._token_request(auth_req_id))
        assert not isinstance(res, ResponseMessage)
        assert res["_session_path"] == list(self.session_manager.decrypt_session_id(sid2))

    def test_post_parse_request_multiple_authentications(self):
        req, auth_req_id = _ciba_authn_request(self.endpoint)
        _user_authenticates(self.session_manager, req)
        _user_authenticates(self.session_manager, req)
        res = self.helper.post_parse_request(self._token_request(auth_req_id))
        assert isinstance(res, ResponseMessage)
        assert res["error"] == "invalid_request"
        assert res["error_description"] == "More then one authentication found"

    def test_post_parse_request_no_subordinates(self, monkeypatch):
        _, auth_req_id = _ciba_authn_request(self.endpoint)
        _orig_get = self.session_manager.get

        def _get(path):
            node = _orig_get(path)
            if len(path) == 2:
                return SimpleNamespace(subordinate=[])
            return node

        monkeypatch.setattr(self.session_manager, "get", _get)
        res = self.helper.post_parse_request(self._token_request(auth_req_id))
        assert isinstance(res, ResponseMessage)
        assert res["error_description"] == "No authentication found"

    def test_post_parse_request_single_subordinate_sets_path(self):
        # Only the CIBA request's own grant exists (see SUBORDINATE_BUG): the request
        # is still annotated with a session path and the session id.
        _, auth_req_id = _ciba_authn_request(self.endpoint)
        res = self.helper.post_parse_request(self._token_request(auth_req_id))
        _sid = self.session_manager.auth_req_id_map[auth_req_id]
        assert res["_session_id"] == _sid
        assert res["_session_path"][:2] == ["diana", CLIENT_ID]

    def test_get_session_info(self):
        req, auth_req_id = _ciba_authn_request(self.endpoint)
        sid2 = _user_authenticates(self.session_manager, req)
        treq = self._manual_post_parse(auth_req_id, sid2)
        info, grant = self.helper._get_session_info(treq, self.session_manager)
        uid, cid, gid = self.session_manager.decrypt_session_id(sid2)
        assert info == {
            "user_id": uid,
            "client_id": cid,
            "grant_id": gid,
            "session_id": treq["_session_id"],
        }
        assert grant is self.session_manager[sid2]

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: src/idpyoidc/server/oidc/backchannel_authentication.py:243 "
        "CIBATokenHelper.process_request reads _session_info['branch_id'] but "
        "_get_session_info() never sets that key -> KeyError on every CIBA token request "
        "that passes the client/redirect_uri checks",
    )
    def test_process_request_issues_tokens(self):
        req, auth_req_id = _ciba_authn_request(self.endpoint)
        sid2 = _user_authenticates(self.session_manager, req)
        res = self.helper.process_request(self._manual_post_parse(auth_req_id, sid2))
        assert "access_token" in res
        assert "id_token" in res


class TestCIBATokenHelperProcess:
    """Exercise process_request with the missing 'branch_id' supplied (see the xfail above)."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.server = make_server()
        self.context = self.server.context
        self.endpoint = self.server.get_endpoint("backchannel_authentication")
        self.token_endpoint = self.server.get_endpoint("token")
        self.session_manager = self.context.session_manager
        self.helper = self.token_endpoint.grant_type_helper[CIBA_GRANT]

        _orig = CIBATokenHelper._get_session_info

        def _with_branch_id(helper, request, session_manager):
            info, grant = _orig(helper, request, session_manager)
            info["branch_id"] = session_manager.encrypted_session_id(*request["_session_path"])
            return info, grant

        monkeypatch.setattr(CIBATokenHelper, "_get_session_info", _with_branch_id)

    def _prepare(self, scope="openid email", redirect_uri=None, **treq_args):
        req, auth_req_id = _ciba_authn_request(self.endpoint, scope, redirect_uri)
        sid = _user_authenticates(self.session_manager, req)
        args = {"grant_type": CIBA_GRANT, "auth_req_id": auth_req_id, "client_id": CLIENT_ID}
        args.update(treq_args)
        treq = Message(**args)
        # What a correct post_parse_request would produce (see SUBORDINATE_BUG)
        treq["_session_path"] = list(self.session_manager.decrypt_session_id(sid))
        treq["_session_id"] = self.session_manager.auth_req_id_map[auth_req_id]
        return treq, sid

    def test_success_with_id_token(self):
        treq, sid = self._prepare()
        res = self.helper.process_request(treq)
        assert res["token_type"] == "Bearer"
        assert res["scope"] == ["openid", "email"]
        assert res["access_token"]
        assert res["expires_in"] > 0
        assert res["id_token"]
        assert "refresh_token" not in res
        _idt = JWT(self.server.keyjar).unpack(res["id_token"])
        assert _idt["aud"] == [CLIENT_ID]

    def test_wrong_client(self):
        treq, _ = self._prepare()
        treq["client_id"] = "someone_else"
        res = self.helper.process_request(treq)
        assert res["error"] == "invalid_grant"
        assert res["error_description"] == "Wrong client"

    def test_redirect_uri_mismatch(self):
        treq, _ = self._prepare(redirect_uri="https://example.com/cb")
        treq["redirect_uri"] = "https://evil.example.com/cb"
        res = self.helper.process_request(treq)
        assert res["error"] == "invalid_request"
        assert res["error_description"] == "redirect_uri mismatch"

    def test_redirect_uri_match(self):
        treq, _ = self._prepare(redirect_uri="https://example.com/cb")
        treq["redirect_uri"] = "https://example.com/cb"
        res = self.helper.process_request(treq)
        assert "access_token" in res

    def test_offline_access_issues_refresh_token(self):
        self.context.cdb[CLIENT_ID]["grant_types_supported"] = [CIBA_GRANT, "refresh_token"]
        treq, _ = self._prepare(scope="openid offline_access")
        res = self.helper.process_request(treq)
        assert res["refresh_token"]
        assert res["access_token"]

    def test_issue_refresh_kwarg_but_not_supported_by_client(self):
        self.context.cdb[CLIENT_ID]["grant_types_supported"] = [CIBA_GRANT]
        treq, _ = self._prepare()
        res = self.helper.process_request(treq, issue_refresh=True)
        assert "refresh_token" not in res

    def test_issue_refresh_kwarg_provider_default(self):
        self.context.provider_info["grant_types_supported"] = [CIBA_GRANT, "refresh_token"]
        treq, _ = self._prepare()
        res = self.helper.process_request(treq, issue_refresh=True)
        assert "refresh_token" in res

    def test_refresh_minting_not_allowed(self, monkeypatch):
        self.context.provider_info["grant_types_supported"] = [CIBA_GRANT, "refresh_token"]
        treq, _ = self._prepare()
        _orig = CIBATokenHelper._mint_token

        def _mint(helper, token_class, **kwargs):
            if token_class == "refresh_token":
                raise MintingNotAllowed("nope")
            return _orig(helper, token_class=token_class, **kwargs)

        monkeypatch.setattr(CIBATokenHelper, "_mint_token", _mint)
        res = self.helper.process_request(treq, issue_refresh=True)
        assert "refresh_token" not in res
        assert "access_token" in res

    def test_access_token_minting_not_allowed(self, monkeypatch):
        treq, _ = self._prepare()
        _orig = CIBATokenHelper._mint_token

        def _mint(helper, token_class, **kwargs):
            if token_class == "access_token":
                raise MintingNotAllowed("nope")
            return _orig(helper, token_class=token_class, **kwargs)

        monkeypatch.setattr(CIBATokenHelper, "_mint_token", _mint)
        res = self.helper.process_request(treq)
        assert "access_token" not in res
        assert "id_token" in res

    def test_access_token_without_expiry(self, monkeypatch):
        treq, _ = self._prepare()
        _orig = CIBATokenHelper._mint_token

        def _mint(helper, token_class, **kwargs):
            tok = _orig(helper, token_class=token_class, **kwargs)
            if token_class == "access_token":
                tok.expires_at = 0
            return tok

        monkeypatch.setattr(CIBATokenHelper, "_mint_token", _mint)
        res = self.helper.process_request(treq)
        assert "access_token" in res
        assert "expires_in" not in res

    def test_id_token_signing_failure(self, monkeypatch):
        treq, _ = self._prepare()
        _orig = CIBATokenHelper._mint_token

        def _mint(helper, token_class, **kwargs):
            if token_class == "id_token":
                raise NoSuitableSigningKeys("no keys")
            return _orig(helper, token_class=token_class, **kwargs)

        monkeypatch.setattr(CIBATokenHelper, "_mint_token", _mint)
        res = self.helper.process_request(treq)
        assert res["error"] == "invalid_request"
        assert res["error_description"] == "Could not sign/encrypt id_token"

    def test_no_openid_scope_no_id_token(self):
        treq, _ = self._prepare(scope="email")
        res = self.helper.process_request(treq)
        assert "id_token" not in res
        assert "access_token" in res

    def test_dpop_enabled_with_jkt(self):
        self.context.dpop_enabled = True
        treq, sid = self._prepare(dpop_jkt="thumbprint")
        res = self.helper.process_request(treq)
        assert res["token_type"] == "DPoP"
        assert self.session_manager[sid].extra["dpop_jkt"] == "thumbprint"

    def test_dpop_enabled_without_jkt(self):
        self.context.dpop_enabled = True
        treq, _ = self._prepare()
        res = self.helper.process_request(treq)
        assert res["token_type"] == "Bearer"


class TestClientNotification:
    def test_process_request_returns_empty(self):
        server = make_server()
        ep = server.get_endpoint("client_notification")
        assert isinstance(ep, ClientNotification)
        assert ep.process_request(Message(auth_req_id="x")) == {}
        assert ep.endpoint_name == "client_notification_endpoint"


class TestClientNotificationAuthn:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.server = make_server()
        self.authn = ClientNotificationAuthn(self.server.unit_get)

    def test_is_usable(self):
        assert self.authn.is_usable(authorization_token="Bearer abc") is True
        assert self.authn.is_usable(authorization_token="Basic abc") is False
        assert self.authn.is_usable() is False

    def test_verify_with_client_id_callback(self):
        res = self.authn._verify(
            authorization_token="Bearer tok123",
            get_client_id_from_token=lambda t: "cid-" + t,
        )
        assert res == {"token": "tok123", "client_id": "cid-tok123"}

    def test_verify_without_callback(self):
        res = self.authn._verify(authorization_token="Bearer tok123")
        assert res == {"token": "tok123", "client_id": ""}

    def test_verify_wrong_type(self):
        with pytest.raises(NoSuchAuthentication):
            self.authn._verify(authorization_token="Basic xyz")
