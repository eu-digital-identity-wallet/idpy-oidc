"""Coverage-oriented tests for idpyoidc.server.oidc.session (OIDC end-session endpoint)."""

import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
import responses
from cryptojwt.jws.exception import JWSException
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import build_keyjar

from idpyoidc.exception import InvalidRequest
from idpyoidc.exception import VerificationError
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.message.oidc import verify_id_token
from idpyoidc.message.oidc.session import BACK_CHANNEL_LOGOUT_EVENT
from idpyoidc.message.oidc.session import EndSessionRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.oidc import userinfo
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.registration import Registration
from idpyoidc.server.oidc.session import Session
from idpyoidc.server.oidc.session import do_front_channel_logout_iframe
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from idpyoidc.time_util import utc_time_sans_frac

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

ISS = "https://example.com/"
CLI1 = "https://client1.example.com/"
CLI2 = "https://client2.example.com/"

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)
KEYJAR.import_jwks(KEYJAR.export_jwks(private=True), ISS)

RESPONSE_TYPES_SUPPORTED = [["code"], ["id_token"], ["code", "id_token"]]

PREFERENCES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

BASEDIR = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(BASEDIR, "users.json")) as _fp:
    USERINFO_DB = json.loads(_fp.read())

COOKIE_CONF = {
    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
    "name": {
        "session": "oidc_op",
        "register": "oidc_op_reg",
        "session_management": "oidc_op_sman",
    },
}


def _client_info(secret, cli, salt):
    return {
        "client_secret": secret,
        "redirect_uris": [("{}cb".format(cli), None)],
        "client_salt": salt,
        "token_endpoint_auth_method": "client_secret_post",
        "response_types_supported": ["code", "code id_token", "id_token"],
        "post_logout_redirect_uri": [f"{cli}logout_cb", ""],
        "post_logout_redirect_uris": [(f"{cli}logout_cb", None)],
        "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access"],
    }


def make_conf(issuer=ISS, session_kwargs=None):
    _skw = {
        "post_logout_uri_path": "post_logout",
        "signing_alg": "ES256",
        "logout_verify_url": "{}/verify_logout".format(issuer.rstrip("/")),
        "client_authn_method": None,
    }
    if session_kwargs:
        _skw.update(session_kwargs)
    return {
        "issuer": issuer,
        "password": "mycket hemlig zebra",
        "verify_ssl": False,
        "preferences": PREFERENCES,
        "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
        "endpoint": {
            "provider_config": {
                "path": "{}/.well-known/openid-configuration",
                "class": ProviderConfiguration,
                "kwargs": {"client_authn_method": None},
            },
            "registration": {
                "path": "{}/registration",
                "class": Registration,
                "kwargs": {"client_authn_method": None},
            },
            "authorization": {
                "path": "{}/authorization",
                "class": Authorization,
                "kwargs": {"client_authn_method": None},
            },
            "token": {"path": "{}/token", "class": Token, "kwargs": {}},
            "userinfo": {
                "path": "{}/userinfo",
                "class": userinfo.UserInfo,
                "kwargs": {"db_file": "users.json"},
            },
            "session": {
                "path": "{}/end_session",
                "class": Session,
                "kwargs": _skw,
            },
        },
        "authentication": {
            "anon": {
                "acr": INTERNETPROTOCOLPASSWORD,
                "class": "idpyoidc.server.user_authn.user.NoAuthn",
                "kwargs": {"user": "diana"},
            }
        },
        "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_DB}},
        "template_dir": "template",
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
        "session_params": SESSION_PARAMS,
    }


def make_server(issuer=ISS, session_kwargs=None, entity_id=""):
    keyjar = build_keyjar(KEYDEFS)
    keyjar.import_jwks(keyjar.export_jwks(private=True), issuer)
    server = Server(
        OPConfiguration(conf=make_conf(issuer, session_kwargs), base_path=BASEDIR),
        cwd=BASEDIR,
        cookie_handler=CookieHandler(**COOKIE_CONF),
        keyjar=keyjar,
        entity_id=entity_id,
    )
    server.context.cdb = {
        "client_1": _client_info("hemligt", CLI1, "salted"),
        "client_2": _client_info("hemligare", CLI2, "saltare"),
    }
    return server


def create_user_session(context, client_id, cli, state, nonce=None, user_id="diana"):
    _args = dict(
        state=state,
        response_type="code",
        redirect_uri="{}cb".format(cli),
        scope=["openid"],
        client_id=client_id,
    )
    if nonce:
        _args["nonce"] = nonce
    authn_event = create_authn_event(user_id, authn_info=INTERNETPROTOCOLPASSWORD)
    return context.session_manager.create_session(
        authn_event=authn_event,
        auth_req=AuthorizationRequest(**_args),
        user_id=user_id,
        client_id=client_id,
    )


class FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class TestFrontChannelIframe:
    def test_no_frontchannel_uri(self):
        assert do_front_channel_logout_iframe({}, ISS, "sid") is None

    def test_without_session_required(self):
        res = do_front_channel_logout_iframe({"frontchannel_logout_uri": "https://rp/fc"}, ISS, "s")
        assert res == '<iframe src="https://rp/fc">'

    def test_session_required_false(self):
        res = do_front_channel_logout_iframe(
            {
                "frontchannel_logout_uri": "https://rp/fc",
                "frontchannel_logout_session_required": False,
            },
            ISS,
            "s",
        )
        assert res == '<iframe src="https://rp/fc">'

    def test_session_required(self):
        res = do_front_channel_logout_iframe(
            {
                "frontchannel_logout_uri": "https://rp/fc",
                "frontchannel_logout_session_required": True,
            },
            ISS,
            "the_sid",
        )
        p = urlparse(res[len('<iframe src="') : -2])
        assert p.path == "/fc"
        assert parse_qs(p.query) == {"iss": [ISS], "sid": ["the_sid"]}

    def test_session_required_with_existing_query(self):
        res = do_front_channel_logout_iframe(
            {
                "frontchannel_logout_uri": "https://rp/fc?a=1&b=2",
                "frontchannel_logout_session_required": True,
            },
            ISS,
            "the_sid",
        )
        p = urlparse(res[len('<iframe src="') : -2])
        assert p.netloc == "rp"
        assert p.path == "/fc"
        assert parse_qs(p.query) == {"a": ["1"], "b": ["2"], "iss": [ISS], "sid": ["the_sid"]}


class TestSessionInit:
    def test_relative_check_session_iframe(self):
        server = make_server(
            session_kwargs={"check_session_iframe": "check_session"}, entity_id=ISS
        )
        ep = server.get_endpoint("session")
        assert ep.kwargs["check_session_iframe"] == "https://example.com/check_session"
        assert isinstance(ep.iv, bytes) and ep.iv

    def test_absolute_check_session_iframe(self):
        server = make_server(
            session_kwargs={"check_session_iframe": "https://other.example.com/csi"}
        )
        ep = server.get_endpoint("session")
        assert ep.kwargs["check_session_iframe"] == "https://other.example.com/csi"


class TestSessionEndpoint:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.server = make_server()
        self.context = self.server.context
        self.session_manager = self.context.session_manager
        self.session_endpoint = self.server.get_endpoint("session")
        self.keyjar = self.server.keyjar

    # ---------------------------------------------------------------- helpers
    def _create_cookie(self, session_id):
        return self.context.new_cookie(name=self.context.cookie_handler.name["session"], sid=session_id)

    # The fork always re-authenticates at the authorization endpoint, so
    # sessions are created directly through the session manager.
    def _code_auth(self, state, client_id="client_1", cli=CLI1):
        return {"session_id": create_user_session(self.context, client_id, cli, state)}

    def _session_info_from_code(self, resp):
        return self.session_manager.get_session_info(resp["session_id"], grant=True)

    def _auth_with_id_token(self, state, client_id="client_1", cli=CLI1):
        sid = create_user_session(self.context, client_id, cli, state, nonce="_nonce_")
        idt = self._mint_id_token(sid)
        return {"id_token": idt.value}, sid

    def _mint_id_token(self, session_id):
        grant = self.session_manager[session_id]
        return grant.mint_token(
            session_id=session_id,
            context=self.context,
            token_class="id_token",
            token_handler=self.session_manager.token_handler["id_token"],
            expires_at=utc_time_sans_frac() + 900,
        )

    def _verified_hint(self, id_token):
        msg = Message(id_token=id_token)
        verify_id_token(msg, keyjar=self.keyjar)
        return msg[verified_claim_name("id_token")]

    # ---------------------------------------------------------------- sid crypto
    def test_encrypt_decrypt_sid_roundtrip(self):
        enc = self.session_endpoint._encrypt_sid("my-session-id")
        assert isinstance(enc, str)
        assert enc != "my-session-id"
        assert self.session_endpoint._decrypt_sid(enc) == "my-session-id"

    # ---------------------------------------------------------------- back channel
    def test_do_back_channel_logout_no_uri(self):
        assert self.session_endpoint.do_back_channel_logout({"client_id": "client_1"}, "s") is None

    def test_do_back_channel_logout_default_alg(self):
        cinfo = {"client_id": "client_1", "backchannel_logout_uri": "https://rp/bc"}
        uri, token = self.session_endpoint.do_back_channel_logout(cinfo, "SID")
        assert uri == "https://rp/bc"
        _alg = self.context.provider_info["id_token_signing_alg_values_supported"][0]
        info = self.session_endpoint.unpack_signed_jwt(token, _alg)
        assert info["sid"] == "SID"
        assert info["aud"] == ["client_1"]
        assert info["iss"] == ISS
        assert BACK_CHANNEL_LOGOUT_EVENT in info["events"]
        assert "jti" in info

    def test_do_back_channel_logout_client_alg(self):
        cinfo = {
            "client_id": "client_1",
            "backchannel_logout_uri": "https://rp/bc",
            "id_token_signed_response_alg": "ES256",
        }
        _, token = self.session_endpoint.do_back_channel_logout(cinfo, "SID")
        info = self.session_endpoint.unpack_signed_jwt(token, "ES256")
        assert info["sid"] == "SID"

    # ---------------------------------------------------------------- unpack_signed_jwt
    def test_unpack_signed_jwt_default_alg(self):
        _jws = JWT(self.keyjar, iss=ISS, sign_alg="ES256")
        sjwt = _jws.pack(payload={"foo": "bar"}, recv=ISS)
        info = self.session_endpoint.unpack_signed_jwt(sjwt)
        assert info["foo"] == "bar"

    def test_unpack_signed_jwt_not_a_jwt(self):
        with pytest.raises(ValueError):
            self.session_endpoint.unpack_signed_jwt("not-a-jwt")

    # ---------------------------------------------------------------- logout_from_client
    def test_logout_from_client_no_logout_uris(self):
        info = self._session_info_from_code(self._code_auth("s1"))
        res = self.session_endpoint.logout_from_client(info["branch_id"])
        assert res == {}
        assert self.session_manager.get_session_info(info["branch_id"], client_session_info=True)[
            "client"
        ].is_revoked()

    def test_logout_from_client_frontchannel(self):
        info = self._session_info_from_code(self._code_auth("s1"))
        self.context.cdb["client_1"]["frontchannel_logout_uri"] = "https://rp/fc"
        self.context.cdb["client_1"]["frontchannel_logout_session_required"] = True
        res = self.session_endpoint.logout_from_client(info["branch_id"])
        assert list(res.keys()) == ["flu"]
        assert "sid=" in res["flu"]["client_1"]

    def test_logout_from_client_backchannel(self):
        info = self._session_info_from_code(self._code_auth("s1"))
        self.context.cdb["client_1"]["backchannel_logout_uri"] = "https://rp/bc"
        self.context.cdb["client_1"]["client_id"] = "client_1"
        res = self.session_endpoint.logout_from_client(info["branch_id"])
        assert list(res.keys()) == ["blu"]
        assert res["blu"]["client_1"][0] == "https://rp/bc"

    # ---------------------------------------------------------------- logout_all_clients
    def test_logout_all_clients_mixed(self):
        resp_args, sid1 = self._auth_with_id_token("s1")
        resp_args2, sid2 = self._auth_with_id_token("s2", "client_2", CLI2)
        _cdb = self.context.cdb
        _cdb["client_1"]["backchannel_logout_uri"] = "https://rp1/bc"
        _cdb["client_1"]["client_id"] = "client_1"
        _cdb["client_2"]["frontchannel_logout_uri"] = "https://rp2/fc"
        _cdb["client_2"]["client_id"] = "client_2"

        res = self.session_endpoint.logout_all_clients(sid1)
        assert set(res.keys()) == {"blu", "flu"}
        assert res["flu"]["client_2"] == '<iframe src="https://rp2/fc">'
        url, token = res["blu"]["client_1"]
        assert url == "https://rp1/bc"
        _alg = self.context.provider_info["id_token_signing_alg_values_supported"][0]
        assert self.session_endpoint.unpack_signed_jwt(token, _alg)["sid"] == sid1
        for sid in (sid1, sid2):
            assert self.session_manager.get_session_info(sid, client_session_info=True)[
                "client"
            ].is_revoked()

    def test_logout_all_clients_without_id_tokens(self):
        # Only codes issued, no ID tokens -> nothing to log out from
        info = self._session_info_from_code(self._code_auth("s1"))
        self._code_auth("s2", "client_2", CLI2)
        self.context.cdb["client_1"]["backchannel_logout_uri"] = "https://rp1/bc"
        self.context.cdb["client_2"]["frontchannel_logout_uri"] = "https://rp2/fc"
        res = self.session_endpoint.logout_all_clients(info["branch_id"])
        assert res == {}

    def test_logout_all_clients_grant_without_authn_event(self):
        resp_args, sid1 = self._auth_with_id_token("s1")
        resp_args2, sid2 = self._auth_with_id_token("s2", "client_2", CLI2)
        self.session_manager[sid1].authentication_event = None
        self.session_manager[sid2].authentication_event = None
        self.context.cdb["client_1"]["backchannel_logout_uri"] = "https://rp1/bc"
        self.context.cdb["client_2"]["frontchannel_logout_uri"] = "https://rp2/fc"
        res = self.session_endpoint.logout_all_clients(sid1)
        assert res == {}

    def test_logout_all_clients_no_logout_uris(self):
        _, sid1 = self._auth_with_id_token("s1")
        res = self.session_endpoint.logout_all_clients(sid1)
        assert res == {}

    # ---------------------------------------------------------------- do_verified_logout
    @pytest.mark.parametrize("status", [200, 501, 504, 400, 302])
    def test_do_verified_logout_backchannel_statuses(self, status):
        info = self._session_info_from_code(self._code_auth("s1"))
        self.context.cdb["client_1"]["backchannel_logout_uri"] = "https://rp/bc"
        self.context.cdb["client_1"]["client_id"] = "client_1"
        calls = []

        def fake_httpc(method, url, data=None, headers=None, **kwargs):
            calls.append((method, url, data, headers))
            return FakeResponse(status)

        self.context.httpc = fake_httpc
        res = self.session_endpoint.do_verified_logout(info["branch_id"])
        assert list(res) == []
        assert len(calls) == 1
        method, url, data, headers = calls[0]
        assert method == "POST"
        assert url == "https://rp/bc"
        assert data.startswith("logout_token=")
        assert headers == {"Content-Type": "application/x-www-form-urlencoded"}

    def test_do_verified_logout_with_responses(self):
        info = self._session_info_from_code(self._code_auth("s1"))
        self.context.cdb["client_1"]["backchannel_logout_uri"] = "https://rp/bc"
        self.context.cdb["client_1"]["client_id"] = "client_1"
        with responses.RequestsMock() as rsps:
            rsps.add("POST", "https://rp/bc", body="OK", status=200)
            res = self.session_endpoint.do_verified_logout(info["branch_id"])
            assert len(rsps.calls) == 1
        assert list(res) == []

    def test_do_verified_logout_frontchannel(self):
        info = self._session_info_from_code(self._code_auth("s1"))
        self.context.cdb["client_1"]["frontchannel_logout_uri"] = "https://rp/fc"
        res = self.session_endpoint.do_verified_logout(info["branch_id"])
        assert list(res) == ['<iframe src="https://rp/fc">']

    def test_do_verified_logout_all(self):
        _, sid1 = self._auth_with_id_token("s1")
        self._auth_with_id_token("s2", "client_2", CLI2)
        self.context.cdb["client_2"]["frontchannel_logout_uri"] = "https://rp2/fc"
        res = self.session_endpoint.do_verified_logout(sid1, alla=True)
        assert list(res) == ['<iframe src="https://rp2/fc">']

    # ---------------------------------------------------------------- process_request
    def test_process_request_post_logout_without_hint(self):
        with pytest.raises(InvalidRequest):
            self.session_endpoint.process_request(
                {"post_logout_redirect_uri": f"{CLI1}logout_cb"}, http_info={}
            )

    def test_process_request_no_cookie(self):
        with pytest.raises(ValueError, match="Missing cookie"):
            self.session_endpoint.process_request({}, http_info={})

    def test_process_request_cookie_with_other_name(self):
        cookie = self.context.new_cookie(name="something_else", sid="x")
        with pytest.raises(ValueError, match="Missing cookie"):
            self.session_endpoint.process_request({}, http_info={"cookie": [cookie]})

    def test_process_request_cookie_verification_error(self, monkeypatch):
        info = self._session_info_from_code(self._code_auth("s1"))
        cookie = self._create_cookie(info["branch_id"])

        def _raise(**kwargs):
            raise VerificationError("bad")

        monkeypatch.setattr(self.context.cookie_handler, "parse_cookie", _raise)
        with pytest.raises(InvalidRequest, match="Cookie error"):
            self.session_endpoint.process_request({}, http_info={"cookie": [cookie]})

    def test_process_request_unknown_session(self):
        info = self._session_info_from_code(self._code_auth("s1"))
        _uid, _cid, _gid = self.session_manager.decrypt_session_id(info["branch_id"])
        cookie = self._create_cookie(self.session_manager.session_key(_uid, "client_66", _gid))
        with pytest.raises(ValueError):
            self.session_endpoint.process_request({}, http_info={"cookie": [cookie]})

    def test_process_request_session_lookup_keyerror(self, monkeypatch):
        info = self._session_info_from_code(self._code_auth("s1"))
        cookie = self._create_cookie(info["branch_id"])

        def _missing(*args, **kwargs):
            raise KeyError("gone")

        monkeypatch.setattr(self.session_manager, "get_session_info", _missing)
        with pytest.raises(ValueError, match="Can't find any corresponding session"):
            self.session_endpoint.process_request({}, http_info={"cookie": [cookie]})

    def test_process_request_default_redirect(self):
        info = self._session_info_from_code(self._code_auth("s1"))
        cookie = self._create_cookie(info["branch_id"])
        # state without post_logout_redirect_uri is ignored
        resp = self.session_endpoint.process_request(
            {"state": "abc"}, http_info={"cookie": [cookie]}
        )
        p = urlparse(resp["redirect_location"])
        assert f"{p.scheme}://{p.netloc}{p.path}" == "https://example.com/verify_logout"
        jwt_info = self.session_endpoint.unpack_signed_jwt(parse_qs(p.query)["sjwt"][0])
        assert jwt_info["sid"] == info["branch_id"]
        assert jwt_info["redirect_uri"] == "https://example.com/post_logout"
        assert "state" not in jwt_info

    def test_process_request_with_hint_and_post_logout_redirect_uri(self):
        resp_args, sid = self._auth_with_id_token("s1")
        id_token = resp_args["id_token"]
        cookie = self._create_cookie(sid)
        request = {
            "id_token_hint": id_token,
            verified_claim_name("id_token_hint"): self._verified_hint(id_token),
            "post_logout_redirect_uri": f"{CLI1}logout_cb",
            "state": "xyz",
        }
        resp = self.session_endpoint.process_request(request, http_info={"cookie": [cookie]})
        p = urlparse(resp["redirect_location"])
        jwt_info = self.session_endpoint.unpack_signed_jwt(parse_qs(p.query)["sjwt"][0])
        assert jwt_info["sid"] == sid
        assert jwt_info["state"] == "xyz"
        assert jwt_info["redirect_uri"] == f"{CLI1}logout_cb?state=xyz"

    def test_process_request_with_hint_no_state(self):
        resp_args, sid = self._auth_with_id_token("s1")
        id_token = resp_args["id_token"]
        cookie = self._create_cookie(sid)
        request = {
            "id_token_hint": id_token,
            verified_claim_name("id_token_hint"): self._verified_hint(id_token),
            "post_logout_redirect_uri": f"{CLI1}logout_cb",
        }
        resp = self.session_endpoint.process_request(request, http_info={"cookie": [cookie]})
        p = urlparse(resp["redirect_location"])
        jwt_info = self.session_endpoint.unpack_signed_jwt(parse_qs(p.query)["sjwt"][0])
        assert jwt_info["redirect_uri"] == f"{CLI1}logout_cb"
        assert "state" not in jwt_info

    def test_process_request_hint_client_mismatch(self):
        resp_args, sid = self._auth_with_id_token("s1")
        _, sid2 = self._auth_with_id_token("s2", "client_2", CLI2)
        cookie = self._create_cookie(sid2)
        id_token = resp_args["id_token"]
        request = {
            "id_token_hint": id_token,
            verified_claim_name("id_token_hint"): self._verified_hint(id_token),
        }
        with pytest.raises(ValueError, match="Client ID"):
            self.session_endpoint.process_request(request, http_info={"cookie": [cookie]})

    def test_process_request_hint_sub_mismatch(self):
        resp_args, sid = self._auth_with_id_token("s1")
        cookie = self._create_cookie(sid)
        hint = self._verified_hint(resp_args["id_token"])
        hint["sub"] = "someone-else"
        request = {"id_token_hint": resp_args["id_token"], verified_claim_name("id_token_hint"): hint}
        with pytest.raises(ValueError, match="Sub"):
            self.session_endpoint.process_request(request, http_info={"cookie": [cookie]})

    # ---------------------------------------------------------------- parse_request
    @pytest.mark.xfail(
        strict=True,
        reason="BUG: src/idpyoidc/server/oidc/session.py:378 parse_request assumes the client "
        "authentication result has a 'token' key; with no/none client authentication "
        "verify_client returns {'client_id': None, 'method': 'none'} -> KeyError('token')",
    )
    def test_parse_request_without_client_authentication(self):
        req = self.session_endpoint.parse_request({"state": "abc"})
        assert isinstance(req, EndSessionRequest)
        assert req["state"] == "abc"

    def _no_client_authn(self, monkeypatch):
        monkeypatch.setattr(self.session_endpoint, "client_authentication", lambda *a, **kw: {})

    def test_parse_request_empty(self, monkeypatch):
        self._no_client_authn(monkeypatch)
        req = self.session_endpoint.parse_request(None)
        assert isinstance(req, EndSessionRequest)
        assert req.to_dict() == {}

    def test_parse_request_with_id_token_hint(self, monkeypatch):
        self._no_client_authn(monkeypatch)
        resp_args, _ = self._auth_with_id_token("s1")
        req = self.session_endpoint.parse_request(
            {"id_token_hint": resp_args["id_token"], "state": "abc"}
        )
        assert isinstance(req, EndSessionRequest)
        assert req[verified_claim_name("id_token_hint")]["aud"] == ["client_1"]
        assert req["state"] == "abc"

    def test_parse_request_unsupported_alg(self, monkeypatch):
        self._no_client_authn(monkeypatch)
        resp_args, _ = self._auth_with_id_token("s1")
        self.context.provider_info["id_token_signing_alg_values_supported"] = ["PS512"]
        with pytest.raises(JWSException):
            self.session_endpoint.parse_request({"id_token_hint": resp_args["id_token"]})

    def test_parse_request_verify_returns_false(self, monkeypatch):
        self._no_client_authn(monkeypatch)
        monkeypatch.setattr(EndSessionRequest, "verify", lambda self, **kw: False)
        with pytest.raises(InvalidRequest):
            self.session_endpoint.parse_request({"state": "abc"})

    def test_parse_request_message_passthrough(self, monkeypatch):
        self._no_client_authn(monkeypatch)
        msg = EndSessionRequest(state="abc")
        assert self.session_endpoint.parse_request(msg) is msg

    def test_parse_request_client_authn_error(self, monkeypatch):
        err = ResponseMessage(error="invalid_client")
        monkeypatch.setattr(
            self.session_endpoint, "client_authentication", lambda *a, **kw: err
        )
        assert self.session_endpoint.parse_request({"state": "x"}) is err

    def test_parse_request_client_authn_info(self, monkeypatch):
        monkeypatch.setattr(
            self.session_endpoint,
            "client_authentication",
            lambda *a, **kw: {"client_id": "client_1", "token": "tok"},
        )
        req = self.session_endpoint.parse_request({"state": "x"})
        assert req["client_id"] == "client_1"
        assert req["access_token"] == "tok"

    # ---------------------------------------------------------------- cookies
    def test_kill_cookies(self):
        info = self.session_endpoint.kill_cookies()
        assert {c["name"] for c in info} == {"oidc_op_sman", "oidc_op"}
        assert all(c["value"] == "" for c in info)
        assert all(c["expires"].startswith("Thu, 01 Jan 1970") for c in info)


class TestSessionIssuerWithoutSlash:
    def test_default_post_logout_uri_issuer_without_trailing_slash(self):
        issuer = "https://example.org"
        server = make_server(issuer=issuer)
        context = server.context
        ep = server.get_endpoint("session")
        info = {"branch_id": create_user_session(context, "client_1", CLI1, "s")}
        cookie = context.new_cookie(name=context.cookie_handler.name["session"], sid=info["branch_id"])
        res = ep.process_request({}, http_info={"cookie": [cookie]})
        p = urlparse(res["redirect_location"])
        jwt_info = ep.unpack_signed_jwt(parse_qs(p.query)["sjwt"][0])
        assert jwt_info["redirect_uri"] == "https://example.org/post_logout"
