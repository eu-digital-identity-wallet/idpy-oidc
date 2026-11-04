"""Coverage tests for idpyoidc.server.user_authn.user."""

import base64
import json
import os
import warnings

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptojwt import jwt as cryptojwt_jwt

from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.exception import FailedAuthentication
from idpyoidc.server.exception import ImproperlyConfigured
from idpyoidc.server.exception import OnlyForTestingWarning
from idpyoidc.server.user_authn import user as user_mod
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_authn.authn_context import UNSPECIFIED
from idpyoidc.server.user_authn.user import BasicAuthn
from idpyoidc.server.user_authn.user import EudiwIssuer
from idpyoidc.server.user_authn.user import NoAuthn
from idpyoidc.server.user_authn.user import PidIssuerAuth
from idpyoidc.server.user_authn.user import SymKeyAuthn
from idpyoidc.server.user_authn.user import UserAuthnMethod
from idpyoidc.server.user_authn.user import UserPass
from idpyoidc.server.user_authn.user import UserPassJinja2
from idpyoidc.server.user_authn.user import create_signed_jwt
from idpyoidc.server.user_authn.user import factory
from idpyoidc.server.user_authn.user import verify_signed_jwt
from idpyoidc.server.util import JSONDictDB

BASEDIR = os.path.abspath(os.path.dirname(__file__))
ISSUER = "https://example.com/"
CLIENT_ID = "client 12345"
NOW = 1_700_000_000

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

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


class _Templates:
    """Minimal template handler that records what it was asked to render."""

    def __init__(self):
        self.calls = []

    def render(self, template, **kwargs):
        self.calls.append((template, kwargs))
        return json.dumps({"template": template, **kwargs})


def _passwd_db(tmp_path):
    fname = tmp_path / "passwd.json"
    fname.write_text(json.dumps({"diana": "krall", "babs": "howes"}))
    return {"class": JSONDictDB, "kwargs": {"filename": str(fname)}}


@pytest.fixture
def server(tmp_path):
    conf = {
        "issuer": ISSUER,
        "httpc_params": {"verify": False, "timeout": 1},
        "keys": {"key_defs": KEYDEFS, "uri_path": "jwks.json", "read_only": False},
        "authentication": {
            "user": {
                "acr": INTERNETPROTOCOLPASSWORD,
                "class": UserPassJinja2,
                "kwargs": {
                    "template": "user_pass.jinja2",
                    "db": _passwd_db(tmp_path),
                },
            },
            "anon": {"acr": UNSPECIFIED, "class": NoAuthn, "kwargs": {"user": "diana"}},
        },
        "template_dir": os.path.join(BASEDIR, "templates"),
        "cookie_handler": {
            "class": "idpyoidc.server.cookie_handler.CookieHandler",
            "kwargs": {
                "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                "name": {
                    "session": "oidc_op",
                    "register": "oidc_op_reg",
                    "session_management": "oidc_op_sman",
                },
            },
        },
        "session_params": {"encrypter": CRYPT_CONFIG},
        "token_handler_args": {
            "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "token": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        },
    }
    srv = Server(OPConfiguration(conf=conf, base_path=str(tmp_path)), cwd=str(tmp_path))
    # Tokens are signed with the server's own keys ("" owner); they are
    # verified by looking up the keys of the issuer named in the token.
    srv.keyjar.import_jwks(srv.keyjar.export_jwks(True, ""), ISSUER)
    return srv


def _cookie(server, client_id=CLIENT_ID, timestamp=None):
    context = server.context
    authn_req = {"state": "state_identifier", "client_id": client_id}
    ae = create_authn_event("diana")
    sid = context.session_manager.create_session(
        ae, authn_req, "diana", client_id=client_id, sub_type="public"
    )
    cookie = context.new_cookie(
        name=context.cookie_handler.name["session"],
        sub="diana",
        sid=sid,
        state="state_identifier",
        client_id=client_id,
    )
    kakor = context.cookie_handler.parse_cookie(
        cookies=[cookie], name=context.cookie_handler.name["session"]
    )
    if timestamp is not None:
        for k in kakor:
            k["timestamp"] = str(timestamp)
    return kakor, sid


# ---------------------------------------------------------------------------
# Base class


class TestUserAuthnMethod:
    def test_abstract_methods(self):
        method = UserAuthnMethod()
        assert method.query_param == "upm_answer"
        assert method.FAILED_AUTHN == (None, True)
        with pytest.raises(NotImplementedError):
            method()
        with pytest.raises(NotImplementedError):
            method.verify(username="x")

    def test_kwargs_are_kept(self):
        assert UserAuthnMethod(foo="bar").kwargs == {"foo": "bar"}

    def test_done(self):
        method = UserAuthnMethod()
        assert method.done({}) is True
        assert method.done({"upm_answer": "yes"}) is False

    def test_authenticated_as_without_cookie(self, server):
        method = NoAuthn(user="x", upstream_get=server.unit_get)
        assert UserAuthnMethod.authenticated_as(method, CLIENT_ID) == (None, 0)

    def test_authenticated_as_with_cookie(self, server, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        kakor, sid = _cookie(server, timestamp=NOW - 10)
        method = UserAuthnMethod(upstream_get=server.unit_get)
        info, ts = method.authenticated_as(CLIENT_ID, kakor)
        assert ts == NOW
        assert info["uid"] == "diana"
        assert info["sid"] == sid
        assert info["timestamp"] == NOW - 10
        assert info["grant_id"]

    def test_authenticated_as_max_age_ok(self, server, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        kakor, _ = _cookie(server, timestamp=NOW - 10)
        method = UserAuthnMethod(upstream_get=server.unit_get)
        info, ts = method.authenticated_as(CLIENT_ID, kakor, max_age=60)
        assert info["uid"] == "diana"
        assert ts == NOW

    def test_authenticated_as_max_age_zero_is_ignored(self, server, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        kakor, _ = _cookie(server, timestamp=NOW - 10_000)
        method = UserAuthnMethod(upstream_get=server.unit_get)
        info, _ = method.authenticated_as(CLIENT_ID, kakor, max_age=0)
        assert info["uid"] == "diana"

    def test_authenticated_as_too_old(self, server, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        kakor, _ = _cookie(server, timestamp=NOW - 120)
        method = UserAuthnMethod(upstream_get=server.unit_get)
        assert method.authenticated_as(CLIENT_ID, kakor, max_age=60) == (None, 0)

    def test_authenticated_as_cookie_for_other_client(self, server, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        kakor, _ = _cookie(server, client_id="other")
        method = UserAuthnMethod(upstream_get=server.unit_get)
        info, ts = method.authenticated_as(CLIENT_ID, kakor)
        assert info == {}
        assert ts == NOW

    def test_cookie_info_unknown_session(self, server):
        method = UserAuthnMethod(upstream_get=server.unit_get)
        cookie = [{"value": json.dumps({"sid": "unknown"}), "timestamp": "1"}]
        assert method.cookie_info(cookie, CLIENT_ID) == {}

    def test_cookie_info_none(self, server):
        method = UserAuthnMethod(upstream_get=server.unit_get)
        assert method.cookie_info(None, CLIENT_ID) == {}

    def test_unpack_token(self, server):
        method = UserAuthnMethod(upstream_get=server.unit_get)
        token = create_signed_jwt(ISSUER, server.keyjar, foo="bar")
        assert method.unpack_token(token)["foo"] == "bar"


# ---------------------------------------------------------------------------
# signed JWT helpers


class TestSignedJwt:
    def test_roundtrip(self, server):
        token = create_signed_jwt(ISSUER, server.keyjar, lifetime=60, state="abc")
        payload = verify_signed_jwt(
            token, server.keyjar, allowed_sign_algs=["RS256"], issuer=ISSUER, require_exp=True
        )
        assert payload["state"] == "abc"
        assert payload["iss"] == ISSUER
        assert "exp" in payload

    def test_wrong_issuer(self, server):
        evil = "https://evil.example.com"
        server.keyjar.import_jwks(server.keyjar.export_jwks(True, ""), evil)
        token = create_signed_jwt(evil, server.keyjar, lifetime=60)
        # Without pinning the issuer it would be accepted
        assert verify_signed_jwt(token, server.keyjar)["iss"] == evil
        with pytest.raises(ValueError, match="not issued"):
            verify_signed_jwt(token, server.keyjar, issuer=ISSUER)

    def test_missing_exp(self, server):
        token = create_signed_jwt(ISSUER, server.keyjar)
        assert "exp" not in verify_signed_jwt(token, server.keyjar)
        with pytest.raises(ValueError, match="without exp"):
            verify_signed_jwt(token, server.keyjar, require_exp=True)

    def test_wrong_alg(self, server):
        token = create_signed_jwt(ISSUER, server.keyjar, sign_alg="ES256", lifetime=60)
        assert verify_signed_jwt(token, server.keyjar, allowed_sign_algs=["ES256"])
        with pytest.raises(Exception):
            verify_signed_jwt(token, server.keyjar, allowed_sign_algs=["RS256"])


# ---------------------------------------------------------------------------
# UserPassJinja2 / UserPass


class TestUserPassJinja2:
    def _method(self, server, tmp_path, **kwargs):
        templates = _Templates()
        method = UserPassJinja2(
            db=_passwd_db(tmp_path),
            template_handler=templates,
            upstream_get=server.unit_get,
            **kwargs,
        )
        return method, templates

    def test_defaults(self, server, tmp_path):
        method, _ = self._method(server, tmp_path)
        assert method.action == "/verify/user_pass_jinja"
        assert method.template == "user_pass.jinja2"
        assert method.kwargs["page_header"] == "Log in"
        assert method.kwargs["submit_btn"] == "Log in"

    def test_custom_settings(self, server, tmp_path):
        method, _ = self._method(
            server, tmp_path, verify_endpoint="verify/user", page_header="Hi"
        )
        assert method.action == "verify/user"
        assert method.kwargs["page_header"] == "Hi"

    def test_call_renders_with_token(self, server, tmp_path):
        method, templates = self._method(server, tmp_path)
        with pytest.warns(OnlyForTestingWarning):
            out = method(state="xyz", tos_uri="https://example.com/tos")
        rendered = json.loads(out)
        assert rendered["template"] == "user_pass.jinja2"
        assert rendered["action"] == "/verify/user_pass_jinja"
        assert rendered["tos_uri"] == "https://example.com/tos"
        assert rendered["tos_label"] == "Terms of Service"
        assert rendered["policy_uri"] == ""
        assert rendered["policy_label"] == ""
        payload = method.unpack_token(rendered["token"])
        assert payload["state"] == "xyz"
        assert payload["iss"] == ISSUER

    def test_call_without_upstream_get(self, tmp_path):
        method = UserPassJinja2(db=_passwd_db(tmp_path), template_handler=_Templates())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with pytest.raises(Exception, match="upstream_get"):
                method()

    def test_verify(self, server, tmp_path):
        method, _ = self._method(server, tmp_path)
        assert method.verify(username="diana", password="krall") == "diana"
        with pytest.raises(FailedAuthentication):
            method.verify(username="diana", password="wrong")
        with pytest.raises(FailedAuthentication):
            method.verify(username="nobody", password="krall")

    def test_configured_through_server(self, server):
        method = server.context.authn_broker.pick(INTERNETPROTOCOLPASSWORD)[0]["method"]
        assert isinstance(method, UserPassJinja2)
        with pytest.warns(OnlyForTestingWarning):
            html = method(state="s")
        assert "<form" in html.lower() or "token" in html


class TestUserPass:
    def test_verify(self, tmp_path):
        method = UserPass(db_conf=_passwd_db(tmp_path))
        assert method() is None
        assert method.verify(username="babs", password="howes") == "babs"
        with pytest.raises(FailedAuthentication):
            method.verify(username="babs", password="nope")
        with pytest.raises(FailedAuthentication):
            method.verify(username="ghost", password="howes")


# ---------------------------------------------------------------------------
# BasicAuthn / SymKeyAuthn / NoAuthn


def _basic(user, pwd):
    return base64.b64encode(f"{user}:{pwd}".encode()).decode()


class TestBasicAuthn:
    def test_ok_with_prefix(self, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        method = BasicAuthn(pwd={"diana": "krall"})
        assert method.ttl == 5
        res, ts = method.authenticated_as(CLIENT_ID, authorization="Basic " + _basic("diana", "krall"))
        assert res == {"uid": "diana"}
        assert ts == NOW

    def test_ok_without_prefix_and_quoted_user(self):
        method = BasicAuthn(pwd={"a b": "pw"}, ttl=10)
        res, _ = method.authenticated_as(CLIENT_ID, authorization=_basic("a%20b", "pw"))
        assert res["uid"] == "a b"

    def test_wrong_password(self):
        method = BasicAuthn(pwd={"diana": "krall"})
        with pytest.raises(FailedAuthentication):
            method.authenticated_as(CLIENT_ID, authorization=_basic("diana", "x"))

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: user_authn/user.py:269 an unknown user raises KeyError, not FailedAuthentication",
    )
    def test_unknown_user_is_failed_authentication(self):
        method = BasicAuthn(pwd={"diana": "krall"})
        with pytest.raises(FailedAuthentication):
            method.authenticated_as(CLIENT_ID, authorization=_basic("ghost", "x"))

    def test_with_cookie(self, server):
        kakor, sid = _cookie(server)
        method = BasicAuthn(pwd={"diana": "krall"}, upstream_get=server.unit_get)
        res, _ = method.authenticated_as(
            CLIENT_ID, cookie=kakor, authorization=_basic("diana", "krall")
        )
        assert res["uid"] == "diana"
        assert res["sid"] == sid


def _sym_token(key, user=b"diana"):
    """Deterministic 'ciphertext:iv' token; neither part may contain ':'."""
    for n in range(1, 256):
        iv = bytes([n]) * 12
        enc = AESGCM(key).encrypt(iv, user, None)
        if b":" not in enc and b":" not in iv:
            return base64.b64encode(enc + b":" + iv).decode()
    raise AssertionError("no usable iv")


class TestSymKeyAuthn:
    KEY = b"0123456789abcdef0123456789abcdef"

    def test_empty_key_refused(self):
        with pytest.raises(ImproperlyConfigured):
            SymKeyAuthn(ttl=5, symkey="")

    def test_str_key_is_encoded(self):
        method = SymKeyAuthn(ttl=5, symkey=self.KEY.decode())
        assert method.symkey == self.KEY
        assert method.ttl == 5

    def test_decrypts_user(self, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        method = SymKeyAuthn(ttl=5, symkey=self.KEY)
        # The encrypted message must not contain ':' for the split to work.
        token = _sym_token(self.KEY)
        res, ts = method.authenticated_as(CLIENT_ID, authorization=token)
        assert res == {"uid": b"diana"}
        assert ts == NOW

    def test_with_cookie(self, server):
        kakor, sid = _cookie(server)
        method = SymKeyAuthn(ttl=5, symkey=self.KEY, upstream_get=server.unit_get)
        token = _sym_token(self.KEY)
        res, _ = method.authenticated_as(CLIENT_ID, cookie=kakor, authorization=token)
        assert res["uid"] == "diana"  # cookie info overrides
        assert res["sid"] == sid

    def test_wrong_key_fails(self):
        method = SymKeyAuthn(ttl=5, symkey=self.KEY)
        other = b"f" * 32
        token = _sym_token(other)
        with pytest.raises((FailedAuthentication, InvalidTag)):
            method.authenticated_as(CLIENT_ID, authorization=token)

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: user_authn/user.py:317 decryption failure raises cryptography InvalidTag "
        "instead of FailedAuthentication (only AssertionError/KeyError are caught)",
    )
    def test_wrong_key_is_failed_authentication(self):
        method = SymKeyAuthn(ttl=5, symkey=self.KEY)
        other = b"f" * 32
        token = _sym_token(other)
        with pytest.raises(FailedAuthentication):
            method.authenticated_as(CLIENT_ID, authorization=token)


class TestNoAuthn:
    def test_without_cookie(self, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        method = NoAuthn(user="diana")
        assert method.fail is None
        assert method.authenticated_as() == ({"uid": "diana"}, NOW)

    def test_forced_failure(self):
        method = NoAuthn(user="diana")
        method.fail = FailedAuthentication
        with pytest.raises(FailedAuthentication):
            method.authenticated_as()

    def test_with_cookie(self, server):
        kakor, sid = _cookie(server)
        method = NoAuthn(user="someone", upstream_get=server.unit_get)
        res, _ = method.authenticated_as(CLIENT_ID, cookie=kakor)
        assert res["uid"] == "diana"
        assert res["sid"] == sid


# ---------------------------------------------------------------------------
# PidIssuerAuth


class _OidcCfg:
    country_redirect = {"dynamic": "https://pid.example.com/dynamic"}


class TestPidIssuerAuth:
    def test_without_upstream_get(self):
        with pytest.raises(Exception, match="upstream_get"):
            PidIssuerAuth()(oidc_config=_OidcCfg(), query="scope=x")

    def test_scope_and_authorization_details(self, server):
        method = PidIssuerAuth(upstream_get=server.unit_get, extra="x")
        out = method(
            oidc_config=_OidcCfg(),
            query="scope=openid+pid&authorization_details=%5B%5D",
            logo_uri="https://example.com/logo.png",
        )
        assert out["url"] == "https://pid.example.com/dynamic"
        assert out["scope"] == ["openid", "pid"]
        assert out["authorization_details"] == "[]"
        payload = method.unpack_token(out["token"])
        assert payload["query"].startswith("scope=")
        assert "oidc_config" not in payload

    def test_no_scope_nor_details(self, server):
        method = PidIssuerAuth(upstream_get=server.unit_get)
        out = method(oidc_config=_OidcCfg(), query="state=abc")
        assert out["error"] == "invalid_authentication"
        assert out["token"]

    def test_verify(self):
        assert PidIssuerAuth().verify(username="u") == "u"

    def test_authenticated_as(self, server, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        method = PidIssuerAuth(upstream_get=server.unit_get)
        assert method.authenticated_as(CLIENT_ID) == (None, 0)
        kakor, _ = _cookie(server, timestamp=NOW - 10)
        info, ts = method.authenticated_as(CLIENT_ID, kakor, max_age=60)
        assert info["uid"] == "diana" and ts == NOW
        kakor, _ = _cookie(server, timestamp=NOW - 100)
        assert method.authenticated_as(CLIENT_ID, kakor, max_age=60) == (None, 0)
        kakor, _ = _cookie(server, client_id="other")
        assert method.authenticated_as(CLIENT_ID, kakor) == ({}, NOW)

    def test_cookie_info(self, server):
        method = PidIssuerAuth(upstream_get=server.unit_get)
        assert method.cookie_info(None, CLIENT_ID) == {}
        bad = [{"value": json.dumps({"sid": "nope"}), "timestamp": "1"}]
        assert method.cookie_info(bad, CLIENT_ID) == {}


# ---------------------------------------------------------------------------
# EudiwIssuer


class TestEudiwIssuer:
    def test_defaults(self):
        method = EudiwIssuer()
        assert method.token_lifetime == EudiwIssuer.DEFAULT_TOKEN_LIFETIME
        assert method.sign_alg == "RS256"
        assert EudiwIssuer(token_lifetime="60").token_lifetime == 60

    def test_without_upstream_get(self):
        with pytest.raises(Exception, match="upstream_get"):
            EudiwIssuer()(query="")

    def test_call_and_unpack(self, server):
        method = EudiwIssuer(upstream_get=server.unit_get, token_lifetime=300)
        out = method(query="scope=pid", state="s1", policy_uri="https://example.com/p")
        assert set(out.keys()) == {"jws"}
        payload = method.unpack_token(out["jws"])
        assert payload["state"] == "s1"
        assert payload["iss"] == ISSUER
        assert payload["exp"] - payload["iat"] == 300

    def test_custom_sign_alg(self, server):
        method = EudiwIssuer(upstream_get=server.unit_get, sign_alg="ES256")
        out = method(query="")
        assert method.unpack_token(out["jws"])["iss"] == ISSUER
        # An RS256-pinned instance refuses the ES256 token
        with pytest.raises(Exception):
            EudiwIssuer(upstream_get=server.unit_get).unpack_token(out["jws"])

    def test_unpack_wrong_alg(self, server):
        token = create_signed_jwt(ISSUER, server.keyjar, sign_alg="ES256", lifetime=60)
        with pytest.raises(Exception):
            EudiwIssuer(upstream_get=server.unit_get).unpack_token(token)

    def test_unpack_wrong_issuer(self, server):
        evil = "https://evil.example.com"
        server.keyjar.import_jwks(server.keyjar.export_jwks(True, ""), evil)
        token = create_signed_jwt(evil, server.keyjar, lifetime=60)
        with pytest.raises(ValueError, match="not issued"):
            EudiwIssuer(upstream_get=server.unit_get).unpack_token(token)

    def test_unpack_missing_exp(self, server):
        token = create_signed_jwt(ISSUER, server.keyjar)
        with pytest.raises(ValueError, match="without exp"):
            EudiwIssuer(upstream_get=server.unit_get).unpack_token(token)

    def test_unpack_expired(self, server, monkeypatch):
        method = EudiwIssuer(upstream_get=server.unit_get, token_lifetime=60)
        token = method(query="")["jws"]
        real_now = cryptojwt_jwt.utc_time_sans_frac()
        monkeypatch.setattr(cryptojwt_jwt, "utc_time_sans_frac", lambda: real_now + 3600)
        with pytest.raises(Exception, match="expired"):
            method.unpack_token(token)

    def test_verify(self):
        assert EudiwIssuer().verify(username="u") == "u"

    def test_authenticated_as(self, server, monkeypatch):
        monkeypatch.setattr(user_mod, "utc_time_sans_frac", lambda: NOW)
        method = EudiwIssuer(upstream_get=server.unit_get)
        assert method.authenticated_as(CLIENT_ID) == (None, 0)
        kakor, sid = _cookie(server, timestamp=NOW - 10)
        info, ts = method.authenticated_as(CLIENT_ID, kakor, max_age=60)
        assert info["sid"] == sid and ts == NOW
        kakor, _ = _cookie(server, timestamp=NOW - 100)
        assert method.authenticated_as(CLIENT_ID, kakor, max_age=60) == (None, 0)
        kakor, _ = _cookie(server, client_id="other")
        assert method.authenticated_as(CLIENT_ID, kakor) == ({}, NOW)

    def test_cookie_info(self, server):
        method = EudiwIssuer(upstream_get=server.unit_get)
        assert method.cookie_info(None, CLIENT_ID) == {}
        bad = [{"value": json.dumps({"sid": "nope"}), "timestamp": "1"}]
        assert method.cookie_info(bad, CLIENT_ID) == {}


# ---------------------------------------------------------------------------
# factory


class TestFactory:
    def test_known_class(self):
        method = factory("NoAuthn", user="diana")
        assert isinstance(method, NoAuthn)
        assert method.user == "diana"

    def test_unknown_class(self):
        assert factory("NoSuchAuthn", user="x") is None

    def test_eudiw_issuer_is_not_a_user_authn_method(self):
        # EudiwIssuer/PidIssuerAuth don't derive from UserAuthnMethod so the
        # factory can't build them.
        assert factory("EudiwIssuer") is None
        assert factory("PidIssuerAuth") is None
