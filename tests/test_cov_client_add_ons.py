"""Coverage tests for the OAuth2 client add-ons: status_check, PAR, DPoP and JAR."""
import json
import os
from hashlib import sha256
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import responses
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.oauth2 import Client
from idpyoidc.client.oauth2.add_on import dpop
from idpyoidc.client.oauth2.add_on import jar
from idpyoidc.client.oauth2.add_on import par
from idpyoidc.client.oauth2.add_on import status_check
from idpyoidc.client.oauth2.add_on.dpop import DPoPClientAuth
from idpyoidc.client.oauth2.add_on.dpop import DPoPProof
from idpyoidc.client.oauth2.add_on.dpop import dpop_header
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationRequest

AS = "https://as.example.com"
SECRET = "a longesh password, long enough"
REDIRECT = "https://rp.example.com/cb"
KEYJAR = build_keyjar(DEFAULT_KEY_DEFS)


def _client(add_ons=None, services=None, **extra):
    config = {
        "client_id": "client_id",
        "client_secret": SECRET,
        "base_url": "https://rp.example.com",
        "redirect_uris": [REDIRECT],
        "preference": {"response_types": ["code"]},
    }
    if add_ons:
        config["add_ons"] = add_ons
    config.update(extra)
    return Client(keyjar=KEYJAR, config=config, services=services or DEFAULT_OAUTH2_SERVICES)


# ---------------------------------------------------------------------------
# status_check
# ---------------------------------------------------------------------------


class TestStatusCheck:
    def _context(self, tmp_path):
        template = tmp_path / "check.html"
        template.write_text("<iframe src='{check_session_iframe}'/><iframe src='{status_check_iframe}'/>")
        return SimpleNamespace(
            add_on={
                "status_check": {
                    "template_file": str(template),
                    "session_changed_iframe": "https://rp/changed",
                    "session_unchanged_iframe": "https://rp/unchanged",
                }
            },
            provider_info={"check_session_iframe": "https://op/check"},
        )

    def test_page_changed(self, tmp_path):
        page = status_check.get_session_status_page(self._context(tmp_path), "changed")
        assert isinstance(page, bytes)
        assert page == b"<iframe src='https://op/check'/><iframe src='https://rp/changed'/>"

    def test_page_unchanged(self, tmp_path):
        page = status_check.get_session_status_page(self._context(tmp_path), "unchanged")
        assert b"https://rp/unchanged" in page
        assert b"https://rp/changed'" not in page

    def test_add_support_with_service_context_attribute(self):
        ctx = SimpleNamespace(add_on={})
        services = {"authorization": SimpleNamespace(service_context=ctx)}
        status_check.add_support(
            services,
            rp_iframe_path="/rp_iframe",
            template_file="tmpl.html",
            session_changed_iframe_path="/changed",
            session_unchanged_iframe_path="/unchanged",
        )
        conf = ctx.add_on["status_check"]
        assert conf["rp_iframe_path"] == "/rp_iframe"
        assert conf["template_file"] == "tmpl.html"
        assert conf["session_changed_iframe"] == "/changed"
        assert conf["session_unchanged_iframe"] == "/unchanged"
        assert conf["get_session_status_page"] is status_check.get_session_status_page

    @pytest.mark.xfail(
        strict=True,
        raises=AttributeError,
        reason="BUG: client/oauth2/add_on/status_check.py:43 uses service.service_context, "
        "which no longer exists on Service (should use upstream_get('context'))",
    )
    def test_add_support_real_client(self):
        client = _client()
        status_check.add_support(client.get_services(), rp_iframe_path="/rp_iframe")
        assert "status_check" in client.get_context().add_on


# ---------------------------------------------------------------------------
# PAR
# ---------------------------------------------------------------------------

PAR_ENDPOINT = "https://as.example.com/push"
PAR_RESPONSE = {"request_uri": "urn:example:bwc4JK-ESC0w8acc191e", "expires_in": 3600}


class RecordingHttp:
    """A fake HTTP client that records calls."""

    def __init__(self, status_code=200, text=json.dumps(PAR_RESPONSE)):
        self.calls = []
        self.status_code = status_code
        self.text = text

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return SimpleNamespace(status_code=self.status_code, text=self.text)


def _par_client(**kwargs):
    client = _client(
        add_ons={
            "pushed_authorization": {
                "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                "kwargs": kwargs,
            }
        }
    )
    client.get_context().provider_info = {
        "issuer": AS,
        "authorization_endpoint": "https://as.example.com/authz",
        "pushed_authorization_request_endpoint": PAR_ENDPOINT,
    }
    return client


class TestPAR:
    def test_add_support_registers_post_construct(self):
        client = _par_client()
        srv = client.get_service("authorization")
        assert par.push_authorization in srv.post_construct
        assert client.get_context().add_on["pushed_authorization"] == {
            "http_client": None,
            "authn_method": "",
        }

    def test_no_authn_uses_entity_httpc(self):
        client = _par_client()
        rec = RecordingHttp()
        client.httpc = rec
        srv = client.get_service("authorization")
        req = srv.construct(request_args={"response_type": "code", "foo": "bar"}, state="S")
        method, url, kwargs = rec.calls[0]
        assert method == "POST"
        assert url == PAR_ENDPOINT
        assert kwargs["headers"] == {}
        sent = parse_qs(kwargs["data"])
        assert sent["foo"] == ["bar"]
        assert sent["state"] == ["S"]
        assert req["request_uri"] == PAR_RESPONSE["request_uri"]
        assert "foo" not in req
        assert req["client_id"] == "client_id"

    def test_http_client_instance_from_class(self):
        client = _par_client(http_client={"class": RecordingHttp, "kwargs": {}})
        _http = client.get_context().add_on["pushed_authorization"]["http_client"]
        assert isinstance(_http, RecordingHttp)
        req = client.get_service("authorization").construct(
            request_args={"response_type": "code"}, state="S"
        )
        assert len(_http.calls) == 1
        assert req["request_uri"] == PAR_RESPONSE["request_uri"]

    def test_http_client_from_function_dict_and_string(self):
        c1 = _par_client(http_client={"function": "requests.request"})
        c2 = _par_client(http_client="requests.request")
        import requests

        assert c1.get_context().add_on["pushed_authorization"]["http_client"] is requests.request
        assert c2.get_context().add_on["pushed_authorization"]["http_client"] is requests.request

        with responses.RequestsMock() as rsps:
            rsps.add("POST", PAR_ENDPOINT, body=json.dumps(PAR_RESPONSE), status=200)
            req = c2.get_service("authorization").construct(
                request_args={"response_type": "code"}, state="S"
            )
        assert req["request_uri"] == PAR_RESPONSE["request_uri"]

    def test_authn_method_string(self):
        client = _par_client(authn_method="client_secret_basic")
        rec = RecordingHttp()
        client.httpc = rec
        client.get_service("authorization").construct(
            request_args={"response_type": "code"}, state="S"
        )
        headers = rec.calls[0][2]["headers"]
        assert headers["Authorization"].startswith("Basic ")
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert "client_secret_basic" in client.get_context().client_authn_methods

    def test_authn_method_dict(self):
        client = _par_client(
            authn_method={
                "client_secret_post": {
                    "class": "idpyoidc.client.client_auth.ClientSecretPost"
                }
            }
        )
        rec = RecordingHttp()
        client.httpc = rec
        client.get_service("authorization").construct(
            request_args={"response_type": "code"}, state="S"
        )
        sent = parse_qs(rec.calls[0][2]["data"])
        assert rec.calls[0][2]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        assert "client_secret_post" in client.get_context().client_authn_methods
        assert sent["response_type"] == ["code"]

    def test_error_status(self):
        client = _par_client()
        client.httpc = RecordingHttp(status_code=400, text='{"error":"invalid_request"}')
        with pytest.raises(ConnectionError, match=PAR_ENDPOINT):
            client.get_service("authorization").construct(
                request_args={"response_type": "code"}, state="S"
            )


# ---------------------------------------------------------------------------
# DPoP
# ---------------------------------------------------------------------------


def _dpop_client(algs=("ES256", "ES512"), with_dpop_header=None, services=None):
    kwargs = {"dpop_signing_alg_values_supported": list(algs)}
    if with_dpop_header is not None:
        kwargs["with_dpop_header"] = with_dpop_header
    client = _client(
        add_ons={
            "dpop": {
                "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                "kwargs": kwargs,
            }
        },
        services=services,
    )
    client.get_context().provider_info = {
        "issuer": AS,
        "authorization_endpoint": "https://as.example.com/authz",
        "token_endpoint": "https://as.example.com/token",
        "userinfo_endpoint": "https://as.example.com/userinfo",
    }
    return client


class TestDPoPProof:
    def _proof(self, **kw):
        key = new_ec_key("P-256")
        args = {
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": key.serialize(),
            "jti": "jti-1",
            "htm": "POST",
            "htu": "https://as.example.com/token",
            "iat": 1700000000,
        }
        args.update(kw)
        return key, DPoPProof(**args)

    def test_init_with_jwk_sets_key(self):
        key, proof = self._proof()
        assert proof.key is not None
        assert proof.key.serialize() == key.serialize()

    def test_init_without_jwk(self):
        proof = DPoPProof(typ="dpop+jwt")
        assert proof.key is None

    def test_from_dict_sets_key(self):
        key = new_ec_key("P-256")
        proof = DPoPProof().from_dict({"typ": "dpop+jwt", "jwk": key.serialize()})
        assert proof.key.serialize() == key.serialize()
        proof2 = DPoPProof().from_dict({"typ": "dpop+jwt"})
        assert proof2.key is None

    def test_verify(self):
        _, proof = self._proof()
        proof.verify()

    def test_verify_wrong_type(self):
        _, proof = self._proof(typ="jwt")
        with pytest.raises(ValueError, match="Wrong type"):
            proof.verify()

    def test_verify_alg_none(self):
        _, proof = self._proof(alg="none")
        with pytest.raises(ValueError, match="none"):
            proof.verify()

    def test_create_and_verify_header(self):
        key, proof = self._proof(ath="abc")
        proof.key = new_ec_key("P-256")
        proof["jwk"] = proof.key.serialize()
        header = proof.create_header()
        _jws = factory(header)
        assert _jws.jwt.headers["typ"] == "dpop+jwt"
        assert _jws.jwt.payload()["ath"] == "abc"

        parsed = DPoPProof().verify_header(header)
        assert parsed["htm"] == "POST"
        assert parsed["htu"] == "https://as.example.com/token"
        assert parsed["typ"] == "dpop+jwt"
        assert parsed["ath"] == "abc"

    def test_verify_header_not_a_jws(self):
        assert DPoPProof().verify_header("not-a-jws") is None

    def test_verify_header_without_jwk(self):
        _jwt = JWT(key_jar=KEYJAR, iss="x", sign_alg="ES256")
        token = _jwt.pack({"htm": "GET"})
        with pytest.raises(Exception):
            DPoPProof().verify_header(token)


class TestDPoPHeader:
    def test_add_support_preferences_and_hooks(self):
        client = _dpop_client(algs=["ES256", "foo"])
        _context = client.get_context()
        assert _context.add_on["dpop"] == {"algs_supported": ["ES256"]}
        assert _context.claims.get_preference("dpop_signing_alg_values_supported") == ["ES256"]
        assert dpop_header in client.get_service("accesstoken").construct_extra_headers

    def test_add_support_with_dpop_header_list(self):
        services = dict(DEFAULT_OAUTH2_SERVICES)
        services["userinfo"] = {"class": "idpyoidc.client.oidc.userinfo.UserInfo"}
        client = _dpop_client(
            with_dpop_header=["accesstoken", "refresh_token", "unknown"], services=services
        )
        assert dpop_header in client.get_service("refresh_token").construct_extra_headers
        assert dpop_header in client.get_service("userinfo").construct_extra_headers
        # accesstoken only once
        assert client.get_service("accesstoken").construct_extra_headers.count(dpop_header) == 1

    def test_header_via_service(self):
        client = _dpop_client()
        srv = client.get_service("accesstoken")
        headers = srv.get_headers(request={"grant_type": "authorization_code"}, http_method="POST")
        _jws = factory(headers["dpop"])
        assert _jws.jwt.payload()["htu"] == "https://as.example.com/token"
        assert _jws.jwt.headers["alg"] == "ES256"
        # The key is minted once and stored
        assert client.get_context().add_on["dpop"]["alg"] == "ES256"
        key = client.get_context().add_on["dpop"]["key"]
        headers2 = srv.get_headers(request={"grant_type": "authorization_code"}, http_method="POST")
        assert factory(headers2["dpop"]).jwt.headers["jwk"] == key.serialize()

    def test_header_explicit_url_and_token(self):
        client = _dpop_client()
        _context = client.get_context()
        headers = dpop_header(
            _context,
            "token_endpoint",
            "GET",
            headers={"X-Foo": "bar"},
            token="access-token",
            endpoint_url="https://rs.example.com/resource",
        )
        assert headers["X-Foo"] == "bar"
        _jws = factory(headers["dpop"])
        payload = _jws.jwt.payload()
        assert payload["htu"] == "https://rs.example.com/resource"
        assert payload["htm"] == "GET"
        assert payload["ath"] == sha256(b"access-token").hexdigest()
        # the proof verifies with the embedded jwk
        assert DPoPProof().verify_header(headers["dpop"])["htm"] == "GET"

    @pytest.mark.xfail(
        strict=True,
        raises=KeyError,
        reason="BUG: client/oauth2/add_on/dpop.py:155 puts the server nonce in the proof "
        "claims, but DPoPProof.body_params (dpop.py:39) lacks 'nonce', so create_header() "
        "silently drops it (RFC 9449 section 8 requires it in the JWT payload)",
    )
    def test_header_nonce_in_proof(self):
        client = _dpop_client()
        headers = dpop_header(client.get_context(), "token_endpoint", "POST", nonce="n-1")
        assert factory(headers["dpop"]).jwt.payload()["nonce"] == "n-1"

    def test_header_endpoint_kwarg(self):
        client = _dpop_client()
        headers = dpop_header(
            client.get_context(), "token_endpoint", "POST", endpoint="https://kw.example.com/t"
        )
        assert factory(headers["dpop"]).jwt.payload()["htu"] == "https://kw.example.com/t"

    def test_header_without_dpop_support(self):
        client = _client()
        client.get_context().provider_info = {"token_endpoint": "https://as.example.com/token"}
        hdrs = {"a": "b"}
        assert dpop_header(client.get_context(), "token_endpoint", "POST", headers=hdrs) is hdrs

    def test_header_alg_none_configured(self):
        client = _dpop_client()
        client.get_context().add_on["dpop"] = {"algs_supported": [None]}
        assert dpop_header(client.get_context(), "token_endpoint", "POST", headers={}) == {}

    @pytest.mark.xfail(
        strict=True,
        raises=IndexError,
        reason="BUG: client/oauth2/add_on/dpop.py:131 indexes [0] on an empty algs_supported "
        "list -> IndexError instead of returning the headers unchanged",
    )
    def test_header_no_supported_algs(self):
        client = _dpop_client(algs=["not-an-alg"])
        assert dpop_header(client.get_context(), "token_endpoint", "POST", headers={}) == {}


class TestDPoPClientAuth:
    def test_token_from_request(self):
        req = Message(access_token="AT-1")
        http_args = DPoPClientAuth().construct(request=req)
        assert http_args == {"headers": {"Authorization": "DPoP AT-1"}}
        assert "access_token" not in req

    def test_token_from_kwargs_existing_headers(self):
        http_args = DPoPClientAuth().construct(
            request=Message(), http_args={"headers": {"X": "y"}}, access_token="AT-2"
        )
        assert http_args["headers"] == {"X": "y", "Authorization": "DPoP AT-2"}

    def test_http_args_without_headers(self):
        http_args = DPoPClientAuth().construct(
            request=Message(access_token="AT-3"), http_args={"timeout": 1}
        )
        assert http_args == {"timeout": 1, "headers": {"Authorization": "DPoP AT-3"}}

    def test_token_from_state(self):
        client = _dpop_client()
        srv = client.get_service("accesstoken")
        client.get_context().cstate.set("ST", {"access_token": "AT-4", "token_type": "DPoP"})
        http_args = DPoPClientAuth().construct(request=Message(), service=srv, state="ST")
        assert http_args["headers"]["Authorization"] == "DPoP AT-4"

    def test_no_token(self):
        with pytest.raises(KeyError):
            DPoPClientAuth().construct(request=Message())


# ---------------------------------------------------------------------------
# JAR
# ---------------------------------------------------------------------------


def _jwt_parts(token):
    import base64

    def _dec(part):
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))

    _h, _p = token.split(".")[:2]
    return _dec(_h), _dec(_p)


def _jar_client(**kwargs):
    client = _client(
        add_ons={"jar": {"function": "idpyoidc.client.oauth2.add_on.jar.add_support",
                         "kwargs": kwargs}}
    )
    client.get_context().provider_info = {
        "issuer": AS,
        "authorization_endpoint": "https://as.example.com/authz",
    }
    return client


AUTHZ_ARGS = {"response_type": "code", "state": "S1", "redirect_uri": REDIRECT}


class TestJarAddSupport:
    def test_defaults(self):
        client = _jar_client()
        assert client.get_context().add_on["jar"] == {
            "request_object_signing_alg": "RS256",
            "expires_in": 3600,
            "with_jti": False,
            "request_parameter": True,
        }
        assert jar.jar_post_construct in client.get_service("authorization").post_construct

    def test_request_uri(self):
        client = _jar_client(request_type="request_uri", request_dir="/x/requests")
        conf = client.get_context().add_on["jar"]
        assert conf["request_uri"] is True
        assert conf["request_dir"] == "/x/requests"
        assert "request_parameter" not in conf

    def test_unknown_request_type(self):
        conf = _jar_client(request_type="other").get_context().add_on["jar"]
        assert "request_uri" not in conf and "request_parameter" not in conf

    def test_encryption_ok(self):
        conf = _jar_client(
            request_object_encryption_alg="RSA-OAEP", request_object_encryption_enc="A128GCM"
        ).get_context().add_on["jar"]
        assert conf["request_object_encryption_alg"] == "RSA-OAEP"
        assert conf["request_object_encryption_enc"] == "A128GCM"

    def test_encryption_bad_alg(self):
        with pytest.raises(AttributeError, match="alg"):
            _jar_client(
                request_object_encryption_alg="XXX", request_object_encryption_enc="A128GCM"
            )

    def test_encryption_bad_enc(self):
        with pytest.raises(AttributeError, match="enc"):
            _jar_client(
                request_object_encryption_alg="RSA-OAEP", request_object_encryption_enc="XXX"
            )

    def test_no_authorization_service(self, caplog):
        services = {"x": SimpleNamespace()}
        with caplog.at_level("WARNING"):
            jar.add_support(services)
        assert "JAR support could NOT be added" in caplog.text


class TestJarRequestParameter:
    def test_request_parameter(self):
        client = _jar_client(with_jti=True)
        srv = client.get_service("authorization")
        req = srv.construct(request_args=dict(AUTHZ_ARGS))
        assert set(req.keys()) == {"request", "response_type", "client_id"}
        _jws = factory(req["request"])
        assert _jws.jwt.headers["alg"] == "RS256"
        payload = _jws.jwt.payload()
        assert payload["iss"] == "client_id"
        assert payload["aud"] == [AS]
        assert payload["state"] == "S1"
        assert "jti" in payload
        assert payload["exp"] > payload["iat"]
        # the full request is remembered under the state
        assert client.get_context().cstate.get("S1")["request"] == req["request"]

    def test_request_param_override_none_alg(self):
        client = _jar_client(request_type="other", expires_in=0)
        srv = client.get_service("authorization")
        req = srv.construct(
            request_args=dict(AUTHZ_ARGS),
            behaviour_args={"request_param": "request", "request_object_signing_alg": "none"},
        )
        _header, _payload = _jwt_parts(req["request"])
        assert _header["alg"] == "none"
        # no exp added when expires_in is 0
        assert "exp" not in _payload
        assert _payload["state"] == "S1"

    def test_no_request_param_configured(self):
        client = _jar_client(request_type="other")
        req = client.get_service("authorization").construct(request_args=dict(AUTHZ_ARGS))
        assert "request" not in req
        assert req["redirect_uri"] == REDIRECT

    def test_get_request_object_signing_alg(self):
        srv = _jar_client().get_service("authorization")
        assert jar.get_request_object_signing_alg(srv, request_object_signing_alg="ES256") == "ES256"
        assert jar.get_request_object_signing_alg(srv, algorithm="PS256") == "PS256"
        assert jar.get_request_object_signing_alg(srv) == "RS256"
        srv.upstream_get("context").add_on["jar"] = {}
        assert jar.get_request_object_signing_alg(srv) == "RS256"

    def test_construct_request_parameter_explicit_args(self):
        srv = _jar_client().get_service("authorization")
        _context = srv.upstream_get("context")
        _context.provider_info = {}
        _context.issuer = "https://fallback.example.com"
        _jwt = jar.construct_request_parameter(
            srv,
            AuthorizationRequest(**AUTHZ_ARGS),
            issuer="me",
            keys=KEYJAR,
        )
        payload = factory(_jwt).jwt.payload()
        assert payload["iss"] == "me"
        assert payload["aud"] == ["https://fallback.example.com"]

    def test_encrypted_request(self):
        client = _jar_client(
            request_object_encryption_alg="RSA-OAEP", request_object_encryption_enc="A128GCM"
        )
        # the AS encryption keys
        as_keys = build_keyjar([{"type": "RSA", "use": ["enc"]}])
        client.get_attribute("keyjar").import_jwks(as_keys.export_jwks(), AS)
        req = client.get_service("authorization").construct(request_args=dict(AUTHZ_ARGS))
        # A JWE has 5 parts
        assert len(req["request"].split(".")) == 5

    @pytest.mark.xfail(
        strict=True,
        raises=TypeError,
        reason="BUG: client/oauth2/add_on/jar.py:159 passes the string 'request_uri' as the "
        "audience to construct_request_parameter, which then passes aud= to "
        "make_openid_request() (jar.py:112) -> TypeError; request_uri mode is unusable",
    )
    def test_request_uri_mode(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        client = _jar_client(request_type="request_uri")
        req = client.get_service("authorization").construct(request_args=dict(AUTHZ_ARGS))
        assert req["request_uri"].startswith("https://rp.example.com/requests/")


class TestJarRequestUri:
    """request_uri mode, with the audience problem (see xfail above) side-stepped."""

    @pytest.fixture(autouse=True)
    def _patch(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _orig = jar.construct_request_parameter
        self.audiences = []

        def _crp(service, req, audience=None, **kwargs):
            self.audiences.append(audience)
            return _orig(service, req, **kwargs)

        monkeypatch.setattr(jar, "construct_request_parameter", _crp)
        self.tmp_path = tmp_path

    def test_request_uri_default_dir(self):
        client = _jar_client(request_type="request_uri")
        req = client.get_service("authorization").construct(request_args=dict(AUTHZ_ARGS))
        assert self.audiences == ["request_uri"]
        assert set(req.keys()) == {"request_uri", "response_type", "client_id"}
        assert req["request_uri"].startswith("https://rp.example.com/requests/")
        _name = req["request_uri"].rsplit("/", 1)[1]
        stored = (self.tmp_path / "requests" / _name).read_text()
        assert factory(stored).jwt.payload()["state"] == "S1"

    def test_request_uri_param_override_requests_dir(self):
        client = _jar_client(request_type="other")
        srv = client.get_service("authorization")
        target = self.tmp_path / "elsewhere"
        req = jar.jar_post_construct(
            AuthorizationRequest(client_id="client_id", **AUTHZ_ARGS),
            srv,
            request_param="request_uri",
            requests_dir=str(target),
        )
        assert set(req.keys()) == {"request_uri", "response_type", "client_id"}
        _name = req["request_uri"].rsplit("/", 1)[1]
        assert (target / _name).exists()

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: client/oauth2/add_on/jar.py:208 add_support stores 'request_dir' but "
        "jar_post_construct (jar.py:146) reads 'requests_dir'; the configured directory "
        "is ignored and ./requests is used",
    )
    def test_request_uri_configured_dir(self):
        target = self.tmp_path / "configured"
        client = _jar_client(request_type="request_uri", request_dir=str(target))
        req = client.get_service("authorization").construct(request_args=dict(AUTHZ_ARGS))
        _name = req["request_uri"].rsplit("/", 1)[1]
        assert (target / _name).exists()


class TestStoreRequestOnFile:
    def test_with_constructed_uri(self, tmp_path):
        srv = _jar_client().get_service("authorization")
        webname = jar.store_request_on_file(
            srv, "JWT-CONTENT", local_dir=str(tmp_path / "r"), base_path="https://rp/requests/"
        )
        assert webname.startswith("https://rp/requests/")
        _name = webname.rsplit("/", 1)[1]
        assert (tmp_path / "r" / _name).read_text() == "JWT-CONTENT"

    def test_with_registered_request_uris(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        srv = _jar_client().get_service("authorization")
        _context = srv.upstream_get("context")
        _context.set_usage("request_uris", ["https://rp.example.com/req.jwt"])
        webname = jar.store_request_on_file(srv, "JWT-2")
        assert webname == "https://rp.example.com/req.jwt"
        _file = _context.filename_from_webname(webname)
        assert open(_file).read() == "JWT-2"
        assert os.path.isabs(_file) or os.path.exists(os.path.join(str(tmp_path), _file))
