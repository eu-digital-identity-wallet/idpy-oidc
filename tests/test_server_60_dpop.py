import os
import time
import uuid

import pytest
from cryptojwt import as_unicode
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar

from idpyoidc.message.oauth2 import AccessTokenRequest
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server import user_info
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.oauth2.add_on.dpop import DPoPProof
from idpyoidc.server.oauth2.add_on.dpop import DPoPErrorResponse
from idpyoidc.server.oauth2.add_on.dpop import access_token_hash
from idpyoidc.server.oauth2.add_on.dpop import par_post_parse_request
from idpyoidc.server.oauth2.add_on.dpop import token_post_parse_request
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

DPOP_HEADER = (
    "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMz"
    "R0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFq"
    "SG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwia"
    "HRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY"
    "yNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
)


def fresh_proof(htu="https://server.example.com/token", htm="POST", alg="ES256", key=None, iat=None):
    """A DPoP proof made now (the static DPOP_HEADER is from 2019)."""
    key = key or new_ec_key(crv="P-256")
    _dpop = DPoPProof(
        typ="dpop+jwt",
        alg=alg,
        jwk=key.serialize(),
        jti=str(uuid.uuid4()),
        htm=htm,
        htu=htu,
        iat=iat or int(time.time()),
    )
    _dpop.key = key
    return _dpop.create_header()


def test_verify_header_rejects_symmetric_key():
    from cryptojwt.jwk.hmac import SYMKey

    key = SYMKey(key="a-very-secret-shared-key-for-hmac", alg="HS256")
    _payload = {"jti": "x", "htm": "POST", "htu": "https://server.example.com/token", "iat": int(time.time())}
    _jws = JWS(_payload, alg="HS256").sign_compact(keys=[key], typ="dpop+jwt", jwk=key.serialize(private=True))
    with pytest.raises(ValueError, match="public asymmetric"):
        DPoPProof().verify_header(_jws)


def test_verify_header_rejects_unsupported_alg():
    with pytest.raises(ValueError, match="not supported"):
        DPoPProof().verify_header(fresh_proof(), allowed_algs=["ES384"])


def test_verify_header():
    _dpop = DPoPProof()
    assert _dpop.verify_header(DPOP_HEADER)
    assert set(_dpop.keys()) == {"typ", "alg", "jwk", "jti", "htm", "htu", "iat"}
    assert _dpop.verify() is None

    _dpop_dict = _dpop.to_dict()
    _dpop2 = DPoPProof().from_dict(_dpop_dict)
    assert isinstance(_dpop2.key, ECKey)

    ec_key = new_ec_key(crv="P-256")
    _dpop2.key = ec_key
    _dpop2["jwk"] = ec_key.serialize()  # public part only: a private jwk is rejected

    _header = _dpop2.create_header()

    _dpop3 = DPoPProof()
    assert _dpop3.verify_header(_header)
    # should have the same content as _dpop only the key is different

    assert _dpop["htm"] == _dpop3["htm"]


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.com/"

KEYJAR = init_key_jar(key_defs=KEYDEFS, issuer_id=ISSUER)
KEYJAR.import_jwks(KEYJAR.export_jwks(True, ISSUER), "")

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["id_token"],
    ["code", "id_token"],
]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    # "request_uri_parameter_supported": True,
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISSUER,
            "httpc_params": {"verify": False, "timeout": 1},
            "capabilities": CAPABILITIES,
            "add_on": {
                "dpop": {
                    "function": "idpyoidc.server.oauth2.add_on.dpop.add_support",
                    "kwargs": {"dpop_signing_alg_values_supported": ["ES256"]},
                },
            },
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                "jwks_file": "private/token_jwks.json",
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "base_claims": {"eduperson_scoped_affiliation": None},
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "id_token": {
                    "class": "idpyoidc.server.token.id_token.IDToken",
                    "kwargs": {
                        "base_claims": {
                            "email": {"essential": True},
                            "email_verified": {"essential": True},
                        }
                    },
                },
            },
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {
                    "path": "{}/token",
                    "class": Token,
                    "kwargs": {"client_authn_method": ["none"]},
                },
            },
            "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": "users.json"},
            },
            "session_params": SESSION_PARAMS,
        }
        server = Server(OPConfiguration(conf, base_path=BASEDIR), keyjar=KEYJAR)
        self.context = server.context
        self.context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access"],
        }
        self.user_id = "diana"
        self.token_endpoint = server.get_endpoint("token")
        self.session_manager = self.context.session_manager

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, client_id):
        session_id = self.session_manager.encrypted_session_id(self.user_id, client_id, grant.id)
        usage_rules = grant.usage_rules.get("authorization_code", {})
        _exp_in = usage_rules.get("expires_in")

        # Constructing an authorization code is now done
        _code = grant.mint_token(
            session_id=session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=self.session_manager.token_handler["authorization_code"],
            usage_rules=usage_rules,
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)
            if _exp_in:
                _code.expires_at = utc_time_sans_frac() + _exp_in
        return _code

    def test_post_parse_request(self):
        auth_req = token_post_parse_request(
            AUTH_REQ.copy(),
            AUTH_REQ["client_id"],
            self.context,
            http_info={
                "headers": {"dpop": fresh_proof()},
                "url": "https://server.example.com/token",
                "method": "POST",
            },
        )
        assert auth_req
        assert "dpop_jkt" in auth_req

    def _parse(self, proof, url="https://server.example.com/token", method="POST"):
        return token_post_parse_request(
            AUTH_REQ.copy(),
            AUTH_REQ["client_id"],
            self.context,
            http_info={"headers": {"dpop": proof}, "url": url, "method": method},
        )

    def _refused(self, result, reason):
        assert isinstance(result, DPoPErrorResponse), result
        assert result["error"] == "invalid_dpop_proof"
        assert reason in result["error_description"]

    def test_post_parse_request_stale_proof(self):
        self._refused(self._parse(fresh_proof(iat=int(time.time()) - 3600)), "iat")

    def test_post_parse_request_wrong_htu(self):
        self._refused(self._parse(fresh_proof(htu="https://evil.example.com/token")), "htu")

    # NISCY fork: the checks the authorization server did itself (dpop.py) before.

    def test_replayed_proof_is_refused(self):
        proof = fresh_proof()
        assert "dpop_jkt" in self._parse(proof)
        self._refused(self._parse(proof), "already used")

    def test_refused_proof_does_not_use_up_its_jti(self):
        key = new_ec_key(crv="P-256")
        jti = str(uuid.uuid4())

        def proof(htm):
            _dpop = DPoPProof(typ="dpop+jwt", alg="ES256", jwk=key.serialize(), jti=jti, htm=htm,
                              htu="https://server.example.com/token", iat=int(time.time()))
            _dpop.key = key
            return _dpop.create_header()

        self._refused(self._parse(proof("GET")), "htm")
        assert "dpop_jkt" in self._parse(proof("POST"))

    def test_typ_must_be_dpop_jwt(self):
        key = new_ec_key(crv="P-256")
        _dpop = DPoPProof(typ="jwt", alg="ES256", jwk=key.serialize(), jti=str(uuid.uuid4()), htm="POST",
                          htu="https://server.example.com/token", iat=int(time.time()))
        _dpop.key = key
        self._refused(self._parse(_dpop.create_header()), "typ")

    def test_iat_window(self):
        assert "dpop_jkt" in self._parse(fresh_proof(iat=int(time.time()) + 30))
        self._refused(self._parse(fresh_proof(iat=int(time.time()) + 120)), "iat")
        assert "dpop_jkt" in self._parse(fresh_proof(iat=int(time.time()) - 200))

    def test_configured_allowed_htu_is_used(self):
        """Behind a proxy the request URL is internal: the proof names a public URL."""
        self.context.add_on["dpop"]["allowed_htu"] = ["https://public.example.com/token"]
        internal = "http://10.0.0.5:5000/token"
        assert "dpop_jkt" in self._parse(fresh_proof(htu="https://public.example.com/token?x=1"), url=internal)
        self._refused(self._parse(fresh_proof(htu=internal), url=internal), "htu")

    def test_allowed_htu_of_another_issuer_is_refused(self):
        """One server, several issuers (CURRENT_ISSUER): only the current issuer's URLs count."""
        from idpyoidc.server.util import CURRENT_ISSUER

        self.context.add_on["dpop"]["allowed_htu"] = ["https://as.example/fe1/token", "https://as.example/fe2/token"]
        marker = CURRENT_ISSUER.set("https://as.example/fe1")
        try:
            assert "dpop_jkt" in self._parse(fresh_proof(htu="https://as.example/fe1/token"))
            self._refused(self._parse(fresh_proof(htu="https://as.example/fe2/token")), "htu")
        finally:
            CURRENT_ISSUER.reset(marker)
        assert "dpop_jkt" in self._parse(fresh_proof(htu="https://as.example/fe2/token"))

    def test_par_allowed_htu_of_another_issuer_is_refused(self):
        from idpyoidc.server.util import CURRENT_ISSUER

        self.context.add_on["dpop"]["par_allowed_htu"] = [
            "https://as.example/fe1/pushed_authorization",
            "https://as.example/fe2/pushed_authorization",
        ]
        marker = CURRENT_ISSUER.set("https://as.example/fe1")
        try:
            proof = fresh_proof(htu="https://as.example/fe1/pushed_authorization")
            assert "dpop_jkt" in self._par(AUTH_REQ.copy(), {"dpop": proof})
            proof = fresh_proof(htu="https://as.example/fe2/pushed_authorization")
            self._refused(self._par(AUTH_REQ.copy(), {"dpop": proof}), "htu")
        finally:
            CURRENT_ISSUER.reset(marker)

    def test_not_a_jws_is_refused(self):
        self._refused(self._parse("not-a-jwt"), "")

    def test_private_jwk_is_refused(self):
        key = new_ec_key(crv="P-256")
        _dpop = DPoPProof(typ="dpop+jwt", alg="ES256", jwk=key.serialize(private=True), jti=str(uuid.uuid4()),
                          htm="POST", htu="https://server.example.com/token", iat=int(time.time()))
        _dpop.key = key
        self._refused(self._parse(_dpop.create_header()), "public asymmetric")

    def test_proof_without_jti_is_refused(self):
        key = new_ec_key(crv="P-256")
        _payload = {"htm": "POST", "htu": "https://server.example.com/token", "iat": int(time.time())}
        proof = JWS(_payload, alg="ES256").sign_compact(keys=[key], typ="dpop+jwt", jwk=key.serialize())
        self._refused(self._parse(proof), "")

    def test_access_token_hash_is_base64url(self):
        import base64
        import hashlib

        expected = base64.urlsafe_b64encode(hashlib.sha256(b"tok").digest()).rstrip(b"=").decode()
        assert access_token_hash("tok") == expected

    def _offline_session(self):
        auth_req = AUTH_REQ.copy()
        auth_req["scope"] = ["openid", "offline_access"]
        session_id = self._create_session(auth_req)
        grant = self.session_manager[session_id]
        return grant, self._mint_code(grant, auth_req["client_id"])

    def _token(self, code, key):
        _req = self.token_endpoint.parse_request(
            {**TOKEN_REQ.to_dict(), "code": code.value},
            http_info={"headers": {"dpop": fresh_proof(key=key)}, "url": "https://server.example.com/token",
                       "method": "POST"},
        )
        return self.token_endpoint.process_request(request=_req)["response_args"]

    def _refresh(self, refresh_token, key=None):
        headers = {"dpop": fresh_proof(key=key)} if key else {}
        _req = self.token_endpoint.parse_request(
            {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": "client_1",
             "client_secret": "hemligt"},
            http_info={"headers": headers, "url": "https://server.example.com/token", "method": "POST"},
        )
        return self.token_endpoint.process_request(request=_req)

    def test_refresh_needs_the_bound_key(self):
        key = new_ec_key(crv="P-256")
        _, code = self._offline_session()
        tokens = self._token(code, key)
        assert tokens["token_type"] == "DPoP" and "refresh_token" in tokens

        other = self._refresh(tokens["refresh_token"], new_ec_key(crv="P-256"))
        assert isinstance(other, DPoPErrorResponse) and other["error"] == "invalid_dpop_proof"
        without = self._refresh(tokens["refresh_token"])
        assert isinstance(without, DPoPErrorResponse)
        same = self._refresh(tokens["refresh_token"], key)
        assert same["response_args"]["token_type"] == "DPoP"

    def test_introspection_returns_the_bound_key(self):
        from idpyoidc.server.oauth2.introspection import Introspection

        introspection = Introspection(self.token_endpoint.upstream_get, enforce_audience_restriction=False)
        key = new_ec_key(crv="P-256")
        _, code = self._offline_session()
        tokens = self._token(code, key)
        info = introspection.process_request({"token": tokens["access_token"]})["response_args"]
        assert info["active"] is True
        assert info["cnf"] == {"jkt": as_unicode(key.thumbprint("SHA-256"))}

    def test_introspection_of_a_bearer_token_has_no_cnf(self):
        from idpyoidc.server.oauth2.introspection import Introspection

        introspection = Introspection(self.token_endpoint.upstream_get, enforce_audience_restriction=False)
        session_id = self._create_session(AUTH_REQ)
        code = self._mint_code(self.session_manager[session_id], "client_1")
        _req = self.token_endpoint.parse_request({**TOKEN_REQ.to_dict(), "code": code.value})
        tokens = self.token_endpoint.process_request(request=_req)["response_args"]
        info = introspection.process_request({"token": tokens["access_token"]})["response_args"]
        assert info["active"] is True and "cnf" not in info

    def test_process_request(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ.to_dict()
        _context = self.context
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(
            _token_request,
            http_info={
                "headers": {"dpop": fresh_proof()},
                "url": "https://server.example.com/token",
                "method": "POST",
            },
        )

        assert "dpop_jkt" in _req

        _resp = self.token_endpoint.process_request(request=_req)
        assert _resp["response_args"]["token_type"] == "DPoP"

        access_token = _resp["response_args"]["access_token"]
        jws = factory(access_token)
        _payload = jws.jwt.payload()
        assert "cnf" in _payload
        assert _payload["cnf"]["jkt"] == _req["dpop_jkt"]

        # Make sure DPoP also is in the session access token instance.
        _session_info = self.session_manager.get_session_info_by_token(
            access_token, handler_key="access_token"
        )
        _token = self.session_manager.find_token(_session_info["branch_id"], access_token)
        assert _token.token_type == "DPoP"


    def _code_token(self, code, key=None):
        headers = {"dpop": fresh_proof(key=key)} if key else {}
        _req = self.token_endpoint.parse_request(
            {**TOKEN_REQ.to_dict(), "code": code.value},
            http_info={"headers": headers, "url": "https://server.example.com/token", "method": "POST"},
        )
        return self.token_endpoint.process_request(request=_req)

    def test_code_bound_by_dpop_jkt_needs_that_key(self):
        # RFC 9449 section 10: dpop_jkt in the authorization request binds the code.
        key = new_ec_key(crv="P-256")
        auth_req = AUTH_REQ.copy()
        auth_req["dpop_jkt"] = as_unicode(key.thumbprint("SHA-256"))
        session_id = self._create_session(auth_req)
        code = self._mint_code(self.session_manager[session_id], auth_req["client_id"])

        other = self._code_token(code, new_ec_key(crv="P-256"))
        assert isinstance(other, DPoPErrorResponse) and other["error"] == "invalid_dpop_proof"
        without = self._code_token(code)
        assert isinstance(without, DPoPErrorResponse) and without["error"] == "invalid_dpop_proof"
        # The refused attempts did not use up the code.
        same = self._code_token(code, key)
        assert same["response_args"]["token_type"] == "DPoP"

    def _par(self, request, headers):
        return par_post_parse_request(
            request,
            request["client_id"],
            self.context,
            http_info={"headers": headers, "url": "https://server.example.com/par", "method": "POST"},
        )

    def test_par_dpop_proof_binds_its_key(self):
        # RFC 9449 section 10.1
        key = new_ec_key(crv="P-256")
        proof = fresh_proof(htu="https://server.example.com/par", key=key)
        request = self._par(AUTH_REQ.copy(), {"dpop": proof})
        assert request["dpop_jkt"] == as_unicode(key.thumbprint("SHA-256"))

    def test_par_dpop_proof_must_match_dpop_jkt(self):
        auth_req = AUTH_REQ.copy()
        auth_req["dpop_jkt"] = as_unicode(new_ec_key(crv="P-256").thumbprint("SHA-256"))
        result = self._par(auth_req, {"dpop": fresh_proof(htu="https://server.example.com/par")})
        self._refused(result, "dpop_jkt")

    def test_par_invalid_dpop_proof_is_refused(self):
        self._refused(self._par(AUTH_REQ.copy(), {"dpop": "not-a-jwt"}), "")
        # A proof for another endpoint is refused too.
        self._refused(self._par(AUTH_REQ.copy(), {"dpop": fresh_proof()}), "htu")

    def test_par_without_dpop_proof_is_unchanged(self):
        auth_req = AUTH_REQ.copy()
        auth_req["dpop_jkt"] = "jkt"
        assert self._par(auth_req, {})["dpop_jkt"] == "jkt"

def test_jti_cache_accepts_a_proof_once_under_concurrency():
    """NISCY fork: the same proof sent by many requests at once is accepted once."""
    import threading

    from idpyoidc.server.oauth2.add_on.dpop import JtiCache

    cache = JtiCache()
    barrier = threading.Barrier(20)
    results = []

    def add():
        barrier.wait()
        results.append(cache.add_once("jkt:jti", 60))

    threads = [threading.Thread(target=add) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
