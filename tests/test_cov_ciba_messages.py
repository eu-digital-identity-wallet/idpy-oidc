"""Coverage-oriented tests for the CIBA messages
(idpyoidc.message.oidc.backchannel_authentication) and the device authorization
messages (idpyoidc.message.oauth2.device_authorization)."""

import time

import pytest
from cryptojwt import JWT
from cryptojwt.key_jar import build_keyjar

from idpyoidc import verified_claim_name
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import ParameterError
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import device_authorization as da
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc.backchannel_authentication import JWT_ARGS
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationRequest
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationRequestJWT
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationResponse
from idpyoidc.message.oidc.backchannel_authentication import NotificationRequest
from idpyoidc.message.oidc.backchannel_authentication import PushErrorPayload
from idpyoidc.message.oidc.backchannel_authentication import TokenRequest

ISSUER = "https://op.example.com"
CLIENT_ID = "s6BhdRkqt3"

KEYDEFS = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]

# Fixed time so the JWT claims are deterministic; lifetimes are large enough that
# validation against the real clock never fails.
NOW = int(time.time())


@pytest.fixture
def keyjars():
    client_kj = build_keyjar(KEYDEFS)
    op_kj = build_keyjar(KEYDEFS)
    # The OP knows the client's public keys and its own
    op_kj.import_jwks(client_kj.export_jwks(), CLIENT_ID)
    op_kj.import_jwks(op_kj.export_jwks(private=True), ISSUER)
    # The client knows the OP's public keys
    client_kj.import_jwks(op_kj.export_jwks(), ISSUER)
    return client_kj, op_kj


def _request_object(client_kj, **payload):
    _jwt = JWT(client_kj, iss=CLIENT_ID, sign_alg="ES256")
    _jwt.with_jti = True
    _payload = {"scope": "openid email", "nbf": NOW, "client_notification_token": "cnt"}
    _payload.update(payload)
    return _jwt.pack(_payload, aud=[ISSUER])


def _id_token(op_kj, sub="Anna"):
    _jwt = JWT(op_kj, iss=ISSUER, sign_alg="ES256", lifetime=3600)
    return _jwt.pack({"sub": sub, "nonce": "n"}, aud=[CLIENT_ID])


# ----------------------------------------------------------------------------- AuthenticationRequest
class TestAuthenticationRequest:
    def test_minimal_login_hint(self):
        req = AuthenticationRequest(scope="openid", login_hint="mail:diana@example.org")
        req.verify()
        assert req["scope"] == ["openid"]

    def test_no_hint_is_allowed_by_message(self):
        AuthenticationRequest(scope="openid").verify()

    @pytest.mark.parametrize(
        "hints",
        [
            {"login_hint": "a", "login_hint_token": "b"},
            {"login_hint": "a", "id_token_hint": "c"},
            {"login_hint_token": "b", "id_token_hint": "c"},
        ],
    )
    def test_more_than_one_hint(self, hints):
        req = AuthenticationRequest(scope="openid", **hints)
        with pytest.raises(ValueError, match="One and only one"):
            req.verify()

    @pytest.mark.parametrize("mode", ["ping", "push"])
    def test_ping_push_require_notification_token(self, mode):
        req = AuthenticationRequest(scope="openid", login_hint="x")
        with pytest.raises(MissingRequiredAttribute):
            req.verify(mode=mode)

    @pytest.mark.parametrize("mode", ["ping", "push", "poll", None])
    def test_modes_with_notification_token(self, mode):
        req = AuthenticationRequest(scope="openid", login_hint="x", client_notification_token="t")
        req.verify(mode=mode)

    def test_poll_without_notification_token(self):
        req = AuthenticationRequest(scope="openid", login_hint="x")
        req.verify(mode="poll")

    def test_id_token_hint_is_verified(self, keyjars):
        client_kj, op_kj = keyjars
        idt = _id_token(op_kj)
        req = AuthenticationRequest(scope="openid", id_token_hint=idt)
        req.verify(keyjar=client_kj, opponent_id=ISSUER)
        _vc = req[verified_claim_name("id_token_hint")]
        assert isinstance(_vc, IdToken)
        assert _vc["sub"] == "Anna"
        assert _vc["iss"] == ISSUER

    def test_id_token_hint_wrong_type(self):
        req = AuthenticationRequest(scope="openid")
        with pytest.raises(ValueError):
            req["id_token_hint"] = {"sub": "x"}

    def test_id_token_hint_bad_signature(self, keyjars):
        client_kj, _ = keyjars
        other = build_keyjar(KEYDEFS)
        other.import_jwks(other.export_jwks(private=True), ISSUER)
        idt = _id_token(other)
        req = AuthenticationRequest(scope="openid", id_token_hint=idt)
        with pytest.raises(Exception):
            req.verify(keyjar=client_kj, opponent_id=ISSUER)

    def test_signed_request_object(self, keyjars):
        client_kj, op_kj = keyjars
        ro = _request_object(client_kj, login_hint="mail:diana@example.org", binding_message="W4")
        req = AuthenticationRequest(
            request=ro,
            client_id=CLIENT_ID,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion="assertion",
        )
        req.verify(keyjar=op_kj, opponent_id=CLIENT_ID, mode="ping")
        # Request object content is copied in, JWT specific claims are not
        assert req["login_hint"] == "mail:diana@example.org"
        assert req["binding_message"] == "W4"
        assert req["scope"] == ["openid", "email"]
        for claim in JWT_ARGS:
            assert claim not in req
        _vc = req[verified_claim_name("request")]
        assert isinstance(_vc, AuthenticationRequestJWT)
        assert _vc["iss"] == CLIENT_ID

    def test_signed_request_object_reverify_drops_old_verified_claim(self, keyjars):
        client_kj, op_kj = keyjars
        ro = _request_object(client_kj, login_hint="x")
        req = AuthenticationRequest(request=ro)
        req[verified_claim_name("request")] = "stale"
        req.verify(keyjar=op_kj, opponent_id=CLIENT_ID)
        assert isinstance(req[verified_claim_name("request")], AuthenticationRequestJWT)

    def test_signed_request_object_with_id_token_hint(self, keyjars):
        client_kj, op_kj = keyjars
        idt = _id_token(op_kj, sub="Bob")
        ro = _request_object(client_kj, id_token_hint=idt)
        req = AuthenticationRequest(request=ro)
        req.verify(keyjar=op_kj, opponent_id=CLIENT_ID)
        assert req[verified_claim_name("id_token_hint")]["sub"] == "Bob"

    def test_signed_request_object_with_two_hints(self, keyjars):
        client_kj, op_kj = keyjars
        ro = _request_object(client_kj, login_hint="x", login_hint_token="y")
        req = AuthenticationRequest(request=ro)
        with pytest.raises(ValueError):
            req.verify(keyjar=op_kj, opponent_id=CLIENT_ID)

    @pytest.mark.parametrize(
        "extra",
        [
            {"scope": "openid"},
            {"login_hint": "x"},
            {"binding_message": "B"},
            {"client_notification_token": "t"},
            {"requested_expiry": 30},
        ],
    )
    def test_request_with_parameter_outside_jwt(self, keyjars, extra):
        client_kj, op_kj = keyjars
        ro = _request_object(client_kj, login_hint="x")
        req = AuthenticationRequest(request=ro, **extra)
        with pytest.raises(ParameterError, match="not allowed outside the request JWT"):
            req.verify(keyjar=op_kj, opponent_id=CLIENT_ID)

    def test_request_object_wrong_key(self, keyjars):
        _, op_kj = keyjars
        stranger = build_keyjar(KEYDEFS)
        ro = _request_object(stranger, login_hint="x")
        req = AuthenticationRequest(request=ro)
        with pytest.raises(Exception):
            req.verify(keyjar=op_kj, opponent_id=CLIENT_ID)

    def test_requested_expiry_type(self):
        req = AuthenticationRequest(scope="openid", login_hint="x", requested_expiry=120)
        req.verify()
        assert req["requested_expiry"] == 120

    def test_urlencoded_roundtrip(self):
        req = AuthenticationRequest(
            scope="openid email", login_hint="x", acr_values=["a", "b"], user_code="1234"
        )
        back = AuthenticationRequest().from_urlencoded(req.to_urlencoded())
        assert back["scope"] == ["openid", "email"]
        assert back["acr_values"] == ["a", "b"]
        assert back["user_code"] == "1234"


# ----------------------------------------------------------------------------- AuthenticationRequestJWT
class TestAuthenticationRequestJWT:
    def _jwt(self, **kwargs):
        args = {
            "iss": CLIENT_ID,
            "aud": [ISSUER],
            "exp": NOW + 300,
            "nbf": NOW,
            "iat": NOW,
            "jti": "jti-1",
            "scope": "openid",
        }
        args.update(kwargs)
        return AuthenticationRequestJWT(**args)

    def test_valid(self):
        msg = self._jwt()
        msg.verify(issuer=ISSUER, client_id=CLIENT_ID)

    def test_valid_without_issuer_and_client(self):
        self._jwt().verify()

    def test_wrong_audience(self):
        with pytest.raises(ParameterError, match="Not among audience"):
            self._jwt().verify(issuer="https://other.example.com")

    def test_issuer_mismatch(self):
        with pytest.raises(ParameterError, match="Issuer mismatch"):
            self._jwt().verify(client_id="another_client")

    @pytest.mark.parametrize("missing", ["iss", "aud", "exp", "nbf", "iat", "jti", "scope"])
    def test_missing_required(self, missing):
        msg = self._jwt()
        del msg[missing]
        with pytest.raises(MissingRequiredAttribute):
            msg.verify()


# ----------------------------------------------------------------------------- Other CIBA messages
class TestCibaOtherMessages:
    def test_authentication_response(self):
        resp = AuthenticationResponse(auth_req_id="abc", expires_in=120)
        assert resp.verify()
        assert resp["interval"] == 5  # c_default

    def test_authentication_response_missing_required(self):
        with pytest.raises(MissingRequiredAttribute):
            AuthenticationResponse(auth_req_id="abc").verify()

    def test_token_request(self):
        req = TokenRequest(grant_type="urn:openid:params:grant-type:ciba", auth_req_id="abc")
        assert req.verify()
        with pytest.raises(MissingRequiredAttribute):
            TokenRequest(grant_type="urn:openid:params:grant-type:ciba").verify()

    def test_notification_request(self):
        assert NotificationRequest(auth_req_id="abc").verify()
        with pytest.raises(MissingRequiredAttribute):
            NotificationRequest().verify()

    def test_push_error_payload(self):
        msg = PushErrorPayload(error="expired_token", auth_req_id="abc")
        assert msg.verify()
        with pytest.raises(MissingRequiredAttribute):
            PushErrorPayload(error="expired_token").verify()


# ----------------------------------------------------------------------------- Device authorization
class TestDeviceAuthorization:
    def test_authorization_request(self):
        req = da.AuthorizationRequest(client_id="cli", scope="openid")
        assert req.verify()
        with pytest.raises(MissingRequiredAttribute):
            da.AuthorizationRequest(scope="openid").verify()

    def test_authorization_response(self):
        resp = da.AuthorizationResponse(
            device_code="dc",
            user_code="UC-1",
            verification_uri="https://op.example.com/device",
            verification_uri_complete="https://op.example.com/device?user_code=UC-1",
            expires_in=1800,
            interval=5,
        )
        assert resp.verify()
        back = da.AuthorizationResponse().from_json(resp.to_json())
        assert back["expires_in"] == 1800

    @pytest.mark.parametrize("missing", ["device_code", "user_code", "verification_uri", "expires_in"])
    def test_authorization_response_missing(self, missing):
        args = {
            "device_code": "dc",
            "user_code": "UC-1",
            "verification_uri": "https://op.example.com/device",
            "expires_in": 1800,
        }
        del args[missing]
        with pytest.raises(MissingRequiredAttribute):
            da.AuthorizationResponse(**args).verify()

    def _token_req(self, **kwargs):
        args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "code": "code",
            "redirect_uri": "https://rp.example.com/cb",
            "client_id": "cli",
            "device_code": "dc",
        }
        args.update(kwargs)
        return da.AccessTokenRequest(**args)

    def test_access_token_request_with_device_code(self):
        self._token_req().verify()

    def test_access_token_request_device_code_missing_client_id(self):
        req = self._token_req()
        del req["client_id"]
        with pytest.raises(MissingRequiredAttribute, match="client_id"):
            req.verify()

    def test_access_token_request_device_code_missing_grant_type(self, monkeypatch):
        # grant_type has a default in the parent class, so make the parent verify
        # succeed and remove grant_type to reach the device_code specific check.
        from idpyoidc.message.oidc import AccessTokenRequest as OidcATR

        monkeypatch.setattr(OidcATR, "verify", lambda self, **kw: True)
        req = self._token_req()
        del req["grant_type"]
        with pytest.raises(MissingRequiredAttribute, match="grant_type"):
            req.verify()

    def test_access_token_request_without_device_code(self):
        req = self._token_req()
        del req["device_code"]
        del req["client_id"]
        req.verify()

    def test_client_status(self):
        msg = da.ClientStatus(status={"status_list": {"idx": 1, "uri": "https://x"}}, exp=NOW + 10)
        assert msg.verify()
        with pytest.raises(MissingRequiredAttribute):
            da.ClientStatus(exp=NOW).verify()

    def test_wallet_instance_attestation(self):
        msg = da.WalletInstanceAttestationJWT(
            sub="client",
            exp=NOW + 3600,
            cnf={"jwk": {"kty": "EC"}},
            wallet_name="w",
            wallet_version="1.0",
            wallet_solution_certification_information={"id": "x"},
            client_status={"status": {}, "exp": NOW + 10},
            wallet_link="https://wallet.example.com",
            iat=NOW,
            nbf=NOW,
        )
        assert msg.verify()
        assert isinstance(msg, Message)
        del msg["wallet_name"]
        with pytest.raises(MissingRequiredAttribute):
            msg.verify()
