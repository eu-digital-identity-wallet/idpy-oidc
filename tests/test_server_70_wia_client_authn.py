"""Attestation-based client authentication with a Wallet Instance Attestation (WIA)."""

import base64
import datetime
import time
import uuid
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jws.jws import JWS

from idpyoidc.server.client_authn import ClientAuthenticationAttestation
from idpyoidc.server.exception import ClientAuthenticationError

ISSUER = "https://as.example.com"
CLIENT_ID = "wallet-client"
REDIRECT_URI = "eudi-openid4ci://authorize"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _certificate(subject_key, cn, issuer_key=None, issuer_cn=None, ca=False, days=(-1, 30)):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn or cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=days[0]))
        .not_valid_after(now + datetime.timedelta(days=days[1]))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key or subject_key, hashes.SHA256())
    )


def _der_b64(cert):
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _ec_jwk(private_key, with_private=False):
    key = ECKey()
    key.load_key(private_key if with_private else private_key.public_key())
    return key


def _sign(claims, private_key, headers, alg="ES256", kid=None):
    key = _ec_jwk(private_key, with_private=True)
    key.kid = kid or ""  # cryptojwt puts the signing key's kid in the header
    return JWS(claims, alg=alg).sign_compact(keys=[key], **headers)


class Pki:
    def __init__(self):
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = _certificate(self.ca_key, "Wallet Provider CA", ca=True)
        self.provider_key = ec.generate_private_key(ec.SECP256R1())
        self.provider = _certificate(self.provider_key, "Wallet Provider", self.ca_key, "Wallet Provider CA")
        self.instance_key = ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def pki():
    return Pki()


def make_wia(pki, signer=None, x5c=None, kid=None, **overrides):
    now = int(time.time())
    claims = {
        "iss": "https://wallet-provider.example.com",
        "sub": CLIENT_ID,
        "iat": now,
        "exp": now + 3600,
        "cnf": {"jwk": _ec_jwk(pki.instance_key).serialize()},
        "wallet_name": "Test wallet",
        "wallet_version": "1.0",
        "wallet_solution_certification_information": "test",
        "client_status": {
            "status": {"status_list": {"idx": 1, "uri": "https://status.example.com/1"}},
            "exp": now + 86400,
        },
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    headers = {"typ": "oauth-client-attestation+jwt"}
    headers["x5c"] = x5c if x5c is not None else [_der_b64(pki.provider), _der_b64(pki.ca)]
    if headers["x5c"] == []:
        del headers["x5c"]
    return _sign(claims, signer or pki.provider_key, headers, kid=kid)


def make_pop(pki, aud=ISSUER, iss=CLIENT_ID, jti=None, iat=None, kid=None):
    claims = {"aud": aud, "jti": jti or str(uuid.uuid4()), "iat": iat or int(time.time())}
    if iss:
        claims["iss"] = iss
    return _sign(claims, pki.instance_key, {"typ": "oauth-client-attestation-pop+jwt"}, kid=kid)


class FakeServer:
    """Just enough of a server for topmost_unit(): a context with issuer and cdb."""

    def __init__(self):
        self.context = SimpleNamespace(issuer=ISSUER, cdb={})
        self.upstream_get = None


@pytest.fixture
def server():
    return FakeServer()


@pytest.fixture
def method(server):
    return ClientAuthenticationAttestation(lambda what: server if what == "unit" else None)


@pytest.fixture
def anchors(tmp_path, pki):
    (tmp_path / "ca.pem").write_text(_pem(pki.ca))
    return str(tmp_path)


def authenticate(method, wia, pop, request=None, **kwargs):
    if request is None:
        request = {"client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI}
    http_info = {"headers": {"OAuth-Client-Attestation": wia, "OAuth-Client-Attestation-PoP": pop}}
    return method.verify(request=request, http_info=http_info, endpoint=None, **kwargs)


def test_valid_wia_local_trust(method, pki, anchors, server):
    res = authenticate(method, make_wia(pki), make_pop(pki), trusted_attesters_path=anchors)
    assert res["client_id"] == CLIENT_ID
    assert res["method"] == "attest_jwt_client_auth"
    assert server.context.cdb[CLIENT_ID]["redirect_uris"] == [(REDIRECT_URI, {})]


def test_trusted_attester_is_the_leaf(method, pki, tmp_path):
    (tmp_path / "leaf.pem").write_text(_pem(pki.provider))
    wia = make_wia(pki, x5c=[_der_b64(pki.provider)])
    assert authenticate(method, wia, make_pop(pki), trusted_attesters_path=str(tmp_path))["client_id"] == CLIENT_ID


def test_without_x5c_signed_by_trusted_attester(method, pki, tmp_path):
    (tmp_path / "leaf.pem").write_text(_pem(pki.provider))
    wia = make_wia(pki, x5c=[])
    assert authenticate(method, wia, make_pop(pki), trusted_attesters_path=str(tmp_path))["client_id"] == CLIENT_ID


def test_forged_signature_with_genuine_x5c_local(method, pki, anchors):
    forged = make_wia(pki, signer=ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ClientAuthenticationError, match="does not verify"):
        authenticate(method, forged, make_pop(pki), trusted_attesters_path=anchors)


def test_forged_signature_with_genuine_x5c_trust_validator(method, pki, monkeypatch):
    """The trust validator only judges the chain: the signature must be checked here."""
    monkeypatch.setattr(method, "call_trust_validator", lambda **kwargs: True)
    forged = make_wia(pki, signer=ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ClientAuthenticationError, match="does not verify"):
        authenticate(method, forged, make_pop(pki), trust_validator_url="https://trust.example.com")


def test_trust_validator_path(method, pki, monkeypatch):
    seen = {}

    def validator(url, chain, verification_context):
        seen["chain"] = chain
        return True

    monkeypatch.setattr(method, "call_trust_validator", validator)
    assert authenticate(method, make_wia(pki), make_pop(pki), trust_validator_url="https://t")["client_id"] == CLIENT_ID
    assert seen["chain"][0] == _der_b64(pki.provider)


def test_trust_validator_rejects(method, pki, monkeypatch):
    monkeypatch.setattr(method, "call_trust_validator", lambda **kwargs: False)
    with pytest.raises(ClientAuthenticationError, match="not trusted"):
        authenticate(method, make_wia(pki), make_pop(pki), trust_validator_url="https://t")


def test_trust_validator_requires_x5c(method, pki, monkeypatch):
    monkeypatch.setattr(method, "call_trust_validator", lambda **kwargs: True)
    with pytest.raises(ClientAuthenticationError, match="x5c"):
        authenticate(method, make_wia(pki, x5c=[]), make_pop(pki), trust_validator_url="https://t")


def test_untrusted_chain(method, pki, tmp_path):
    other = Pki()
    (tmp_path / "other.pem").write_text(_pem(other.ca))
    with pytest.raises(ClientAuthenticationError, match="not trusted"):
        authenticate(method, make_wia(pki), make_pop(pki), trusted_attesters_path=str(tmp_path))


def test_expired_leaf(method, pki, anchors):
    pki.provider = _certificate(pki.provider_key, "Wallet Provider", pki.ca_key, "Wallet Provider CA", days=(-30, -1))
    with pytest.raises(ClientAuthenticationError, match="expired or not yet valid"):
        authenticate(method, make_wia(pki), make_pop(pki), trusted_attesters_path=anchors)


def test_symmetric_algorithm_rejected(method, pki, anchors):
    wia = make_wia(pki)
    header, payload, _ = wia.split(".")
    tampered = base64.urlsafe_b64encode(
        base64.urlsafe_b64decode(header + "==").replace(b'"ES256"', b'"HS256"')
    ).rstrip(b"=").decode()
    with pytest.raises(ClientAuthenticationError, match="disallowed signature algorithm"):
        authenticate(method, f"{tampered}.{payload}.c2ln", make_pop(pki), trusted_attesters_path=anchors)


def test_preauth_redirect_uri_does_not_skip_client_id_check(method, pki, anchors):
    """A client cannot turn off the sub == client_id check with redirect_uri=preauth."""
    request = {"client_id": "victim-wallet", "redirect_uri": "preauth"}
    with pytest.raises(ClientAuthenticationError, match="must match"):
        authenticate(method, make_wia(pki), make_pop(pki), request=request, trusted_attesters_path=anchors)


def test_server_side_skip_of_client_id_check(method, pki, anchors):
    request = {"client_id": "internal-client", "redirect_uri": "preauth"}
    res = authenticate(
        method, make_wia(pki), make_pop(pki), request=request, trusted_attesters_path=anchors, skip_client_id_check=True
    )
    assert res["client_id"] == "internal-client"


def test_client_id_from_wia_when_request_has_none(method, pki, anchors):
    res = authenticate(method, make_wia(pki), make_pop(pki), request={}, trusted_attesters_path=anchors)
    assert res["client_id"] == CLIENT_ID


@pytest.mark.parametrize("aud", ["https://evil.example.com", "https://as.example.com.evil"])
def test_pop_wrong_audience(method, pki, anchors, aud):
    with pytest.raises(ClientAuthenticationError, match="'aud'"):
        authenticate(method, make_wia(pki), make_pop(pki, aud=aud), trusted_attesters_path=anchors)


def test_pop_audience_trailing_slash(method, pki, anchors):
    assert authenticate(method, make_wia(pki), make_pop(pki, aud=ISSUER + "/"), trusted_attesters_path=anchors)


def test_pop_audience_configured_frontend(method, pki, anchors):
    frontends = ["https://frontend.example.com"]
    pop = make_pop(pki, aud="https://frontend.example.com")
    res = authenticate(method, make_wia(pki), pop, trusted_attesters_path=anchors, pop_allowed_aud=frontends)
    assert res["client_id"] == CLIENT_ID


def test_pop_audience_unlisted_frontend(method, pki, anchors):
    pop = make_pop(pki, aud="https://other-frontend.example.com")
    with pytest.raises(ClientAuthenticationError, match="'aud'"):
        authenticate(
            method, make_wia(pki), pop, trusted_attesters_path=anchors, pop_allowed_aud=["https://frontend.example.com"]
        )


def test_pop_audience_current_issuer(method, pki, anchors):
    """With a per-request issuer, the PoP names that issuer, not the configured one."""
    from idpyoidc.server.util import CURRENT_ISSUER

    marker = CURRENT_ISSUER.set(ISSUER + "/frontend-a")
    try:
        assert authenticate(method, make_wia(pki), make_pop(pki, aud=ISSUER + "/frontend-a"), trusted_attesters_path=anchors)
        with pytest.raises(ClientAuthenticationError, match="'aud'"):
            authenticate(method, make_wia(pki), make_pop(pki, aud=ISSUER + "/frontend-b"), trusted_attesters_path=anchors)
    finally:
        CURRENT_ISSUER.reset(marker)


def test_pop_wrong_issuer(method, pki, anchors):
    with pytest.raises(ClientAuthenticationError, match="'iss'"):
        authenticate(method, make_wia(pki), make_pop(pki, iss="someone-else"), trusted_attesters_path=anchors)


def test_pop_replay(method, pki, anchors):
    wia, pop = make_wia(pki), make_pop(pki)
    authenticate(method, wia, pop, trusted_attesters_path=anchors)
    with pytest.raises(ClientAuthenticationError, match="already been used"):
        authenticate(method, wia, pop, trusted_attesters_path=anchors)


def test_pop_stale(method, pki, anchors):
    with pytest.raises(ClientAuthenticationError, match="freshness"):
        authenticate(method, make_wia(pki), make_pop(pki, iat=int(time.time()) - 3600), trusted_attesters_path=anchors)


@pytest.mark.parametrize("pop_kid", [None, "wallet-key-1"])
def test_pop_signed_by_other_key(method, pki, anchors, pop_kid):
    wia = make_wia(pki)
    pki.instance_key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ClientAuthenticationError, match="PoP signature"):
        authenticate(method, wia, make_pop(pki, kid=pop_kid), trusted_attesters_path=anchors)


@pytest.mark.parametrize("cnf_kid", [None, "cnf-kid"])
@pytest.mark.parametrize("pop_kid", [None, "cnf-kid", "wallet-key-1"])
def test_pop_kid_is_only_a_hint(method, pki, anchors, cnf_kid, pop_kid):
    # The PoP key is the WIA cnf key whatever kid either side carries (iOS wallets send one).
    jwk = _ec_jwk(pki.instance_key).serialize()
    if cnf_kid:
        jwk["kid"] = cnf_kid
    wia = make_wia(pki, cnf={"jwk": jwk})
    res = authenticate(method, wia, make_pop(pki, kid=pop_kid), trusted_attesters_path=anchors)
    assert res["client_id"] == CLIENT_ID


def test_wia_kid_with_x5c(method, pki, anchors):
    wia = make_wia(pki, kid="11")
    res = authenticate(method, wia, make_pop(pki), trusted_attesters_path=anchors)
    assert res["client_id"] == CLIENT_ID


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"iat": None}, "iat"),
        ({"exp": int(time.time()) - 100}, "expired"),
        ({"iat": int(time.time()) - 7200}, "too old"),
        ({"client_status": {"status": {"status_list": {"idx": 1, "uri": "u"}}, "exp": 1}}, "client_status"),
        ({"client_status": {"exp": 9999999999}}, "client_status"),
        ({"cnf": "not-a-dict"}, "cnf"),
    ],
)
def test_wia_claims(method, pki, anchors, overrides, message):
    with pytest.raises(ClientAuthenticationError, match=message):
        authenticate(method, make_wia(pki, **overrides), make_pop(pki), trusted_attesters_path=anchors)


def test_private_key_in_cnf_rejected(method, pki, anchors):
    wia = make_wia(pki, cnf={"jwk": _ec_jwk(pki.instance_key, with_private=True).serialize(private=True)})
    with pytest.raises(ClientAuthenticationError, match="private key"):
        authenticate(method, wia, make_pop(pki), trusted_attesters_path=anchors)


def test_revoked_wia(method, pki, anchors, monkeypatch):
    monkeypatch.setattr(method, "check_wia_revocation", lambda **kwargs: True)
    with pytest.raises(ClientAuthenticationError, match="revoked"):
        authenticate(method, make_wia(pki), make_pop(pki), trusted_attesters_path=anchors, status_validator_url="https://s")


@pytest.mark.parametrize(
    "configured, expected",
    [(None, "WalletOrKeyStorageStatus"), ("CustomStatus", "CustomStatus")],
)
def test_revocation_check_validation_context(method, pki, anchors, monkeypatch, configured, expected):
    sent = {}

    def post(url, json, **kwargs):
        sent.update(json)
        return SimpleNamespace(json=lambda: {"valid": True}, raise_for_status=lambda: None)

    monkeypatch.setattr("idpyoidc.server.client_authn.requests.post", post)
    kwargs = {"status_validation_context": configured} if configured else {}
    authenticate(
        method, make_wia(pki), make_pop(pki), trusted_attesters_path=anchors, status_validator_url="https://s", **kwargs
    )
    assert sent["validation_context"] == expected


@pytest.mark.parametrize("wia", ["", "not-a-jws", "a.b"])
def test_malformed_wia_is_an_authentication_error(method, pki, anchors, wia):
    with pytest.raises(ClientAuthenticationError):
        authenticate(method, wia, make_pop(pki), trusted_attesters_path=anchors)


def test_missing_headers(method):
    with pytest.raises(ClientAuthenticationError):
        method.verify(request={}, http_info=None)
    assert not method.is_usable(request={"client_id": CLIENT_ID}, http_info=None)


def test_client_registration_is_merged(method, pki, anchors, server):
    server.context.cdb[CLIENT_ID] = {"redirect_uris": [("https://other.example.com/cb", {})], "dpop_jkt": "x"}
    authenticate(method, make_wia(pki), make_pop(pki), trusted_attesters_path=anchors)
    info = server.context.cdb[CLIENT_ID]
    assert info["redirect_uris"] == [("https://other.example.com/cb", {}), (REDIRECT_URI, {})]
    assert info["dpop_jkt"] == "x"
