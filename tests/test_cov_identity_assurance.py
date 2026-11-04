"""Coverage tests for idpyoidc.message.oidc.identity_assurance."""
import datetime
import json
import time
from types import SimpleNamespace

import pytest

from idpyoidc.exception import FormatError
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
from idpyoidc.message.oidc import Claims
from idpyoidc.message.oidc import ClaimsRequest
from idpyoidc.message.oidc import identity_assurance as ia


@pytest.fixture
def utc(monkeypatch):
    """Run the test with the local time zone pinned to UTC."""
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.fixture
def fixed_now(monkeypatch, utc):
    """Freeze datetime.now() as seen by the module."""

    class FakeDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2021, 3, 4, 5, 6, 7)

    monkeypatch.setattr(ia, "datetime", SimpleNamespace(datetime=FakeDateTime))
    return FakeDateTime


# 2020-01-02T03:04:05Z
TS = 1577934245


# ---------------------------------------------------------------- PlaceOfBirth


class TestPlaceOfBirth:
    def test_deser_from_dict_value_json_format(self):
        """A non string value with json format is dumped and parsed."""
        pob = ia.place_of_birth_deser({"country": "SE", "locality": "Umeå"}, "json")
        assert isinstance(pob, ia.PlaceOfBirth)
        assert pob["country"] == "SE"
        assert pob["locality"] == "Umeå"

    def test_deser_urlencoded_is_treated_as_json(self):
        pob = ia.place_of_birth_deser('{"country": "DE", "locality": "Berlin"}', "urlencoded")
        assert pob.to_dict() == {"country": "DE", "locality": "Berlin"}

    def test_deser_json_string(self):
        pob = ia.place_of_birth_deser('{"country": "DE", "locality": "Bonn"}', "json")
        assert pob["locality"] == "Bonn"

    def test_deser_dict_format_with_string(self):
        pob = ia.place_of_birth_deser('{"country": "FR", "locality": "Paris"}', "dict")
        assert pob["country"] == "FR"

    def test_deser_unknown_format(self):
        """Formats other than json/urlencoded/dict are passed straight on."""
        with pytest.raises(FormatError):
            ia.place_of_birth_deser("whatever", "xml")

    def test_deser_dict_format_with_dict(self):
        pob = ia.place_of_birth_deser({"country": "FR", "locality": "Lyon"}, "dict")
        assert pob["locality"] == "Lyon"

    def test_verify_missing_required(self):
        with pytest.raises(MissingRequiredAttribute):
            ia.PlaceOfBirth(country="SE").verify()

    def test_in_ida_claims(self):
        claims = ia.IdentityAssuranceClaims().from_json(
            json.dumps(
                {
                    "sub": "foo",
                    "place_of_birth": {"country": "SE", "locality": "Kiruna"},
                    "nationalities": ["SE", "FI"],
                    "birth_family_name": "Andersson",
                    "salutation": "Mr",
                    "msisdn": "4670123",
                }
            )
        )
        claims.verify()
        assert isinstance(claims["place_of_birth"], ia.PlaceOfBirth)
        assert claims["nationalities"] == ["SE", "FI"]
        # serialised back to json
        assert json.loads(claims.to_json())["place_of_birth"]["locality"] == "Kiruna"


# ------------------------------------------------------------ time handling


class TestTimeHelpers:
    def test_to_iso_from_int(self, utc):
        assert ia.to_iso8601_2004(TS) == "2020-01-02T03:04:05+0000"

    def test_to_iso_from_float(self, utc):
        assert ia.to_iso8601_2004(float(TS)) == "2020-01-02T03:04:05+0000"

    def test_to_iso_from_datetime(self, utc):
        d = datetime.datetime(2019, 12, 31, 23, 59, 58)
        assert ia.to_iso8601_2004(d) == "2019-12-31T23:59:58+0000"

    def test_to_iso_date_format(self, utc):
        assert ia.to_iso8601_2004(TS, format=ia.DATE_FORMAT) == "2020-01-02"

    def test_to_iso_unsupported_type(self, utc):
        with pytest.raises(ValueError):
            ia.to_iso8601_2004("2020-01-01")

    def test_to_iso_default_uses_now(self, fixed_now):
        assert ia.to_iso8601_2004() == "2021-03-04T05:06:07+0000"
        assert ia.to_iso8601_2004_date() == "2021-03-04"
        assert ia.to_iso8601_2004_time() == "2021-03-04T05:06:07+0000"

    def test_from_iso_time(self):
        assert ia.from_iso8601_2004("2020-01-02T03:04:05+0000") == TS
        assert ia.from_iso8601_2004_time("2020-01-02T05:04:05+0200") == TS

    def test_from_iso_date(self, utc):
        assert ia.from_iso8601_2004_date("2020-01-02") == 1577923200

    def test_from_iso_bad_string(self):
        with pytest.raises(ValueError):
            ia.from_iso8601_2004_time("not a date")

    def test_round_trip(self, utc):
        assert ia.from_iso8601_2004_time(ia.to_iso8601_2004_time(TS)) == TS
        assert ia.to_iso8601_2004_date(TS) == "2020-01-02"

    @pytest.mark.parametrize("val", [TS, float(TS) + 0.7])
    def test_time_stamp_ser_numbers(self, utc, val):
        assert ia.time_stamp_ser(val) == "2020-01-02T03:04:05+0000"

    def test_time_stamp_ser_numeric_string(self, utc):
        assert ia.time_stamp_ser(str(TS)) == "2020-01-02T03:04:05+0000"

    def test_time_stamp_ser_wrong_type(self):
        with pytest.raises(ValueError):
            ia.time_stamp_ser([TS])

    def test_time_stamp_deser(self):
        assert ia.time_stamp_deser(TS) == TS
        assert ia.time_stamp_deser(1.5) == 1.5
        assert ia.time_stamp_deser("2020-01-02T03:04:05+0000") == TS

    @pytest.mark.parametrize("val", [TS, float(TS), str(TS)])
    def test_date_ser(self, utc, val):
        assert ia.date_ser(val) == "2020-01-02"

    def test_date_ser_wrong_type(self):
        with pytest.raises(ValueError):
            ia.date_ser(None)

    def test_date_deser(self, utc):
        assert ia.date_deser(7) == 7
        assert ia.date_deser(7.5) == 7.5
        assert ia.date_deser("1970-01-02") == 86400


# --------------------------------------------------------- simple messages


class TestSimpleMessages:
    def test_ida_claims_deser(self):
        c = ia.identity_assurance_claims_deser({"sub": "x", "title": "Dr"}, "dict")
        assert isinstance(c, ia.IdentityAssuranceClaims)
        assert c["title"] == "Dr"

    def test_address_deser_urlencoded_and_json(self):
        a = ia.address_deser("country_code=SE&locality=Stockholm", "urlencoded")
        assert isinstance(a, ia.Address)
        assert a["country_code"] == "SE"
        a = ia.address_deser({"country_code": "NO"}, "dict")
        assert a["country_code"] == "NO"

    def test_verifier(self):
        v = ia.verifier_deser({"organization": "TÜV", "txn": "1"}, "dict")
        assert isinstance(v, ia.Verifier)
        v.verify()
        with pytest.raises(MissingRequiredAttribute):
            ia.Verifier(organization="x").verify()

    def test_verifier_list_deser(self):
        vl = ia.verifier_list_deser(
            [{"organization": "a", "txn": "1"}, {"organization": "b", "txn": "2"}], "dict"
        )
        assert [v["organization"] for v in vl] == ["a", "b"]
        assert all(isinstance(v, ia.Verifier) for v in vl)

    def test_issuer_deser_variants(self):
        msg = ia.Issuer(name="Stadt", country_code="DE")
        assert ia.issuer_deser(msg) is msg

        i = ia.issuer_deser({"name": "Stadt", "country_code": "DE", "locality": "Augsburg"}, "dict")
        assert isinstance(i, ia.Issuer)
        assert i["locality"] == "Augsburg"

        i = ia.issuer_deser('{"name": "N", "country_code": "SE"}', "json")
        assert i["country_code"] == "SE"

        i = ia.issuer_deser("name=N&country_code=FI", "urlencoded")
        assert i["country_code"] == "FI"
        i.verify()

    def test_issuer_missing_country(self):
        with pytest.raises(MissingRequiredAttribute):
            ia.Issuer(name="x").verify()

    def test_json_list_deserializer(self):
        assert ia.json_list_deserializer([{"a": 1}], "dict") == [{"a": 1}]
        assert ia.json_list_deserializer('[{"a": 1}]', "json") == [{"a": 1}]
        assert ia.json_list_deserializer("a=1", "urlencoded") is None

    def test_digest_and_external_attachment(self):
        d = ia.digest_deser({"alg": "sha-256", "value": "abc"}, "dict")
        assert isinstance(d, ia.Digest)
        ea = ia.ExternalAttachments().from_dict(
            {"url": "https://example.com/a", "expires_in": 30, "digest": {"alg": "s", "value": "v"}}
        )
        ea.verify()
        assert isinstance(ea["digest"], ia.Digest)
        assert ea["expires_in"] == 30

    def test_embedded_attachment_required(self):
        ia.EmbeddedAttachments(content_type="image/png", content="AAA").verify()
        with pytest.raises(MissingRequiredAttribute):
            ia.EmbeddedAttachments(content="AAA").verify()

    def test_provider_deser_variants(self):
        p = ia.Provider(name="Power")
        assert ia.provider_deser(p) is p
        p = ia.provider_deser({"name": "Power", "country_code": "DE"}, "dict")
        assert isinstance(p, ia.Provider)
        assert p["name"] == "Power"
        p = ia.provider_deser('{"name": "Oil"}', "json")
        assert p["name"] == "Oil"
        p = ia.provider_deser("name=Gas", "urlencoded")
        assert p["name"] == "Gas"

    def test_record_and_voucher(self, utc):
        r = ia.record_deser({"type": "population_register", "created_at": "2020-01-02"}, "dict")
        assert isinstance(r, ia.Record)
        # a str value already matches the declared type so it is kept verbatim
        assert r["created_at"] == "2020-01-02"
        v = ia.voucher_deser({"name": "Jane", "occupation": "doctor"}, "dict")
        assert isinstance(v, ia.Voucher)
        assert v["occupation"] == "doctor"

    def test_attestation(self, utc):
        a = ia.attestation_deser(
            {"type": "digital", "date_of_issuance": "2020-01-02", "voucher": {"name": "Jane"}},
            "dict",
        )
        assert isinstance(a, ia.Attestation)
        assert isinstance(a["voucher"], ia.Voucher)
        assert a["date_of_issuance"] == "2020-01-02"

    def test_vouch_deser_variants(self):
        v = ia.Vouch(type="vouch")
        assert ia.vouch_deser(v) is v
        v = ia.vouch_deser({"type": "vouch", "time": 5}, "dict")
        assert isinstance(v, ia.Vouch)
        assert v["time"] == 5
        v = ia.vouch_deser('{"type": "json_vouch"}', "json")
        assert v["type"] == "json_vouch"
        v = ia.vouch_deser("type=vouch", "urlencoded")
        assert v["type"] == "vouch"

    def test_evidence_metadata_ref_and_details(self):
        md = ia.evidence_metadata_deser({"evidence_classification": "primary"}, "dict")
        assert isinstance(md, ia.EvidenceMetadata)
        ref = ia.evidence_ref_deser(
            {"txn": "t1", "evidence_metadata": {"evidence_classification": "x"}}, "dict"
        )
        assert isinstance(ref, ia.EvidenceRef)
        assert isinstance(ref["evidence_metadata"], ia.EvidenceMetadata)
        det = ia.assurance_details_deser(
            {"assurance_type": "a", "evidence_ref": {"txn": "t2"}}, "dict"
        )
        assert isinstance(det["evidence_ref"], ia.EvidenceRef)
        proc = ia.assurance_process_deser(
            {"policy": "p", "assurance_details": {"assurance_type": "b"}}, "dict"
        )
        assert isinstance(proc, ia.AssuranceProcess)
        assert isinstance(proc["assurance_details"], ia.AssuranceDetails)

    def test_check_details(self, utc):
        cd = ia.check_details_deser({"check_method": "vpip", "time": TS}, "dict")
        assert isinstance(cd, ia.CheckDetails)
        cdl = ia.check_details_list_deser([{"check_method": "a"}, {"check_method": "b"}], "dict")
        assert [c["check_method"] for c in cdl] == ["a", "b"]
        with pytest.raises(MissingRequiredAttribute):
            ia.CheckDetails(organization="x").verify()

    def test_document_deser(self, utc):
        doc = ia.document_deser(
            {
                "type": "document",
                "method": "pipp",
                "time": "2020-01-02T03:04:05+0000",
                "verifier": [{"organization": "o", "txn": "t"}],
                "check_details": [{"check_method": "vcrypt"}],
            },
            "dict",
        )
        assert isinstance(doc, ia.Document)
        assert doc["time"] == "2020-01-02T03:04:05+0000"
        assert isinstance(doc["verifier"][0], ia.Verifier)
        assert isinstance(doc["check_details"][0], ia.CheckDetails)

    def test_document_details_deser_returns_message(self):
        res = ia.document_details_deser({"type": "idcard", "document_number": "1"}, "dict")
        assert res["document_number"] == "1"

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: identity_assurance.py:328 document_details_deser deserializes into "
        "Document instead of DocumentDetails",
    )
    def test_document_details_deser_type(self):
        res = ia.document_details_deser({"type": "idcard", "document_number": "1"}, "dict")
        assert isinstance(res, ia.DocumentDetails)

    def test_utility_bill_requires_provider(self):
        with pytest.raises(MissingRequiredAttribute):
            ia.UtilityBill(type="utility_bill").verify()
        ub = ia.UtilityBill().from_dict({"type": "utility_bill", "provider": {"name": "Gas"}})
        ub.verify()
        assert isinstance(ub["provider"], ia.Provider)

    def test_electronic_signature_requires(self):
        with pytest.raises(MissingRequiredAttribute):
            ia.ElectronicSignature(type="electronic_signature", issuer="x").verify()


# ---------------------------------------------------------------- Evidence


class TestEvidence:
    def test_document_evidence_with_attachments(self):
        ev = ia.Evidence(
            type="document",
            attachments=[
                {"url": "https://example.com/doc", "desc": "front"},
                {"content_type": "image/png", "content": "AAAA"},
            ],
        )
        ev.verify()
        att = ev["attachments"]
        assert isinstance(att[0], ia.ExternalAttachments)
        assert isinstance(att[1], ia.EmbeddedAttachments)

    @pytest.mark.parametrize(
        "info",
        [
            {"type": "utility_bill", "provider": {"name": "x"}},
            {"type": "electronic_record"},
            {"type": "voucher"},
            {
                "type": "electronic_signature",
                "signature_type": "qes",
                "issuer": "x",
                "serial_number": "1",
            },
        ],
    )
    def test_known_types_verify(self, info):
        ia.Evidence(**info).verify()

    def test_type_specific_requirements_enforced(self):
        """The evidence is re-verified with the type specific class."""
        with pytest.raises(MissingRequiredAttribute):
            ia.Evidence(type="utility_bill").verify()

    def test_unknown_type(self):
        with pytest.raises(ValueError, match="Unknown event type"):
            ia.Evidence(type="dna").verify()

    def test_type_mapped_to_nothing(self, monkeypatch):
        monkeypatch.setitem(ia.EVIDENCE_TYPES, "ghost", None)
        with pytest.raises(ValueError, match="Unknown type"):
            ia.Evidence(type="ghost").verify()

    def test_missing_type(self):
        with pytest.raises(MissingRequiredAttribute):
            ia.Evidence().verify()

    def test_evidence_deser(self):
        ev = ia.evidence_deser({"type": "document"}, "dict")
        assert isinstance(ev, ia.Evidence)
        ev = ia.evidence_deser("type=document", "urlencoded")
        assert ev["type"] == "document"

    def test_evidence_list_deser(self):
        res = ia.evidence_list_deser([{"type": "document"}, {"type": "voucher"}], "dict")
        assert [e["type"] for e in res] == ["document", "voucher"]
        assert all(isinstance(e, ia.Evidence) for e in res)

    def test_evidence_list_deser_single_dict(self):
        res = ia.evidence_list_deser({"type": "document"})
        assert len(res) == 1
        assert res[0]["type"] == "document"


# ------------------------------------------------------- VerificationElement


VERIFIED_CLAIMS = {
    "verification": {
        "trust_framework": "de_aml",
        "time": "2020-01-02T03:04:05+0000",
        "verification_process": "676q3636461467647q8498785747q487",
        "evidence": [
            {
                "type": "document",
                "method": "pipp",
                "document_details": {
                    "type": "idcard",
                    "document_number": "53554554",
                },
            }
        ],
        "assurance_process": {"policy": "p", "procedure": "x"},
    },
    "claims": {"given_name": "Max", "family_name": "Meier"},
}


class TestVerification:
    def test_verification_element_deser_variants(self):
        ve = ia.VerificationElement(trust_framework="eidas")
        assert ia.verification_element_deser(ve) is ve

        ve = ia.verification_element_deser({"trust_framework": "eidas"}, "dict")
        assert isinstance(ve, ia.VerificationElement)
        assert ve["trust_framework"] == "eidas"

        ve = ia.verification_element_deser('{"trust_framework": "jp_aml"}', "json")
        assert ve["trust_framework"] == "jp_aml"

        with pytest.raises(AttributeError):
            # a JSON array is not a JSON object
            ia.verification_element_deser(["not", "a", "dict"], "json")

        assert ia.verification_element_deser("trust_framework=x", "urlencoded") is None

    def test_verified_claims_from_json(self):
        vc = ia.VerifiedClaims().from_json(json.dumps(VERIFIED_CLAIMS))
        vc.verify()
        ver = vc["verification"]
        assert isinstance(ver, ia.VerificationElement)
        assert ver["time"] == "2020-01-02T03:04:05+0000"
        assert isinstance(ver["evidence"][0], ia.Evidence)
        assert isinstance(ver["assurance_process"], ia.AssuranceProcess)
        assert isinstance(vc["claims"], Claims)
        assert vc["claims"]["given_name"] == "Max"

    def test_verified_claims_bad_evidence(self):
        info = {"verification": {"trust_framework": "x", "evidence": [{"type": "magic"}]}}
        vc = ia.VerifiedClaims().from_json(json.dumps(info))
        with pytest.raises(ValueError):
            vc.verify()

    def test_verification_element_verify_noop_when_empty(self):
        ve = ia.VerificationElement(trust_framework="x", evidence=[])
        ve.verify()
        assert ve["evidence"] == []

    def test_verified_claims_no_parts(self):
        vc = ia.VerifiedClaims()
        vc.verify()
        assert vc.to_dict() == {}

    def test_verified_claims_deser_json_string(self):
        vc = ia.verified_claims_deser(json.dumps(VERIFIED_CLAIMS), "json")
        assert isinstance(vc, ia.VerifiedClaims)
        assert vc["verification"]["trust_framework"] == "de_aml"

    def test_verified_claims_deser_list_value(self):
        with pytest.raises(AttributeError):
            ia.verified_claims_deser([], "json")

    def test_verified_claims_deser_urlencoded(self):
        assert ia.verified_claims_deser("a=b", "urlencoded") is None

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: identity_assurance.py:681 verified_claims_deser rebinds 'val' to an "
        "empty VerifiedClaims before copying, so a Message input loses all content",
    )
    def test_verified_claims_deser_message_keeps_content(self):
        src = ia.VerifiedClaims(claims={"given_name": "Max"})
        res = ia.verified_claims_deser(src, "dict")
        assert res.to_dict() == {"claims": {"given_name": "Max"}}

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: identity_assurance.py:686 verified_claims_deser returns a "
        "VerificationElement for dict input instead of VerifiedClaims",
    )
    def test_verified_claims_deser_dict_type(self):
        res = ia.verified_claims_deser({"claims": {"given_name": "Max"}}, "dict")
        assert isinstance(res, ia.VerifiedClaims)

    def test_verification_element_request(self):
        req = ia.verification_element_request_deser({"trust_framework": "eidas"}, "dict")
        assert isinstance(req, ia.VerificationElementRequest)
        req.verify()
        with pytest.raises(MissingRequiredAttribute):
            ia.VerificationElementRequest(time=1).verify()


# -------------------------------------------------------------- ClaimsSpec


class TestClaimsSpec:
    def setup_method(self):
        self.spec = ia.ClaimsSpec()

    def test_none_and_non_dict(self):
        assert self.spec._verify_claims_request_value(None) is True
        assert self.spec._verify_claims_request_value("text") is True

    def test_valid_full(self):
        val = {
            "essential": True,
            "value": "a",
            "values": ["b", "c"],
            "purpose": "To be able to do things",
            "max_age": 60,
        }
        assert self.spec._verify_claims_request_value(val) is True

    def test_bad_essential(self):
        assert self.spec._verify_claims_request_value({"essential": "yes"}) is False

    def test_wrong_value_type(self):
        assert self.spec._verify_claims_request_value({"value": 1}) is False
        assert self.spec._verify_claims_request_value({"value": 1}, int) is True

    def test_wrong_values_type(self):
        assert self.spec._verify_claims_request_value({"values": ["a", 2]}) is False

    @pytest.mark.parametrize("purpose", ["ab", "x" * 301, "tab\tchar"])
    def test_bad_purpose(self, purpose):
        assert self.spec._verify_claims_request_value({"purpose": purpose}) is False

    def test_bad_max_age(self):
        assert self.spec._verify_claims_request_value({"max_age": "10"}) is False

    def test_message_value_type_is_accepted(self):
        assert ia._correct_value_type(5, ia.Verifier()) is True
        assert ia._correct_value_type(5, str) is False
        assert ia._correct_value_type("5", str) is True

    def test_verify(self):
        ia.ClaimsSpec(essential=True, purpose="abc", max_age=4).verify()


# --------------------------------------------------------- IDAClaimsRequest


class TestIDAClaimsRequest:
    def test_verified_claims_dict(self):
        req = ia.IDAClaimsRequest(
            verified_claims={
                "verification": {"trust_framework": "eidas"},
                "claims": {"given_name": None},
            }
        )
        req.verify()
        assert isinstance(req["verified_claims"], ia.VerifiedClaims)

    def test_verified_claims_list(self):
        req = ia.IDAClaimsRequest(verified_claims=[{"verification": {"trust_framework": "a"}}])
        req.verify()
        assert isinstance(req["verified_claims"], list)

    def test_verified_claims_str(self):
        req = ia.IDAClaimsRequest(verified_claims="foo")
        req.verify()
        assert req["verified_claims"] == "foo"

    def test_is_claims_request(self):
        assert issubclass(ia.IDAClaimsRequest, ClaimsRequest)


# -------------------------------------------------------- ClaimsConstructor


class TestClaimsConstructor:
    @pytest.mark.parametrize(
        "base",
        [
            ia.Verifier,
            ia.Verifier(),
            "idpyoidc.message.oidc.identity_assurance.Verifier",
        ],
    )
    def test_base_class_variants(self, base):
        cc = ia.ClaimsConstructor(base)
        assert isinstance(cc.base_class, ia.Verifier)
        assert cc.info == {}

    def test_set_and_serialize(self):
        cc = ia.ClaimsConstructor(ia.Verifier)
        cc["organization"] = None
        cc["txn"] = "1234"
        cc["unknown"] = {"essential": True}  # no value type -> no check
        assert cc.to_dict() == {
            "organization": None,
            "txn": "1234",
            "unknown": {"essential": True},
        }
        assert json.loads(cc.to_json()) == cc.to_dict()

    def test_unsupported_base_class(self):
        cc = ia.ClaimsConstructor(42)
        assert not hasattr(cc, "base_class")
        assert cc.to_dict() == {}

    def test_wrong_simple_type(self):
        cc = ia.ClaimsConstructor(ia.Verifier)
        with pytest.raises(ValueError, match="Wrong type of value 'txn'"):
            cc["txn"] = 12

    def test_nested_constructor(self):
        doc = ia.ClaimsConstructor(ia.ExternalAttachments)
        digest = ia.ClaimsConstructor(ia.Digest)
        digest["alg"] = None
        doc["digest"] = digest
        doc["url"] = None
        assert doc.to_dict() == {"digest": {"alg": None}, "url": None}

    def test_nested_constructor_wrong_type(self):
        doc = ia.ClaimsConstructor(ia.ExternalAttachments)
        with pytest.raises(ValueError, match="Wrong type of value 'digest'"):
            doc["digest"] = ia.ClaimsConstructor(ia.Verifier)

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: identity_assurance.py:807 ClaimsConstructor rejects a claims request "
        "dict ({'essential': True}) for a str-typed claim although its docstring allows it",
    )
    def test_claims_request_dict_for_simple_claim(self):
        cc = ia.ClaimsConstructor(ia.Verifier)
        cc["txn"] = {"essential": True}
        assert cc.to_dict() == {"txn": {"essential": True}}


# ------------------------------------------------------ ClaimsDeconstructor


class _InstanceTyped(Message):
    """A Message whose c_param type slots are instances (what the code expects)."""

    c_param = {
        "simple": ("", False, None, None, False),
        "simple_list": ([""], False, None, None, False),
        "sub": (ia.Digest(), False, None, None, False),
        "other": ([ia.Digest], False, None, None, False),
    }


def _base(**kwargs):
    m = _InstanceTyped()
    m._dict.update(kwargs)
    return m


class TestClaimsDeconstructor:
    @pytest.mark.parametrize(
        "base",
        [ia.Verifier, ia.Verifier(), "idpyoidc.message.oidc.identity_assurance.Verifier"],
    )
    def test_base_class_variants(self, base):
        cd = ia.ClaimsDeconstructor(base)
        assert isinstance(cd.base_class, ia.Verifier)
        assert cd.info == {}

    def test_unknown_keys(self):
        cd = ia.ClaimsDeconstructor(
            ia.Verifier, foo={"essential": True}, bar=None, baz="plain"
        )
        assert isinstance(cd.info["foo"], ia.ClaimsSpec)
        assert cd.info["foo"]["essential"] is True
        assert cd.info["bar"] is None
        assert cd.info["baz"] == "plain"

    def test_unknown_key_invalid_spec(self):
        with pytest.raises(Exception):
            ia.ClaimsDeconstructor(ia.Verifier, foo={"essential": "maybe"})

    def test_simple_type_dict_becomes_claims_spec(self):
        cd = ia.ClaimsDeconstructor(_base(simple="x"), simple={"essential": True})
        assert isinstance(cd.info["simple"], ia.ClaimsSpec)

    def test_simple_type_plain_value(self):
        cd = ia.ClaimsDeconstructor(_base(simple="x"), simple="y")
        assert cd.info["simple"] == "y"

    def test_simple_list(self):
        cd = ia.ClaimsDeconstructor(_base(simple_list=["x"]), simple_list=["a", "b"])
        assert cd.info["simple_list"] == ["a", "b"]

    def test_message_type(self, monkeypatch):
        """The Message branch is only reachable if the instance answers to [0]."""
        sub = ia.Digest()
        sub._dict[0] = ia.Digest  # makes _list_of_simple_type() return False
        monkeypatch.setitem(_InstanceTyped.c_param, "sub", (sub, False, None, None, False))
        cd = ia.ClaimsDeconstructor(_base(sub="x"), sub={"alg": None})
        assert cd.info["sub"] == {"alg": None}

    def test_message_instance_type_fails(self):
        """A plain Message instance as value type breaks on the [0] lookup."""
        with pytest.raises(KeyError):
            ia.ClaimsDeconstructor(_base(sub="x"), sub={"alg": None})

    def test_missing_value(self):
        cd = ia.ClaimsDeconstructor(_base(simple="x"), unrelated=None)
        assert cd.info == {"simple": None, "unrelated": None}

    def test_unknown_key_verify_error_propagates(self, monkeypatch):
        def boom(self, **kwargs):
            raise ValueError("bad spec")

        monkeypatch.setattr(ia.ClaimsSpec, "verify", boom)
        with pytest.raises(ValueError, match="bad spec"):
            ia.ClaimsDeconstructor(ia.Verifier, foo={"essential": True})

    def test_unsupported_base_class(self):
        """Anything that is not a str, Message instance or Message class is ignored."""
        cd = ia.ClaimsDeconstructor(42)
        assert not hasattr(cd, "base_class")
        assert cd.info == {}

    def test_other_type(self):
        with pytest.raises(ValueError, match="Other value_type"):
            ia.ClaimsDeconstructor(_base(other="x"), other={"a": 1})

    def test_helpers(self):
        cd = ia.ClaimsDeconstructor(ia.Verifier)
        assert cd._is_simple_type("a") is True
        assert cd._is_simple_type(1) is True
        assert cd._is_simple_type(str) is False
        assert cd._list_of_simple_type(["a"]) is True

    @pytest.mark.xfail(
        strict=True,
        raises=TypeError,
        reason="BUG: identity_assurance.py:859-866 ClaimsDeconstructor._is_simple_type tests "
        "isinstance(typ, str) on the c_param *type* (str class), then subscripts it -> TypeError "
        "for any populated standard Message",
    )
    def test_standard_message_known_key(self):
        cd = ia.ClaimsDeconstructor(
            ia.Verifier(organization="a", txn="b"), organization={"essential": True}
        )
        assert isinstance(cd.info["organization"], ia.ClaimsSpec)
