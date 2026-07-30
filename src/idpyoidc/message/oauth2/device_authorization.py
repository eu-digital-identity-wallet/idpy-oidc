from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import (
    OPTIONAL_LIST_OF_STRINGS,
    REQUIRED_LIST_OF_STRINGS,
    SINGLE_OPTIONAL_INT,
    SINGLE_OPTIONAL_STRING,
    SINGLE_REQUIRED_INT,
    SINGLE_REQUIRED_JSON,
    SINGLE_REQUIRED_STRING,
    Message,
    oidc,
)


class AuthorizationRequest(Message):
    c_param = {
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING,
    }


class AuthorizationResponse(Message):
    c_param = {
        "device_code": SINGLE_REQUIRED_STRING,
        "user_code": SINGLE_REQUIRED_STRING,
        "verification_uri": SINGLE_REQUIRED_STRING,
        "verification_uri_complete": SINGLE_OPTIONAL_STRING,
        "expires_in": SINGLE_REQUIRED_INT,
        "interval": SINGLE_OPTIONAL_INT,
    }


class AccessTokenRequest(oidc.AccessTokenRequest):
    def verify(self, **kwargs):
        super(AccessTokenRequest, self).verify(**kwargs)

        if "device_code" in self:
            # then both client_id and grant_type MUST be present
            for claim in ["grant_type", "client_id"]:
                if claim not in self:
                    raise MissingRequiredAttribute(claim)


class ClientStatus(Message):
    """
    The WIA `client_status` object (Section 2.3.1 / 2.4.1).
    Represents revocation state of the Wallet Instance, plus the
    revocation-maintenance commitment period.
    """

    c_param = {
        "status": SINGLE_REQUIRED_JSON,  # nested status_list reference
        "exp": SINGLE_REQUIRED_INT,  # revocation maintenance expiry,
    }


class WalletInstanceAttestationJWT(Message):
    """
    Wallet Instance Attestation (WIA) payload per TS3 v1.5.2, Section 2.3.1.
    """

    c_param = {
        # Required by Appendix E of OID4VCI (the underlying wallet-attestation
        # format) and by this spec
        "sub": SINGLE_REQUIRED_STRING,  # = client_id
        "exp": SINGLE_REQUIRED_INT,  # technical token expiry,
        # TTL < 24h from integrity check
        "cnf": SINGLE_REQUIRED_JSON,  # holder PoP key
        # EUDI-specific additions, Section 2.3.1
        "wallet_name": SINGLE_REQUIRED_STRING,  # Wallet Solution identifier,
        # as on the Wallet Provider Trusted List
        "wallet_version": SINGLE_REQUIRED_STRING,  # Wallet Solution version
        "wallet_solution_certification_information": SINGLE_REQUIRED_JSON,
        "client_status": SINGLE_REQUIRED_JSON,  # { status: {...}, exp: ... }
        # SHOULD, not REQUIRED
        "wallet_link": SINGLE_OPTIONAL_STRING,  # info URI about Wallet Solution
        # Optional freshness claims used by your PoP/attestation freshness checks
        # (not formally required by TS3 itself, but commonly carried)
        "iat": SINGLE_OPTIONAL_INT,
        "nbf": SINGLE_OPTIONAL_INT,
    }
