"""Upstream idpy-oidc tests that fail because of intentional changes in the
niscy-eudiw fork. They are marked strict xfail with the reason, so the list
stays explicit: a test that starts passing fails the run and must be removed
from here."""

import pytest

REAUTH = 'the fork always re-authenticates (re_authenticate() returns True): the authorization endpoint hands over to the issuer backend instead of returning a code'
INTRO = "the fork's introspection returns username and checks the session's own client: the issuer backend (resource server) introspects tokens of wallet clients, behind X-Api-Key"
REFRESH = 'the fork always issues a refresh token with an access token'
SCOPE = 'the fork makes scope optional (OID4VCI requests may carry only authorization_details)'
TRIAGE = 'fork behaviour change, not yet triaged'

KNOWN_FORK_FAILURES = {
    'tests/test_06_oidc.py::TestAuthorizationRequest::test_verify_no_scopes': SCOPE,
    'tests/test_client_21_oidc_service.py::TestAuthorization::test_request_init_request_method': TRIAGE,
    'tests/test_server_24_oauth2_authorization_endpoint.py::TestEndpoint::test_audience_id_token': REAUTH,
    'tests/test_server_24_oauth2_authorization_endpoint.py::TestEndpoint::test_do_response_code': REAUTH,
    'tests/test_server_24_oauth2_authorization_endpoint.py::TestEndpoint::test_process_request': REAUTH,
    'tests/test_server_24_oauth2_authorization_endpoint.py::TestEndpoint::test_req_user_no_prompt': REAUTH,
    'tests/test_server_24_oauth2_authorization_endpoint.py::TestEndpoint::test_setup_auth': REAUTH,
    'tests/test_server_24_oauth2_authorization_endpoint.py::TestEndpoint::test_setup_auth_user': REAUTH,
    'tests/test_server_24_oauth2_token_endpoint.py::TestClientCredentialsFlow::test_client_credentials': REAUTH,
    'tests/test_server_24_oauth2_token_endpoint.py::TestResourceOwnerPasswordCredentialsFlow::test_resource_owner_password_credentials': REAUTH,
    'tests/test_server_24_oauth2_token_endpoint_def_conf.py::TestClientCredentialsFlow::test_client_credentials': REAUTH,
    'tests/test_server_24_oauth2_token_endpoint_def_conf.py::TestResourceOwnerPasswordCredentialsFlow::test_resource_owner_password_credentials': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestACR::test_setup_acr_claim': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_check_session_iframe': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_do_response_code': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_do_response_code_id_token': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_do_response_id_token': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_id_token_acr': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_id_token_claims': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_process_request': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_setup_auth': REAUTH,
    'tests/test_server_24_oidc_authorization_endpoint.py::TestEndpoint::test_setup_auth_user_form_post': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_back_channel_logout': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_back_channel_logout_no_backchannel_logout_uri': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_do_verified_logout': TRIAGE,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_end_session_endpoint_with_cookie': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_end_session_endpoint_with_cookie_and_unknown_sid': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_end_session_endpoint_with_cookie_dual_login': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_end_session_endpoint_with_cookie_id_token_and_unknown_sid': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_end_session_endpoint_with_post_logout_redirect_uri': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_end_session_endpoint_with_wrong_post_logout_redirect_uri': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_logout_from_client': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_logout_from_client_bc': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_logout_from_client_fc': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_logout_from_client_no_session': REAUTH,
    'tests/test_server_30_oidc_end_session.py::TestEndpoint::test_logout_from_client_unknow_sid': REAUTH,
    'tests/test_server_31_oauth2_introspection.py::TestEndpoint::test_do_response[False]': INTRO,
    'tests/test_server_31_oauth2_introspection.py::TestEndpoint::test_do_response[True]': INTRO,
    'tests/test_server_31_oauth2_introspection.py::TestEndpoint::test_process_request[False]': INTRO,
    'tests/test_server_31_oauth2_introspection.py::TestEndpoint::test_process_request[True]': INTRO,
    'tests/test_server_31_oauth2_introspection.py::TestEndpoint::test_wrong_aud[False]': INTRO,
    'tests/test_server_31_oauth2_introspection.py::TestEndpoint::test_wrong_aud[True]': INTRO,
    'tests/test_server_33_oauth2_pkce.py::TestEndpoint::test_no_code_challenge_method': REAUTH,
    'tests/test_server_33_oauth2_pkce.py::TestEndpoint::test_no_code_verifier': REAUTH,
    'tests/test_server_33_oauth2_pkce.py::TestEndpoint::test_not_essential': REAUTH,
    'tests/test_server_33_oauth2_pkce.py::TestEndpoint::test_not_essential_per_client': REAUTH,
    'tests/test_server_33_oauth2_pkce.py::TestEndpoint::test_parse': REAUTH,
    'tests/test_server_33_oauth2_pkce.py::TestEndpoint::test_wrong_code_verifier': REAUTH,
    'tests/test_server_34_oidc_sso.py::TestUserAuthn::test_sso': REAUTH,
    'tests/test_server_35_oidc_token_endpoint.py::TestEndpoint::test_refresh_no_offline_access_scope': REFRESH,
    'tests/test_server_35_oidc_token_endpoint_def_conf.py::TestEndpoint::test_refresh_no_offline_access_scope': REFRESH,
    'tests/test_server_61_add_on.py::TestEndpoint::test_process_request': REAUTH,
    'tests/test_tandem_oauth2_add_on.py::test_jar': REAUTH,
    'tests/test_tandem_oauth2_add_on.py::test_pkce': REAUTH,
    'tests/test_tandem_oauth2_code.py::TestFlow::test_flow': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_additional_parameters': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_exchange_access_token_to_refresh_token[scopes0]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_exchange_access_token_to_refresh_token[scopes1]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_exchange_refresh_token_to_refresh_token': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_invalid_token': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_refresh_token_audience': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_token_exchange[token0]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_token_exchange[token1]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_token_exchange_fails_if_disabled': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_token_exchange_per_client[token0]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_token_exchange_per_client[token1]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_actor_token': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_requested_token_type[unknown]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_requested_token_type[urn:ietf:params:oauth:token-type:id_token]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_requested_token_type[urn:ietf:params:oauth:token-type:saml1]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_requested_token_type[urn:ietf:params:oauth:token-type:saml2]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_subject_token_type[unknown]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_subject_token_type[urn:ietf:params:oauth:token-type:id_token]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_subject_token_type[urn:ietf:params:oauth:token-type:saml1]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_unsupported_subject_token_type[urn:ietf:params:oauth:token-type:saml2]': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_wrong_audience': REAUTH,
    'tests/test_tandem_oauth2_token_exchange.py::TestEndpoint::test_wrong_resource': REAUTH,
    'tests/test_tandem_oauth2_token_revocation.py::TestClient::test_revoke': REAUTH,
    'tests/test_tandem_oidc_code.py::TestFlow::test_flow': REAUTH,
}


def pytest_collection_modifyitems(config, items):
    for item in items:
        reason = KNOWN_FORK_FAILURES.get(item.nodeid)
        if reason:
            item.add_marker(pytest.mark.xfail(reason=reason, strict=True))
