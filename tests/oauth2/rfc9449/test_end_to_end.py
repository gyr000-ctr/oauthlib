"""End-to-end RFC 9449 DPoP tests against pre-configured oauthlib servers."""
import json
import time
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2 import (
    BackendApplicationClient, BackendApplicationServer,
    LegacyApplicationServer, RequestValidator, WebApplicationClient,
    WebApplicationServer,
)
from oauthlib.oauth2.rfc9449 import (
    DPoPProofValidator, DPoPProtectedToken, InvalidDPoPTokenError,
    create_dpop_proof, enable_dpop, generate_dpop_key, jwk_thumbprint,
)

from tests.unittest import TestCase

TOKEN_URI = 'https://as.example.com/token'
RESOURCE_URI = 'https://rs.example.com/resource'


class FakeValidator(RequestValidator):
    """Minimal in-memory validator supporting client credentials + DPoP."""

    def __init__(self):
        self.saved_tokens = []
        self.dpop_bindings = {}

    def authenticate_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'c1'
        return True

    def validate_grant_type(self, *args, **kwargs):
        return True

    def validate_scopes(self, *args, **kwargs):
        return True

    def get_default_scopes(self, *args, **kwargs):
        return ['foo']

    def validate_user(self, username, password, client, request, *a, **k):
        request.user = 'user-1'
        return True

    def save_bearer_token(self, token, request, *args, **kwargs):
        self.saved_tokens.append(dict(token))
        if 'cnf' in token:
            self.dpop_bindings[token['access_token']] = token['cnf']['jkt']

    def validate_dpop_token(self, token, jkt, scopes, request, *a, **k):
        return self.dpop_bindings.get(token) == jkt

    def validate_bearer_token(self, token, scopes, request, *a, **k):
        # Tokens issued as plain Bearer are accepted through the ordinary
        # RFC 6750 validation path even after DPoP is enabled.
        return token not in self.dpop_bindings

    def validate_refresh_token(self, refresh_token, client, request, *a, **k):
        request.user = 'user-1'
        return refresh_token == 'rt-1'

    def get_original_scopes(self, refresh_token, request, *a, **k):
        return ['foo']


class DPoPTokenEndpointTest(TestCase):

    def setUp(self):
        self.validator = FakeValidator()
        self.server = BackendApplicationServer(self.validator)
        self.proof_validator = enable_dpop(self.server)
        self.private_key, self.public_jwk = generate_dpop_key()
        self.client = BackendApplicationClient(
            'c1', dpop_private_key=self.private_key)

    def _post(self, client):
        _, headers, body = client.prepare_token_request(TOKEN_URI)
        return self.server.create_token_response(
            TOKEN_URI, 'POST', body, headers)

    def test_dpop_token_issued_with_cnf_thumbprint(self):
        _headers, body, status = self._post(self.client)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload['token_type'], 'DPoP')
        self.assertEqual(payload['cnf'],
                         {'jkt': jwk_thumbprint(self.public_jwk)})
        saved = self.validator.saved_tokens[-1]
        self.assertEqual(saved['cnf']['jkt'],
                         jwk_thumbprint(self.public_jwk))

    def test_bearer_request_unchanged_zero_regression(self):
        plain = BackendApplicationClient('c1')
        _, headers, body = plain.prepare_token_request(TOKEN_URI)
        _, response_body, status = self.server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        payload = json.loads(response_body)
        self.assertEqual(status, 200)
        self.assertEqual(payload['token_type'], 'Bearer')
        self.assertNotIn('cnf', payload)

    def test_invalid_proof_returns_serialized_error_not_exception(self):
        _, good_headers, body = self.client.prepare_token_request(TOKEN_URI)
        good_headers['DPoP'] = 'not-a-jwt'
        _response_headers, response_body, status = self.server.create_token_response(
            TOKEN_URI, 'POST', body, good_headers)
        payload = json.loads(response_body)
        self.assertEqual(status, 400)
        self.assertEqual(payload['error'], 'invalid_dpop_proof')
        # No token was persisted on failure.
        self.assertEqual(self.validator.saved_tokens, [])

    def test_replayed_proof_rejected(self):
        _, headers, body = self.client.prepare_token_request(TOKEN_URI)
        first = self.server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        self.assertEqual(first[2], 200)
        second = self.server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        self.assertEqual(second[2], 400)
        self.assertEqual(json.loads(second[1])['error'],
                         'invalid_dpop_proof')

    def test_method_url_binding_errors_distinguishable_as_invalid_proof(self):
        proof = create_dpop_proof(
            self.private_key, 'POST', 'https://evil.example.com/token')
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'DPoP': proof,
        }
        _, body, status = self.server.create_token_response(
            TOKEN_URI, 'POST',
            'grant_type=client_credentials', headers)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'],
                         'invalid_dpop_proof')

    def test_require_proof_mode_rejects_bearer_requests(self):
        strict_server = BackendApplicationServer(FakeValidator())
        enable_dpop(strict_server, require_proof=True)
        plain = BackendApplicationClient('c1')
        _, headers, body = plain.prepare_token_request(TOKEN_URI)
        _, response_body, status = strict_server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(response_body)['error'],
                         'invalid_dpop_proof')

    def test_nonce_challenge_then_successful_retry(self):
        nonce_server = BackendApplicationServer(FakeValidator())
        enable_dpop(nonce_server, proof_validator=DPoPProofValidator(
            nonce_validator=lambda nonce, request: nonce == 'n-1',
            expected_nonce='n-1'))

        _, headers, body = self.client.prepare_token_request(TOKEN_URI)
        challenge_headers, challenge_body, status = \
            nonce_server.create_token_response(
                TOKEN_URI, 'POST', body, headers)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(challenge_body)['error'],
                         'use_dpop_nonce')
        self.assertEqual(challenge_headers['DPoP-Nonce'], 'n-1')

        self.client.update_dpop_nonce('n-1')
        _, retry_headers, retry_body = self.client.prepare_token_request(
            TOKEN_URI)
        _, ok_body, ok_status = nonce_server.create_token_response(
            TOKEN_URI, 'POST', retry_body, retry_headers)
        self.assertEqual(ok_status, 200)
        self.assertEqual(json.loads(ok_body)['token_type'], 'DPoP')


class DPoPResourceEndpointTest(TestCase):

    def setUp(self):
        self.validator = FakeValidator()
        self.server = BackendApplicationServer(self.validator)
        enable_dpop(self.server)
        self.private_key, self.public_jwk = generate_dpop_key()
        self.client = BackendApplicationClient(
            'c1', dpop_private_key=self.private_key)

        _, headers, body = self.client.prepare_token_request(TOKEN_URI)
        _, response_body, status = self.server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        assert status == 200
        self.access_token = json.loads(response_body)['access_token']
        self.client.access_token = self.access_token
        self.client.token_type = 'DPoP'

    def test_valid_dpop_resource_request(self):
        uri, headers, _ = self.client.add_token(RESOURCE_URI)
        valid, request = self.server.verify_request(
            uri, 'GET', '', headers, scopes=['foo'])
        self.assertTrue(valid)
        self.assertEqual(request.token_type, 'DPoP')
        self.assertEqual(request.dpop_jkt,
                         jwk_thumbprint(self.public_jwk))

    def test_wrong_key_thumbprint_fails_cnf_check(self):
        other_key, _ = generate_dpop_key()
        proof = create_dpop_proof(
            other_key, 'GET', RESOURCE_URI,
            access_token=self.access_token)
        valid, _ = self.server.verify_request(
            RESOURCE_URI, 'GET', '',
            {'Authorization': 'DPoP ' + self.access_token,
             'DPoP': proof}, scopes=['foo'])
        self.assertFalse(valid)

    def test_missing_proof_raises_401(self):
        with self.assertRaises(InvalidDPoPTokenError) as cm:
            self.server.verify_request(
                RESOURCE_URI, 'GET', '',
                {'Authorization': 'DPoP ' + self.access_token},
                scopes=['foo'])
        self.assertEqual(cm.exception.status_code, 401)

    def test_stale_iat_rejected_at_resource(self):
        proof = create_dpop_proof(
            self.private_key, 'GET', RESOURCE_URI,
            access_token=self.access_token,
            issued_at=time.time() - 999)
        with self.assertRaises(InvalidDPoPTokenError):
            self.server.verify_request(
                RESOURCE_URI, 'GET', '',
                {'Authorization': 'DPoP ' + self.access_token,
                 'DPoP': proof}, scopes=['foo'])

    def test_plain_bearer_still_routed_alongside_dpop(self):
        # A Bearer request must keep being identified as a Bearer token
        # type rather than hijacked by the DPoP handler.
        plain = BackendApplicationClient('c1')
        _, headers, body = plain.prepare_token_request(TOKEN_URI)
        _h, response_body, status = self.server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        bearer_token = json.loads(response_body)['access_token']
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(response_body)['token_type'], 'Bearer')

        request = Request(
            RESOURCE_URI, http_method='GET',
            headers={'Authorization': 'Bearer ' + bearer_token})
        self.assertEqual(self.server.find_token_type(request), 'Bearer')

        # The plain Bearer validation path still authorises the request,
        # proving zero regression on a DPoP-enabled server.
        valid, bearer_request = self.server.verify_request(
            RESOURCE_URI, 'GET', '',
            {'Authorization': 'Bearer ' + bearer_token},
            scopes=['foo'])
        self.assertTrue(valid)
        self.assertEqual(bearer_request.token_type, 'Bearer')

        dpop_request = Request(
            RESOURCE_URI, http_method='GET',
            headers={'Authorization': 'DPoP ' + self.access_token})
        self.assertEqual(self.server.find_token_type(dpop_request), 'DPoP')


class DPoPPasswordGrantTest(TestCase):
    """DPoP must work uniformly across grant types via the post_token hook."""

    def test_password_grant_issues_dpop_token(self):
        validator = FakeValidator()
        server = LegacyApplicationServer(validator)
        enable_dpop(server)
        private_key, public_jwk = generate_dpop_key()
        client = BackendApplicationClient(
            'c1', dpop_private_key=private_key)

        _, headers, _ = client.prepare_token_request(
            TOKEN_URI, body='grant_type=password&username=u&password=p')
        _, body, status = server.create_token_response(
            TOKEN_URI, 'POST',
            'grant_type=password&username=u&password=p', headers)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload['token_type'], 'DPoP')
        self.assertEqual(payload['cnf']['jkt'],
                         jwk_thumbprint(public_jwk))


class DPoPRefreshGrantTest(TestCase):
    """A refresh request carrying a DPoP proof yields a bound new token."""

    def test_refresh_issues_dpop_token_with_fresh_proof(self):
        validator = FakeValidator()
        # The all-grants Server supports the refresh_token grant.
        server = WebApplicationServer(validator)
        enable_dpop(server)
        private_key, public_jwk = generate_dpop_key()
        client = WebApplicationClient(
            'c1', dpop_private_key=private_key)

        _, headers, body = client.prepare_refresh_token_request(
            TOKEN_URI, refresh_token='rt-1')
        _, response_body, status = server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        self.assertEqual(status, 200)
        payload = json.loads(response_body)
        self.assertEqual(payload['token_type'], 'DPoP')
        self.assertEqual(payload['cnf']['jkt'],
                         jwk_thumbprint(public_jwk))

    def test_refresh_replay_rejected(self):
        validator = FakeValidator()
        server = WebApplicationServer(validator)
        enable_dpop(server)
        private_key, _public_jwk = generate_dpop_key()
        client = WebApplicationClient(
            'c1', dpop_private_key=private_key)

        _, headers, body = client.prepare_refresh_token_request(
            TOKEN_URI, refresh_token='rt-1')
        first = server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        self.assertEqual(first[2], 200)
        # Re-send the identical request (same proof jti).
        second = server.create_token_response(
            TOKEN_URI, 'POST', body, headers)
        self.assertEqual(second[2], 400)
        self.assertEqual(json.loads(second[1])['error'],
                         'invalid_dpop_proof')


class StandaloneTokenHandlerTest(TestCase):
    """DPoPProtectedToken used directly, without enable_dpop()."""

    def test_create_token_validates_proof_and_binds_cnf(self):
        validator = mock.MagicMock()
        handler = DPoPProtectedToken(request_validator=validator)
        private_key, public_jwk = generate_dpop_key()
        proof = create_dpop_proof(private_key, 'POST', TOKEN_URI)
        request = Request(
            TOKEN_URI, http_method='POST',
            headers={'DPoP': proof},
            body='grant_type=client_credentials')
        request.scopes = ['foo']

        token = handler.create_token(request)
        self.assertEqual(token['token_type'], 'DPoP')
        self.assertEqual(token['cnf'],
                         {'jkt': jwk_thumbprint(public_jwk)})
        self.assertEqual(request.dpop_jkt, jwk_thumbprint(public_jwk))

    def test_create_token_without_proof_stays_bearer(self):
        validator = mock.MagicMock()
        handler = DPoPProtectedToken(request_validator=validator)
        request = Request(
            TOKEN_URI, http_method='POST',
            body='grant_type=client_credentials')
        request.scopes = ['foo']

        token = handler.create_token(request)
        self.assertEqual(token['token_type'], 'Bearer')
        self.assertNotIn('cnf', token)
