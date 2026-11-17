"""Tests for the server-side RFC 9449 DPoP proof validator."""
import json
import time

import jwt

from oauthlib.common import Request
from oauthlib.oauth2.rfc9449 import (
    DPoPProofValidator, DPoPReplayError, InMemoryDPoPReplayCache,
    InvalidDPoPProofError, InvalidDPoPTokenError,
    MissingDPoPProofError, UseDPoPNonceError,
    UseDPoPNonceResourceError, access_token_hash, create_dpop_proof,
    generate_dpop_key,
)

from tests.unittest import TestCase

TOKEN_URI = 'https://as.example.com/token'
RESOURCE_URI = 'https://rs.example.com/resource'


class ValidatorTestBase(TestCase):

    def setUp(self):
        self.private_key, self.jwk = generate_dpop_key()
        self.validator = DPoPProofValidator()

    def request(self, proof=None, uri=TOKEN_URI, method='POST',
                access_token=None):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if proof is not None:
            headers['DPoP'] = proof
        return Request(uri, http_method=method, headers=headers,
                       body='grant_type=client_credentials')

    def proof(self, **kwargs):
        return create_dpop_proof(self.private_key, 'POST', TOKEN_URI,
                                 **kwargs)


class TokenRequestValidationTest(ValidatorTestBase):

    def test_valid_proof_sets_jwk_jkt_and_claims(self):
        proof = self.proof()
        request = self.request(proof)
        self.assertTrue(
            self.validator.validate_token_request_proof(request))
        self.assertEqual(request.dpop_jwk, self.jwk)
        self.assertEqual(request.dpop_claims['htm'], 'POST')
        self.assertIsInstance(request.dpop_jkt, str)

    def test_missing_proof_optional_returns_false(self):
        request = self.request()
        self.assertFalse(
            self.validator.validate_token_request_proof(request))
        self.assertIsNone(request.dpop_jkt)

    def test_missing_proof_required_raises_distinct_error(self):
        validator = DPoPProofValidator(require_proof=True)
        with self.assertRaises(MissingDPoPProofError) as cm:
            validator.validate_token_request_proof(self.request())
        self.assertEqual(cm.exception.error, 'invalid_dpop_proof')
        self.assertEqual(cm.exception.status_code, 400)

    def test_garbage_header_raises_invalid_proof(self):
        for bad in ('garbage', 'a.b', 'a.b.c.d', ' a.b.c ', 'a.b,c.d.e'):
            with self.assertRaises(InvalidDPoPProofError):
                self.validator.validate_token_request_proof(
                    self.request(bad))

    def test_wrong_typ_rejected(self):
        # Hand-craft a proof whose JOSE typ is not "DPoP".
        proof = jwt.encode(
            {'htm': 'POST', 'htu': TOKEN_URI, 'iat': int(time.time()),
             'jti': 'x'},
            self.private_key, algorithm='ES256',
            headers={'typ': 'JWT', 'jwk': self.jwk})
        with self.assertRaises(InvalidDPoPProofError):
            self.validator.validate_token_request_proof(
                self.request(proof))

    def test_unsupported_algorithm_rejected(self):
        # RS256 is accepted by default; craft an ES384 proof and build a
        # validator that only accepts ES256.
        other_key, _other_jwk = generate_dpop_key('ES384')
        proof = create_dpop_proof(other_key, 'POST', TOKEN_URI,
                                  algorithm='ES384')
        validator = DPoPProofValidator(accepted_algorithms=('ES256',))
        with self.assertRaises(InvalidDPoPProofError):
            validator.validate_token_request_proof(self.request(proof))

    def test_algorithm_jwk_mismatch_rejected(self):
        _rsa_key, rsa_jwk = generate_dpop_key('RS256')
        # Hand-craft a compact JWS: valid ES256 signature but with an RSA JWK
        # embedded, so parsing succeeds and the internal alg/jwk check (not
        # the compact-JWT shape check) must reject it.
        es_key, _es_jwk = generate_dpop_key('ES256')
        proof = jwt.encode(
            {'htm': 'POST', 'htu': TOKEN_URI, 'iat': int(time.time()),
             'jti': 'x'},
            es_key, algorithm='ES256',
            headers={'typ': 'DPoP', 'jwk': rsa_jwk})
        self.assertEqual(len(proof.split('.')), 3)
        with self.assertRaises(InvalidDPoPProofError):
            self.validator.validate_token_request_proof(
                self.request(proof))

    def test_curve_algorithm_mismatch_rejected(self):
        # A validator restricted to ES256 must reject an ES384/P-384 proof
        # even though the algorithm is otherwise DPoP-legal.
        other_key, other_jwk = generate_dpop_key('ES384')
        proof = jwt.encode(
            {'htm': 'POST', 'htu': TOKEN_URI, 'iat': int(time.time()),
             'jti': 'x'},
            other_key, algorithm='ES384',
            headers={'typ': 'DPoP', 'jwk': other_jwk})
        validator = DPoPProofValidator(accepted_algorithms=('ES256',))
        with self.assertRaises(InvalidDPoPProofError):
            validator.validate_token_request_proof(self.request(proof))

    def test_private_jwk_in_header_rejected(self):
        proof = jwt.encode(
            {'htm': 'POST', 'htu': TOKEN_URI, 'iat': int(time.time()),
             'jti': 'x'},
            self.private_key, algorithm='ES256',
            headers={'typ': 'DPoP', 'jwk': {**self.jwk, 'd': 'leaked'}})
        with self.assertRaises(InvalidDPoPProofError):
            self.validator.validate_token_request_proof(
                self.request(proof))

    def test_bad_signature_rejected(self):
        proof = self.proof()
        header, payload, signature = proof.split('.')
        tampered = '.'.join([header, payload, signature[:-2] + 'AA'])
        with self.assertRaises(InvalidDPoPProofError):
            self.validator.validate_token_request_proof(
                self.request(tampered))

    def test_missing_required_claim_rejected(self):
        for omitted in ('jti', 'htm', 'htu', 'iat'):
            claims = {'jti': 'x', 'htm': 'POST', 'htu': TOKEN_URI,
                      'iat': int(time.time())}
            del claims[omitted]
            proof = jwt.encode(
                claims, self.private_key, algorithm='ES256',
                headers={'typ': 'DPoP', 'jwk': self.jwk})
            with self.assertRaises(InvalidDPoPProofError):
                self.validator.validate_token_request_proof(
                    self.request(proof))

    def test_htm_mismatch_rejected(self):
        proof = create_dpop_proof(self.private_key, 'GET', TOKEN_URI)
        with self.assertRaises(InvalidDPoPProofError):
            self.validator.validate_token_request_proof(
                self.request(proof))

    def test_htu_mismatch_rejected(self):
        proof = create_dpop_proof(
            self.private_key, 'POST', 'https://evil.example.com/token')
        with self.assertRaises(InvalidDPoPProofError):
            self.validator.validate_token_request_proof(
                self.request(proof))

    def test_htu_normalization_accepted(self):
        # Query/fragment/default port are removed on both sides.
        proof = create_dpop_proof(
            self.private_key, 'POST',
            'https://as.example.com:443/token?x=1#f')
        request = self.request(proof)
        self.assertTrue(
            self.validator.validate_token_request_proof(request))

    def test_iat_too_old_rejected(self):
        proof = self.proof(issued_at=time.time() - 999)
        with self.assertRaises(InvalidDPoPProofError):
            self.validator.validate_token_request_proof(
                self.request(proof))

    def test_iat_in_future_beyond_skew_rejected(self):
        proof = self.proof(issued_at=time.time() + 3600)
        with self.assertRaises(InvalidDPoPProofError):
            self.validator.validate_token_request_proof(
                self.request(proof))

    def test_iat_within_skew_accepted(self):
        proof = self.proof(issued_at=time.time() + 5)
        request = self.request(proof)
        self.assertTrue(
            self.validator.validate_token_request_proof(request))

    def test_jti_replay_raises_dedicated_error(self):
        proof = self.proof()
        self.validator.validate_token_request_proof(self.request(proof))
        with self.assertRaises(InvalidDPoPProofError) as cm:
            self.validator.validate_token_request_proof(
                self.request(proof))
        # Replay uses its own subclass, distinguishable from malformed proofs.
        self.assertIsInstance(cm.exception, DPoPReplayError)

    def test_replay_cache_injected(self):
        cache = InMemoryDPoPReplayCache()
        validator = DPoPProofValidator(replay_cache=cache)
        proof = self.proof()
        validator.validate_token_request_proof(self.request(proof))
        self.assertEqual(len(cache._seen), 1)
        with self.assertRaises(InvalidDPoPProofError):
            validator.validate_token_request_proof(self.request(proof))


class NonceTest(ValidatorTestBase):

    def setUp(self):
        super().setUp()
        self.validator = DPoPProofValidator(
            nonce_validator=lambda nonce, request: nonce == 'good',
            expected_nonce='fresh-nonce')

    def test_missing_nonce_challenges_with_header(self):
        with self.assertRaises(UseDPoPNonceError) as cm:
            self.validator.validate_token_request_proof(
                self.request(self.proof()))
        self.assertEqual(cm.exception.error, 'use_dpop_nonce')
        self.assertEqual(cm.exception.status_code, 400)
        self.assertEqual(cm.exception.headers['DPoP-Nonce'],
                         'fresh-nonce')

    def test_bad_nonce_challenges(self):
        proof = self.proof(nonce='stale')
        with self.assertRaises(UseDPoPNonceError):
            self.validator.validate_token_request_proof(
                self.request(proof))

    def test_good_nonce_passes(self):
        proof = self.proof(nonce='good')
        request = self.request(proof)
        self.assertTrue(
            self.validator.validate_token_request_proof(request))

    def test_nonce_provider_callable(self):
        validator = DPoPProofValidator(
            nonce_validator=lambda nonce, request: False,
            nonce_provider=lambda request: 'generated-%s' % request.uri)
        with self.assertRaises(UseDPoPNonceError) as cm:
            validator.validate_token_request_proof(
                self.request(self.proof()))
        self.assertEqual(cm.exception.headers['DPoP-Nonce'],
                         'generated-%s' % TOKEN_URI)

    def test_no_nonce_enforcement_when_validator_unset(self):
        validator = DPoPProofValidator()
        request = self.request(self.proof())
        self.assertTrue(
            validator.validate_token_request_proof(request))


class ResourceRequestValidationTest(ValidatorTestBase):

    def setUp(self):
        super().setUp()
        self.access_token = 'access-token-xyz'

    def _resource_request(self, proof, uri=RESOURCE_URI, method='GET',
                          token=None):
        headers = {
            'Authorization': 'DPoP ' + (token or self.access_token),
            'DPoP': proof,
        }
        return Request(uri, http_method=method, headers=headers)

    def test_valid_resource_proof_returns_thumbprint(self):
        proof = create_dpop_proof(
            self.private_key, 'GET', RESOURCE_URI,
            access_token=self.access_token)
        request = self._resource_request(proof)
        jkt = self.validator.validate_resource_request_proof(
            request, self.access_token)
        self.assertEqual(jkt, request.dpop_jkt)

    def test_missing_proof_is_401_resource_error(self):
        request = Request(
            RESOURCE_URI, http_method='GET',
            headers={'Authorization': 'DPoP ' + self.access_token})
        with self.assertRaises(InvalidDPoPTokenError) as cm:
            self.validator.validate_resource_request_proof(
                request, self.access_token)
        self.assertEqual(cm.exception.status_code, 401)
        self.assertIn('DPoP', cm.exception.headers['WWW-Authenticate'])

    def test_ath_mismatch_rejected(self):
        # Proof bound to a different token.
        proof = create_dpop_proof(
            self.private_key, 'GET', RESOURCE_URI,
            access_token='some-other-token')
        request = self._resource_request(proof)
        with self.assertRaises(InvalidDPoPTokenError):
            self.validator.validate_resource_request_proof(
                request, self.access_token)

    def test_missing_ath_rejected(self):
        proof = create_dpop_proof(self.private_key, 'GET', RESOURCE_URI)
        request = self._resource_request(proof)
        with self.assertRaises(InvalidDPoPTokenError):
            self.validator.validate_resource_request_proof(
                request, self.access_token)

    def test_htm_htu_binding_enforced(self):
        proof = create_dpop_proof(
            self.private_key, 'POST', RESOURCE_URI,
            access_token=self.access_token)
        request = self._resource_request(proof)
        with self.assertRaises(InvalidDPoPTokenError):
            self.validator.validate_resource_request_proof(
                request, self.access_token)

    def test_replay_is_401(self):
        proof = create_dpop_proof(
            self.private_key, 'GET', RESOURCE_URI,
            access_token=self.access_token)
        request = self._resource_request(proof)
        self.validator.validate_resource_request_proof(
            request, self.access_token)
        with self.assertRaises(InvalidDPoPTokenError):
            self.validator.validate_resource_request_proof(
                self._resource_request(proof), self.access_token)

    def test_nonce_failure_uses_resource_variant(self):
        validator = DPoPProofValidator(
            nonce_validator=lambda nonce, request: False,
            expected_nonce='rs-nonce')
        proof = create_dpop_proof(
            self.private_key, 'GET', RESOURCE_URI,
            access_token=self.access_token)
        with self.assertRaises(UseDPoPNonceResourceError) as cm:
            validator.validate_resource_request_proof(
                self._resource_request(proof), self.access_token)
        self.assertEqual(cm.exception.status_code, 401)
        self.assertEqual(cm.exception.error, 'use_dpop_nonce')
        self.assertEqual(cm.exception.headers['DPoP-Nonce'], 'rs-nonce')
        self.assertIn('DPoP', cm.exception.headers['WWW-Authenticate'])

    def test_exception_chaining_not_swallowed(self):
        # A decoder failure is wrapped in a resource error but its original
        # PyJWT cause is retained on __cause__.
        request = self._resource_request('a.b.c')
        with self.assertRaises(InvalidDPoPTokenError) as cm:
            self.validator.validate_resource_request_proof(
                request, self.access_token)
        self.assertIsNotNone(cm.exception.__cause__)


class ErrorSerializationTest(TestCase):

    def test_token_endpoint_error_is_json_with_400_and_no_challenge(self):
        error = InvalidDPoPProofError()
        payload = json.loads(error.json)
        self.assertEqual(payload['error'], 'invalid_dpop_proof')
        self.assertEqual(error.status_code, 400)
        self.assertEqual(error.headers, {})

    def test_missing_and_replay_share_wire_code_but_distinct_classes(self):
        self.assertEqual(MissingDPoPProofError.error, 'invalid_dpop_proof')
        self.assertEqual(DPoPReplayError.error, 'invalid_dpop_proof')
        self.assertNotEqual(MissingDPoPProofError, DPoPReplayError)

    def test_resource_error_401_dpop_challenge(self):
        error = InvalidDPoPTokenError()
        self.assertEqual(error.status_code, 401)
        challenge = error.headers['WWW-Authenticate']
        self.assertTrue(challenge.startswith('DPoP '))
        self.assertIn('error="invalid_token"', challenge)
