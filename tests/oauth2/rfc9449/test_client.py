"""Tests for the client-side RFC 9449 DPoP primitives."""
import base64
import hashlib
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from oauthlib.common import Request
from oauthlib.oauth2 import BackendApplicationClient, WebApplicationClient
from oauthlib.oauth2.rfc6749.clients.base import FORM_ENC_HEADERS
from oauthlib.oauth2.rfc9449 import (
    DPOP_ALGORITHMS, InMemoryDPoPReplayCache, access_token_hash,
    create_dpop_proof, generate_dpop_key, jwk_thumbprint, normalize_htu,
    public_jwk_from_private_key,
)
from oauthlib.oauth2.rfc9449.client import base64url_encode

from tests.unittest import TestCase

TOKEN_URI = 'https://as.example.com/token'
RESOURCE_URI = 'https://rs.example.com/resource'


def _b64u_decode(value):
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


class ThumbprintTest(TestCase):
    """RFC 7638 thumbprint vectors and JWK handling."""

    def test_rfc7638_rsa_known_vector(self):
        # Appendix A.1 of RFC 7638
        jwk = {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
                 "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst"
                 "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0"
                 "_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajr"
                 "n1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XP"
                 "ksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        }
        self.assertEqual(
            jwk_thumbprint(jwk),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")

    def test_thumbprint_ignores_non_required_members(self):
        _private_key, jwk = generate_dpop_key()
        decorated = dict(jwk, kid='abc', use='sig')
        self.assertEqual(jwk_thumbprint(jwk), jwk_thumbprint(decorated))

    def test_thumbprint_is_base64url_sha256_of_canonical_json(self):
        _private_key, jwk = generate_dpop_key()
        canonical = json.dumps(
            {k: jwk[k] for k in ('crv', 'kty', 'x', 'y')},
            sort_keys=True, separators=(',', ':'))
        expected = base64url_encode(
            hashlib.sha256(canonical.encode('ascii')).digest())
        self.assertEqual(jwk_thumbprint(jwk), expected)

    def test_unsupported_kty(self):
        with self.assertRaises(ValueError):
            jwk_thumbprint({'kty': 'oct', 'k': 'aaa'})

    def test_public_jwk_strips_private_members(self):
        _private_key, jwk = generate_dpop_key()
        private_jwk = {**jwk, 'd': 'secret'}
        self.assertNotIn('d', public_jwk_from_private_key(private_jwk))


class KeyGenerationTest(TestCase):

    def test_ec_default_key(self):
        _private_key, jwk = generate_dpop_key()
        self.assertEqual(jwk['kty'], 'EC')
        self.assertEqual(jwk['crv'], 'P-256')
        for member in ('x', 'y'):
            self.assertEqual(len(_b64u_decode(jwk[member])), 32)
        self.assertNotIn('d', jwk)

    def test_ec_curves(self):
        for algorithm, curve, length in (
                ('ES256', 'P-256', 32),
                ('ES384', 'P-384', 48),
                ('ES512', 'P-521', 66)):
            with self.subTest(algorithm=algorithm):
                _private_key, jwk = generate_dpop_key(algorithm)
                self.assertEqual(jwk['crv'], curve)
                self.assertEqual(len(_b64u_decode(jwk['x'])), length)

    def test_rsa_key(self):
        for algorithm in ('RS256', 'PS256'):
            _private_key, jwk = generate_dpop_key(algorithm)
            self.assertEqual(jwk['kty'], 'RSA')
            self.assertEqual(jwk['e'], 'AQAB')
            self.assertIn('n', jwk)

    def test_unknown_algorithm_rejected(self):
        with self.assertRaises(ValueError):
            generate_dpop_key('HS256')


class ProofCreationTest(TestCase):

    def setUp(self):
        self.private_key, self.jwk = generate_dpop_key()

    def _decode(self, proof, key=None):
        return jwt.decode(
            proof, key or jwt.PyJWK(self.jwk).key,
            algorithms=['ES256'],
            options={'verify_aud': False, 'verify_iss': False})

    def test_proof_header_and_claims(self):
        proof = create_dpop_proof(self.private_key, 'post', TOKEN_URI)
        header = jwt.get_unverified_header(proof)
        self.assertEqual(header['typ'], 'DPoP')
        self.assertEqual(header['alg'], 'ES256')
        self.assertEqual(header['jwk'], self.jwk)

        claims = self._decode(proof)
        self.assertEqual(claims['htm'], 'POST')
        self.assertEqual(claims['htu'], TOKEN_URI)
        self.assertIsInstance(claims['iat'], int)
        self.assertIsInstance(claims['jti'], str)
        self.assertTrue(claims['jti'])
        self.assertNotIn('nonce', claims)
        self.assertNotIn('ath', claims)

    def test_jti_unique_per_proof(self):
        jtis = set()
        for _ in range(5):
            proof = create_dpop_proof(self.private_key, 'POST', TOKEN_URI)
            jtis.add(self._decode(proof)['jti'])
        self.assertEqual(len(jtis), 5)

    def test_explicit_jti_and_iat(self):
        fixed = 1700000000
        proof = create_dpop_proof(
            self.private_key, 'POST', TOKEN_URI,
            jti='fixed-jti', issued_at=fixed)
        claims = self._decode(proof)
        self.assertEqual(claims['jti'], 'fixed-jti')
        self.assertEqual(claims['iat'], fixed)

    def test_nonce_claim(self):
        proof = create_dpop_proof(
            self.private_key, 'POST', TOKEN_URI, nonce='server-nonce')
        self.assertEqual(self._decode(proof)['nonce'], 'server-nonce')

    def test_ath_claim_matches_sha256_hash(self):
        token = 'abc123-access-token'
        proof = create_dpop_proof(
            self.private_key, 'GET', RESOURCE_URI, access_token=token)
        self.assertEqual(self._decode(proof)['ath'],
                         access_token_hash(token))

    def test_additional_claims(self):
        proof = create_dpop_proof(
            self.private_key, 'POST', TOKEN_URI,
            additional_claims={'foo': 'bar'})
        self.assertEqual(self._decode(proof)['foo'], 'bar')

    def test_htu_normalization_strips_query_fragment_and_default_port(self):
        proof = create_dpop_proof(
            self.private_key, 'POST',
            'https://As.Example.com:443/token?drop=1#frag')
        self.assertEqual(self._decode(proof)['htu'],
                         'https://as.example.com/token')

    def test_htu_normalization_keeps_non_default_port_and_path(self):
        self.assertEqual(
            normalize_htu('https://as.example.com:8443/path/?q=1'),
            'https://as.example.com:8443/path/')

    def test_http_default_port_removed(self):
        self.assertEqual(normalize_htu('http://as.example.com:80/p'),
                         'http://as.example.com/p')

    def test_signature_verifies_and_tampering_invalidates(self):
        proof = create_dpop_proof(self.private_key, 'POST', TOKEN_URI)
        # A valid proof verifies against the embedded JWK.
        self._decode(proof)
        # Tamper with the payload segment.
        header, payload, signature = proof.split('.')
        tampered = '.'.join([header, payload + 'x', signature])
        with self.assertRaises(jwt.exceptions.PyJWTError):
            self._decode(tampered)

    def test_algorithm_key_mismatch_rejected(self):
        rsa_key, _ = generate_dpop_key('RS256')
        with self.assertRaises(ValueError):
            create_dpop_proof(rsa_key, 'POST', TOKEN_URI, algorithm='ES256')

    def test_private_jwk_dict_roundtrip(self):
        numbers = self.private_key.private_numbers()
        private_jwk = {
            'kty': 'EC', 'crv': 'P-256',
            'x': self.jwk['x'], 'y': self.jwk['y'],
            'd': base64url_encode(
                numbers.private_value.to_bytes(32, 'big')),
        }
        proof = create_dpop_proof(private_jwk, 'POST', TOKEN_URI)
        self._decode(proof)
        self.assertIsInstance(self.private_key,
                              ec.EllipticCurvePrivateKey)

    def test_all_advertised_algorithms_are_supported(self):
        for algorithm in DPOP_ALGORITHMS:
            key, _jwk = generate_dpop_key(algorithm)
            proof = create_dpop_proof(key, 'POST', TOKEN_URI,
                                      algorithm=algorithm)
            header = jwt.get_unverified_header(proof)
            self.assertEqual(header['alg'], algorithm)


class ClientIntegrationTest(TestCase):
    """DPoP support on the RFC 6749 Client subclasses."""

    def setUp(self):
        self.private_key, self.jwk = generate_dpop_key()

    def test_client_without_key_emits_no_dpop_header(self):
        client = BackendApplicationClient('c1')
        _url, headers, _body = client.prepare_token_request(TOKEN_URI)
        self.assertNotIn('DPoP', headers)
        self.assertIsNone(client.dpop_public_jwk)

    def test_token_request_carries_valid_proof_header(self):
        client = BackendApplicationClient('c1',
                                          dpop_private_key=self.private_key)
        _url, headers, _body = client.prepare_token_request(TOKEN_URI)
        self.assertIn('DPoP', headers)
        self.assertEqual(headers['Content-Type'],
                         'application/x-www-form-urlencoded')

        claims = jwt.decode(
            headers['DPoP'], jwt.PyJWK(self.jwk).key,
            algorithms=['ES256'],
            options={'verify_aud': False, 'verify_iss': False})
        self.assertEqual(claims['htm'], 'POST')
        self.assertEqual(claims['htu'], TOKEN_URI)

    def test_refresh_request_carries_proof(self):
        client = WebApplicationClient('c1',
                                      dpop_private_key=self.private_key)
        _url, headers, _body = client.prepare_refresh_token_request(
            TOKEN_URI, refresh_token='rt')
        self.assertIn('DPoP', headers)

    def test_prepare_dpop_proof_without_key_raises(self):
        client = BackendApplicationClient('c1')
        with self.assertRaises(ValueError):
            client.prepare_dpop_proof(TOKEN_URI)

    def test_nonce_retry_includes_server_nonce(self):
        client = BackendApplicationClient('c1',
                                          dpop_private_key=self.private_key)
        client.update_dpop_nonce('nonce-xyz')
        _, headers, _ = client.prepare_token_request(TOKEN_URI)
        claims = jwt.decode(
            headers['DPoP'], jwt.PyJWK(self.jwk).key,
            algorithms=['ES256'],
            options={'verify_aud': False, 'verify_iss': False})
        self.assertEqual(claims['nonce'], 'nonce-xyz')

    def test_add_token_uses_dpop_scheme_with_ath_bound_proof(self):
        client = BackendApplicationClient('c1',
                                          dpop_private_key=self.private_key)
        client.access_token = 'tok-123'
        client.token_type = 'DPoP'
        _uri, headers, _body = client.add_token(RESOURCE_URI)
        self.assertEqual(headers['Authorization'], 'DPoP tok-123')
        claims = jwt.decode(
            headers['DPoP'], jwt.PyJWK(self.jwk).key,
            algorithms=['ES256'],
            options={'verify_aud': False, 'verify_iss': False})
        self.assertEqual(claims['htm'], 'GET')
        self.assertEqual(claims['htu'], RESOURCE_URI)
        self.assertEqual(claims['ath'], access_token_hash('tok-123'))

    def test_add_token_dpop_requires_auth_header_placement(self):
        client = BackendApplicationClient('c1',
                                          dpop_private_key=self.private_key)
        client.access_token = 'tok'
        client.token_type = 'DPoP'
        with self.assertRaises(ValueError):
            client.add_token(RESOURCE_URI, token_placement='query')

    def test_form_headers_are_not_mutated_between_requests(self):
        client = BackendApplicationClient('c1',
                                          dpop_private_key=self.private_key)
        client.prepare_token_request(TOKEN_URI)
        self.assertNotIn('DPoP', FORM_ENC_HEADERS)


class ReplayCacheTest(TestCase):

    def test_first_seen_accepted_duplicate_rejected(self):
        cache = InMemoryDPoPReplayCache()
        self.assertTrue(cache.add_if_absent('jti-1'))
        self.assertFalse(cache.add_if_absent('jti-1'))
        self.assertTrue(cache.add_if_absent('jti-2'))

    def test_ttl_expiry(self):
        cache = InMemoryDPoPReplayCache()
        now = time.time()
        self.assertTrue(cache.add_if_absent('jti-1', expires_at=now - 1))
        # Expired entry is pruned on the next write and can be reused.
        self.assertTrue(cache.add_if_absent('jti-2', expires_at=now + 100))
        self.assertTrue(cache.add_if_absent('jti-1', expires_at=now + 100))

    def test_max_entries_bounded(self):
        cache = InMemoryDPoPReplayCache(max_entries=2)
        cache.add_if_absent('a')
        cache.add_if_absent('b')
        cache.add_if_absent('c')
        self.assertEqual(len(cache._seen), 2)

    def test_request_slots_default_to_none(self):
        request = Request(TOKEN_URI, http_method='POST')
        self.assertIsNone(request.dpop_jwk)
        self.assertIsNone(request.dpop_jkt)
        self.assertIsNone(request.dpop_claims)
