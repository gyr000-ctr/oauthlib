"""Unit tests for the RFC 8705 mutual-TLS primitives.

Covers thumbprint calculation, certificate parsing (cryptography objects,
PEM/DER bytes and the ssl-style dict form), DN/SAN comparison and the
distinct error classes required by the task.

Certificate fixtures are generated in ``conftest.py`` and exposed on each
test instance through an autouse fixture (unittest.TestCase methods cannot
receive pytest fixtures as direct arguments).
"""
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from oauthlib.common import Request
from oauthlib.oauth2.rfc8705 import (
    MtlsEndpointMixin,
    calculate_x5t_s256,
    get_client_certificate,
)
from oauthlib.oauth2.rfc8705.errors import (
    InvalidClientCertificateError,
    InvalidTokenCertificateBindingError,
    MismatchingCertificateSubjectError,
    MismatchingCertificateThumbprintError,
    MissingClientCertificateError,
    MissingClientCertificateRegistrationError,
    UntrustedClientCertificateError,
)
from oauthlib.oauth2.rfc8705.mtls import (
    load_certificate,
    normalize_dn,
    parse_dn_string,
    san_name_matches,
)

from tests.unittest import TestCase


class ThumbprintTest(TestCase):

    def test_x5t_s256_matches_manual_hash(self):
        cert, _ = self.client_cert
        der = cert.public_bytes(Encoding.DER)
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(der).digest()).rstrip(b'=').decode('ascii')
        self.assertEqual(calculate_x5t_s256(cert), expected)

    def test_x5t_s256_from_pem_and_der_equivalent(self):
        cert, _ = self.client_cert
        self.assertEqual(calculate_x5t_s256(cert),
                         calculate_x5t_s256(self.cert_pem))
        self.assertEqual(calculate_x5t_s256(cert),
                         calculate_x5t_s256(self.cert_der))

    def test_x5t_s256_has_no_padding(self):
        cert, _ = self.client_cert
        self.assertNotIn('=', calculate_x5t_s256(cert))

    def test_distinct_certificates_distinct_thumbprints(self):
        self.assertNotEqual(self.client_thumbprint, self.other_thumbprint)

    def test_invalid_certificate_raises_specific_error(self):
        bad_pem = (b'-----BEGIN CERTIFICATE-----\n'
                   b'not-valid-base64!!!\n'
                   b'-----END CERTIFICATE-----\n')
        with self.assertRaises(InvalidClientCertificateError) as ctx:
            calculate_x5t_s256(bad_pem)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.error, 'invalid_client')

    def test_load_certificate_rejects_garbage_der(self):
        with self.assertRaises(InvalidClientCertificateError):
            load_certificate(b'not a certificate at all')

    def test_load_certificate_accepts_ssl_dict(self):
        peercert = {
            'subject': ((('C', 'US'),), (('O', 'Example Org'),),
                        (('CN', 'client.example'),)),
            'subjectAltName': (('DNS', 'client.example'),),
        }
        parsed = load_certificate(peercert)
        self.assertEqual(parsed.subject_dn['CN'], 'client.example')
        self.assertIn(('DNS', 'client.example'), parsed.sans)


class CertificateExtractionTest(TestCase):

    def test_extract_from_request_attribute(self):
        cert, _ = self.client_cert
        request = Request('https://as.example/token',
                          headers={}, body='')
        request.client_cert = cert
        self.assertIs(get_client_certificate(request), cert)

    def test_extract_from_header_pem(self):
        request = Request(
            'https://as.example/token',
            headers={'X-SSL-CERT': self.cert_pem.decode('ascii')},
            body='',
        )
        extracted = get_client_certificate(request)
        self.assertEqual(calculate_x5t_s256(extracted),
                         calculate_x5t_s256(self.cert_pem))

    def test_extract_from_header_flattened(self):
        # Some proxies strip newlines and PEM markers, leaving a single
        # line of base64.
        body = ''.join(
            line for line in self.cert_pem.decode('ascii').splitlines()
            if 'CERTIFICATE' not in line
        ).replace('\n', '')
        request = Request(
            'https://as.example/token',
            headers={'X-Client-Cert': body},
            body='',
        )
        extracted = get_client_certificate(request)
        self.assertEqual(calculate_x5t_s256(extracted),
                         calculate_x5t_s256(self.cert_pem))

    def test_missing_certificate_returns_none(self):
        request = Request('https://as.example/token', headers={}, body='')
        self.assertIsNone(get_client_certificate(request))


class DnNormalizationTest(TestCase):

    def test_dict_round_trip(self):
        dn = {'CN': 'client.example', 'O': 'Example Org'}
        self.assertEqual(normalize_dn(dn),
                         {'CN': 'client.example', 'O': 'Example Org'})

    def test_rfc4514_string_parsed_reversed(self):
        # RFC 4514 order: most specific last.
        parsed = dict(parse_dn_string(
            'CN=client.example,O=Example Org,C=US'))
        self.assertEqual(parsed, {
            'CN': 'client.example',
            'O': 'Example Org',
            'C': 'US',
        })

    def test_whitespace_and_case_normalized(self):
        self.assertEqual(
            normalize_dn({'cn': '  client.example  '}),
            normalize_dn({'CN': 'client.example'}),
        )

    def test_dn_inequality(self):
        self.assertNotEqual(
            normalize_dn({'CN': 'client.example'}),
            normalize_dn({'CN': 'other.example'}),
        )


class SanComparisonTest(TestCase):

    def test_dns_case_insensitive(self):
        self.assertTrue(san_name_matches(
            ('DNS', 'Client.Example'), ('DNS', 'client.example')))

    def test_dns_type_mismatch(self):
        self.assertFalse(san_name_matches(
            ('DNS', 'client.example'), ('URI', 'client.example')))

    def test_ip_address_comparison(self):
        self.assertTrue(san_name_matches(
            ('IP Address', '203.0.113.7'),
            ('IP Address', '203.0.113.7'),
        ))

    def test_ip_address_mismatch(self):
        self.assertFalse(san_name_matches(
            ('IP Address', '203.0.113.7'),
            ('IP Address', '198.51.100.9'),
        ))


class _StubClient:

    def __init__(self, client_id='mocked'):
        self.client_id = client_id


class _StubValidator:
    """Validator recording which registration data is returned."""

    def __init__(self, registration=None, client=None):
        self._registration = registration
        self._client = client or _StubClient()

    def authenticate_client_id(self, client_id, request):
        request.client = self._client
        return True

    def get_client_from_client_certificate(self, request):
        request.client = self._client
        return self._client

    def get_client_certificate_registration(self, client_id, request):
        return self._registration


class MtlsAuthenticationFlowTest(TestCase):

    def _request(self, cert, verify=None, client_id='mocked'):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if verify is not None:
            headers['X-SSL-Client-Verify'] = verify
        request = Request(
            'https://as.example/token',
            body='grant_type=client_credentials&client_id=' + client_id,
            headers=headers,
        )
        request.client_cert = cert
        return request

    def _mixin(self, registration=None):
        mixin = MtlsEndpointMixin()
        mixin.request_validator = _StubValidator(registration=registration)
        return mixin

    def test_missing_certificate_raises_distinct_error(self):
        mixin = self._mixin()
        request = Request('https://as.example/token', body='', headers={})
        with self.assertRaises(MissingClientCertificateError) as ctx:
            mixin.authenticate_mtls_client(request)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_untrusted_chain_separate_from_subject_mismatch(self):
        mixin = self._mixin(registration={'thumbprint': 'whatever'})
        request = self._request(self.client_cert[0], verify='FAILED')
        with self.assertRaises(UntrustedClientCertificateError) as ctx:
            mixin.authenticate_mtls_client(request)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn('chain', ctx.exception.description.lower())

    def test_missing_registration_raises_distinct_error(self):
        mixin = self._mixin(registration=None)
        request = self._request(self.client_cert[0])
        with self.assertRaises(
                MissingClientCertificateRegistrationError) as ctx:
            mixin.authenticate_mtls_client(request)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_thumbprint_match_authenticates(self):
        mixin = self._mixin(
            registration={'thumbprint': self.client_thumbprint})
        request = self._request(self.client_cert[0])
        client = mixin.authenticate_mtls_client(request)
        self.assertEqual(client.client_id, 'mocked')
        self.assertEqual(request.client_cert_thumbprint,
                         self.client_thumbprint)

    def test_thumbprint_mismatch_raises_distinct_error(self):
        mixin = self._mixin(
            registration={'thumbprint': self.other_thumbprint})
        request = self._request(self.client_cert[0])
        with self.assertRaises(MismatchingCertificateThumbprintError) as ctx:
            mixin.authenticate_mtls_client(request)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.error, 'invalid_token')

    def test_subject_dn_match_authenticates(self):
        mixin = self._mixin(registration={'subject_dn': {
            'C': 'US',
            'O': 'Example Org',
            'CN': 'client.example',
        }})
        request = self._request(self.client_cert[0])
        client = mixin.authenticate_mtls_client(request)
        self.assertEqual(client.client_id, 'mocked')

    def test_subject_dn_string_form(self):
        mixin = self._mixin(
            registration={'dn': 'CN=client.example,O=Example Org,C=US'})
        request = self._request(self.client_cert[0])
        self.assertEqual(
            mixin.authenticate_mtls_client(request).client_id, 'mocked')

    def test_subject_dn_mismatch_raises_distinct_error(self):
        mixin = self._mixin(
            registration={'subject_dn': {'CN': 'wrong.example'}})
        request = self._request(self.client_cert[0])
        with self.assertRaises(MismatchingCertificateSubjectError) as ctx:
            mixin.authenticate_mtls_client(request)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_san_match_authenticates(self):
        mixin = self._mixin(
            registration={'san': [('DNS', 'alias.example')]})
        request = self._request(self.client_cert[0])
        self.assertEqual(
            mixin.authenticate_mtls_client(request).client_id, 'mocked')

    def test_san_bare_string_form(self):
        mixin = self._mixin(
            registration={'san': ['client.example']})
        request = self._request(self.client_cert[0])
        self.assertEqual(
            mixin.authenticate_mtls_client(request).client_id, 'mocked')

    def test_san_mismatch_raises_subject_error(self):
        mixin = self._mixin(
            registration={'san': [('DNS', 'client.example')]})
        request = self._request(self.other_cert[0])
        with self.assertRaises(MismatchingCertificateSubjectError):
            mixin.authenticate_mtls_client(request)

    def test_ip_san_match(self):
        mixin = self._mixin(
            registration={'san': [('IP Address', '203.0.113.7')]})
        request = self._request(self.mixed_cert[0])
        self.assertEqual(
            mixin.authenticate_mtls_client(request).client_id, 'mocked')

    def test_pem_bytes_certificate_supported(self):
        mixin = self._mixin(
            registration={'thumbprint': self.client_thumbprint})
        request = self._request(self.cert_pem)
        self.assertEqual(
            mixin.authenticate_mtls_client(request).client_id, 'mocked')

    def test_chain_failure_and_subject_failure_are_different(self):
        mixin = self._mixin(
            registration={'subject_dn': {'CN': 'wrong.example'}})

        chain_request = self._request(self.client_cert[0], verify='FAILED')
        with self.assertRaises(UntrustedClientCertificateError):
            mixin.authenticate_mtls_client(chain_request)

        subject_request = self._request(self.client_cert[0])
        with self.assertRaises(MismatchingCertificateSubjectError):
            mixin.authenticate_mtls_client(subject_request)


class TokenBindingVerificationTest(TestCase):

    def _mixin(self):
        mixin = MtlsEndpointMixin()
        mixin.request_validator = _StubValidator()
        return mixin

    def test_unbound_token_passes_through(self):
        mixin = self._mixin()
        request = Request('https://rs.example/resource', headers={})
        self.assertTrue(mixin.verify_token_binding(request, {'sub': 'x'}))

    def test_bound_token_requires_certificate(self):
        mixin = self._mixin()
        request = Request('https://rs.example/resource', headers={})
        with self.assertRaises(InvalidTokenCertificateBindingError):
            mixin.verify_token_binding(
                request,
                {'cnf': {'x5t#S256': 'abc'}},
            )

    def test_bound_token_matching_thumbprint(self):
        mixin = self._mixin()
        request = Request('https://rs.example/resource', headers={})
        request.client_cert = self.client_cert[0]
        self.assertTrue(mixin.verify_token_binding(
            request, {'cnf': {'x5t#S256': self.client_thumbprint}}))

    def test_bound_token_wrong_thumbprint(self):
        mixin = self._mixin()
        request = Request('https://rs.example/resource', headers={})
        request.client_cert = self.client_cert[0]
        with self.assertRaises(MismatchingCertificateThumbprintError):
            mixin.verify_token_binding(
                request, {'cnf': {'x5t#S256': self.other_thumbprint}})

    def test_bound_token_untrusted_chain(self):
        mixin = self._mixin()
        request = Request(
            'https://rs.example/resource',
            headers={'X-SSL-Client-Verify': 'FAILED'},
        )
        request.client_cert = self.client_cert[0]
        with self.assertRaises(UntrustedClientCertificateError):
            mixin.verify_token_binding(
                request, {'cnf': {'x5t#S256': self.client_thumbprint}})


@pytest.fixture(autouse=True)
def _inject_cert_fixtures(request, ca, client_cert, other_cert, mixed_cert,
                          cert_pem, cert_der, other_cert_pem,
                          client_thumbprint, other_thumbprint):
    """Expose session fixtures as attributes for unittest.TestCase."""
    if request.instance is None:
        return
    for name, value in (
        ('ca', ca),
        ('client_cert', client_cert),
        ('other_cert', other_cert),
        ('mixed_cert', mixed_cert),
        ('cert_pem', cert_pem),
        ('cert_der', cert_der),
        ('other_cert_pem', other_cert_pem),
        ('client_thumbprint', client_thumbprint),
        ('other_thumbprint', other_thumbprint),
    ):
        setattr(request.instance, name, value)
