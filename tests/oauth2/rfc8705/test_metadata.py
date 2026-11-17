"""RFC 8705 discovery / metadata and ssl-style certificate tests.

Covers:
- ``mtls_endpoint_aliases`` advertisement and validation in the
  authorization server metadata document (RFC 8705 section 6);
- ``tls_client_auth`` appearing in the supported auth-method lists;
- the ``build_mtls_metadata_aliases`` helper;
- authentication driven by the dict returned by
  ``SSLSocket.getpeercert()`` instead of a cryptography object.
"""
import json
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2 import (
    BackendApplicationServer,
    MetadataEndpoint,
    MtlsEndpointMixin,
    RequestValidator,
)
from oauthlib.oauth2.rfc8705.mtls import build_mtls_metadata_aliases

from tests.unittest import TestCase


class _SimpleValidator(RequestValidator):

    def get_client_certificate_registration(self, client_id, request):
        return getattr(self, 'registration', None)

    def authenticate_client_id(self, client_id, request):
        request.client = mock.MagicMock(client_id='mocked')
        return True

    def get_client_from_client_certificate(self, request):
        request.client = mock.MagicMock(client_id='mocked')
        return request.client


class MetadataMtlsTest(TestCase):

    def _endpoint(self, mtls_enabled, extra_claims=None):
        validator = mock.MagicMock(spec=RequestValidator)
        server = BackendApplicationServer(validator, mtls_enabled=mtls_enabled)
        claims = {
            'issuer': 'https://as.example',
            'token_endpoint': 'https://as.example/token',
            'revocation_endpoint': 'https://as.example/revoke',
            'introspection_endpoint': 'https://as.example/introspect',
        }
        if extra_claims:
            claims.update(extra_claims)
        return MetadataEndpoint([server], claims=claims)

    def test_tls_client_auth_advertised_when_enabled(self):
        endpoint = self._endpoint(True)
        methods = endpoint.claims['token_endpoint_auth_methods_supported']
        self.assertIn('tls_client_auth', methods)
        self.assertIn('client_secret_basic', methods)
        self.assertIn('client_secret_post', methods)

    def test_tls_client_auth_absent_when_disabled(self):
        endpoint = self._endpoint(False)
        methods = endpoint.claims['token_endpoint_auth_methods_supported']
        self.assertNotIn('tls_client_auth', methods)

    def test_mtls_endpoint_aliases_preserved(self):
        aliases = {
            'token_endpoint': 'https://mtls.as.example/token',
            'revocation_endpoint': 'https://mtls.as.example/revoke',
            'introspection_endpoint': 'https://mtls.as.example/introspect',
        }
        endpoint = self._endpoint(
            True, extra_claims={'mtls_endpoint_aliases': aliases})
        self.assertEqual(
            endpoint.claims['mtls_endpoint_aliases']['token_endpoint'],
            'https://mtls.as.example/token',
        )
        # Auth-method lists inside the aliases include tls_client_auth.
        alias_claims = endpoint.claims['mtls_endpoint_aliases']
        self.assertIn(
            'tls_client_auth',
            alias_claims['token_endpoint_auth_methods_supported'],
        )

    def test_invalid_alias_raises(self):
        with self.assertRaises(ValueError):
            self._endpoint(
                True,
                extra_claims={
                    'mtls_endpoint_aliases': {
                        'token_endpoint': 'not-an-url',
                    },
                },
            )

    def test_metadata_response_serializes_aliases(self):
        aliases = {
            'token_endpoint': 'https://mtls.as.example/token',
        }
        endpoint = self._endpoint(
            True, extra_claims={'mtls_endpoint_aliases': aliases})
        _h, body, status = endpoint.create_metadata_response(
            'https://as.example/.well-known/oauth-authorization-server')
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(
            payload['mtls_endpoint_aliases']['token_endpoint'],
            'https://mtls.as.example/token',
        )

    def test_build_mtls_metadata_aliases_helper(self):
        base = {
            'token_endpoint_auth_methods_supported':
                ['client_secret_basic'],
        }
        aliases = build_mtls_metadata_aliases(
            {'token_endpoint': 'https://mtls.as.example/token'},
            base,
        )
        self.assertEqual(aliases['token_endpoint'],
                         'https://mtls.as.example/token')
        self.assertIn(
            'tls_client_auth',
            aliases['token_endpoint_auth_methods_supported'],
        )

    def test_build_aliases_skips_unknown_endpoint(self):
        aliases = build_mtls_metadata_aliases(
            {'bogus_endpoint': 'https://mtls.as.example/bogus'}, {})
        self.assertNotIn('bogus_endpoint', aliases)


class SslDictCertificateTest(TestCase):
    """Certificates as produced by ssl.SSLSocket.getpeercert()."""

    def test_authenticate_with_ssl_peercert_dict(self):
        validator = _SimpleValidator()
        validator.registration = {
            'subject_dn': {
                'C': 'US', 'O': 'Example Org',
                'CN': 'client.example',
            },
        }
        peercert = {
            'subject': (
                (('C', 'US'),),
                (('O', 'Example Org'),),
                (('CN', 'client.example'),),
            ),
            'subjectAltName': (('DNS', 'client.example'),),
        }
        mixin = MtlsEndpointMixin()
        mixin.request_validator = validator
        request = Request(
            'https://as.example/token',
            body='grant_type=client_credentials',
            headers={},
        )
        request.client_cert = peercert
        client = mixin.authenticate_mtls_client(request)
        self.assertEqual(client.client_id, 'mocked')

    def test_ssl_dict_san_only_registration(self):
        validator = _SimpleValidator()
        validator.registration = {
            'san': [('DNS', 'alias.example')],
        }
        peercert = {
            'subject': ((('CN', 'client.example'),),),
            'subjectAltName': (
                ('DNS', 'client.example'),
                ('DNS', 'alias.example'),
            ),
        }
        mixin = MtlsEndpointMixin()
        mixin.request_validator = validator
        request = Request('https://as.example/token', body='', headers={})
        request.client_cert = peercert
        self.assertEqual(
            mixin.authenticate_mtls_client(request).client_id, 'mocked')
