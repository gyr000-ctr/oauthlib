"""End-to-end RFC 8705 tests against the pre-configured OAuth2 servers.

These tests exercise the full request path through the token, introspect
and revocation endpoints and verify that:

1. mutual-TLS client authentication succeeds with a matching registered
   thumbprint or subject DN/SAN, and issued tokens carry the
   ``cnf.x5t#S256`` binding;
2. each failure mode (missing certificate, untrusted chain, DN mismatch,
   thumbprint mismatch, missing registration) produces its own error
   instead of a generic 401;
3. the pre-existing HTTP Basic and POST-body client authentication paths
   behave exactly as before when mTLS is not involved;
4. introspection and revocation share the same mTLS semantics.

The framework integration layer (WSGI/ASGI server or reverse proxy) is
emulated by :class:`CertInjectingServer`, which attaches the handshake
peer certificate to every request as ``request.client_cert`` — the
attribute the RFC 8705 layer reads by convention.
"""
import contextlib
import json
from unittest import mock

import pytest

from oauthlib.common import Request
from oauthlib.oauth2 import (
    BackendApplicationServer,
    CertificateBoundBearerToken,
    InvalidTokenCertificateBindingError,
    LegacyApplicationServer,
    MismatchingCertificateThumbprintError,
    RequestValidator,
    WebApplicationServer,
)
import oauthlib.oauth2.rfc6749.endpoints.introspect as intro_mod
import oauthlib.oauth2.rfc6749.endpoints.revocation as rev_mod
import oauthlib.oauth2.rfc6749.endpoints.token as token_mod

from tests.unittest import TestCase


class MtlsValidator(RequestValidator):
    """Validator with both secret-based and certificate-based auth."""

    def __init__(self, registration, thumbprint_lookup=None):
        self.registration = registration
        self.thumbprint_lookup = dict(thumbprint_lookup or {})
        self.client = mock.MagicMock()
        self.client.client_id = 'mocked'
        self.saved_tokens = []

    # -- regular secret-based authentication (unchanged behavior) --------

    def authenticate_client(self, request):
        auth = request.headers.get('Authorization', '')
        if auth == 'john:doe' or request.client_secret == 'secret':
            request.client = self.client
            return True
        return False

    def authenticate_client_id(self, client_id, request):
        request.client = self.client
        return True

    # -- RFC 8705 hooks ---------------------------------------------------

    def get_client_from_client_certificate(self, request):
        request.client = self.client
        return self.client

    def get_client_certificate_registration(self, client_id, request):
        return self.registration

    def get_token_certificate_binding(self, token, request):
        return self.thumbprint_lookup.get(token)

    # -- plumbing required by the grants ----------------------------------

    def client_authentication_required(self, request):
        return True

    def validate_grant_type(self, client_id, grant_type, client, request):
        return True

    def get_default_scopes(self, client_id, request):
        return ['profile']

    def validate_scopes(self, client_id, scopes, client, request):
        return True

    def save_bearer_token(self, token, request):
        self.saved_tokens.append(dict(token))

    def validate_bearer_token(self, token, scopes, request):
        request.token_claims = {
            'cnf': {'x5t#S256': self.thumbprint_lookup.get(token)}}
        return token in self.thumbprint_lookup

    def introspect_token(self, token, token_type_hint, request):
        if token in self.thumbprint_lookup:
            return {'cnf': {'x5t#S256':
                            self.thumbprint_lookup[token]}}
        return None

    def revoke_token(self, token, token_type_hint, request):
        self.thumbprint_lookup.pop(token, None)


class CertInjector:
    """Emulates a TLS-terminating framework attaching the peer cert."""

    def __init__(self, cert=None):
        self.cert = cert

    def attach(self, request):
        if self.cert is not None:
            request.client_cert = self.cert


@contextlib.contextmanager
def patched_request_factory(injector):
    """Temporarily make every endpoint ``Request`` carry the peer cert.

    The three endpoint modules each construct an
    :class:`oauthlib.common.Request` locally, so the ``Request`` symbol is
    patched in each module for the duration of one endpoint call. This is
    precisely what a framework integration does (attaching the handshake
    certificate to the request before it reaches the OAuth layer).
    """
    class _PatchedRequest(Request):
        def __init__(self, uri, http_method='GET', body=None,
                     headers=None, encoding='utf-8'):
            super().__init__(uri, http_method, body, headers, encoding)
            injector.attach(self)

    modules = (token_mod, intro_mod, rev_mod)
    originals = {m: m.Request for m in modules}
    for module in modules:
        module.Request = _PatchedRequest
    try:
        yield
    finally:
        for module in modules:
            module.Request = originals[module]


def make_server(server_cls, validator, cert=None, require_mtls=False,
                bound_tokens=False, **kwargs):
    """Build a pre-configured server wired with a cert-injecting hook."""
    token_handler = None
    if bound_tokens:
        token_handler = CertificateBoundBearerToken(validator)
    server = server_cls(
        validator,
        token_generator=(lambda request: 'token-' + request.grant_type),
        mtls_enabled=True,
        require_mtls=require_mtls,
        **kwargs,
    )
    if token_handler is not None:
        server.bearer = token_handler
        # Re-point every grant at the bound token handler.
        server._default_token_type = token_handler
    injector = CertInjector(cert)
    server.cert_injector = injector

    def wrap(original):
        def wrapped(uri, http_method='POST', body=None, headers=None,
                    **kw):
            with patched_request_factory(injector):
                return original(uri, http_method=http_method, body=body,
                                headers=headers, **kw)
        return wrapped

    server.create_token_response = wrap(server.create_token_response)
    server.create_introspect_response = wrap(
        server.create_introspect_response)
    server.create_revocation_response = wrap(
        server.create_revocation_response)
    return server


class TokenEndpointMtlsTest(TestCase):

    def setUp(self):
        self.uri = 'https://as.example/token'
        self.form_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

    def test_thumbprint_authentication_issues_bound_token(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        server = make_server(
            BackendApplicationServer, validator,
            cert=self.client_cert[0], bound_tokens=True)
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers=self.form_headers,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(payload['cnf']['x5t#S256'],
                         self.client_thumbprint)
        self.assertEqual(
            validator.saved_tokens[0]['cnf']['x5t#S256'],
            self.client_thumbprint)

    def test_basic_auth_still_works_alongside_mtls(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        server = make_server(BackendApplicationServer, validator, cert=None)
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'john:doe',
            },
        )
        self.assertEqual(status, 200, body)
        self.assertNotIn('cnf', json.loads(body))

    def test_post_body_auth_still_works_alongside_mtls(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        validator.client.client_id = 'abc'
        server = make_server(BackendApplicationServer, validator, cert=None)
        _h, body, status = server.create_token_response(
            self.uri,
            body=('grant_type=client_credentials'
                  '&client_id=abc&client_secret=secret'),
            headers=self.form_headers,
        )
        self.assertEqual(status, 200, body)

    def test_missing_certificate_when_mtls_required(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        server = make_server(
            BackendApplicationServer, validator, cert=None,
            require_mtls=True)
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertEqual(payload['error'], 'invalid_client')
        self.assertIn('certificate', payload['error_description'])

    def test_missing_certificate_without_require_flag_falls_back(self):
        # mtls_enabled but no cert and no secret: standard invalid_client
        # from the untouched authenticate_client path (returns False).
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        server = make_server(BackendApplicationServer, validator, cert=None)
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers=self.form_headers,
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'invalid_client')

    def test_untrusted_chain_reported_separately(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        server = make_server(
            BackendApplicationServer, validator,
            cert=self.client_cert[0], bound_tokens=True)
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-SSL-Client-Verify': 'FAILED',
            },
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertEqual(payload['error'], 'invalid_client')
        self.assertIn('chain verification failed',
                      payload['error_description'])

    def test_subject_dn_mismatch_reported_separately(self):
        validator = MtlsValidator(
            {'subject_dn': {'CN': 'wrong.example'}})
        server = make_server(
            BackendApplicationServer, validator,
            cert=self.client_cert[0])
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertEqual(payload['error'], 'invalid_client')
        self.assertIn('subject', payload['error_description'].lower())

    def test_thumbprint_mismatch_reported_separately(self):
        validator = MtlsValidator(
            {'thumbprint': self.other_thumbprint})
        server = make_server(
            BackendApplicationServer, validator,
            cert=self.client_cert[0])
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertIn('thumbprint', payload['error_description'].lower())

    def test_missing_registration_reported_separately(self):
        validator = MtlsValidator(None)
        server = make_server(
            BackendApplicationServer, validator,
            cert=self.client_cert[0])
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 400)
        self.assertEqual(payload['error'], 'invalid_client')
        self.assertIn('registered', payload['error_description'])

    def test_dn_path_issues_bound_token(self):
        validator = MtlsValidator({
            'subject_dn': {
                'C': 'US', 'O': 'Example Org',
                'CN': 'client.example',
            },
        })
        server = make_server(
            BackendApplicationServer, validator,
            cert=self.client_cert[0], bound_tokens=True)
        _h, body, status = server.create_token_response(
            self.uri,
            body='grant_type=client_credentials',
            headers=self.form_headers,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            json.loads(body)['cnf']['x5t#S256'],
            self.client_thumbprint,
        )

    def test_mtls_disabled_by_default_keeps_legacy_semantics(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        # mtls_enabled left at its default False.
        server = BackendApplicationServer(validator)
        injector = CertInjector(self.client_cert[0])

        with patched_request_factory(injector):
            _h, body, status = server.create_token_response(
                self.uri,
                body='grant_type=client_credentials',
                headers=self.form_headers,
            )
        # Certificate ignored; secret path fails as it always did.
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'invalid_client')


class IntrospectionRevocationMtlsTest(TestCase):

    def setUp(self):
        self.uri_introspect = 'https://as.example/introspect'
        self.uri_revoke = 'https://as.example/revoke'
        self.form_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

    def _server(self, cert=None, registration=None, require_mtls=False):
        validator = MtlsValidator(
            registration if registration is not None
            else {'thumbprint': self.client_thumbprint},
            thumbprint_lookup={'bound-token': self.client_thumbprint},
        )
        return validator, make_server(
            LegacyApplicationServer, validator, cert=cert,
            require_mtls=require_mtls)

    def test_introspect_with_valid_certificate(self):
        _, server = self._server(cert=self.client_cert[0])
        _h, body, status = server.create_introspect_response(
            self.uri_introspect,
            body='token=bound-token',
            headers=self.form_headers,
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)['active'])

    def test_introspect_without_certificate_when_required(self):
        _, server = self._server(cert=None, require_mtls=True)
        _h, body, status = server.create_introspect_response(
            self.uri_introspect,
            body='token=bound-token',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertEqual(payload['error'], 'invalid_client')
        self.assertIn('certificate', payload['error_description'])

    def test_introspect_thumbprint_mismatch(self):
        validator, server = self._server(cert=self.client_cert[0])
        validator.registration = {'thumbprint': self.other_thumbprint}
        _h, body, status = server.create_introspect_response(
            self.uri_introspect,
            body='token=bound-token',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertIn('thumbprint', payload['error_description'].lower())

    def test_introspect_untrusted_chain(self):
        _, server = self._server(cert=self.client_cert[0])
        _h, body, status = server.create_introspect_response(
            self.uri_introspect,
            body='token=bound-token',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-SSL-Client-Verify': 'FAILED',
            },
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertIn('chain verification failed',
                      payload['error_description'])

    def test_introspect_missing_registration(self):
        validator, server = self._server(cert=self.client_cert[0])
        validator.registration = None
        _h, body, status = server.create_introspect_response(
            self.uri_introspect,
            body='token=bound-token',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 400)
        self.assertIn('registered', payload['error_description'])

    def test_introspect_basic_auth_unchanged(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint},
            thumbprint_lookup={'bound-token': self.client_thumbprint})
        # mTLS not enabled: plain basic-auth path.
        server = LegacyApplicationServer(validator)
        _h, body, status = server.create_introspect_response(
            self.uri_introspect,
            body='token=bound-token',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'john:doe',
            },
        )
        self.assertEqual(status, 200, body)

    def test_revoke_with_valid_certificate(self):
        validator, server = self._server(cert=self.client_cert[0])
        _h, body, status = server.create_revocation_response(
            self.uri_revoke,
            body='token=bound-token',
            headers=self.form_headers,
        )
        self.assertEqual(status, 200, body)
        self.assertNotIn('bound-token', validator.thumbprint_lookup)

    def test_revoke_subject_mismatch(self):
        validator, server = self._server(cert=self.client_cert[0])
        validator.registration = {'subject_dn': {'CN': 'wrong.example'}}
        _h, body, status = server.create_revocation_response(
            self.uri_revoke,
            body='token=bound-token',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertIn('subject', payload['error_description'].lower())

    def test_revoke_missing_registration(self):
        validator, server = self._server(cert=self.client_cert[0])
        validator.registration = None
        _h, body, status = server.create_revocation_response(
            self.uri_revoke,
            body='token=bound-token',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 400)
        self.assertIn('registered', payload['error_description'])

    def test_revoke_basic_auth_unchanged(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint},
            thumbprint_lookup={'bound-token': self.client_thumbprint})
        server = LegacyApplicationServer(validator)
        _h, body, status = server.create_revocation_response(
            self.uri_revoke,
            body='token=bound-token',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'john:doe',
            },
        )
        self.assertEqual(status, 200, body)

    def test_revoke_without_certificate_when_required(self):
        _, server = self._server(cert=None, require_mtls=True)
        _h, body, status = server.create_revocation_response(
            self.uri_revoke,
            body='token=bound-token',
            headers=self.form_headers,
        )
        payload = json.loads(body)
        self.assertEqual(status, 401)
        self.assertEqual(payload['error'], 'invalid_client')
        self.assertIn('certificate', payload['error_description'])

    def test_introspect_and_revoke_share_error_semantics(self):
        # The same malformed registration must surface the same distinct
        # error class on both endpoints.
        validator, server = self._server(cert=self.client_cert[0])
        validator.registration = None
        _h, intro_body, intro_status = \
            server.create_introspect_response(
                self.uri_introspect,
                body='token=bound-token',
                headers=self.form_headers,
            )
        _h, revoke_body, revoke_status = \
            server.create_revocation_response(
                self.uri_revoke,
                body='token=bound-token',
                headers=self.form_headers,
            )
        self.assertEqual(intro_status, revoke_status)
        self.assertEqual(
            json.loads(intro_body)['error'],
            json.loads(revoke_body)['error'],
        )
        self.assertIn(
            'registered',
            json.loads(intro_body)['error_description'],
        )


class CertificateBoundTokenTest(TestCase):

    def _token_handler(self, validator):
        return CertificateBoundBearerToken(validator)

    def _request(self, **extra):
        request = Request('https://rs.example/resource', headers={})
        request.scopes = extra.get('scopes', ['profile'])
        request.extra_credentials = None
        request.client_cert_thumbprint = extra.get('thumbprint')
        request.token = extra.get('token')
        request.client_cert = extra.get('client_cert')
        return request

    def test_create_token_embeds_cnf(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        handler = self._token_handler(validator)
        request = self._request(thumbprint=self.client_thumbprint)
        token = handler.create_token(request, refresh_token=False)
        self.assertEqual(token['cnf']['x5t#S256'],
                         self.client_thumbprint)

    def test_create_token_without_cert_is_unbound(self):
        validator = MtlsValidator(None)
        handler = self._token_handler(validator)
        request = self._request(thumbprint=None)
        token = handler.create_token(request, refresh_token=False)
        self.assertNotIn('cnf', token)

    def test_create_token_derives_thumbprint_from_cert(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        handler = self._token_handler(validator)
        request = self._request(thumbprint=None)
        request.client_cert = self.client_cert[0]
        token = handler.create_token(request, refresh_token=False)
        self.assertEqual(token['cnf']['x5t#S256'],
                         self.client_thumbprint)

    def test_validate_bound_token_with_matching_cert(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint},
            thumbprint_lookup={'abc': self.client_thumbprint})
        handler = self._token_handler(validator)
        request = self._request(token='abc')
        request.client_cert = self.client_cert[0]

        def fake_validate(token, scopes, req):
            req.token_claims = {
                'cnf': {'x5t#S256': self.client_thumbprint}}
            return True

        validator.validate_bearer_token = fake_validate
        self.assertTrue(handler.validate_request(request))

    def test_validate_bound_token_without_cert_raises(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint},
            thumbprint_lookup={'abc': self.client_thumbprint})
        handler = self._token_handler(validator)
        request = self._request(token='abc')
        request.client_cert = None

        def fake_validate(token, scopes, req):
            req.token_claims = {
                'cnf': {'x5t#S256': self.client_thumbprint}}
            return True

        validator.validate_bearer_token = fake_validate
        with self.assertRaises(InvalidTokenCertificateBindingError):
            handler.validate_request(request)

    def test_validate_bound_token_wrong_cert_raises(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint},
            thumbprint_lookup={'abc': self.client_thumbprint})
        handler = self._token_handler(validator)
        request = self._request(token='abc')
        request.client_cert = self.other_cert[0]

        def fake_validate(token, scopes, req):
            req.token_claims = {
                'cnf': {'x5t#S256': self.client_thumbprint}}
            return True

        validator.validate_bearer_token = fake_validate
        with self.assertRaises(MismatchingCertificateThumbprintError):
            handler.validate_request(request)

    def test_validate_unbound_token_unchanged(self):
        validator = MtlsValidator(None)
        handler = self._token_handler(validator)
        request = self._request(token='plain')
        request.client_cert = None

        def fake_validate(token, scopes, req):
            req.token_claims = {}
            return True

        validator.validate_bearer_token = fake_validate
        self.assertTrue(handler.validate_request(request))


class WebServerMtlsTest(TestCase):

    def test_authorization_code_grant_mtls_path(self):
        validator = MtlsValidator(
            {'thumbprint': self.client_thumbprint})
        validator.confirm_redirect_uri = mock.Mock(return_value=True)
        validator.validate_code = mock.Mock(return_value=True)
        validator.invalidate_authorization_code = mock.Mock()
        validator.get_original_scopes = mock.Mock(
            return_value=['profile'])
        server = make_server(
            WebApplicationServer, validator,
            cert=self.client_cert[0], bound_tokens=True)
        _h, body, status = server.create_token_response(
            'https://as.example/token',
            body=('grant_type=authorization_code&code=abc'
                  '&redirect_uri=https://client.example/cb'),
            headers=self.form_headers if hasattr(self, 'form_headers')
            else {'Content-Type': 'application/x-www-form-urlencoded'},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            json.loads(body)['cnf']['x5t#S256'],
            self.client_thumbprint,
        )


@pytest.fixture(autouse=True)
def _inject_cert_fixtures(request, ca, client_cert, other_cert, mixed_cert,
                          cert_pem, cert_der, other_cert_pem,
                          client_thumbprint, other_thumbprint):
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
