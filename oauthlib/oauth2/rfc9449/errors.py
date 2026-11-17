"""
oauthlib.oauth2.rfc9449.errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Errors defined by `RFC 9449`_ (OAuth 2.0 Demonstrating Proof of Possession,
DPoP).

The four failure modes that can occur while validating a DPoP proof at the
token endpoint are kept as *distinct* exception classes even though three of
them share the ``invalid_dpop_proof`` wire error code, so callers can react
differently (e.g. only :class:`UseDPoPNonceError` triggers a nonce retry) and
the conditions are not collapsed into a generic error.

All classes inherit from
:class:`oauthlib.oauth2.rfc6749.errors.OAuth2Error`, so the existing
grant-level ``except errors.OAuth2Error`` blocks serialise them into the
regular JSON error responses without any change and without swallowing them.

.. _`RFC 9449`: https://www.rfc-editor.org/rfc/rfc9449
"""
from ..rfc6749.errors import OAuth2Error


class DPoPError(OAuth2Error):
    """Base class for DPoP failures.

    On the protected resource (HTTP 401) the error is advertised through a
    ``WWW-Authenticate: DPoP`` challenge rather than the Bearer challenge the
    base class emits. At the token endpoint DPoP errors use HTTP 400 and no
    challenge header is returned, exactly like every other token-endpoint
    error in RFC 6749.
    """

    #: Token endpoint failures are HTTP 400 per RFC 9449 Section 5.7;
    #: resource-endpoint failures override this to 401.
    status_code = 400

    #: When non-empty, a ``DPoP-Nonce`` response header carrying this value is
    #: added by the endpoints.
    dpop_nonce = None

    @property
    def headers(self):
        if self.status_code != 401:
            headers = {}
        else:
            authvalues = ['error="{}"'.format(self.error)]
            if self.description:
                authvalues.append(
                    'error_description="{}"'.format(self.description))
            headers = {"WWW-Authenticate": "DPoP " + ", ".join(authvalues)}
        if self.dpop_nonce is not None:
            headers["DPoP-Nonce"] = self.dpop_nonce
        return headers


class InvalidDPoPProofError(DPoPError):
    """The DPoP proof is missing, malformed, signed with an unsupported
    algorithm, has a bad signature, fails the method/URL binding, or is
    outside the accepted ``iat`` window.

    RFC 9449 Section 5.7 error code ``invalid_dpop_proof``.
    """

    error = 'invalid_dpop_proof'
    description = 'The DPoP proof is invalid.'


class MissingDPoPProofError(InvalidDPoPProofError):
    """A DPoP proof was required but no (usable) ``DPoP`` header was sent.

    Distinguishable from :class:`InvalidDPoPProofError` as its own class while
    sharing the ``invalid_dpop_proof`` wire code, per RFC 9449 Section 5.7.
    """

    description = 'Missing DPoP proof.'


class DPoPReplayError(InvalidDPoPProofError):
    """The proof ``jti`` has already been presented.

    Its own class so replay protection failures are distinguishable from
    other malformed proofs; the wire code stays ``invalid_dpop_proof``.
    """

    description = 'The DPoP proof has already been used.'


class UseDPoPNonceError(DPoPError):
    """The server requires a fresh server-provided nonce in the proof.

    RFC 9449 Section 8: the client must retry the same request with the
    ``nonce`` claim taken from the ``DPoP-Nonce`` response header. This is
    the only DPoP failure with the ``use_dpop_nonce`` error code and is a
    regular HTTP 400 at the token endpoint.
    """

    error = 'use_dpop_nonce'
    description = 'Authorization server requires nonce in DPoP proof.'

    def __init__(self, description=None, uri=None, state=None,
                 status_code=None, request=None, nonce=None):
        super().__init__(description=description, uri=uri, state=state,
                         status_code=status_code, request=request)
        self.dpop_nonce = nonce


class InvalidDPoPTokenError(DPoPError):
    """A DPoP-bound access token was presented at a protected resource
    without a valid DPoP proof (or the proof key does not match the token's
    ``cnf`` binding).

    RFC 9449 Section 7.3: resource-server DPoP failures use HTTP 401 with a
    ``WWW-Authenticate: DPoP`` challenge and the RFC 6750-style
    ``invalid_token`` error code.
    """

    error = 'invalid_token'
    status_code = 401
    description = 'The DPoP-bound access token is invalid.'


class UseDPoPNonceResourceError(UseDPoPNonceError, InvalidDPoPTokenError):
    """Nonce challenge returned from a protected resource.

    Combines the ``use_dpop_nonce`` error code with the HTTP 401 /
    ``WWW-Authenticate: DPoP`` treatment required on the resource side
    (RFC 9449 Section 9.2.2).
    """

    description = 'Resource server requires nonce in DPoP proof.'
