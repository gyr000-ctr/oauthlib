"""
oauthlib.oauth2.rfc9449
~~~~~~~~~~~~~~~~~~~~~~~

Implementation of `RFC 9449`_: OAuth 2.0 Demonstrating Proof of Possession
(DPoP).

Client side::

    from oauthlib.oauth2.rfc9449 import generate_dpop_key, create_dpop_proof

    private_key, public_jwk = generate_dpop_key()
    proof = create_dpop_proof(private_key, 'POST', 'https://as.example/token')

Server side::

    from oauthlib.oauth2.rfc9449 import DPoPProtectedToken, enable_dpop

    validator = enable_dpop(server)

.. _`RFC 9449`: https://www.rfc-editor.org/rfc/rfc9449
"""
from .client import (
    DPOP_ALGORITHMS, DEFAULT_ACCEPTED_ALGORITHMS,
    access_token_hash, create_dpop_proof, generate_dpop_key,
    jwk_thumbprint, normalize_htu,
    public_jwk_from_private_key,
)
from .errors import (
    DPoPError, DPoPReplayError, InvalidDPoPProofError,
    InvalidDPoPTokenError, MissingDPoPProofError, UseDPoPNonceError,
    UseDPoPNonceResourceError,
)
from .server import (
    DPoPProtectedToken, DPoPProofValidator, DPoPReplayCache,
    InMemoryDPoPReplayCache, enable_dpop,
)

__all__ = [
    'DEFAULT_ACCEPTED_ALGORITHMS',
    'DPOP_ALGORITHMS',
    'DPoPError',
    'DPoPProofValidator',
    'DPoPProtectedToken',
    'DPoPReplayCache',
    'DPoPReplayError',
    'InMemoryDPoPReplayCache',
    'InvalidDPoPProofError',
    'InvalidDPoPTokenError',
    'MissingDPoPProofError',
    'UseDPoPNonceError',
    'UseDPoPNonceResourceError',
    'access_token_hash',
    'create_dpop_proof',
    'enable_dpop',
    'generate_dpop_key',
    'jwk_thumbprint',
    'normalize_htu',
    'public_jwk_from_private_key',
]
