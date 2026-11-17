"""
oauthlib.oauth2.rfc8705._crypto
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Thin, optional-dependency boundary around the ``cryptography`` package.

RFC 8705 support itself only needs the standard library (hashlib,
base64, ipaddress). Parsing PEM/DER certificates and reading X.509
attributes does require an ASN.1 implementation, which ``cryptography``
provides when installed. Every import of that package lives in this
module so the rest of the package stays dependency-free.
"""
try:
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509 import (
        DNSName,
        IPAddress,
        RFC822Name,
        SubjectAlternativeName,
        UniformResourceIdentifier,
    )
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover - exercised only without the dep
    _x509 = None
    Encoding = None
    DNSName = IPAddress = RFC822Name = None
    SubjectAlternativeName = UniformResourceIdentifier = None
    NameOID = None


def cryptography_available():
    """Return whether the optional cryptography package is importable."""
    return _x509 is not None


def certificate_public_der(certificate):
    """Return the DER encoding of a cryptography ``Certificate``."""
    return certificate.public_bytes(Encoding.DER)


def load_pem_certificate(data):
    return _x509.load_pem_x509_certificate(data)


def load_der_certificate(data):
    return _x509.load_der_x509_certificate(data)


def parse_certificate_attributes(cert):
    """Extract subject DN attributes and SAN entries from a certificate.

    :returns: ``(subject_dict, san_list)`` where *subject_dict* maps RDN
        attribute names to values and *san_list* contains
        ``(type_name, value)`` tuples.
    """
    oid_names = {
        NameOID.COMMON_NAME: 'CN',
        NameOID.COUNTRY_NAME: 'C',
        NameOID.LOCALITY_NAME: 'L',
        NameOID.STATE_OR_PROVINCE_NAME: 'ST',
        NameOID.ORGANIZATION_NAME: 'O',
        NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
        NameOID.EMAIL_ADDRESS: 'emailAddress',
        NameOID.SERIAL_NUMBER: 'serialNumber',
    }
    subject = {}
    for attribute in cert.subject:
        name = oid_names.get(attribute.oid, attribute.oid.dotted_string)
        subject.setdefault(name, attribute.value)

    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_class(
            SubjectAlternativeName)
    except _x509.ExtensionNotFound:
        san_ext = None
    if san_ext is not None:
        for entry in san_ext.value:
            if isinstance(entry, DNSName):
                sans.append(('DNS', entry.value))
            elif isinstance(entry, IPAddress):
                sans.append(('IP Address', str(entry.value)))
            elif isinstance(entry, RFC822Name):
                sans.append(('email', entry.value))
            elif isinstance(entry, UniformResourceIdentifier):
                sans.append(('URI', entry.value))
    return subject, sans
