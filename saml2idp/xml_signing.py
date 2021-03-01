# -*- coding: utf-8 -*-
"""
Signing code goes here.
"""
from __future__ import absolute_import, print_function, unicode_literals
import hashlib
import string

import M2Crypto
import six

from . import saml2idp_metadata as smd
from .codex import nice64
from .xml_templates import SIGNED_INFO, SIGNATURE
from .logging import get_saml_logger

logger = get_saml_logger()


def load_certificate(config):
    if smd.CERTIFICATE_DATA in config:
        return config.get(smd.CERTIFICATE_DATA, '')

    certificate_filename = config.get(smd.CERTIFICATE_FILENAME)
    logger.info('Using certificate file: ' + certificate_filename)

    certificate = M2Crypto.X509.load_cert(certificate_filename)

    # as_pem returns base64 text as bytes, so we can safely decode it
    # as ascii.
    pem = certificate.as_pem().decode('ascii')
    return ''.join(pem.split('\n')[1:-2])


def load_private_key(config):
    private_key_data = config.get(smd.PRIVATE_KEY_DATA)

    if private_key_data:
        return M2Crypto.EVP.load_key_string(private_key_data)

    private_key_file = config.get(smd.PRIVATE_KEY_FILENAME)
    logger.info('Using private key file: {}'.format(private_key_file))

    # The filename need to be encoded because it is using a C extension under
    # the hood which means it expects a 'const char*' type and will fail with
    # unencoded unicode string.
    return M2Crypto.EVP.load_key(private_key_file.encode('utf-8'))


def sign_with_rsa(private_key, data):
    """
    Sign the given sequence of bytes with the private key.
    If 'data' is unicode, it's encoded as utf8 before signing.
    """
    private_key.sign_init()
    if isinstance(data, six.text_type):
        private_key.sign_update(data.encode('utf8'))
    else:
        private_key.sign_update(data)

    return nice64(private_key.sign_final())


def get_signature_xml(subject, reference_uri):
    """
    Returns XML Signature for subject.
    """
    logger.debug('get_signature_xml - Begin.')
    config = smd.SAML2IDP_CONFIG

    private_key = load_private_key(config)
    certificate = load_certificate(config)

    logger.debug('Subject: ' + subject)

    # Hash the subject; we expect that to be a Unicode
    # string, but we'll handle either bytes or Unicode.
    subject_hash = hashlib.sha1()
    if isinstance(subject, six.text_type):
        subject_hash.update(subject.encode('utf8'))
    else:
        subject_hash.update(subject)

    subject_digest = nice64(subject_hash.digest())
    logger.debug('Subject digest: ' + subject_digest)

    # Create signed_info.
    signed_info = string.Template(SIGNED_INFO).substitute({
        'REFERENCE_URI': reference_uri,
        'SUBJECT_DIGEST': subject_digest,
        })
    logger.debug('SignedInfo XML: ' + signed_info)

    rsa_signature = sign_with_rsa(private_key, signed_info)
    logger.debug('RSA Signature: ' + rsa_signature)

    # Put the signed_info and rsa_signature into the XML signature.
    signed_info_short = signed_info.replace(' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', '')
    signature_xml = string.Template(SIGNATURE).substitute({
        'RSA_SIGNATURE': rsa_signature,
        'SIGNED_INFO': signed_info_short,
        'CERTIFICATE': certificate,
        })
    logger.info('Signature XML: ' + signature_xml)
    return signature_xml
