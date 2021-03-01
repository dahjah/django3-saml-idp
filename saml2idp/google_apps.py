from __future__ import absolute_import, print_function, unicode_literals

import six

from . import (
    base,
    codex,
    exceptions,
    xml_render
)

class Processor(base.Processor):
    """
    Google-specific SAML 2.0 AuthnRequest to Response Handler Processor.
    """
    def _decode_request(self):
        """
        Decodes request using both Base64 and Zipping.
        On successful return, self._request_xml will be a Unicode XML string.
        """
        xml_bytes = codex.decode_base64_and_inflate(self._saml_request)
        # We need to set self._request_xml to Unicode
        self._request_xml = xml_bytes.decode('utf8')

    def _validate_request(self):
        """
        Validates the _saml_request. Sub-classes should override this and
        throw an Exception if the validation does not succeed.
        """
        super(Processor, self)._validate_request()
        if not '.google.com/a/' in self._request_params['ACS_URL']:
            raise exceptions.CannotHandleAssertion('AssertionConsumerService is not a Google Apps URL.')

    def _format_assertion(self):
        self._assertion_xml = xml_render.get_assertion_googleapps_xml(self._assertion_params, signed=True)
