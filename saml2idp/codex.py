from __future__ import absolute_import, print_function, unicode_literals
# Portions borrowed from:
# http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
import zlib
import base64

import six

def decode_base64_and_inflate( b64string ):
    # b64decode needs a bytes-like object, so
    # we encode any Unicode input.
    if isinstance(b64string, six.text_type):
        b64string = b64string.encode('utf8')
    decoded_data = base64.b64decode( b64string )
    return zlib.decompress( decoded_data , -15)

def deflate_and_base64_encode( string_val ):
    # zlib only works on bytes, so we encode any unicode data.
    if isinstance(string_val, six.text_type):
        string_val = string_val.encode('utf8')
    zlibbed_str = zlib.compress( string_val )
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode( compressed_string )

def nice64(src):
    """
    Returns src base64-encoded and formatted nicely for our XML,
    as Unicode.
    """
    # If src is a Unicode string, we encode it as UTF8.
    if isinstance(src, six.text_type):
        src = src.encode('utf8')
    return base64.b64encode(src).decode('utf8').replace('\n', '')
