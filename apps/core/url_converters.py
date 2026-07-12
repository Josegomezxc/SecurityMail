
from .url_signer import encode_id, decode_id


class SignedIdConverter:

    regex = r'[A-Za-z0-9:_\-=]+'

    def to_python(self, value):
        try:
            return decode_id(value)
        except ValueError:

            raise

    def to_url(self, value):
        return encode_id(value)
