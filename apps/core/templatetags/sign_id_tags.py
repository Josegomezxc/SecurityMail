from django import template
from apps.core.url_signer import encode_id

register = template.Library()

@register.filter
def sign_id(value):
    return encode_id(value)
