
from django.core.signing import Signer, BadSignature

_SIGNER = Signer(salt='url-id')

_B36 = '0123456789abcdefghijklmnopqrstuvwxyz'


def _to_b36(n: int) -> str:
    if n == 0:
        return '0'
    out = []
    while n:
        n, r = divmod(n, 36)
        out.append(_B36[r])
    return ''.join(reversed(out))


def encode_id(pk) -> str:

    if pk is None or pk == '':
        return ''
    return _SIGNER.sign(_to_b36(int(pk)))


def decode_id(token: str) -> int:

    try:
        b36 = _SIGNER.unsign(token)
        return int(b36, 36)
    except (BadSignature, ValueError, TypeError):
        raise ValueError('token inválido')
