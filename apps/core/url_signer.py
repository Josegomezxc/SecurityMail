"""
URL ID signer — convierte enteros (PKs) en tokens opacos firmados y viceversa.

¿Por qué?
  Las URLs como /notificaciones/35/ exponen el id secuencial. Aunque el
  control de acceso ya filtra por `user=request.user`, es feo y permite
  a un atacante enumerar el espacio de ids para perfilar volúmenes.

¿Cómo?
  Codificamos el pk en base36 (corto) y lo firmamos con SECRET_KEY +
  un salt específico. Si alguien cambia un solo carácter del token,
  la firma falla y el converter levanta Resolver404 → 404 limpio.
"""
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
    """Convierte un entero (o str numérico) en un token URL-safe firmado."""
    if pk is None or pk == '':
        return ''
    return _SIGNER.sign(_to_b36(int(pk)))


def decode_id(token: str) -> int:
    """Devuelve el pk original. Lanza ValueError si el token fue manipulado
    o tiene formato inválido — el caller suele convertirlo en 404."""
    try:
        b36 = _SIGNER.unsign(token)
        return int(b36, 36)
    except (BadSignature, ValueError, TypeError):
        raise ValueError('token inválido')
