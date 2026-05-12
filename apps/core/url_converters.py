"""
URL converter `sid` — usa apps.core.url_signer para que las URLs muestren
un token firmado opaco en vez del pk entero. Uso:

    path('notificaciones/<sid:pk>/', view, name='notification_detail')

La vista sigue recibiendo `pk` como int. Si el token está manipulado o
es inválido, Django devuelve 404 sin levantar excepción ruidosa.
"""
from .url_signer import encode_id, decode_id


class SignedIdConverter:
    # Mismo set de chars que el output del signer (base36 + ':' + base64-url-safe).
    # Aceptamos también '-' y '_' porque son válidos en el output base64-url-safe
    # de Signer.
    regex = r'[A-Za-z0-9:_\-=]+'

    def to_python(self, value):
        try:
            return decode_id(value)
        except ValueError:
            # Sin esto, Django retornaría 500. Levantando ValueError hacemos
            # que el resolver intente otras rutas o falle en 404 limpio.
            raise

    def to_url(self, value):
        return encode_id(value)
