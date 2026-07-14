
import re
import unicodedata
from typing import List, Optional, Tuple


def _strip_accents(s: str) -> str:

    if not s:
        return ''
    nfd = unicodedata.normalize('NFD', s)
    return ''.join(c for c in nfd if unicodedata.category(c) != 'Mn').lower()


def normalize_whitespace(s: str) -> str:

    if not s:
        return ''
    return re.sub(r'\s+', ' ', s).strip()




USERNAME_MIN_LENGTH = 2
USERNAME_MAX_LENGTH = 30
_USER_HEAD = r"A-Za-zÁÉÍÓÚÜÑáéíóúüñ"
_USER_BODY = r"A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9_\-"
USERNAME_REGEX = re.compile(rf"^[{_USER_HEAD}][{_USER_BODY}]*$")

USERNAME_BLOCKLIST = {
    'admin', 'administrator', 'administrador', 'root', 'test', 'testing',
    'user', 'usuario', 'null', 'undefined', 'none', 'demo', 'guest',
    'invitado', 'anonymous', 'anonimo', 'bot', 'system', 'api', 'www',
    'mail', 'email', 'support', 'soporte', 'help', 'ayuda', 'info',
    'contact', 'contacto', 'dockershield', 'docker', 'shield',
}


def clean_username(raw: str) -> Tuple[str, Optional[str]]:

    if not raw:
        return '', 'El nombre de usuario es obligatorio.'

    user = re.sub(r'\s+', '', raw)
    user = ''.join(c for c in user if c.isprintable())

    if not user:
        return '', 'El nombre de usuario no puede ser solo espacios.'

    if len(user) < USERNAME_MIN_LENGTH:
        return user, f'El nombre de usuario debe tener al menos {USERNAME_MIN_LENGTH} caracteres.'
    if len(user) > USERNAME_MAX_LENGTH:
        return user, f'El nombre de usuario no puede superar {USERNAME_MAX_LENGTH} caracteres.'

    if user.lower() in USERNAME_BLOCKLIST:
        return user, 'Ese nombre de usuario está reservado, elige otro.'

    if not USERNAME_REGEX.match(user):
        return user, 'Solo letras, números, guion bajo (_) y guion medio (-). Debe empezar con una letra.'


    if re.search(r'(.)\1{4,}', user):
        return user, 'El nombre de usuario tiene demasiados caracteres repetidos.'


    if user.isdigit():
        return user, 'El nombre de usuario no puede ser solo números.'

    return user, None



clean_name = clean_username

EMAIL_MAX_LENGTH = 254       
EMAIL_LOCAL_MAX  = 64        
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)


DISPOSABLE_DOMAINS = {
    'tempmail.com', 'mailinator.com', '10minutemail.com', 'guerrillamail.com',
    'throwaway.email', 'trashmail.com', 'yopmail.com', 'sharklasers.com',
    'maildrop.cc', 'getnada.com', 'dispostable.com', 'fakeinbox.com',
    'temp-mail.org', 'mohmal.com', 'tempinbox.com', 'emailondeck.com',
}


def clean_email(raw: str) -> Tuple[str, Optional[str]]:

    if not raw:
        return '', 'El correo electrónico es obligatorio.'

    email = raw.strip().lower()

    if ' ' in email:
        return email, 'El correo no puede contener espacios.'

    if '\n' in email or '\r' in email or '\t' in email:
        return email, 'El correo contiene caracteres no válidos.'

    if len(email) > EMAIL_MAX_LENGTH:
        return email, f'El correo es demasiado largo (máximo {EMAIL_MAX_LENGTH} caracteres).'

    if '@' not in email:
        return email, 'El correo debe incluir un "@" y un dominio válido.'

    local, _, domain = email.partition('@')
    if not local:
        return email, 'Falta la parte antes del "@".'
    if not domain:
        return email, 'Falta el dominio después del "@".'
    if len(local) > EMAIL_LOCAL_MAX:
        return email, 'La parte antes del "@" es demasiado larga.'
    if '.' not in domain:
        return email, 'El dominio del correo no es válido (falta la extensión, ej. .com).'
    if email.count('@') > 1:
        return email, 'El correo tiene más de un "@".'
    if '..' in email:
        return email, 'El correo no puede tener dos puntos seguidos.'
    if email.startswith('.') or email.endswith('.'):
        return email, 'El correo no puede empezar o terminar con un punto.'

    if not EMAIL_REGEX.match(email):
        return email, 'El formato del correo no es válido.'

    if domain in DISPOSABLE_DOMAINS:
        return email, 'No permitimos correos desechables. Usa tu correo real.'

    return email, None


PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128     


COMMON_PASSWORDS = {
    '12345678', '123456789', '1234567890', 'qwertyuiop', 'qwerty123',
    'password', 'password1', 'password12', 'password123', 'admin123',
    'administrator', 'welcome1', 'welcome123', 'letmein1', 'iloveyou',
    '1qaz2wsx', 'qazwsxedc', 'zaq12wsx', 'monkey123', 'dragon123',
    'abcd1234', 'abcdefgh', 'asdfghjk', 'trustno1', 'starwars1',
    'superman1', 'batman123', 'football1', 'baseball1', 'jordan23',
    '11111111', '00000000', 'aaaaaaaa', 'qwerty12', 'changeme1',
}


def validate_password(password: str, email: str = '', name: str = '') -> List[str]:

    errors: List[str] = []

    if not password:
        return ['La contraseña es obligatoria.']

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f'La contraseña debe tener al menos {PASSWORD_MIN_LENGTH} caracteres.')
    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(f'La contraseña no puede superar {PASSWORD_MAX_LENGTH} caracteres.')
    if password != password.strip():
        errors.append('La contraseña no puede empezar ni terminar con espacios.')

    if not re.search(r'[A-ZÁÉÍÓÚÜÑ]', password):
        errors.append('Debe incluir al menos una letra mayúscula.')
    if not re.search(r'[a-záéíóúüñ]', password):
        errors.append('Debe incluir al menos una letra minúscula.')
    if not re.search(r'\d', password):
        errors.append('Debe incluir al menos un número.')
    if not re.search(r'[^A-Za-z0-9ÁÉÍÓÚÜÑáéíóúüñ]', password):
        errors.append('Debe incluir al menos un símbolo (!@#$%&*…).')

    pwd_lower = password.lower()
    if pwd_lower in COMMON_PASSWORDS:
        errors.append('Esta contraseña es demasiado común. Elige una más segura.')
    if re.search(r'(.)\1{5,}', password):
        errors.append('La contraseña tiene demasiados caracteres repetidos seguidos.')

    if re.search(r'(?:abcdef|qwerty|asdfgh|zxcvbn|123456|098765)', pwd_lower):
        errors.append('La contraseña no puede contener secuencias típicas del teclado.')

    if email:
        email_lower = email.lower()
        if pwd_lower == email_lower:
            errors.append('La contraseña no puede ser igual al correo.')
        else:
            local = email_lower.split('@', 1)[0]
            if len(local) >= 4 and local in pwd_lower:
                errors.append('La contraseña no puede contener parte de tu correo.')

    if name:
        pwd_ascii = _strip_accents(password)
        for part in normalize_whitespace(name).split():
            part_ascii = _strip_accents(part)
            if len(part_ascii) >= 4 and part_ascii in pwd_ascii:
                errors.append('La contraseña no puede contener tu nombre.')
                break

    seen = set()
    return [e for e in errors if not (e in seen or seen.add(e))]

def clean_login_identifier(raw: str) -> Tuple[str, Optional[str]]:

    if not raw:
        return '', 'Ingresa tu correo o usuario.'

    ident = raw.strip().lower()

    if len(ident) > EMAIL_MAX_LENGTH:
        return ident, 'El identificador es demasiado largo.'
    if '\n' in ident or '\r' in ident or '\t' in ident:
        return ident, 'El identificador contiene caracteres no válidos.'
    if ' ' in ident:
        return ident, 'No puede contener espacios.'

    return ident, None


def clean_login_password(raw: str) -> Tuple[str, Optional[str]]:

    if raw is None or raw == '':
        return '', 'Ingresa tu contraseña.'
    if len(raw) > PASSWORD_MAX_LENGTH:
        return raw, f'La contraseña es demasiado larga (máx. {PASSWORD_MAX_LENGTH}).'
    return raw, None


def get_client_ip(request) -> str:

    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')
