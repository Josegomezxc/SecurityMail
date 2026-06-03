"""
Códigos de verificación por correo para flujos sobre Users que YA EXISTEN.

NOTA IMPORTANTE: este módulo NO se usa para verificar el registro.
El registro usa `pending_registration_service` (los datos viven en
`PendingRegistration` y el User se crea recién al verificar el código,
para evitar llenar `auth_user` con cuentas inactivas).

Acá viven los códigos para acciones sensibles sobre usuarios reales:
  - create_verification_code(user, purpose='delete_account')
  - verify_deletion_code(user, code) → eliminar cuenta
  - can_resend(user, purpose=...)    → cooldown

Las helpers `cleanup_abandoned_registrations`, `verify_code` y
`get_valid_code_by_token` quedan disponibles solo por retro-compat con
datos legacy y NO se usan en las vistas actuales.
"""
import secrets
from datetime import timedelta
from typing import Optional, Tuple

from django.contrib.auth.models import User
from django.utils import timezone

from apps.accounts.models import EmailVerificationCode


# ── Configuración ────────────────────────────────────────────────────
CODE_VALIDITY_MINUTES   = 15
TOKEN_BYTES             = 32   # → 43 chars en base64-url
RESEND_COOLDOWN_SECS    = 60   # mínimo entre reenvíos del mismo usuario
MAX_CODES_PER_HOUR      = 6    # rate limit anti spam
ABANDONED_AFTER_MINUTES = 30   # tras esto, borramos la cuenta no verificada


def _generate_code() -> str:
    """Devuelve un string de 6 dígitos aleatorios usando RNG criptográfico."""
    # secrets.randbelow es uniforme y criptográficamente seguro
    return f"{secrets.randbelow(1_000_000):06d}"


# Alias retro-compat: código viejo importa `_generate_six_digit_code`.
_generate_six_digit_code = _generate_code


def create_verification_code(user: User, purpose: str = 'register') -> Optional[EmailVerificationCode]:
    """
    Genera un código nuevo y lo guarda. Invalida códigos anteriores del mismo
    usuario PARA EL MISMO PURPOSE (los códigos de registro no se mezclan con
    los de eliminación de cuenta). Devuelve None si excede el rate limit.

    `purpose`: 'register' (default) o 'delete_account'.
    """
    last_hour = timezone.now() - timedelta(hours=1)
    recent_count = EmailVerificationCode.objects.filter(
        user=user, purpose=purpose, created_at__gte=last_hour,
    ).count()
    if recent_count >= MAX_CODES_PER_HOUR:
        return None

    # Marcamos los códigos previos no usados como "usados" para invalidarlos
    # (solo del mismo purpose — no afectamos códigos de otro flujo).
    EmailVerificationCode.objects.filter(
        user=user, purpose=purpose, used_at__isnull=True,
    ).update(used_at=timezone.now())

    # Los códigos de eliminación expiran más rápido (más sensible)
    validity = 10 if purpose == 'delete_account' else CODE_VALIDITY_MINUTES

    return EmailVerificationCode.objects.create(
        user=user,
        purpose=purpose,
        code=_generate_code(),
        token=secrets.token_urlsafe(TOKEN_BYTES),
        expires_at=timezone.now() + timedelta(minutes=validity),
    )


def get_valid_code_by_token(token_str: str) -> Optional[EmailVerificationCode]:
    """
    Devuelve el EmailVerificationCode si existe y sigue siendo válido
    (no usado, no expirado, attempts < 5). None en caso contrario.
    """
    if not token_str:
        return None
    try:
        ev = EmailVerificationCode.objects.select_related('user').get(token=token_str)
    except EmailVerificationCode.DoesNotExist:
        return None
    return ev if ev.is_valid else None


def verify_code(token_str: str, code_input: str) -> Tuple[bool, str, Optional[User]]:
    """
    Verifica si el código ingresado por el usuario coincide.

    Devuelve (ok, mensaje_error, user):
      • (True,  '',                user)  → válido. La vista debe activar la cuenta.
      • (False, 'expirado',        None)  → el código expiró
      • (False, 'no_encontrado',   None)  → token inválido
      • (False, 'demasiados',      None)  → demasiados intentos fallidos
      • (False, 'incorrecto',      None)  → código mal escrito (incrementa attempts)
    """
    if not token_str or not code_input:
        return False, 'no_encontrado', None

    try:
        ev = EmailVerificationCode.objects.select_related('user').get(token=token_str)
    except EmailVerificationCode.DoesNotExist:
        return False, 'no_encontrado', None

    if ev.is_used:
        return False, 'no_encontrado', None
    if ev.is_expired:
        return False, 'expirado', None
    if ev.attempts >= 5:
        return False, 'demasiados', None

    code_clean = (code_input or '').strip().replace(' ', '').replace('-', '')
    if code_clean != ev.code:
        ev.attempts += 1
        ev.save(update_fields=['attempts'])
        return False, 'incorrecto', None

    # ¡Éxito! Marca el código como usado.
    ev.mark_used()
    return True, '', ev.user


def cleanup_abandoned_registrations() -> int:
    """
    Borra de la BD las cuentas que nunca completaron la verificación.

    Una cuenta se considera "abandonada" si:
      • is_active = False  (nunca se activó)
      • email_verified = False  (nunca verificó el correo)
      • date_joined es de hace más de ABANDONED_AFTER_MINUTES

    Esto cubre el caso típico: usuario escribe mal su correo, no le llega
    el código, vuelve a registrarse. La cuenta vieja queda como basura
    en la BD; este helper la limpia.

    Se llama automáticamente al entrar a /registro/ para mantener limpio
    el panel de administración. Devuelve cuántas cuentas borró.
    """
    from datetime import timedelta
    cutoff = timezone.now() - timedelta(minutes=ABANDONED_AFTER_MINUTES)

    qs = User.objects.filter(
        is_active=False,
        profile__email_verified=False,
        date_joined__lt=cutoff,
    )
    count = qs.count()
    if count:
        qs.delete()
    return count


def can_resend(user: User, purpose: str = 'register') -> Tuple[bool, int]:
    """
    Devuelve (puede_reenviar, segundos_para_proximo_envio).
    Implementa el cooldown de RESEND_COOLDOWN_SECS entre reenvíos.
    El cooldown es por (user, purpose), así que pedir un código de
    eliminación no afecta el cooldown de un código de registro.
    """
    last = (
        EmailVerificationCode.objects
        .filter(user=user, purpose=purpose)
        .order_by('-created_at')
        .first()
    )
    if last is None:
        return True, 0
    elapsed = (timezone.now() - last.created_at).total_seconds()
    if elapsed >= RESEND_COOLDOWN_SECS:
        return True, 0
    return False, int(RESEND_COOLDOWN_SECS - elapsed)


# ─────────────────────────────────────────────────────────────────────
#  Helpers específicos para CONFIRMAR ELIMINACIÓN DE CUENTA
#  Reusa la misma tabla EmailVerificationCode pero con purpose='delete_account'.
# ─────────────────────────────────────────────────────────────────────

def create_deletion_code(user: User) -> Optional[EmailVerificationCode]:
    """Genera un código de 6 dígitos para confirmar la eliminación de cuenta."""
    return create_verification_code(user, purpose='delete_account')


def verify_deletion_code(user: User, code_input: str) -> Tuple[bool, str]:
    """
    Verifica un código de eliminación contra el ÚLTIMO código vigente
    del usuario con purpose='delete_account'.

    Devuelve (ok, mensaje_error):
      • (True,  '')             → código válido, listo para borrar cuenta
      • (False, 'no_encontrado') → no hay código activo (expiró o nunca se generó)
      • (False, 'expirado')      → el código existe pero ya expiró
      • (False, 'demasiados')    → demasiados intentos fallidos
      • (False, 'incorrecto')    → código mal escrito (incrementa attempts)
    """
    if not code_input:
        return False, 'no_encontrado'

    ev = (
        EmailVerificationCode.objects
        .filter(user=user, purpose='delete_account', used_at__isnull=True)
        .order_by('-created_at')
        .first()
    )
    if ev is None:
        return False, 'no_encontrado'
    if ev.is_expired:
        return False, 'expirado'
    if ev.attempts >= 5:
        return False, 'demasiados'

    code_clean = (code_input or '').strip().replace(' ', '').replace('-', '')
    if code_clean != ev.code:
        ev.attempts += 1
        ev.save(update_fields=['attempts'])
        return False, 'incorrecto'

    ev.mark_used()
    return True, ''


# ─────────────────────────────────────────────────────────────────────
#  Envío del correo con el código
# ─────────────────────────────────────────────────────────────────────

def send_verification_email(user: User, ev: EmailVerificationCode) -> bool:
    """
    Envía el correo HTML con el código de verificación al user.email.
    Usa SendGrid (a través del helper que ya usa el webhook para alertas).
    Devuelve True si se envió, False si falló.
    """
    from django.conf import settings
    from apps.mail.webhook import _send_via_sendgrid

    domain = getattr(settings, 'MAIL_DOMAIN', 'dockershield.lat')
    from_addr = f"DockerShield <noreply@{domain}>"

    html = _build_verification_html(user, ev)
    return _send_via_sendgrid(
        from_addr = from_addr,
        to_email  = user.email,
        subject   = f"Tu código de verificación: {ev.code}",
        html_body = html,
    )


def _build_verification_html(user: User, ev: EmailVerificationCode) -> str:
    """HTML del correo con el código en una caja grande y destacada."""
    from apps.core.services.email_service import get_site_url
    code = ev.code
    minutes = CODE_VALIDITY_MINUTES
    name = user.first_name or user.username or 'usuario'
    logo_url = f"{get_site_url()}/static/core/img/logo.png"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifica tu correo · DockerShield</title>
</head>
<body style="margin:0;padding:0;background:#0d0c1a;font-family:'Helvetica Neue',Arial,sans-serif;-webkit-font-smoothing:antialiased">

<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0c1a;padding:32px 16px">
  <tr>
    <td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:520px">
        <tr>
          <td style="background:#161527;border:1px solid rgba(109,74,255,0.25);border-radius:14px;overflow:hidden">

            <!-- HEADER morado con LOGO REAL -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#6d4aff 0%,#9b6dff 100%)">
              <tr>
                <td style="padding:26px 28px" align="center">
                  <img src="{logo_url}" alt="DockerShield" width="200" style="display:inline-block;height:auto;max-width:200px;border:0;outline:none;text-decoration:none">
                  <div style="color:rgba(255,255,255,0.75);font-size:11.5px;font-family:monospace;letter-spacing:0.1em;margin-top:12px;text-transform:uppercase">Verificación de correo</div>
                </td>
              </tr>
            </table>

            <!-- CUERPO -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:32px 28px 8px">
                  <h1 style="margin:0 0 12px;color:#f0eeff;font-size:18px;font-weight:700;letter-spacing:-0.01em">¡Hola {name}!</h1>
                  <p style="margin:0 0 24px;color:#b8b6cf;font-size:14px;line-height:1.6">
                    Casi terminamos. Para completar tu registro y activar tu cuenta, ingresa este código en la página de verificación:
                  </p>

                  <!-- Caja del código -->
                  <table width="100%" cellpadding="0" cellspacing="0" style="background:#1a1829;border:1px solid rgba(109,74,255,0.4);border-radius:12px;margin-bottom:20px">
                    <tr>
                      <td align="center" style="padding:24px 12px">
                        <div style="font-family:'Courier New',Consolas,monospace;font-size:36px;font-weight:800;color:#a78bfa;letter-spacing:0.4em;text-align:center">{code}</div>
                      </td>
                    </tr>
                  </table>

                  <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.22);border-radius:9px;margin-bottom:20px">
                    <tr>
                      <td style="padding:12px 14px">
                        <span style="color:#fbbf24;font-size:12.5px;line-height:1.5">
                          &#9888; Este código expira en <strong>{minutes} minutos</strong>.
                          Solo se usa una vez.
                        </span>
                      </td>
                    </tr>
                  </table>

                  <p style="margin:0 0 16px;color:#7d7a96;font-size:12px;line-height:1.6">
                    Si tú no creaste esta cuenta, puedes ignorar este correo — sin verificar el código, la cuenta no se activa.
                  </p>
                </td>
              </tr>
            </table>

            <!-- FOOTER -->
            <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid rgba(255,255,255,0.05);background:#08070f">
              <tr>
                <td style="padding:14px 28px">
                  <span style="font-size:11px;color:#5e5b75;font-family:monospace">&copy; DockerShield &middot; correo automático</span>
                </td>
              </tr>
            </table>

          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

</body>
</html>"""
