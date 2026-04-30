"""
Lógica de verificación de correo electrónico al registrarse:
  - create_verification_code(user)  → genera código de 6 dígitos + token URL
  - get_valid_code_by_token(token)  → busca un código vigente
  - verify_code(token, code_input)  → valida e invalida tras el uso
  - send_verification_email(...)    → envía el correo HTML con el código
  - can_resend(user)                → rate limit para reenvíos

Flujo:
  1. Usuario se registra → User(is_active=False) + UserProfile(email_verified=False)
  2. Llamamos a create_verification_code(user) que genera código y token
  3. send_verification_email() manda el correo vía SendGrid
  4. Redirigimos a /verificar-correo/<token>/ con el form
  5. El form usa verify_code() para validar
  6. Si OK: marcamos email_verified=True, is_active=True, login automático
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


def _generate_six_digit_code() -> str:
    """Devuelve un string de 6 dígitos aleatorios usando RNG criptográfico."""
    # secrets.randbelow es uniforme y criptográficamente seguro
    return f"{secrets.randbelow(1_000_000):06d}"


def create_verification_code(user: User) -> Optional[EmailVerificationCode]:
    """
    Genera un código nuevo y lo guarda. Invalida códigos anteriores del mismo
    usuario para que solo el último sea válido. Devuelve None si excede el
    rate limit (anti spam de "reenviar" mil veces).
    """
    last_hour = timezone.now() - timedelta(hours=1)
    recent_count = EmailVerificationCode.objects.filter(
        user=user, created_at__gte=last_hour,
    ).count()
    if recent_count >= MAX_CODES_PER_HOUR:
        return None

    # Marcamos los códigos previos no usados como "usados" para invalidarlos.
    EmailVerificationCode.objects.filter(
        user=user, used_at__isnull=True,
    ).update(used_at=timezone.now())

    return EmailVerificationCode.objects.create(
        user=user,
        code=_generate_six_digit_code(),
        token=secrets.token_urlsafe(TOKEN_BYTES),
        expires_at=timezone.now() + timedelta(minutes=CODE_VALIDITY_MINUTES),
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


def can_resend(user: User) -> Tuple[bool, int]:
    """
    Devuelve (puede_reenviar, segundos_para_proximo_envio).
    Implementa el cooldown de RESEND_COOLDOWN_SECS entre reenvíos.
    """
    last = (
        EmailVerificationCode.objects
        .filter(user=user)
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
    code = ev.code
    minutes = CODE_VALIDITY_MINUTES
    name = user.first_name or user.username or 'usuario'

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

            <!-- HEADER morado -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#6d4aff 0%,#9b6dff 100%)">
              <tr>
                <td style="padding:26px 28px" align="center">
                  <div style="display:inline-block;width:48px;height:48px;background:rgba(255,255,255,0.18);border-radius:12px;text-align:center;line-height:48px;font-size:24px;color:#ffffff">&#128737;</div>
                  <div style="color:#ffffff;font-size:20px;font-weight:800;letter-spacing:-0.01em;margin-top:12px">DockerShield</div>
                  <div style="color:rgba(255,255,255,0.75);font-size:11.5px;font-family:monospace;letter-spacing:0.1em;margin-top:4px;text-transform:uppercase">Verificación de correo</div>
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
