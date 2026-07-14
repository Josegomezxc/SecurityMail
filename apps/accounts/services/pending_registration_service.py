
from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Optional, Tuple

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.utils import timezone

from apps.accounts.models import PendingRegistration


CODE_VALIDITY_MINUTES   = 15
TOKEN_BYTES             = 32   
RESEND_COOLDOWN_SECS    = 60
MAX_PENDING_PER_HOUR    = 6    
EXPIRED_AFTER_MINUTES   = 60   


def _generate_code() -> str:

    return f"{secrets.randbelow(1_000_000):06d}"


def create_pending_registration(
    email: str, first_name: str, password: str,
) -> Optional[PendingRegistration]:

    email_norm = (email or '').strip().lower()
    if not email_norm:
        return None

    last_hour = timezone.now() - timedelta(hours=1)
    recent = PendingRegistration.objects.filter(
        email__iexact=email_norm, created_at__gte=last_hour,
    ).count()
    if recent >= MAX_PENDING_PER_HOUR:
        return None

    PendingRegistration.objects.filter(
        email__iexact=email_norm, used_at__isnull=True,
    ).update(used_at=timezone.now())

    return PendingRegistration.objects.create(
        email=email_norm,
        first_name=(first_name or '')[:150],
        password_hash=make_password(password),
        code=_generate_code(),
        token=secrets.token_urlsafe(TOKEN_BYTES),
        expires_at=timezone.now() + timedelta(minutes=CODE_VALIDITY_MINUTES),
    )


def get_valid_pending_by_token(token_str: str) -> Optional[PendingRegistration]:

    if not token_str:
        return None
    try:
        pr = PendingRegistration.objects.get(token=token_str)
    except PendingRegistration.DoesNotExist:
        return None
    return pr if pr.is_valid else None


def get_pending_by_token_any(token_str: str) -> Optional[PendingRegistration]:
    if not token_str:
        return None
    try:
        return PendingRegistration.objects.get(token=token_str)
    except PendingRegistration.DoesNotExist:
        return None


def verify_pending_code(
    token_str: str, code_input: str,
) -> Tuple[bool, str, Optional[User]]:

    if not token_str or not code_input:
        return False, 'no_encontrado', None

    try:
        pr = PendingRegistration.objects.get(token=token_str)
    except PendingRegistration.DoesNotExist:
        return False, 'no_encontrado', None

    if pr.is_used:
        return False, 'no_encontrado', None
    if pr.is_expired:
        return False, 'expirado', None
    if pr.attempts >= 5:
        return False, 'demasiados', None

    code_clean = (code_input or '').strip().replace(' ', '').replace('-', '')
    if code_clean != pr.code:
        pr.attempts += 1
        pr.save(update_fields=['attempts'])
        return False, 'incorrecto', None

    if User.objects.filter(email__iexact=pr.email).exists():
        pr.mark_used()
        return False, 'email_tomado', None
    user = User(
        username=pr.email,
        email=pr.email,
        first_name=pr.first_name[:150],
        last_name='',
        is_active=True,
    )
    user.password = pr.password_hash
    user.save()
    from apps.accounts.models import UserProfile
    UserProfile.objects.update_or_create(
        user=user, defaults={'email_verified': True},
    )

    pr.mark_used()
    PendingRegistration.objects.filter(
        email__iexact=pr.email, used_at__isnull=True,
    ).exclude(pk=pr.pk).update(used_at=timezone.now())

    return True, '', user


def can_resend_pending(pr: Optional[PendingRegistration]) -> Tuple[bool, int]:
    if pr is None:
        return False, RESEND_COOLDOWN_SECS
    elapsed = (timezone.now() - pr.created_at).total_seconds()
    if elapsed >= RESEND_COOLDOWN_SECS:
        return True, 0
    return False, int(RESEND_COOLDOWN_SECS - elapsed)


def cleanup_expired_pending_registrations() -> int:

    cutoff = timezone.now() - timedelta(minutes=EXPIRED_AFTER_MINUTES)
    qs = PendingRegistration.objects.filter(created_at__lt=cutoff)
    count = qs.count()
    if count:
        qs.delete()
    return count


def send_pending_registration_email(pr: PendingRegistration) -> bool:
    from django.conf import settings
    from apps.mail.webhook import _send_via_resend

    domain = getattr(settings, 'MAIL_DOMAIN', 'dockershield.lat')
    from_addr = f"DockerShield <noreply@{domain}>"

    html = _build_verification_html(pr)
    return _send_via_resend(
        from_addr = from_addr,
        to_email  = pr.email,
        subject   = f"Tu código de verificación: {pr.code}",
        html_body = html,
    )


def _build_verification_html(pr: PendingRegistration) -> str:
    from apps.core.services.email_service import get_site_url
    code = pr.code
    minutes = CODE_VALIDITY_MINUTES
    name = pr.first_name or 'usuario'
    logo_url = f"{get_site_url()}/static/core/img/logo-purple.png"

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

            <table width="100%" cellpadding="0" cellspacing="0" style="background:#6d4aff">
              <tr>
                <td style="padding:26px 28px" align="center">
                  <img src="{logo_url}" alt="DockerShield" width="200" style="display:inline-block;height:auto;max-width:200px;border:0;outline:none;text-decoration:none">
                  <div style="color:rgba(255,255,255,0.75);font-size:11.5px;font-family:monospace;letter-spacing:0.1em;margin-top:12px;text-transform:uppercase">Verificación de correo</div>
                </td>
              </tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:32px 28px 8px">
                  <h1 style="margin:0 0 12px;color:#f0eeff;font-size:18px;font-weight:700;letter-spacing:-0.01em">¡Hola {name}!</h1>
                  <p style="margin:0 0 24px;color:#b8b6cf;font-size:14px;line-height:1.6">
                    Casi terminamos. Para completar tu registro y activar tu cuenta, ingresa este código en la página de verificación:
                  </p>

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
                          <span style="display:inline-block;width:14px;height:14px;line-height:14px;text-align:center;background-color:#fbbf24;color:#1a1829;font-weight:bold;font-size:11px;border-radius:3px;margin-right:6px">!</span>Este código expira en <strong>{minutes} minutos</strong>.
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
