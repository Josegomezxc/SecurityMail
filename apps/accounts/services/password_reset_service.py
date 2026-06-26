"""
Lógica de recuperación de contraseña:
  - create_token(user, ip)      → genera un token y lo guarda en BD.
  - get_valid_token(token_str)  → valida un token recibido por URL.
  - send_reset_email(user, t)   → envía el correo HTML con el link.
  - invalidate_other_tokens     → marca como usados los demás tokens del user.

Todas las expiraciones están en UTC (USE_TZ=True en settings).
"""
import secrets
from datetime import timedelta
from typing import Optional, Tuple

from django.contrib.auth.models import User
from django.utils import timezone

from apps.accounts.models import PasswordResetToken
from apps.core.services.email_service import send_email, get_site_url


TOKEN_VALIDITY_HOURS = 24
TOKEN_BYTES          = 32  # → 43 caracteres en base64-url

# Rate limit: máximo de tokens que un usuario puede pedir por hora
MAX_TOKENS_PER_HOUR = 5


def create_token(user: User, ip: Optional[str] = None) -> Optional[PasswordResetToken]:
    """
    Genera un token nuevo y lo guarda. Devuelve None si el usuario ha
    superado el rate limit (demasiados tokens en la última hora).
    """
    last_hour = timezone.now() - timedelta(hours=1)
    recent_count = PasswordResetToken.objects.filter(
        user=user, created_at__gte=last_hour,
    ).count()
    if recent_count >= MAX_TOKENS_PER_HOUR:
        return None

    token_str = secrets.token_urlsafe(TOKEN_BYTES)
    return PasswordResetToken.objects.create(
        user=user,
        token=token_str,
        expires_at=timezone.now() + timedelta(hours=TOKEN_VALIDITY_HOURS),
        ip_address=ip,
    )


def get_valid_token(token_str: str) -> Optional[PasswordResetToken]:
    """Devuelve el token si existe y sigue siendo válido. None en caso contrario."""
    if not token_str or len(token_str) > 64:
        return None
    try:
        t = PasswordResetToken.objects.select_related('user').get(token=token_str)
    except PasswordResetToken.DoesNotExist:
        return None
    return t if t.is_valid else None


def invalidate_other_tokens(user: User, except_pk: Optional[int] = None):
    """Marca como usados los demás tokens activos del mismo usuario."""
    qs = PasswordResetToken.objects.filter(user=user, used_at__isnull=True)
    if except_pk is not None:
        qs = qs.exclude(pk=except_pk)
    qs.update(used_at=timezone.now())


def send_reset_email(user: User, token: PasswordResetToken) -> Tuple[bool, str]:
    """Envía el correo HTML con el link de recuperación."""
    base_url  = get_site_url()
    reset_url = f"{base_url}/reset-password/{token.token}/"
    expires   = token.expires_at.strftime('%d/%m/%Y · %H:%M UTC')

    html = _build_reset_email_html(user, reset_url, expires, token.token[:8])
    return send_email(
        to=user.email,
        subject="Recupera tu contraseña — DockerShield",
        html=html,
    )


# ─────────────────────────────────────────────────────────────────────
#  Plantilla HTML del correo
# ─────────────────────────────────────────────────────────────────────

def _build_reset_email_html(user, reset_url: str, expires: str, token_short: str) -> str:
    from apps.core.services.email_service import get_site_url
    display_name = (user.first_name or user.email or 'Usuario').strip()
    logo_url = f"{get_site_url()}/static/core/img/logo-dark-card.png"

    # Email HTML — diseño profesional basado en tables (máx compat con Gmail,
    # Outlook, iOS Mail, etc.) + estilos 100% inline (muchos clientes strippean
    # <style>). Sin JavaScript, sin SVG, sin fuentes externas.
    return f"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="x-apple-disable-message-reformatting">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>Recupera tu contraseña — DockerShield</title>
</head>
<body style="margin:0;padding:0;background:#0b0a14;width:100% !important;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">

<!-- Preheader: vista previa de la bandeja, oculto en el cuerpo -->
<div style="display:none;max-height:0;overflow:hidden;font-size:1px;line-height:1px;color:#0b0a14;opacity:0">
  Alguien solicitó restablecer tu contraseña. El enlace es válido por 24 h y solo funciona una vez.
</div>

<!-- Wrapper -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0b0a14;padding:32px 12px">
  <tr>
    <td align="center">

      <!-- ═══════════ CARD PRINCIPAL ═══════════ -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:580px;background:#14121f;border:1px solid rgba(124,92,255,0.18);border-radius:20px;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,0.55)">

        <!-- Barra de acento superior -->
        <tr>
          <td height="4" style="background:#6d4aff;background:linear-gradient(90deg,#6d4aff 0%,#9b6dff 50%,#c3a8ff 100%);font-size:0;line-height:0">&nbsp;</td>
        </tr>

        <!-- ── Logo real DockerShield centrado ── -->
        <tr>
          <td align="center" style="padding:32px 32px 12px">
            <img src="{logo_url}" alt="DockerShield" width="200" style="display:block;height:auto;max-width:200px;margin:0 auto 10px;border:0;outline:none;text-decoration:none">
            <div style="font-size:10.5px;font-weight:700;color:#a78bfa;font-family:'SF Mono',Menlo,Consolas,monospace;letter-spacing:0.14em;text-transform:uppercase;display:inline-block;padding:4px 11px;background:rgba(124,92,255,0.12);border:1px solid rgba(124,92,255,0.3);border-radius:20px">Recuperar contraseña</div>
          </td>
        </tr>

        <!-- ── Hero: insignia circular + título ── -->
        <tr>
          <td align="center" style="padding:40px 32px 10px">
            <!-- Insignia -->
            <table role="presentation" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td style="width:96px;height:96px;background:radial-gradient(circle at center,rgba(124,92,255,0.28) 0%,rgba(124,92,255,0.03) 70%);border-radius:50%;text-align:center;vertical-align:middle">
                  <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center">
                    <tr>
                      <td style="width:68px;height:68px;background:#6d4aff;background:linear-gradient(135deg,#6d4aff 0%,#9b6dff 100%);border-radius:50%;text-align:center;vertical-align:middle;line-height:68px;box-shadow:0 10px 28px rgba(109,74,255,0.45);font-size:30px">
                        &#128274;
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
            <!-- Título -->
            <h1 style="margin:22px 0 6px;font-size:26px;font-weight:800;color:#f0eeff;letter-spacing:-0.02em;line-height:1.25">
              Recupera tu contraseña
            </h1>
            <p style="margin:0;font-size:13.5px;color:#8a87a8;letter-spacing:0.01em">
              Solo faltan dos pasos para volver a entrar.
            </p>
          </td>
        </tr>

        <!-- ── Saludo + cuerpo ── -->
        <tr>
          <td style="padding:26px 38px 0;font-size:14.5px;line-height:1.7;color:#a9a6c1">
            Hola <strong style="color:#f0eeff">{display_name}</strong>,<br><br>
            Recibimos una solicitud para <strong style="color:#f0eeff">restablecer la contraseña</strong> de tu cuenta de DockerShield. Si fuiste tú, usa el botón de abajo para crear una contraseña nueva.
          </td>
        </tr>

        <!-- ── CTA: botón grande ── -->
        <tr>
          <td align="center" style="padding:28px 38px 10px">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td align="center" style="border-radius:13px;background:#6d4aff;background:linear-gradient(135deg,#6d4aff 0%,#9b6dff 100%);box-shadow:0 10px 30px rgba(109,74,255,0.45)">
                  <a href="{reset_url}" style="display:inline-block;padding:15px 42px;color:#ffffff !important;text-decoration:none;font-weight:700;font-size:14.5px;letter-spacing:0.02em;line-height:1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
                    Restablecer contraseña &nbsp;→
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Link de respaldo ── -->
        <tr>
          <td style="padding:14px 38px 26px">
            <p style="margin:0 0 8px;font-size:11.5px;color:#6b6884;text-align:center">
              ¿No funciona el botón? Copia y pega este enlace en tu navegador:
            </p>
            <p style="margin:0;background:#1e1b2d;border:1px solid rgba(255,255,255,0.05);border-radius:9px;padding:11px 13px;font-family:'SF Mono',Menlo,Consolas,monospace;font-size:11.5px;color:#b69dff;word-break:break-all;line-height:1.55;text-align:left">
              {reset_url}
            </p>
          </td>
        </tr>

        <!-- ── Info cards: expiración + uso único ── -->
        <tr>
          <td style="padding:0 38px 26px">
            <!-- Card 1: expiración -->
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.22);border-radius:12px;margin-bottom:10px">
              <tr>
                <td width="40" valign="top" style="padding:14px 0 14px 15px">
                  <div style="width:32px;height:32px;background:rgba(245,158,11,0.18);border-radius:9px;text-align:center;line-height:32px;font-size:16px">&#9203;</div>
                </td>
                <td valign="middle" style="padding:14px 15px 14px 12px">
                  <div style="color:#fbbf24;font-size:10.5px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:3px">Expira</div>
                  <div style="color:#f0eeff;font-size:13.5px;font-weight:600;line-height:1.5">{expires}</div>
                </td>
              </tr>
            </table>
            <!-- Card 2: uso único -->
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:rgba(124,92,255,0.08);border:1px solid rgba(124,92,255,0.22);border-radius:12px">
              <tr>
                <td width="40" valign="top" style="padding:14px 0 14px 15px">
                  <div style="width:32px;height:32px;background:rgba(124,92,255,0.22);border-radius:9px;text-align:center;line-height:32px;font-size:16px">
                    &#128273;
                  </div>
                </td>
                <td valign="middle" style="padding:14px 15px 14px 12px">
                  <div style="color:#a78bfa;font-size:10.5px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:3px">Un solo uso</div>
                  <div style="color:#f0eeff;font-size:13.5px;font-weight:600;line-height:1.5">Este enlace deja de funcionar después de usarlo.</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Aviso de seguridad ── -->
        <tr>
          <td style="padding:0 38px 28px">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:rgba(46,204,113,0.06);border:1px solid rgba(46,204,113,0.2);border-radius:12px">
              <tr>
                <td width="40" valign="top" style="padding:14px 0 14px 15px;font-size:20px">&#128737;&#65039;</td>
                <td valign="top" style="padding:14px 15px 14px 10px">
                  <div style="color:#bbf2c9;font-size:12.5px;font-weight:700;margin-bottom:3px">¿No solicitaste esto?</div>
                  <div style="color:#86e6a6;font-size:12.5px;line-height:1.65">
                    Ignora este mensaje y tu contraseña seguirá siendo la misma. Nadie puede usar este enlace sin acceso a tu correo.
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Footer interno (dentro de la card) ── -->
        <tr>
          <td style="padding:18px 38px 22px;border-top:1px solid rgba(255,255,255,0.05)">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr>
                <td style="font-size:11px;color:#6b6884;letter-spacing:0.01em">
                  Enviado desde <strong style="color:#a9a6c1">DockerShield</strong>
                </td>
                <td align="right" style="font-size:11px;color:#6b6884;font-family:'SF Mono',Menlo,Consolas,monospace">
                  ID: {token_short}
                </td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
      <!-- ═══════════ FIN CARD ═══════════ -->

      <!-- Footer exterior -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:580px">
        <tr>
          <td align="center" style="padding:20px 20px 8px">
            <p style="margin:0 0 4px;color:#5e5b75;font-size:11px;line-height:1.6">
              Este es un mensaje automático. No respondas a este correo.
            </p>
            <p style="margin:0;color:#3f3d55;font-size:10.5px;line-height:1.6">
              © DockerShield · Protección de correo con sandbox
            </p>
          </td>
        </tr>
      </table>

    </td>
  </tr>
</table>

</body>
</html>"""
