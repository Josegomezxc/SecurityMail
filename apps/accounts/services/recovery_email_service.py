"""
Notificación por correo cuando un admin REACTIVA una cuenta que había
sido bloqueada permanentemente por intentos fallidos de login.

Se invoca desde apps/core/views.py::admin_account_recovery_request_resolve
cuando el admin aprueba la solicitud (action='approve'). No bloquea la
recuperación si el envío falla — devuelve (ok, info).
"""
from typing import Tuple, Optional

from apps.core.services.email_service import send_email, get_site_url


def send_account_reactivated_email(
    *,
    to_email: str,
    display_name: str,
    admin_note: str = '',
    admin_username: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Envía la confirmación de reactivación al correo personal del usuario.
    El email contiene un CTA para volver al login y una nota del admin
    si la dejó (consejos de seguridad, motivo de la reactivación, etc.).
    """
    if not to_email:
        return False, 'sin destinatario'
    try:
        html = _build_reactivated_html(
            display_name   = display_name,
            admin_note     = admin_note,
            admin_username = admin_username,
        )
        return send_email(
            to      = to_email,
            subject = 'Tu cuenta fue reactivada — DockerShield',
            html    = html,
        )
    except Exception as e:
        return False, f'error: {e}'


def _build_reactivated_html(
    *,
    display_name: str,
    admin_note: str,
    admin_username: Optional[str],
) -> str:
    """HTML estilo verde (positivo) avisando la reactivación."""
    base_url  = get_site_url()
    login_url = f"{base_url}/"
    logo_url  = f"{base_url}/static/core/img/logo.png"
    name_safe = (display_name or 'Usuario').strip() or 'Usuario'

    # Bloque opcional con la nota del admin
    admin_block = ''
    if admin_note.strip():
        admin_label = (
            f"Mensaje de <strong>{admin_username}</strong>:" if admin_username
            else 'Mensaje del administrador:'
        )
        admin_block = f"""
                  <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(124,58,237,0.08);border:1px solid rgba(124,58,237,0.25);border-radius:9px;margin-bottom:18px">
                    <tr>
                      <td style="padding:14px 16px">
                        <div style="color:#a78bfa;font-size:11px;font-family:monospace;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:6px;font-weight:700">{admin_label}</div>
                        <div style="color:#d1ccef;font-size:13px;line-height:1.55;white-space:pre-wrap">{admin_note}</div>
                      </td>
                    </tr>
                  </table>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cuenta reactivada · DockerShield</title>
</head>
<body style="margin:0;padding:0;background:#0d0c1a;font-family:'Helvetica Neue',Arial,sans-serif;-webkit-font-smoothing:antialiased">

<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0c1a;padding:32px 16px">
  <tr>
    <td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:520px">
        <tr>
          <td style="background:#161527;border:1px solid rgba(34,197,94,0.32);border-radius:14px;overflow:hidden">

            <!-- HEADER VERDE de éxito -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#15803d 0%,#22c55e 100%)">
              <tr>
                <td style="padding:26px 28px" align="center">
                  <img src="{logo_url}" alt="DockerShield" width="200" style="display:inline-block;height:auto;max-width:200px;border:0;outline:none;text-decoration:none">
                  <div style="color:rgba(255,255,255,0.92);font-size:11.5px;font-family:monospace;letter-spacing:0.1em;margin-top:12px;text-transform:uppercase">Cuenta reactivada</div>
                </td>
              </tr>
            </table>

            <!-- CUERPO -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:32px 28px 8px">
                  <h1 style="margin:0 0 12px;color:#f0eeff;font-size:18px;font-weight:700;letter-spacing:-0.01em">Hola {name_safe},</h1>
                  <p style="margin:0 0 18px;color:#b8b6cf;font-size:14px;line-height:1.6">
                    Tu solicitud de recuperación fue <strong style="color:#86efac">aprobada</strong>.
                    Tu cuenta de DockerShield ya está activa nuevamente y podés
                    iniciar sesión con tu contraseña habitual.
                  </p>

                  {admin_block}

                  <!-- CTA: volver al login -->
                  <table width="100%" cellpadding="0" cellspacing="0" style="margin:6px 0 22px">
                    <tr>
                      <td align="center">
                        <a href="{login_url}" style="display:inline-block;padding:14px 26px;background:linear-gradient(135deg,#22c55e,#16a34a);color:#fff;font-size:14px;font-weight:700;border-radius:10px;text-decoration:none;letter-spacing:0.01em">
                          Iniciar sesión &rarr;
                        </a>
                      </td>
                    </tr>
                  </table>

                  <!-- Recordatorio de seguridad -->
                  <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.20);border-radius:9px;margin-bottom:14px">
                    <tr>
                      <td style="padding:12px 14px">
                        <span style="color:#fbbf24;font-size:12.5px;line-height:1.55">
                          <strong>Recomendado:</strong> cambiá tu contraseña apenas
                          entres, especialmente si sospechás que alguien intentó
                          acceder sin tu permiso.
                        </span>
                      </td>
                    </tr>
                  </table>

                  <!-- Aviso "no fui yo" -->
                  <p style="margin:14px 0 0;color:#7d7a96;font-size:12px;line-height:1.55">
                    Si vos no pediste reactivar esta cuenta, alguien más podría
                    estar intentando acceder. Contactá al administrador de inmediato.
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
