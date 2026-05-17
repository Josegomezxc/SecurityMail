"""
Notificación por correo cuando un usuario elimina su cuenta.

  - send_account_deleted_email(...) → envía un correo HTML al correo
    PERSONAL del usuario (NO a un alias — los alias se acaban de borrar).
    Incluye un resumen de lo eliminado, la fecha/IP de la operación y un
    aviso de seguridad por si la acción no fue suya.

Es una notificación informativa: si el envío falla NO debemos romper la
eliminación de la cuenta (que ya se hizo). Por eso esta función nunca
levanta excepciones — devuelve (ok, info) y los errores se loguean.
"""
from typing import Tuple, Optional

from apps.core.services.email_service import send_email, get_site_url


def send_account_deleted_email(
    *,
    to_email: str,
    display_name: str,
    alias_count: int,
    total_emails: int,
    threats_count: int,
    deleted_at_str: str,
    ip: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Envía la confirmación de eliminación al correo personal del usuario.
    Todos los datos se pasan ya resueltos (el caller los captura antes
    del delete porque el objeto User ya no existe cuando enviamos).
    """
    if not to_email:
        return False, 'sin destinatario'
    try:
        html = _build_account_deleted_html(
            display_name   = display_name,
            alias_count    = alias_count,
            total_emails   = total_emails,
            threats_count  = threats_count,
            deleted_at_str = deleted_at_str,
            ip             = ip or '—',
        )
        return send_email(
            to      = to_email,
            subject = 'Tu cuenta ha sido eliminada — DockerShield',
            html    = html,
        )
    except Exception as e:
        return False, f'error: {e}'


# ─────────────────────────────────────────────────────────────────────
#  Plantilla HTML (mismo lenguaje visual que password_reset_service)
# ─────────────────────────────────────────────────────────────────────

def _build_account_deleted_html(
    *,
    display_name: str,
    alias_count: int,
    total_emails: int,
    threats_count: int,
    deleted_at_str: str,
    ip: str,
) -> str:
    base_url    = get_site_url()
    register_url = f"{base_url}/registro/"
    name_safe    = (display_name or 'Usuario').strip() or 'Usuario'
    logo_url     = f"{base_url}/static/core/img/logo.png"

    return f"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="x-apple-disable-message-reformatting">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>Tu cuenta ha sido eliminada — DockerShield</title>
</head>
<body style="margin:0;padding:0;background:#0b0a14;width:100% !important;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">

<!-- Preheader: vista previa en bandeja, oculto en el cuerpo -->
<div style="display:none;max-height:0;overflow:hidden;font-size:1px;line-height:1px;color:#0b0a14;opacity:0">
  Tu cuenta DockerShield se eliminó correctamente. Resumen de lo borrado y aviso de seguridad dentro.
</div>

<!-- Wrapper -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0b0a14;padding:32px 12px">
  <tr>
    <td align="center">

      <!-- ═══════════ CARD PRINCIPAL ═══════════ -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:580px;background:#14121f;border:1px solid rgba(232,64,64,0.22);border-radius:20px;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,0.55)">

        <!-- Barra de acento superior (rojo: esto es destructivo / informativo) -->
        <tr>
          <td height="4" style="background:#e84040;background:linear-gradient(90deg,#e84040 0%,#f87171 50%,#fca5a5 100%);font-size:0;line-height:0">&nbsp;</td>
        </tr>

        <!-- ── Logo real DockerShield centrado ── -->
        <tr>
          <td align="center" style="padding:32px 32px 12px">
            <img src="{logo_url}" alt="DockerShield" width="200" style="display:block;height:auto;max-width:200px;margin:0 auto 10px;border:0;outline:none;text-decoration:none">
            <div style="font-size:10.5px;font-weight:700;color:#fca5a5;font-family:'SF Mono',Menlo,Consolas,monospace;letter-spacing:0.14em;text-transform:uppercase;display:inline-block;padding:4px 11px;background:rgba(232,64,64,0.12);border:1px solid rgba(232,64,64,0.3);border-radius:20px">Cuenta cerrada</div>
          </td>
        </tr>

        <!-- ── Hero: insignia + título ── -->
        <tr>
          <td align="center" style="padding:40px 32px 10px">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td style="width:96px;height:96px;background:radial-gradient(circle at center,rgba(232,64,64,0.28) 0%,rgba(232,64,64,0.03) 70%);border-radius:50%;text-align:center;vertical-align:middle">
                  <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center">
                    <tr>
                      <td style="width:68px;height:68px;background:#e84040;background:linear-gradient(135deg,#e84040 0%,#f87171 100%);border-radius:50%;text-align:center;vertical-align:middle;line-height:68px;box-shadow:0 10px 28px rgba(232,64,64,0.45)">
                        <span style="font-size:30px;line-height:68px;vertical-align:middle">👋</span>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
            <h1 style="margin:22px 0 6px;font-size:26px;font-weight:800;color:#f0eeff;letter-spacing:-0.02em;line-height:1.25">
              Tu cuenta ha sido eliminada
            </h1>
            <p style="margin:0;font-size:13.5px;color:#8a87a8;letter-spacing:0.01em">
              Confirmación oficial — todo se borró correctamente.
            </p>
          </td>
        </tr>

        <!-- ── Saludo + cuerpo ── -->
        <tr>
          <td style="padding:26px 38px 0;font-size:14.5px;line-height:1.7;color:#a9a6c1">
            Hola <strong style="color:#f0eeff">{name_safe}</strong>,<br><br>
            Hemos procesado tu solicitud y tu cuenta de DockerShield ha sido <strong style="color:#fca5a5">eliminada de forma permanente</strong>. Este correo es la confirmación oficial de la operación.
          </td>
        </tr>

        <!-- ── Resumen de lo borrado ── -->
        <tr>
          <td style="padding:22px 38px 0">
            <div style="font-size:11px;font-weight:700;color:#6b6884;letter-spacing:0.14em;text-transform:uppercase;margin-bottom:10px">Lo que se eliminó</div>
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:rgba(232,64,64,0.06);border:1px solid rgba(232,64,64,0.18);border-radius:14px">
              <tr>
                <td align="center" width="33%" style="padding:18px 8px;border-right:1px solid rgba(232,64,64,0.14)">
                  <div style="font-size:24px;font-weight:800;color:#fca5a5;line-height:1;margin-bottom:6px">{alias_count}</div>
                  <div style="font-size:10px;font-weight:700;color:#8a87a8;letter-spacing:0.1em;text-transform:uppercase">Alias</div>
                </td>
                <td align="center" width="34%" style="padding:18px 8px;border-right:1px solid rgba(232,64,64,0.14)">
                  <div style="font-size:24px;font-weight:800;color:#fca5a5;line-height:1;margin-bottom:6px">{total_emails}</div>
                  <div style="font-size:10px;font-weight:700;color:#8a87a8;letter-spacing:0.1em;text-transform:uppercase">Correos</div>
                </td>
                <td align="center" width="33%" style="padding:18px 8px">
                  <div style="font-size:24px;font-weight:800;color:#fca5a5;line-height:1;margin-bottom:6px">{threats_count}</div>
                  <div style="font-size:10px;font-weight:700;color:#8a87a8;letter-spacing:0.1em;text-transform:uppercase">Amenazas</div>
                </td>
              </tr>
            </table>
            <p style="margin:12px 2px 0;font-size:11.5px;color:#6b6884;line-height:1.55">
              También se borraron tus notificaciones, configuración de privacidad y la foto de perfil.
            </p>
          </td>
        </tr>

        <!-- ── Datos técnicos: cuándo y desde dónde ── -->
        <tr>
          <td style="padding:18px 38px 0">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#1e1b2d;border:1px solid rgba(255,255,255,0.05);border-radius:12px">
              <tr>
                <td width="50%" valign="top" style="padding:14px 16px;border-right:1px solid rgba(255,255,255,0.05)">
                  <div style="color:#6b6884;font-size:10px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:5px">Fecha</div>
                  <div style="color:#f0eeff;font-size:13px;font-weight:600;line-height:1.45;font-family:'SF Mono',Menlo,Consolas,monospace">{deleted_at_str}</div>
                </td>
                <td width="50%" valign="top" style="padding:14px 16px">
                  <div style="color:#6b6884;font-size:10px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:5px">Desde la IP</div>
                  <div style="color:#f0eeff;font-size:13px;font-weight:600;line-height:1.45;font-family:'SF Mono',Menlo,Consolas,monospace">{ip}</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Sobre tus alias (info útil de privacidad) ── -->
        <tr>
          <td style="padding:18px 38px 0">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:rgba(124,92,255,0.08);border:1px solid rgba(124,92,255,0.22);border-radius:12px">
              <tr>
                <td width="40" valign="top" style="padding:14px 0 14px 15px;color:#a78bfa;font-size:17px">📭</td>
                <td valign="top" style="padding:14px 15px 14px 10px">
                  <div style="color:#c3a8ff;font-size:12.5px;font-weight:700;margin-bottom:3px">Tus alias dejaron de existir</div>
                  <div style="color:#a9a6c1;font-size:12.5px;line-height:1.65">
                    Cualquier correo enviado a las direcciones que tenías será rechazado automáticamente. Los servicios que tenían tu alias <strong style="color:#f0eeff">no podrán contactarte</strong> a través de DockerShield. Si vuelves a registrarte se generarán alias nuevos y distintos.
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Aviso de seguridad: ¿no fuiste tú? ── -->
        <tr>
          <td style="padding:14px 38px 0">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.22);border-radius:12px">
              <tr>
                <td width="40" valign="top" style="padding:14px 0 14px 15px"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></td>
                <td valign="top" style="padding:14px 15px 14px 10px">
                  <div style="color:#fbbf24;font-size:12.5px;font-weight:700;margin-bottom:3px">¿No fuiste tú?</div>
                  <div style="color:#fde68a;font-size:12.5px;line-height:1.65">
                    Si no eliminaste tu cuenta, alguien tuvo acceso a tu correo y a tu contraseña. <strong>Cambia ahora mismo la contraseña de tu correo personal</strong> y revisa los inicios de sesión recientes. Después de eso puedes volver a registrarte en DockerShield.
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── CTA: volver a registrarse ── -->
        <tr>
          <td align="center" style="padding:28px 38px 14px">
            <p style="margin:0 0 14px;font-size:13px;color:#8a87a8;line-height:1.55">
              Si quieres volver, puedes crear una cuenta nueva en cualquier momento:
            </p>
            <table role="presentation" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td align="center" style="border-radius:13px;background:#6d4aff;background:linear-gradient(135deg,#6d4aff 0%,#9b6dff 100%);box-shadow:0 10px 30px rgba(109,74,255,0.45)">
                  <a href="{register_url}" style="display:inline-block;padding:13px 36px;color:#ffffff !important;text-decoration:none;font-weight:700;font-size:13.5px;letter-spacing:0.02em;line-height:1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
                    Crear cuenta nueva &nbsp;→
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Footer interno ── -->
        <tr>
          <td style="padding:18px 38px 22px;border-top:1px solid rgba(255,255,255,0.05)">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr>
                <td style="font-size:11px;color:#6b6884;letter-spacing:0.01em">
                  Enviado desde <strong style="color:#a9a6c1">DockerShield</strong>
                </td>
                <td align="right" style="font-size:11px;color:#6b6884;font-family:'SF Mono',Menlo,Consolas,monospace">
                  Notificación de cuenta
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
