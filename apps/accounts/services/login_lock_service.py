"""
Bloqueo de cuentas por intentos fallidos de login — tracking PER-USER.

Distinto del rate limit por IP de auth_service (login_is_locked) — ese
defiende contra fuerza bruta desde una IP, este protege la cuenta del
usuario aunque el atacante rote IPs.

Flujo:
  1) Cada contraseña incorrecta → register_user_failure() sube el contador.
  2) Al llegar a MAX_ATTEMPTS → temp_lock 3 min + temp_lock_triggered=True.
     Se muestra una card al usuario advirtiendo que la próxima falla es
     bloqueo permanente.
  3) Después de que expira el temp lock, la siguiente falla →
     User.is_active=False + permanent_lock_at + permanent_lock_reason.
  4) Login exitoso (clear_user_failures) resetea todo el estado.

Distinción entre "permanently locked" y "soft delete":
  - Ambos ponen User.is_active = False.
  - permanent_lock_at != None  → bloqueado por intentos (puede pedir
    recuperación al admin).
  - profile.is_deleted = True  → cuenta eliminada por el dueño.
"""
from datetime import timedelta

from django.utils import timezone

from apps.accounts.models import AccountLock


# ── Configuración ────────────────────────────────────────────────────
# Fácil de subir en producción (5–10) — 3 es solo para testing rápido.
MAX_ATTEMPTS       = 3
TEMP_LOCK_MINUTES  = 1


# ── Estados que devuelve check_user_lock_state ───────────────────────
STATE_OK              = 'ok'
STATE_TEMP_LOCKED     = 'temp_locked'
STATE_PERMANENT_LOCK  = 'permanent_locked'
STATE_SOFT_DELETED    = 'soft_deleted'


def check_user_lock_state(user):
    """
    Inspecciona el estado de bloqueo del user SIN tocar la BD.
    Devuelve (state, context_dict).

    `state` es uno de STATE_*. `context_dict` lleva info útil para la UI:
      - temp_locked:    {'until': dt, 'remaining_seconds': int, 'warning_permanent': bool}
      - permanent_locked: {'reason': str, 'locked_at': dt, 'pending_request': bool}
      - soft_deleted: {}
      - ok: {}
    """
    profile = getattr(user, 'profile', None)
    if profile is None:
        return STATE_OK, {}

    # Soft delete tiene prioridad sobre bloqueo por intentos.
    if getattr(profile, 'is_deleted', False):
        return STATE_SOFT_DELETED, {}

    # Bloqueo permanente: User.is_active=False + permanent_lock_at != None.
    lock = getattr(profile, 'lock', None)
    if not user.is_active and lock and lock.permanent_lock_at:
        from apps.accounts.models import AccountRecoveryRequest
        pending = AccountRecoveryRequest.objects.filter(
            user=user, status='pending',
        ).exists()
        return STATE_PERMANENT_LOCK, {
            'reason':          lock.permanent_lock_reason or _default_lock_reason(),
            'locked_at':       lock.permanent_lock_at,
            'pending_request': pending,
        }

    # Temp lock activo.
    now = timezone.now()
    if lock and lock.temp_locked_until and lock.temp_locked_until > now:
        remaining = int((lock.temp_locked_until - now).total_seconds())
        return STATE_TEMP_LOCKED, {
            'until':             lock.temp_locked_until,
            'remaining_seconds': max(0, remaining),
            # Si ya disparamos un temp lock antes y el usuario está en
            # otro, no debería pasar — pero mantenemos el flag para que
            # la card siempre sepa avisar de bloqueo permanente.
            'warning_permanent': True,
        }

    return STATE_OK, {}


def register_user_failure(user):
    """
    Llamar tras una autenticación fallida POR PASSWORD (el user existe).

    Devuelve (new_state, context_dict). El caller debe renderizar la
    card apropiada según new_state:
      - STATE_OK             → siguen quedando intentos
      - STATE_TEMP_LOCKED    → se acaba de disparar el temp lock
      - STATE_PERMANENT_LOCK → ya quedó bloqueada permanentemente
    """
    profile = user.profile
    lock, _ = AccountLock.objects.get_or_create(profile=profile)
    now = timezone.now()

    # Caso A: temp_lock_triggered y ya expiró el temp_locked_until.
    # Esta era la "última oportunidad" — fallar acá = bloqueo permanente.
    if (lock.temp_lock_triggered
            and (not lock.temp_locked_until or lock.temp_locked_until <= now)):
        return _apply_permanent_lock(user, profile, lock)

    # Caso B: aún dentro del primer ciclo de intentos.
    lock.failed_login_attempts = (lock.failed_login_attempts or 0) + 1

    if lock.failed_login_attempts >= MAX_ATTEMPTS:
        # Llegó al tope → activar temp lock.
        lock.temp_locked_until   = now + timedelta(minutes=TEMP_LOCK_MINUTES)
        lock.temp_lock_triggered = True
        lock.save(update_fields=[
            'failed_login_attempts',
            'temp_locked_until',
            'temp_lock_triggered',
        ])
        return STATE_TEMP_LOCKED, {
            'until':             lock.temp_locked_until,
            'remaining_seconds': TEMP_LOCK_MINUTES * 60,
            'warning_permanent': True,
        }

    # Sigue habiendo intentos — solo persiste el contador.
    lock.save(update_fields=['failed_login_attempts'])
    remaining = MAX_ATTEMPTS - lock.failed_login_attempts
    return STATE_OK, {'attempts_left': remaining}


def clear_user_failures(user):
    """
    Login exitoso → limpia todo el tracking de fallos (contador, temp lock,
    flag de trigger). No toca permanent_lock_* — si la cuenta está bloqueada
    permanentemente, no debería poder hacer login para empezar.
    """
    profile = getattr(user, 'profile', None)
    if profile is None:
        return
    lock = getattr(profile, 'lock', None)
    if lock is None:
        return
    if not (lock.failed_login_attempts
            or lock.temp_locked_until
            or lock.temp_lock_triggered):
        return  # nada que limpiar
    lock.failed_login_attempts = 0
    lock.temp_locked_until     = None
    lock.temp_lock_triggered   = False
    lock.save(update_fields=[
        'failed_login_attempts',
        'temp_locked_until',
        'temp_lock_triggered',
    ])


def unlock_user_after_recovery(user, admin):
    """
    Llamar cuando un admin aprueba una AccountRecoveryRequest.
    Restaura la cuenta a estado normal: is_active=True y limpia los
    campos de lock (incluyendo los permanentes).
    """
    profile = user.profile
    lock, _ = AccountLock.objects.get_or_create(profile=profile)
    user.is_active = True
    user.save(update_fields=['is_active'])

    lock.failed_login_attempts = 0
    lock.temp_locked_until     = None
    lock.temp_lock_triggered   = False
    lock.permanent_lock_at     = None
    lock.permanent_lock_reason = ''
    lock.save(update_fields=[
        'failed_login_attempts',
        'temp_locked_until',
        'temp_lock_triggered',
        'permanent_lock_at',
        'permanent_lock_reason',
    ])
    profile.malicious_attachment_attempts = 0
    profile.malicious_attempt_data = {}
    profile.save(update_fields=['malicious_attachment_attempts', 'malicious_attempt_data'])


# ─────────────────────────────────────────────────────────────────────
#  Internos
# ─────────────────────────────────────────────────────────────────────

def _apply_permanent_lock(user, profile, lock):
    """Marca la cuenta como permanentemente bloqueada y devuelve el estado."""
    now = timezone.now()
    user.is_active = False
    user.save(update_fields=['is_active'])

    lock.permanent_lock_at     = now
    lock.permanent_lock_reason = _default_lock_reason()
    # Mantenemos failed_login_attempts y temp_lock_triggered como auditoría.
    lock.save(update_fields=[
        'permanent_lock_at',
        'permanent_lock_reason',
    ])
    return STATE_PERMANENT_LOCK, {
        'reason':          lock.permanent_lock_reason,
        'locked_at':       lock.permanent_lock_at,
        'pending_request': False,
    }


def _default_lock_reason():
    """Lista de motivos que se muestran en la card de bloqueo permanente."""
    return (
        "Tu cuenta fue bloqueada permanentemente por seguridad. Motivos:\n"
        f"• Se superó el límite de {MAX_ATTEMPTS} intentos consecutivos de "
        "contraseña incorrecta.\n"
        f"• Tras el bloqueo temporal de {TEMP_LOCK_MINUTES} minutos, el "
        "intento de recuperación también falló.\n"
        "• El patrón de fallos sugiere acceso no autorizado o que "
        "perdiste el control de la contraseña.\n\n"
        "Si reconocés esta cuenta como tuya, podés solicitar al "
        "administrador que la reactive enviando una solicitud de "
        "recuperación con tu motivo."
    )
