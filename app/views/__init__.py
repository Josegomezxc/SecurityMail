"""
app/views/
──────────────────────────────────────────────────────────────────────
Vistas (controllers en MVC) divididas por dominio.

Cada archivo agrupa las vistas que manejan un mismo módulo:
    auth_views       → login / registro / logout / recuperar / cambiar password
    dashboard_views  → dashboard + endpoint live
    inbox_views      → bandeja + endpoints de live y marcar leído
    alias_views      → CRUD de alias
    sandbox_views    → lista y reporte de análisis sandbox
    perfil_views     → perfil del usuario
    admin_views      → panel de administración (is_staff)
    ai_views         → integración con Groq (análisis IA)

Este __init__ re-exporta todas las vistas para que urls.py siga
importándolas con el alias `views.login_view`, sin tener que tocar las
rutas que ya existen.
"""

# ─── Auth ─────────────────────────────────────────────────────────────
from .auth_views import (
    login_view,
    registro_view,
    logout_view,
    recuperar_view,
    reset_password_view,
    cambiar_password,
    verificar_correo_view,
    reenviar_codigo_view,
)

# ─── Dashboard ────────────────────────────────────────────────────────
from .dashboard_views import (
    dashboard_view,
    dashboard_live_api,
)

# ─── Inbox ────────────────────────────────────────────────────────────
from .inbox_views import (
    inbox_view,
    mark_email_read_api,
    inbox_new_api,
    email_html_api,
    inbox_clear_api,
)

# ─── Alias ────────────────────────────────────────────────────────────
from .alias_views import (
    alias_list_view,
    alias_create_view,
    alias_destroy_view,
)

# ─── Sandbox ──────────────────────────────────────────────────────────
from .sandbox_views import (
    sandbox_list_view,
    sandbox_analyze_view,
    sandbox_report_view,
)

# ─── Perfil ───────────────────────────────────────────────────────────
from .perfil_views import (
    perfil_view,
)

# ─── Admin ────────────────────────────────────────────────────────────
from .admin_views import (
    admin_dashboard_view,
    admin_users_view,
    admin_user_detail_view,
    admin_toggle_staff,
    admin_toggle_alias,
    admin_threats_view,
    admin_aliases_view,
)

# ─── IA ───────────────────────────────────────────────────────────────
from .ai_views import (
    ai_analysis_view,
)

# ─── Notificaciones ───────────────────────────────────────────────────
from .notification_views import (
    notification_list_view,
    notification_detail_view,
    notification_unread_api,
    notification_mark_read_api,
    notification_mark_all_read_api,
    notification_forward_api,
    notification_discard_api,
    notification_clear_api,
)

# El decorator sigue disponible como `views.admin_required`
from ..services.auth_service import admin_required


__all__ = [
    # Auth
    'login_view', 'registro_view', 'logout_view', 'recuperar_view',
    'reset_password_view', 'cambiar_password',
    'verificar_correo_view', 'reenviar_codigo_view',
    # Dashboard
    'dashboard_view', 'dashboard_live_api',
    # Inbox
    'inbox_view', 'mark_email_read_api', 'inbox_new_api', 'email_html_api',
    'inbox_clear_api',
    # Alias
    'alias_list_view', 'alias_create_view', 'alias_destroy_view',
    # Sandbox
    'sandbox_list_view', 'sandbox_analyze_view', 'sandbox_report_view',
    # Perfil
    'perfil_view',
    # Admin
    'admin_dashboard_view', 'admin_users_view',
    'admin_user_detail_view', 'admin_toggle_staff', 'admin_toggle_alias',
    'admin_threats_view', 'admin_aliases_view',
    # IA
    'ai_analysis_view',
    # Notificaciones
    'notification_list_view', 'notification_detail_view',
    'notification_unread_api', 'notification_mark_read_api',
    'notification_mark_all_read_api',
    'notification_forward_api', 'notification_discard_api',
    'notification_clear_api',
    # Helpers
    'admin_required',
]
