"""
Lógica de perfil: subida, validación y borrado de la imagen de avatar.
"""
from typing import Optional, Tuple

from django.core.files.uploadedfile import UploadedFile


# Configuración de seguridad para la subida de imágenes
MAX_AVATAR_SIZE_BYTES = 2 * 1024 * 1024        # 2 MB
ALLOWED_AVATAR_TYPES  = {
    'image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif',
}
ALLOWED_AVATAR_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}


def validate_avatar(upload: UploadedFile) -> Optional[str]:
    """
    Devuelve None si la imagen es válida, o un mensaje de error si no.
    Verifica:
      - existencia
      - tamaño (≤ 2 MB)
      - tipo MIME permitido (jpg, png, webp, gif)
      - extensión del nombre
      - que realmente sea imagen (Pillow puede abrirlo)
    """
    if not upload:
        return "No se recibió ninguna imagen."

    if upload.size > MAX_AVATAR_SIZE_BYTES:
        return f"La imagen supera el tamaño máximo de {MAX_AVATAR_SIZE_BYTES // 1024 // 1024} MB."

    # MIME reportado por el navegador
    if upload.content_type not in ALLOWED_AVATAR_TYPES:
        return "Formato no permitido. Usa JPG, PNG, WEBP o GIF."

    # Extensión del nombre (defensa en profundidad)
    import os
    ext = os.path.splitext(upload.name or '')[1].lower()
    if ext not in ALLOWED_AVATAR_EXTENSIONS:
        return "La extensión del archivo no es válida."

    # Verificación real con Pillow — rechaza archivos disfrazados de imagen
    try:
        from PIL import Image
        upload.seek(0)
        img = Image.open(upload)
        img.verify()
        upload.seek(0)
    except Exception:
        return "El archivo no es una imagen válida o está dañado."

    return None


def save_avatar(user, upload: UploadedFile) -> Tuple[bool, str]:
    """
    Sube el avatar del usuario. Borra el anterior primero.
    Devuelve (exito, mensaje).
    """
    error = validate_avatar(upload)
    if error:
        return False, error

    profile = _get_or_create_profile(user)

    # Borramos el archivo anterior del disco si existe
    profile.delete_avatar_file()

    profile.avatar = upload
    profile.save()
    return True, "Foto de perfil actualizada."


def remove_avatar(user) -> Tuple[bool, str]:
    """Borra el avatar del usuario (volverá a usar el avatar por defecto)."""
    profile = _get_or_create_profile(user)

    if not profile.has_avatar:
        return False, "No tienes foto de perfil para quitar."

    profile.delete_avatar_file()
    profile.avatar = None
    profile.save()
    return True, "Foto de perfil eliminada. Se usará el avatar por defecto."


def get_user_initials(user) -> str:
    """
    Iniciales para el avatar por defecto.

    Orden de prioridad:
      1. first_name + last_name → primera letra de cada uno (ej. "Jose Gomez" → "JG")
      2. first_name solo → si tiene varias palabras, iniciales de las dos primeras;
         si es una sola palabra, primeras 2 letras
      3. username → primeras 2 letras
      4. email → primeras 2 letras
    Siempre devuelve 1-2 letras en mayúsculas.
    """
    first = (user.first_name or '').strip()
    last  = (user.last_name or '').strip()

    if first and last:
        return (first[0] + last[0]).upper()

    if first:
        parts = [p for p in first.split() if p]
        if len(parts) >= 2:
            return (parts[0][0] + parts[1][0]).upper()
        letters = [c for c in first if c.isalpha()]
        if len(letters) >= 2:
            return (letters[0] + letters[1]).upper()
        if letters:
            return letters[0].upper()

    source = (user.username or '').strip() or (user.email or '').strip()
    if not source:
        return '??'
    letters = [c for c in source if c.isalpha()]
    if not letters:
        return source[:2].upper()
    if len(letters) >= 2:
        return (letters[0] + letters[1]).upper()
    return letters[0].upper()


def get_user_color(user) -> str:
    """
    Color determinístico para el fondo del avatar por defecto.
    El mismo usuario siempre recibe el mismo color.
    """
    palette = [
        '#6d4aff', '#7c3aed', '#8b5cf6',   # morados
        '#3b82f6', '#2563eb',              # azules
        '#10b981', '#059669',              # verdes
        '#f59e0b', '#d97706',              # naranjas
        '#ef4444', '#dc2626',              # rojos
        '#ec4899', '#db2777',              # rosas
    ]
    key = (user.email or user.username or 'x')
    idx = sum(ord(c) for c in key) % len(palette)
    return palette[idx]


# ─────────────────────────────────────────────────────────────────────
#  Helpers internos
# ─────────────────────────────────────────────────────────────────────

def _get_or_create_profile(user):
    """Obtiene o crea el UserProfile para el usuario."""
    from apps.accounts.models import UserProfile
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile
