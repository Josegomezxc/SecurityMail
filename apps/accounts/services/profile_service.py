
from typing import Optional, Tuple

from django.core.files.uploadedfile import UploadedFile


MAX_AVATAR_SIZE_BYTES = 2 * 1024 * 1024        
ALLOWED_AVATAR_TYPES  = {
    'image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif',
}
ALLOWED_AVATAR_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}


def validate_avatar(upload: UploadedFile) -> Optional[str]:

    if not upload:
        return "No se recibió ninguna imagen."

    if upload.size > MAX_AVATAR_SIZE_BYTES:
        return f"La imagen supera el tamaño máximo de {MAX_AVATAR_SIZE_BYTES // 1024 // 1024} MB."

    if upload.content_type not in ALLOWED_AVATAR_TYPES:
        return "Formato no permitido. Usa JPG, PNG, WEBP o GIF."

    import os
    ext = os.path.splitext(upload.name or '')[1].lower()
    if ext not in ALLOWED_AVATAR_EXTENSIONS:
        return "La extensión del archivo no es válida."

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

    error = validate_avatar(upload)
    if error:
        return False, error

    profile = _get_or_create_profile(user)

    profile.delete_avatar_file()

    profile.avatar = upload
    profile.save()
    return True, "Foto de perfil actualizada."


def remove_avatar(user) -> Tuple[bool, str]:
    profile = _get_or_create_profile(user)

    if not profile.has_avatar:
        return False, "No tienes foto de perfil para quitar."

    profile.delete_avatar_file()
    profile.avatar = None
    profile.save()
    return True, "Foto de perfil eliminada. Se usará el avatar por defecto."


def get_user_initials(user) -> str:

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

    palette = [
        '#6d4aff', '#7c3aed', '#8b5cf6',  
        '#3b82f6', '#2563eb',           
        '#10b981', '#059669',             
        '#f59e0b', '#d97706',             
        '#ef4444', '#dc2626',           
        '#ec4899', '#db2777',            
    ]
    key = (user.email or user.username or 'x')
    idx = sum(ord(c) for c in key) % len(palette)
    return palette[idx]



def _get_or_create_profile(user):
    from apps.accounts.models import UserProfile
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile
