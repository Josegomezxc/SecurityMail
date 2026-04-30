"""
Vistas CRUD de alias desechables:
  - Lista con búsqueda y filtros.
  - Crear nuevo alias.
  - Destruir (marcar inactivo).
"""
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import Alias
from .services.alias_service import generate_alias_address, generate_creative_label


# Cuántos alias ACTIVOS puede tener un usuario común al mismo tiempo.
# Los destruidos (is_active=False) no cuentan — quedan en la BD por
# seguridad (el address no se puede reutilizar gracias a unique=True)
# pero el usuario puede crear otros nuevos en su lugar.
# Los administradores (is_staff) NO tienen límite.
ALIAS_LIMIT_PER_USER = 5


@login_required(login_url='login')
def alias_list_view(request):
    """
    Lista todos los alias del usuario con sus contadores anotados
    (correos totales, amenazas) para la UI.
    """
    # Ojo: los nombres de anotaciones NO pueden empezar con "_"
    # porque Django templates rechaza variables con underscore inicial.
    aliases = Alias.objects.filter(user=request.user).annotate(
        emails_total  = Count('emails'),
        threats_total = Count('emails', filter=Q(emails__risk_score__gte=61)),
    ).order_by('-created_at')

    active_count    = sum(1 for a in aliases if a.is_active)
    destroyed_count = sum(1 for a in aliases if not a.is_active)
    total_emails    = sum(a.emails_total for a in aliases)
    total_threats   = sum(a.threats_total for a in aliases)

    # Para la UI: cuántos alias puede crear todavía + límite total
    is_unlimited     = request.user.is_staff
    alias_limit      = None if is_unlimited else ALIAS_LIMIT_PER_USER
    alias_remaining  = None if is_unlimited else max(0, ALIAS_LIMIT_PER_USER - active_count)

    return render(request, 'alias.html', {
        'aliases':         aliases,
        'active_count':    active_count,
        'destroyed_count': destroyed_count,
        'total_emails':    total_emails,
        'total_threats':   total_threats,
        'alias_limit':     alias_limit,
        'alias_remaining': alias_remaining,
        'is_unlimited':    is_unlimited,
    })


@login_required(login_url='login')
def alias_create_view(request):
    """
    Crea un nuevo alias con etiqueta y dirección 100% autogeneradas.

    El usuario NO escribe nada — el sistema genera una etiqueta creativa
    (adjetivo + sustantivo, ej: 'silver-tiger') y la convierte en una
    dirección única tipo 'silver-tiger_x7k2m@dockershield.lat'.

    Esto evita por completo cualquier riesgo de palabras vulgares,
    información personal o etiquetas ofensivas.
    """
    if request.method == 'POST':
        # Defensa anti doble-submit + anti abuso: chequea el límite SIEMPRE
        # en el backend (el JS del front solo es UX, no se debe confiar).
        if not request.user.is_staff:
            active_count = Alias.objects.filter(
                user=request.user, is_active=True,
            ).count()
            if active_count >= ALIAS_LIMIT_PER_USER:
                messages.error(
                    request,
                    f'Has alcanzado el límite de {ALIAS_LIMIT_PER_USER} alias '
                    f'activos. Destruye alguno antes de crear uno nuevo.',
                )
                return redirect('alias_list')

        # Genera etiqueta creativa (silver-tiger, cosmic-falcon, etc.) y
        # dirección única. Si por mala suerte la dirección ya existe en
        # la BD (colisión muy improbable: ~36^6 = 2.000M combinaciones
        # por etiqueta), reintentamos hasta 5 veces.
        for _ in range(5):
            label   = generate_creative_label()
            address = generate_alias_address(label)
            if not Alias.objects.filter(address=address).exists():
                break
        else:
            messages.error(request, 'No se pudo generar un alias único. Inténtalo de nuevo.')
            return redirect('alias_list')

        Alias.objects.create(
            user=request.user,
            label=label,
            address=address,
        )
        messages.success(request, f'Alias creado: {address}')

    return redirect('alias_list')


@login_required(login_url='login')
def alias_destroy_view(request, pk):
    """Marca un alias como inactivo (soft delete)."""
    alias = get_object_or_404(Alias, pk=pk, user=request.user)
    if request.method == 'POST':
        alias.is_active   = False
        alias.destroyed_at = timezone.now()
        alias.save()
        messages.success(
            request, f'Alias {alias.address} destruido correctamente.',
        )
    return redirect('alias_list')
