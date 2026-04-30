"""
HISTÓRICO de migraciones del proyecto monolítico (app/) anterior a la
refactorización a arquitectura modular en capas.

Esta carpeta NO es 'migrations/' — Django NO la considera como migraciones
activas. Se conserva como referencia/auditoría del esquema de BD que se
fue construyendo a lo largo del desarrollo (0001 → 0014).

Las migraciones activas viven ahora en cada app:
  apps/accounts/migrations/
  apps/aliases/migrations/
  apps/mail/migrations/
  apps/sandbox/migrations/
  apps/notifications/migrations/

Cuando se reseteó la BD durante la refactorización, se generaron
migraciones iniciales limpias por app con `makemigrations`.
"""
