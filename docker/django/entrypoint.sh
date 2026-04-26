#!/bin/sh

echo "Esperando a que PostgreSQL esté listo..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "PostgreSQL está listo!"

python manage.py migrate --noinput || echo "Migraciones ya aplicadas o error (continuando)"
python manage.py collectstatic --noinput || true

exec "$@"