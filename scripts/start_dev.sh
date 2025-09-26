#!/bin/bash
# Script de démarrage pour développement

echo "🚀 Démarrage de GESTORE Backend - Développement"

# Activer l'environnement virtuel
source venv/Scripts/activate

# Variables d'environnement
export DJANGO_SETTINGS_MODULE=gestore.settings.development

# Migrations
echo "📊 Application des migrations..."
python manage.py makemigrations
python manage.py migrate

# Collecte des fichiers statiques
echo "📁 Collecte des fichiers statiques..."
python manage.py collectstatic --noinput

# Création d'un superuser si nécessaire
echo "👤 Vérification du superuser..."
python manage.py shell << PYTHON
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    print("Création du superuser admin...")
    User.objects.create_superuser('admin', 'admin@gestore.com', 'admin123')
PYTHON

# Démarrage du serveur
echo "🌐 Démarrage du serveur Django..."
python manage.py runserver 0.0.0.0:8000
