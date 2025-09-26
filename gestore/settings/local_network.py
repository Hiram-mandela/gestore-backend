"""
Configuration réseau local pour GESTORE
"""
from .base import *

DEBUG = True

# Autoriser toutes les IPs du réseau local
ALLOWED_HOSTS = ['*']

# Database SQLite pour réseau local simple
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'gestore_local.db',
    }
}

# Cache simple en mémoire
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# CORS très permissif pour réseau local
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
