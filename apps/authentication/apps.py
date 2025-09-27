"""
Configuration de l'application authentication - GESTORE
"""
from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.authentication'
    verbose_name = 'Authentification et utilisateurs'

    def ready(self):
        """
        Importer les signaux quand l'app est prête
        """
        import apps.authentication.signals  # noqa