"""
Configuration de l'application inventory - GESTORE
"""
from django.apps import AppConfig


class InventoryConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.inventory'
    verbose_name = 'Gestion des Stocks'
    
    def ready(self):
        """
        Code à exécuter au démarrage de l'application
        """
        # Import des signaux si nécessaire
        # import apps.inventory.signals
        pass