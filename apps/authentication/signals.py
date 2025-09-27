"""
Signaux pour l'application authentication - GESTORE
Création automatique des profils utilisateur et autres automatisations
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Signal pour créer automatiquement un UserProfile quand un User est créé
    """
    if created:
        # Créer le profil seulement s'il n'existe pas déjà
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Signal pour sauvegarder le profil quand l'utilisateur est sauvegardé
    """
    if hasattr(instance, 'profile'):
        instance.profile.save()