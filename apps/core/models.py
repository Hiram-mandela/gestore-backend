"""
Modèles de base pour l'application core - GESTORE
Ces modèles abstraits sont utilisés par toutes les autres applications
"""
import uuid
from django.db import models
from django.utils import timezone


class TimestampedModel(models.Model):
    """
    Modèle abstrait qui ajoute automatiquement des timestamps
    de création et de modification à tous les modèles
    """
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Date de création",
        help_text="Date et heure de création automatique"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="Date de modification", 
        help_text="Date et heure de dernière modification automatique"
    )

    class Meta:
        abstract = True


class UUIDModel(models.Model):
    """
    Modèle abstrait qui utilise UUID comme clé primaire
    Garantit l'unicité même en cas de synchronisation multi-bases
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="Identifiant unique",
        help_text="Identifiant UUID unique généré automatiquement"
    )

    class Meta:
        abstract = True


class SoftDeleteModel(models.Model):
    """
    Modèle abstrait pour la suppression logique
    Les enregistrements ne sont jamais vraiment supprimés
    """
    is_deleted = models.BooleanField(
        default=False,
        verbose_name="Supprimé",
        help_text="Marque l'enregistrement comme supprimé sans le supprimer physiquement"
    )
    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Date de suppression",
        help_text="Date et heure de suppression logique"
    )

    def soft_delete(self):
        """Marque l'enregistrement comme supprimé"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()

    def restore(self):
        """Restaure un enregistrement supprimé logiquement"""
        self.is_deleted = False
        self.deleted_at = None
        self.save()

    class Meta:
        abstract = True


class SyncModel(models.Model):
    """
    Modèle abstrait pour la synchronisation entre bases
    Suit l'état de synchronisation de chaque enregistrement
    """
    SYNC_STATUS_CHOICES = [
        ('synced', 'Synchronisé'),
        ('pending', 'En attente de synchronisation'),
        ('conflict', 'Conflit de synchronisation'),
        ('error', 'Erreur de synchronisation'),
    ]
    
    sync_status = models.CharField(
        max_length=20,
        choices=SYNC_STATUS_CHOICES,
        default='pending',
        verbose_name="Statut de synchronisation",
        help_text="État de synchronisation avec la base distante"
    )
    last_sync_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Dernière synchronisation",
        help_text="Date et heure de dernière synchronisation réussie"
    )
    sync_hash = models.CharField(
        max_length=64,
        blank=True,
        verbose_name="Hash de synchronisation",
        help_text="Hash MD5 des données pour détecter les modifications"
    )

    def mark_for_sync(self):
        """Marque l'enregistrement pour synchronisation"""
        self.sync_status = 'pending'
        self.save(update_fields=['sync_status'])

    def mark_synced(self):
        """Marque l'enregistrement comme synchronisé"""
        self.sync_status = 'synced'
        self.last_sync_at = timezone.now()
        self.save(update_fields=['sync_status', 'last_sync_at'])

    class Meta:
        abstract = True


class BaseModel(UUIDModel, TimestampedModel, SoftDeleteModel, SyncModel):
    """
    Modèle de base principal combinant tous les comportements
    Utilisé par la plupart des modèles métier de GESTORE
    """
    class Meta:
        abstract = True


class AuditableModel(BaseModel):
    """
    Modèle avec audit trail complet
    Enregistre qui a créé/modifié chaque enregistrement
    """
    created_by = models.ForeignKey(
        'authentication.User',
        on_delete=models.PROTECT,
        related_name='%(class)s_created',
        null=True,
        blank=True,
        verbose_name="Créé par",
        help_text="Utilisateur qui a créé cet enregistrement"
    )
    updated_by = models.ForeignKey(
        'authentication.User',
        on_delete=models.PROTECT,
        related_name='%(class)s_updated', 
        null=True,
        blank=True,
        verbose_name="Modifié par",
        help_text="Utilisateur qui a modifié cet enregistrement en dernier"
    )

    class Meta:
        abstract = True


class CodedModel(models.Model):
    """
    Modèle abstrait pour les entités avec code unique
    Utilisé pour articles, fournisseurs, etc.
    """
    code = models.CharField(
        max_length=50,
        unique=True,
        verbose_name="Code",
        help_text="Code unique identifiant cet élément"
    )
    
    class Meta:
        abstract = True


class NamedModel(models.Model):
    """
    Modèle abstrait pour les entités avec nom/désignation
    """
    name = models.CharField(
        max_length=200,
        verbose_name="Nom",
        help_text="Nom ou désignation"
    )
    description = models.TextField(
        blank=True,
        verbose_name="Description",
        help_text="Description détaillée (optionnelle)"
    )
    
    def __str__(self):
        return self.name
    
    class Meta:
        abstract = True


class ActivableModel(models.Model):
    """
    Modèle abstrait pour les entités activables/désactivables
    """
    is_active = models.BooleanField(
        default=True,
        verbose_name="Actif",
        help_text="Indique si cet élément est actif"
    )
    
    class Meta:
        abstract = True


class PricedModel(models.Model):
    """
    Modèle abstrait pour les entités avec prix
    """
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Prix",
        help_text="Prix en devise locale"
    )
    
    class Meta:
        abstract = True


class OrderedModel(models.Model):
    """
    Modèle abstrait pour les entités ordonnables
    """
    order = models.IntegerField(
        default=0,
        verbose_name="Ordre",
        help_text="Ordre d'affichage"
    )
    
    class Meta:
        abstract = True
        ordering = ['order']