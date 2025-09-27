"""
Modèles de synchronisation pour GESTORE - CORRECTION DES RELATIONS
Système de synchronisation online/offline et résolution de conflits
"""
import hashlib
import json
from django.db import models
from django.core.validators import MinValueValidator
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from apps.core.models import BaseModel, AuditableModel, NamedModel

User = get_user_model()


class SyncNode(BaseModel, NamedModel):
    """
    Nœuds de synchronisation
    Représente chaque instance de GESTORE (serveur, client)
    """
    NODE_TYPES = [
        ('server', 'Serveur principal'),
        ('client', 'Client desktop'),
        ('mobile', 'Application mobile'),
        ('backup', 'Serveur de sauvegarde'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Actif'),
        ('inactive', 'Inactif'),
        ('maintenance', 'Maintenance'),
        ('error', 'Erreur'),
    ]
    
    node_type = models.CharField(
        max_length=20,
        choices=NODE_TYPES,
        verbose_name="Type de nœud"
    )
    
    node_id = models.CharField(
        max_length=64,
        unique=True,
        verbose_name="Identifiant unique du nœud",
        help_text="Identifiant généré automatiquement"
    )
    
    # Informations de connexion
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name="Adresse IP"
    )
    
    port = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MinValueValidator(65535)],
        verbose_name="Port"
    )
    
    api_endpoint = models.URLField(
        blank=True,
        verbose_name="Endpoint API",
        help_text="URL complète de l'API de ce nœud"
    )
    
    # Authentification
    api_key = models.CharField(
        max_length=128,
        unique=True,
        verbose_name="Clé API",
        help_text="Clé d'authentification pour la synchronisation"
    )
    
    # Statut
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active',
        verbose_name="Statut"
    )
    
    # Informations système
    version = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Version GESTORE"
    )
    
    os_info = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Informations OS"
    )
    
    hardware_fingerprint = models.CharField(
        max_length=64,
        blank=True,
        verbose_name="Empreinte matérielle"
    )
    
    # Synchronisation
    last_sync_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Dernière synchronisation"
    )
    
    last_seen_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Dernière activité"
    )
    
    # Configuration
    sync_enabled = models.BooleanField(
        default=True,
        verbose_name="Synchronisation activée"
    )
    
    sync_priority = models.IntegerField(
        default=50,
        validators=[MinValueValidator(1), MinValueValidator(100)],
        verbose_name="Priorité de synchronisation",
        help_text="1 = priorité maximale, 100 = priorité minimale"
    )
    
    # Statistiques
    total_syncs = models.IntegerField(
        default=0,
        verbose_name="Nombre total de synchronisations"
    )
    
    successful_syncs = models.IntegerField(
        default=0,
        verbose_name="Synchronisations réussies"
    )
    
    failed_syncs = models.IntegerField(
        default=0,
        verbose_name="Synchronisations échouées"
    )
    
    def save(self, *args, **kwargs):
        if not self.node_id:
            # Générer un ID unique pour le nœud
            import uuid
            import socket
            hostname = socket.gethostname()
            unique_string = f"{hostname}-{uuid.uuid4()}-{timezone.now().isoformat()}"
            self.node_id = hashlib.sha256(unique_string.encode()).hexdigest()
        
        if not self.api_key:
            # Générer une clé API unique
            import secrets
            self.api_key = secrets.token_urlsafe(64)
        
        super().save(*args, **kwargs)
    
    def get_success_rate(self):
        """Calcule le taux de succès de synchronisation"""
        if self.total_syncs > 0:
            return (self.successful_syncs / self.total_syncs) * 100
        return 0
    
    def is_online(self, timeout_minutes=15):
        """Vérifie si le nœud est en ligne"""
        if not self.last_seen_at:
            return False
        
        cutoff = timezone.now() - timezone.timedelta(minutes=timeout_minutes)
        return self.last_seen_at > cutoff
    
    def ping(self):
        """Met à jour le timestamp de dernière activité"""
        self.last_seen_at = timezone.now()
        self.save(update_fields=['last_seen_at'])

    class Meta:
        db_table = 'sync_node'
        verbose_name = 'Nœud de synchronisation'
        verbose_name_plural = 'Nœuds de synchronisation'
        ordering = ['node_type', 'name']


class SyncSession(AuditableModel):
    """
    Sessions de synchronisation
    Enregistre chaque session de sync entre nœuds
    """
    SESSION_STATUS = [
        ('started', 'Démarrée'),
        ('running', 'En cours'),
        ('completed', 'Terminée'),
        ('failed', 'Échouée'),
        ('cancelled', 'Annulée'),
    ]
    
    SYNC_DIRECTIONS = [
        ('pull', 'Réception'),
        ('push', 'Envoi'),
        ('bidirectional', 'Bidirectionnelle'),
    ]
    
    # Nœuds impliqués
    source_node = models.ForeignKey(
        SyncNode,
        on_delete=models.CASCADE,
        related_name='outgoing_sessions',
        verbose_name="Nœud source"
    )
    
    target_node = models.ForeignKey(
        SyncNode,
        on_delete=models.CASCADE,
        related_name='incoming_sessions',
        verbose_name="Nœud cible"
    )
    
    # Configuration
    direction = models.CharField(
        max_length=20,
        choices=SYNC_DIRECTIONS,
        verbose_name="Direction"
    )
    
    status = models.CharField(
        max_length=20,
        choices=SESSION_STATUS,
        default='started',
        verbose_name="Statut"
    )
    
    # Timing
    started_at = models.DateTimeField(
        default=timezone.now,
        verbose_name="Démarrée à"
    )
    
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Terminée à"
    )
    
    duration = models.DurationField(
        null=True,
        blank=True,
        verbose_name="Durée"
    )
    
    # Statistiques
    records_processed = models.IntegerField(
        default=0,
        verbose_name="Enregistrements traités"
    )
    
    records_created = models.IntegerField(
        default=0,
        verbose_name="Enregistrements créés"
    )
    
    records_updated = models.IntegerField(
        default=0,
        verbose_name="Enregistrements mis à jour"
    )
    
    records_deleted = models.IntegerField(
        default=0,
        verbose_name="Enregistrements supprimés"
    )
    
    conflicts_detected = models.IntegerField(
        default=0,
        verbose_name="Conflits détectés"
    )
    
    conflicts_resolved = models.IntegerField(
        default=0,
        verbose_name="Conflits résolus"
    )
    
    # Données transférées
    data_size_bytes = models.BigIntegerField(
        default=0,
        verbose_name="Taille des données (octets)"
    )
    
    # Erreurs
    error_message = models.TextField(
        blank=True,
        verbose_name="Message d'erreur"
    )
    
    error_details = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Détails des erreurs"
    )
    
    # Métadonnées
    sync_metadata = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Métadonnées de synchronisation"
    )
    
    def complete_session(self):
        """Marque la session comme terminée"""
        self.completed_at = timezone.now()
        self.duration = self.completed_at - self.started_at
        self.status = 'completed'
        self.save()
        
        # Mettre à jour les statistiques des nœuds
        self.source_node.total_syncs += 1
        self.source_node.successful_syncs += 1
        self.source_node.last_sync_at = self.completed_at
        self.source_node.save()
        
        if self.target_node != self.source_node:
            self.target_node.total_syncs += 1
            self.target_node.successful_syncs += 1
            self.target_node.last_sync_at = self.completed_at
            self.target_node.save()
    
    def fail_session(self, error_message=""):
        """Marque la session comme échouée"""
        self.completed_at = timezone.now()
        self.duration = self.completed_at - self.started_at
        self.status = 'failed'
        self.error_message = error_message
        self.save()
        
        # Mettre à jour les statistiques des nœuds
        self.source_node.total_syncs += 1
        self.source_node.failed_syncs += 1
        self.source_node.save()
        
        if self.target_node != self.source_node:
            self.target_node.total_syncs += 1
            self.target_node.failed_syncs += 1
            self.target_node.save()
    
    def get_data_size_mb(self):
        """Retourne la taille des données en MB"""
        return round(self.data_size_bytes / (1024 * 1024), 2)

    class Meta:
        db_table = 'sync_session'
        verbose_name = 'Session de synchronisation'
        verbose_name_plural = 'Sessions de synchronisation'
        ordering = ['-started_at']


class SyncOperation(BaseModel):
    """
    Opérations de synchronisation individuelles
    Détail des modifications pour chaque enregistrement
    """
    OPERATION_TYPES = [
        ('create', 'Création'),
        ('update', 'Mise à jour'),
        ('delete', 'Suppression'),
        ('conflict', 'Conflit'),
    ]
    
    OPERATION_STATUS = [
        ('pending', 'En attente'),
        ('processing', 'En cours'),
        ('completed', 'Terminée'),
        ('failed', 'Échouée'),
        ('skipped', 'Ignorée'),
    ]
    
    session = models.ForeignKey(
        SyncSession,
        on_delete=models.CASCADE,
        related_name='operations',
        verbose_name="Session"
    )
    
    # Enregistrement concerné
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        verbose_name="Type de contenu"
    )
    
    object_id = models.UUIDField(
        verbose_name="ID de l'objet"
    )
    
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Opération
    operation_type = models.CharField(
        max_length=20,
        choices=OPERATION_TYPES,
        verbose_name="Type d'opération"
    )
    
    status = models.CharField(
        max_length=20,
        choices=OPERATION_STATUS,
        default='pending',
        verbose_name="Statut"
    )
    
    # Données
    local_data = models.JSONField(
        null=True,
        blank=True,
        verbose_name="Données locales",
        help_text="État local de l'enregistrement"
    )
    
    remote_data = models.JSONField(
        null=True,
        blank=True,
        verbose_name="Données distantes",
        help_text="État distant de l'enregistrement"
    )
    
    merged_data = models.JSONField(
        null=True,
        blank=True,
        verbose_name="Données fusionnées",
        help_text="Résultat après résolution de conflit"
    )
    
    # Hash pour détecter les modifications
    local_hash = models.CharField(
        max_length=64,
        blank=True,
        verbose_name="Hash local"
    )
    
    remote_hash = models.CharField(
        max_length=64,
        blank=True,
        verbose_name="Hash distant"
    )
    
    # Timestamps
    local_timestamp = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Timestamp local"
    )
    
    remote_timestamp = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Timestamp distant"
    )
    
    # Conflit
    is_conflict = models.BooleanField(
        default=False,
        verbose_name="Conflit détecté"
    )
    
    conflict_resolution_strategy = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Stratégie de résolution de conflit",
        help_text="Méthode utilisée pour résoudre le conflit"
    )
    
    # Erreur
    error_message = models.TextField(
        blank=True,
        verbose_name="Message d'erreur"
    )
    
    # Ordre de traitement
    sequence = models.IntegerField(
        default=0,
        verbose_name="Séquence",
        help_text="Ordre de traitement dans la session"
    )
    
    def calculate_hash(self, data):
        """Calcule le hash MD5 des données"""
        if not data:
            return ""
        
        # Normaliser les données pour un hash cohérent
        normalized = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def detect_conflict(self):
        """Détecte s'il y a un conflit entre les données locales et distantes"""
        if not self.local_data or not self.remote_data:
            return False
        
        # Conflit si les deux ont été modifiées après la dernière sync
        if (self.local_timestamp and self.remote_timestamp and 
            self.local_hash != self.remote_hash):
            self.is_conflict = True
            return True
        
        return False

    class Meta:
        db_table = 'sync_operation'
        verbose_name = 'Opération de synchronisation'
        verbose_name_plural = 'Opérations de synchronisation'
        ordering = ['session', 'sequence']


class ConflictResolution(BaseModel):
    """
    Résolutions de conflits
    Historique des conflits et de leur résolution
    """
    RESOLUTION_STRATEGIES = [
        ('local_wins', 'Version locale gagne'),
        ('remote_wins', 'Version distante gagne'),
        ('latest_wins', 'Version la plus récente gagne'),
        ('manual', 'Résolution manuelle'),
        ('merge', 'Fusion automatique'),
        ('user_choice', 'Choix utilisateur'),
    ]
    
    RESOLUTION_STATUS = [
        ('pending', 'En attente'),
        ('resolved', 'Résolu'),
        ('failed', 'Échec'),
    ]
    
    # CORRECTION: Changement du related_name pour éviter le conflit
    sync_operation = models.OneToOneField(
        SyncOperation,
        on_delete=models.CASCADE,
        related_name='resolution',  # CHANGÉ de 'conflict_resolution' à 'resolution'
        verbose_name="Opération de sync"
    )
    
    # Détection du conflit
    detected_at = models.DateTimeField(
        default=timezone.now,
        verbose_name="Détecté le"
    )
    
    conflict_type = models.CharField(
        max_length=50,
        verbose_name="Type de conflit",
        help_text="Description du type de conflit détecté"
    )
    
    # Résolution
    resolution_strategy = models.CharField(
        max_length=20,
        choices=RESOLUTION_STRATEGIES,
        verbose_name="Stratégie de résolution"
    )
    
    status = models.CharField(
        max_length=20,
        choices=RESOLUTION_STATUS,
        default='pending',
        verbose_name="Statut"
    )
    
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Résolu le"
    )
    
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Résolu par"
    )
    
    # Données conflictuelles
    field_conflicts = models.JSONField(
        default=dict,
        verbose_name="Conflits par champ",
        help_text="Détail des conflits par champ"
    )
    
    # Résolution finale
    final_data = models.JSONField(
        null=True,
        blank=True,
        verbose_name="Données finales",
        help_text="Données après résolution du conflit"
    )
    
    # Notes
    resolution_notes = models.TextField(
        blank=True,
        verbose_name="Notes de résolution"
    )
    
    def auto_resolve(self):
        """Tente une résolution automatique du conflit"""
        if self.resolution_strategy == 'latest_wins':
            # La version avec le timestamp le plus récent gagne
            if (self.sync_operation.local_timestamp and 
                self.sync_operation.remote_timestamp):
                
                if (self.sync_operation.local_timestamp > 
                    self.sync_operation.remote_timestamp):
                    self.final_data = self.sync_operation.local_data
                else:
                    self.final_data = self.sync_operation.remote_data
                
                self.status = 'resolved'
                self.resolved_at = timezone.now()
                self.save()
                return True
        
        elif self.resolution_strategy == 'local_wins':
            self.final_data = self.sync_operation.local_data
            self.status = 'resolved'
            self.resolved_at = timezone.now()
            self.save()
            return True
        
        elif self.resolution_strategy == 'remote_wins':
            self.final_data = self.sync_operation.remote_data
            self.status = 'resolved'
            self.resolved_at = timezone.now()
            self.save()
            return True
        
        return False

    class Meta:
        db_table = 'sync_conflict_resolution'
        verbose_name = 'Résolution de conflit'
        verbose_name_plural = 'Résolutions de conflit'
        ordering = ['-detected_at']


class SyncQueue(BaseModel):
    """
    File d'attente de synchronisation
    Enregistrements en attente de synchronisation
    """
    QUEUE_STATUS = [
        ('pending', 'En attente'),
        ('processing', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
        ('retry', 'Nouvelle tentative'),
    ]
    
    PRIORITY_LEVELS = [
        ('high', 'Haute'),
        ('normal', 'Normale'),
        ('low', 'Basse'),
    ]
    
    # Nœud source
    node = models.ForeignKey(
        SyncNode,
        on_delete=models.CASCADE,
        related_name='sync_queue',
        verbose_name="Nœud"
    )
    
    # Enregistrement à synchroniser
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        verbose_name="Type de contenu"
    )
    
    object_id = models.UUIDField(
        verbose_name="ID de l'objet"
    )
    
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Configuration
    operation = models.CharField(
        max_length=20,
        choices=SyncOperation.OPERATION_TYPES,
        verbose_name="Opération"
    )
    
    priority = models.CharField(
        max_length=10,
        choices=PRIORITY_LEVELS,
        default='normal',
        verbose_name="Priorité"
    )
    
    status = models.CharField(
        max_length=20,
        choices=QUEUE_STATUS,
        default='pending',
        verbose_name="Statut"
    )
    
    # Données
    data_snapshot = models.JSONField(
        null=True,
        blank=True,
        verbose_name="Snapshot des données",
        help_text="État des données au moment de la mise en queue"
    )
    
    # Tentatives
    retry_count = models.IntegerField(
        default=0,
        verbose_name="Nombre de tentatives"
    )
    
    max_retries = models.IntegerField(
        default=3,
        verbose_name="Tentatives maximum"
    )
    
    next_retry_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Prochaine tentative"
    )
    
    # Timestamp
    queued_at = models.DateTimeField(
        default=timezone.now,
        verbose_name="Mis en queue le"
    )
    
    processed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Traité le"
    )
    
    # Erreur
    last_error = models.TextField(
        blank=True,
        verbose_name="Dernière erreur"
    )
    
    def should_retry(self):
        """Détermine si une nouvelle tentative doit être faite"""
        return (
            self.status in ['failed', 'retry'] and
            self.retry_count < self.max_retries and
            (not self.next_retry_at or self.next_retry_at <= timezone.now())
        )
    
    def schedule_retry(self, delay_minutes=5):
        """Programme une nouvelle tentative"""
        self.retry_count += 1
        self.next_retry_at = timezone.now() + timezone.timedelta(minutes=delay_minutes)
        self.status = 'retry'
        self.save()

    class Meta:
        db_table = 'sync_queue'
        verbose_name = 'File de synchronisation'
        verbose_name_plural = 'File de synchronisation'
        ordering = ['-priority', 'queued_at']
        indexes = [
            models.Index(fields=['status', 'priority']),
            models.Index(fields=['node', 'status']),
            models.Index(fields=['next_retry_at']),
        ]


class SyncConfiguration(BaseModel, NamedModel):
    """
    Configuration de synchronisation
    Paramètres et règles de synchronisation
    """
    # Tables à synchroniser
    enabled_models = models.JSONField(
        default=list,
        verbose_name="Modèles activés",
        help_text="Liste des modèles Django à synchroniser"
    )
    
    excluded_fields = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Champs exclus",
        help_text="Champs à exclure par modèle"
    )
    
    # Stratégies de résolution de conflits par modèle
    conflict_strategies = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Stratégies de conflit",
        help_text="Stratégie de résolution par modèle"
    )
    
    # Filtres de synchronisation
    sync_filters = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Filtres de synchronisation",
        help_text="Filtres à appliquer par modèle"
    )
    
    # Configuration temporelle
    sync_interval_minutes = models.IntegerField(
        default=15,
        validators=[MinValueValidator(1)],
        verbose_name="Intervalle de sync (minutes)"
    )
    
    max_records_per_batch = models.IntegerField(
        default=1000,
        validators=[MinValueValidator(1)],
        verbose_name="Enregistrements max par lot"
    )
    
    # Configuration réseau
    connection_timeout_seconds = models.IntegerField(
        default=30,
        validators=[MinValueValidator(1)],
        verbose_name="Timeout connexion (secondes)"
    )
    
    retry_delay_minutes = models.IntegerField(
        default=5,
        validators=[MinValueValidator(1)],
        verbose_name="Délai entre tentatives (minutes)"
    )
    
    # Sécurité
    encryption_enabled = models.BooleanField(
        default=True,
        verbose_name="Chiffrement activé"
    )
    
    compression_enabled = models.BooleanField(
        default=True,
        verbose_name="Compression activée"
    )
    
    # Nettoyage automatique
    auto_cleanup_days = models.IntegerField(
        default=30,
        validators=[MinValueValidator(1)],
        verbose_name="Nettoyage auto (jours)",
        help_text="Supprimer les logs de sync après X jours"
    )
    
    # Status
    is_active = models.BooleanField(
        default=True,
        verbose_name="Configuration active"
    )

    class Meta:
        db_table = 'sync_configuration'
        verbose_name = 'Configuration de synchronisation'
        verbose_name_plural = 'Configurations de synchronisation'


class SyncLog(BaseModel):
    """
    Logs de synchronisation
    Journal détaillé des opérations de synchronisation
    """
    LOG_LEVELS = [
        ('debug', 'Debug'),
        ('info', 'Information'),
        ('warning', 'Avertissement'),
        ('error', 'Erreur'),
        ('critical', 'Critique'),
    ]
    
    session = models.ForeignKey(
        SyncSession,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='logs',
        verbose_name="Session"
    )
    
    node = models.ForeignKey(
        SyncNode,
        on_delete=models.CASCADE,
        related_name='logs',
        verbose_name="Nœud"
    )
    
    level = models.CharField(
        max_length=10,
        choices=LOG_LEVELS,
        verbose_name="Niveau"
    )
    
    message = models.TextField(
        verbose_name="Message"
    )
    
    # Contexte
    context = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Contexte",
        help_text="Informations contextuelles additionnelles"
    )
    
    # Performance
    execution_time_ms = models.IntegerField(
        null=True,
        blank=True,
        verbose_name="Temps d'exécution (ms)"
    )

    class Meta:
        db_table = 'sync_log'
        verbose_name = 'Log de synchronisation'
        verbose_name_plural = 'Logs de synchronisation'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['level', 'created_at']),
            models.Index(fields=['session', 'created_at']),
            models.Index(fields=['node', 'created_at']),
        ]