"""
Modèles de gestion des licences pour GESTORE
Système complet de licences avec protection anti-piratage
"""
import hashlib
import secrets
import socket
import platform
from decimal import Decimal
from datetime import timedelta
from django.db import models
from django.core.validators import MinValueValidator, RegexValidator
from django.utils import timezone
from django.contrib.auth import get_user_model
from apps.core.models import BaseModel, AuditableModel, NamedModel, ActivableModel

User = get_user_model()


class LicenseType(BaseModel, NamedModel, ActivableModel):
    """
    Types de licences GESTORE
    Définit les différents niveaux de licence disponibles
    """
    LICENSE_LEVELS = [
        ('starter', 'Starter'),
        ('professional', 'Professional'),
        ('enterprise', 'Enterprise'),
        ('custom', 'Personnalisée'),
    ]
    
    level = models.CharField(
        max_length=20,
        choices=LICENSE_LEVELS,
        unique=True,
        verbose_name="Niveau de licence"
    )
    
    # Limitations
    max_users = models.IntegerField(
        validators=[MinValueValidator(1)],
        verbose_name="Nombre maximum d'utilisateurs"
    )
    
    max_articles = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        verbose_name="Nombre maximum d'articles",
        help_text="NULL = illimité"
    )
    
    max_transactions_per_month = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        verbose_name="Transactions max par mois",
        help_text="NULL = illimité"
    )
    
    max_storage_mb = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        verbose_name="Stockage maximum (MB)",
        help_text="NULL = illimité"
    )
    
    # Modules autorisés
    modules_included = models.JSONField(
        default=list,
        verbose_name="Modules inclus",
        help_text="Liste des modules autorisés"
    )
    
    # Fonctionnalités
    features_included = models.JSONField(
        default=list,
        verbose_name="Fonctionnalités incluses",
        help_text="Liste des fonctionnalités autorisées"
    )
    
    # Support
    support_level = models.CharField(
        max_length=20,
        choices=[
            ('basic', 'Support de base'),
            ('standard', 'Support standard'),
            ('priority', 'Support prioritaire'),
            ('premium', 'Support premium 24/7'),
        ],
        default='basic',
        verbose_name="Niveau de support"
    )
    
    # Synchronisation
    allows_sync = models.BooleanField(
        default=True,
        verbose_name="Synchronisation autorisée"
    )
    
    allows_multi_site = models.BooleanField(
        default=False,
        verbose_name="Multi-sites autorisé"
    )
    
    allows_api_access = models.BooleanField(
        default=False,
        verbose_name="Accès API autorisé"
    )
    
    # Tarification
    price_monthly = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=0,
        verbose_name="Prix mensuel"
    )
    
    price_yearly = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=0,
        verbose_name="Prix annuel"
    )
    
    # Durée par défaut
    default_duration_days = models.IntegerField(
        default=365,  # 1 an
        validators=[MinValueValidator(1)],
        verbose_name="Durée par défaut (jours)"
    )

    class Meta:
        db_table = 'licensing_license_type'
        verbose_name = 'Type de licence'
        verbose_name_plural = 'Types de licence'
        ordering = ['level']


class Customer(BaseModel, NamedModel, ActivableModel):
    """
    Clients ayant acheté une licence
    """
    CUSTOMER_TYPES = [
        ('individual', 'Particulier'),
        ('company', 'Entreprise'),
        ('reseller', 'Revendeur'),
        ('government', 'Gouvernement'),
        ('ngo', 'ONG'),
    ]
    
    customer_type = models.CharField(
        max_length=20,
        choices=CUSTOMER_TYPES,
        default='company',
        verbose_name="Type de client"
    )
    
    customer_code = models.CharField(
        max_length=20,
        unique=True,
        verbose_name="Code client"
    )
    
    # Informations de contact
    company_name = models.CharField(
        max_length=200,
        blank=True,
        verbose_name="Nom de l'entreprise"
    )
    
    contact_name = models.CharField(
        max_length=100,
        verbose_name="Nom du contact principal"
    )
    
    email = models.EmailField(
        verbose_name="Email"
    )
    
    phone = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Téléphone"
    )
    
    # Adresse
    address = models.TextField(
        verbose_name="Adresse"
    )
    
    city = models.CharField(
        max_length=100,
        verbose_name="Ville"
    )
    
    postal_code = models.CharField(
        max_length=10,
        verbose_name="Code postal"
    )
    
    country = models.CharField(
        max_length=50,
        default='Côte d\'Ivoire',
        verbose_name="Pays"
    )
    
    # Informations fiscales
    tax_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro fiscal"
    )
    
    # Informations commerciales
    acquisition_date = models.DateField(
        default=timezone.now,
        verbose_name="Date d'acquisition"
    )
    
    acquisition_channel = models.CharField(
        max_length=50,
        choices=[
            ('direct', 'Vente directe'),
            ('reseller', 'Revendeur'),
            ('online', 'En ligne'),
            ('referral', 'Référence'),
            ('marketing', 'Campagne marketing'),
        ],
        default='direct',
        verbose_name="Canal d'acquisition"
    )
    
    # Statistiques
    total_licenses = models.IntegerField(
        default=0,
        verbose_name="Nombre total de licences"
    )
    
    active_licenses = models.IntegerField(
        default=0,
        verbose_name="Licences actives"
    )
    
    total_revenue = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        verbose_name="Chiffre d'affaires total"
    )
    
    def save(self, *args, **kwargs):
        if not self.customer_code:
            # Générer le code client
            last_customer = Customer.objects.filter(
                customer_code__isnull=False
            ).order_by('customer_code').last()
            
            if last_customer and last_customer.customer_code:
                try:
                    last_number = int(last_customer.customer_code.replace('CUST', ''))
                    self.customer_code = f'CUST{last_number + 1:05d}'
                except ValueError:
                    self.customer_code = 'CUST00001'
            else:
                self.customer_code = 'CUST00001'
        
        super().save(*args, **kwargs)
    
    def update_license_stats(self):
        """Met à jour les statistiques de licences"""
        licenses = self.licenses.all()
        self.total_licenses = licenses.count()
        self.active_licenses = licenses.filter(
            status='active',
            expires_at__gt=timezone.now()
        ).count()
        self.total_revenue = sum(
            license.purchase_price for license in licenses 
            if license.purchase_price
        )
        self.save(update_fields=['total_licenses', 'active_licenses', 'total_revenue'])

    class Meta:
        db_table = 'licensing_customer'
        verbose_name = 'Client licence'
        verbose_name_plural = 'Clients licence'
        ordering = ['company_name', 'contact_name']


class License(AuditableModel):
    """
    Licences individuelles
    Chaque licence correspond à une installation GESTORE
    """
    LICENSE_STATUS = [
        ('pending', 'En attente'),
        ('active', 'Active'),
        ('suspended', 'Suspendue'),
        ('expired', 'Expirée'),
        ('revoked', 'Révoquée'),
        ('terminated', 'Résiliée'),
    ]
    
    # Identification
    license_key = models.CharField(
        max_length=64,
        unique=True,
        verbose_name="Clé de licence",
        help_text="Clé unique générée automatiquement"
    )
    
    # Client et type
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='licenses',
        verbose_name="Client"
    )
    
    license_type = models.ForeignKey(
        LicenseType,
        on_delete=models.PROTECT,
        verbose_name="Type de licence"
    )
    
    # Statut
    status = models.CharField(
        max_length=20,
        choices=LICENSE_STATUS,
        default='pending',
        verbose_name="Statut"
    )
    
    # Dates
    issued_at = models.DateTimeField(
        default=timezone.now,
        verbose_name="Émise le"
    )
    
    activated_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Activée le"
    )
    
    expires_at = models.DateTimeField(
        verbose_name="Expire le"
    )
    
    # Limitation personnalisée (override le type de licence)
    custom_max_users = models.IntegerField(
        null=True,
        blank=True,
        verbose_name="Utilisateurs max (personnalisé)"
    )
    
    custom_modules = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Modules personnalisés"
    )
    
    custom_features = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Fonctionnalités personnalisées"
    )
    
    # Installation
    installation_name = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Nom de l'installation",
        help_text="Nom donné à cette installation"
    )
    
    hardware_fingerprint = models.CharField(
        max_length=64,
        blank=True,
        verbose_name="Empreinte matérielle",
        help_text="Identifiant unique du matériel"
    )
    
    # Informations commerciales
    purchase_date = models.DateField(
        default=timezone.now,
        verbose_name="Date d'achat"
    )
    
    purchase_price = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Prix d'achat"
    )
    
    invoice_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro de facture"
    )
    
    # Maintenance et support
    maintenance_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Maintenance expire le"
    )
    
    support_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Support expire le"
    )
    
    # Métadonnées
    notes = models.TextField(
        blank=True,
        verbose_name="Notes internes"
    )
    
    # Signature cryptographique
    license_signature = models.TextField(
        blank=True,
        verbose_name="Signature de licence",
        help_text="Signature cryptographique pour validation"
    )
    
    def save(self, *args, **kwargs):
        if not self.license_key:
            # Générer une clé de licence unique
            while True:
                key = self.generate_license_key()
                if not License.objects.filter(license_key=key).exists():
                    self.license_key = key
                    break
        
        # Définir la date d'expiration si pas définie
        if not self.expires_at:
            duration = timedelta(days=self.license_type.default_duration_days)
            self.expires_at = self.issued_at + duration
        
        super().save(*args, **kwargs)
    
    def generate_license_key(self):
        """Génère une clé de licence unique"""
        # Format: GEST-XXXX-XXXX-XXXX-XXXX
        segments = []
        for _ in range(4):
            segment = secrets.token_hex(2).upper()
            segments.append(segment)
        return f"GEST-{'-'.join(segments)}"
    
    def is_valid(self):
        """Vérifie si la licence est valide"""
        now = timezone.now()
        return (
            self.status == 'active' and
            self.expires_at > now and
            (not self.maintenance_expires_at or self.maintenance_expires_at > now)
        )
    
    def is_expired(self):
        """Vérifie si la licence est expirée"""
        return timezone.now() > self.expires_at
    
    def days_until_expiry(self):
        """Retourne le nombre de jours avant expiration"""
        if self.expires_at:
            delta = self.expires_at - timezone.now()
            return delta.days
        return 0
    
    def activate(self, hardware_fingerprint=None):
        """Active la licence"""
        if self.status == 'pending':
            self.status = 'active'
            self.activated_at = timezone.now()
            if hardware_fingerprint:
                self.hardware_fingerprint = hardware_fingerprint
            self.save()
            return True
        return False
    
    def suspend(self, reason=""):
        """Suspend la licence"""
        if self.status == 'active':
            self.status = 'suspended'
            if reason:
                self.notes += f"\nSuspendue: {reason} ({timezone.now()})"
            self.save()
            return True
        return False
    
    def revoke(self, reason=""):
        """Révoque la licence"""
        self.status = 'revoked'
        if reason:
            self.notes += f"\nRévoquée: {reason} ({timezone.now()})"
        self.save()
    
    def get_max_users(self):
        """Retourne le nombre maximum d'utilisateurs autorisés"""
        return self.custom_max_users or self.license_type.max_users
    
    def get_allowed_modules(self):
        """Retourne la liste des modules autorisés"""
        if self.custom_modules:
            return self.custom_modules
        return self.license_type.modules_included
    
    def get_allowed_features(self):
        """Retourne la liste des fonctionnalités autorisées"""
        if self.custom_features:
            return self.custom_features
        return self.license_type.features_included

    class Meta:
        db_table = 'licensing_license'
        verbose_name = 'Licence'
        verbose_name_plural = 'Licences'
        ordering = ['-issued_at']
        indexes = [
            models.Index(fields=['license_key']),
            models.Index(fields=['customer', 'status']),
            models.Index(fields=['status', 'expires_at']),
        ]


class LicenseActivation(BaseModel):
    """
    Activations de licence
    Historique des activations et tentatives d'activation
    """
    ACTIVATION_STATUS = [
        ('success', 'Réussie'),
        ('failed', 'Échouée'),
        ('blocked', 'Bloquée'),
        ('revoked', 'Révoquée'),
    ]
    
    license = models.ForeignKey(
        License,
        on_delete=models.CASCADE,
        related_name='activations',
        verbose_name="Licence"
    )
    
    status = models.CharField(
        max_length=20,
        choices=ACTIVATION_STATUS,
        verbose_name="Statut"
    )
    
    # Informations système
    hardware_fingerprint = models.CharField(
        max_length=64,
        verbose_name="Empreinte matérielle"
    )
    
    machine_name = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Nom de la machine"
    )
    
    os_info = models.CharField(
        max_length=200,
        blank=True,
        verbose_name="Informations OS"
    )
    
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name="Adresse IP"
    )
    
    # Informations GESTORE
    gestore_version = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Version GESTORE"
    )
    
    # Timestamps
    activation_date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Date d'activation"
    )
    
    last_heartbeat = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Dernier heartbeat"
    )
    
    # Détails de l'échec
    failure_reason = models.TextField(
        blank=True,
        verbose_name="Raison de l'échec"
    )
    
    def is_recent_heartbeat(self, hours=24):
        """Vérifie si le heartbeat est récent"""
        if not self.last_heartbeat:
            return False
        
        cutoff = timezone.now() - timedelta(hours=hours)
        return self.last_heartbeat > cutoff
    
    def send_heartbeat(self):
        """Met à jour le heartbeat"""
        self.last_heartbeat = timezone.now()
        self.save(update_fields=['last_heartbeat'])

    class Meta:
        db_table = 'licensing_activation'
        verbose_name = 'Activation de licence'
        verbose_name_plural = 'Activations de licence'
        ordering = ['-activation_date']


class LicenseUsage(BaseModel):
    """
    Utilisation des licences
    Statistiques d'utilisation pour le monitoring
    """
    license = models.ForeignKey(
        License,
        on_delete=models.CASCADE,
        related_name='usage_stats',
        verbose_name="Licence"
    )
    
    # Période de mesure
    period_start = models.DateTimeField(
        verbose_name="Début de période"
    )
    
    period_end = models.DateTimeField(
        verbose_name="Fin de période"
    )
    
    # Utilisateurs
    active_users = models.IntegerField(
        default=0,
        verbose_name="Utilisateurs actifs"
    )
    
    peak_users = models.IntegerField(
        default=0,
        verbose_name="Pic d'utilisateurs"
    )
    
    # Articles
    total_articles = models.IntegerField(
        default=0,
        verbose_name="Nombre d'articles"
    )
    
    # Transactions
    transactions_count = models.IntegerField(
        default=0,
        verbose_name="Nombre de transactions"
    )
    
    sales_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0,
        verbose_name="Montant des ventes"
    )
    
    # Stockage
    storage_used_mb = models.IntegerField(
        default=0,
        verbose_name="Stockage utilisé (MB)"
    )
    
    # Modules utilisés
    modules_used = models.JSONField(
        default=list,
        verbose_name="Modules utilisés",
        help_text="Liste des modules utilisés pendant cette période"
    )
    
    # Fonctionnalités utilisées
    features_used = models.JSONField(
        default=list,
        verbose_name="Fonctionnalités utilisées"
    )
    
    # Performance
    avg_response_time_ms = models.IntegerField(
        null=True,
        blank=True,
        verbose_name="Temps de réponse moyen (ms)"
    )
    
    error_count = models.IntegerField(
        default=0,
        verbose_name="Nombre d'erreurs"
    )
    
    def check_limits(self):
        """Vérifie si les limites de licence sont respectées"""
        violations = []
        
        # Vérifier le nombre d'utilisateurs
        max_users = self.license.get_max_users()
        if self.peak_users > max_users:
            violations.append(f"Dépassement utilisateurs: {self.peak_users}/{max_users}")
        
        # Vérifier le nombre d'articles
        if self.license.license_type.max_articles:
            if self.total_articles > self.license.license_type.max_articles:
                violations.append(
                    f"Dépassement articles: {self.total_articles}/"
                    f"{self.license.license_type.max_articles}"
                )
        
        # Vérifier les transactions
        if self.license.license_type.max_transactions_per_month:
            if self.transactions_count > self.license.license_type.max_transactions_per_month:
                violations.append(
                    f"Dépassement transactions: {self.transactions_count}/"
                    f"{self.license.license_type.max_transactions_per_month}"
                )
        
        # Vérifier le stockage
        if self.license.license_type.max_storage_mb:
            if self.storage_used_mb > self.license.license_type.max_storage_mb:
                violations.append(
                    f"Dépassement stockage: {self.storage_used_mb}/"
                    f"{self.license.license_type.max_storage_mb}MB"
                )
        
        return violations

    class Meta:
        db_table = 'licensing_usage'
        verbose_name = 'Utilisation de licence'
        verbose_name_plural = 'Utilisations de licence'
        ordering = ['-period_end']
        unique_together = ['license', 'period_start', 'period_end']


class LicenseViolation(BaseModel):
    """
    Violations de licence
    Enregistrement des violations des conditions de licence
    """
    VIOLATION_TYPES = [
        ('user_limit', 'Dépassement utilisateurs'),
        ('article_limit', 'Dépassement articles'),
        ('transaction_limit', 'Dépassement transactions'),
        ('storage_limit', 'Dépassement stockage'),
        ('module_unauthorized', 'Module non autorisé'),
        ('feature_unauthorized', 'Fonctionnalité non autorisée'),
        ('hardware_change', 'Changement de matériel'),
        ('multiple_activation', 'Activation multiple'),
        ('expired_license', 'Licence expirée'),
        ('revoked_license', 'Licence révoquée'),
    ]
    
    VIOLATION_SEVERITY = [
        ('low', 'Faible'),
        ('medium', 'Moyenne'),
        ('high', 'Élevée'),
        ('critical', 'Critique'),
    ]
    
    license = models.ForeignKey(
        License,
        on_delete=models.CASCADE,
        related_name='violations',
        verbose_name="Licence"
    )
    
    violation_type = models.CharField(
        max_length=30,
        choices=VIOLATION_TYPES,
        verbose_name="Type de violation"
    )
    
    severity = models.CharField(
        max_length=10,
        choices=VIOLATION_SEVERITY,
        verbose_name="Gravité"
    )
    
    # Détails
    description = models.TextField(
        verbose_name="Description"
    )
    
    details = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Détails techniques"
    )
    
    # Résolution
    is_resolved = models.BooleanField(
        default=False,
        verbose_name="Résolue"
    )
    
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Résolue le"
    )
    
    resolution_notes = models.TextField(
        blank=True,
        verbose_name="Notes de résolution"
    )
    
    # Action automatique
    auto_action_taken = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Action automatique prise"
    )

    class Meta:
        db_table = 'licensing_violation'
        verbose_name = 'Violation de licence'
        verbose_name_plural = 'Violations de licence'
        ordering = ['-created_at']


class LicenseRenewal(AuditableModel):
    """
    Renouvellements de licence
    Gestion des renouvellements et mises à niveau
    """
    RENEWAL_STATUS = [
        ('pending', 'En attente'),
        ('approved', 'Approuvé'),
        ('rejected', 'Rejeté'),
        ('processed', 'Traité'),
    ]
    
    RENEWAL_TYPES = [
        ('renewal', 'Renouvellement'),
        ('upgrade', 'Mise à niveau'),
        ('downgrade', 'Rétrogradation'),
        ('extension', 'Extension'),
    ]
    
    original_license = models.ForeignKey(
        License,
        on_delete=models.CASCADE,
        related_name='renewals',
        verbose_name="Licence originale"
    )
    
    renewal_type = models.CharField(
        max_length=20,
        choices=RENEWAL_TYPES,
        verbose_name="Type de renouvellement"
    )
    
    status = models.CharField(
        max_length=20,
        choices=RENEWAL_STATUS,
        default='pending',
        verbose_name="Statut"
    )
    
    # Nouvelle configuration
    new_license_type = models.ForeignKey(
        LicenseType,
        on_delete=models.PROTECT,
        verbose_name="Nouveau type de licence"
    )
    
    new_duration_days = models.IntegerField(
        validators=[MinValueValidator(1)],
        verbose_name="Nouvelle durée (jours)"
    )
    
    # Tarification
    renewal_price = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        verbose_name="Prix de renouvellement"
    )
    
    discount_applied = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        verbose_name="Remise appliquée (%)"
    )
    
    # Dates
    requested_at = models.DateTimeField(
        default=timezone.now,
        verbose_name="Demandé le"
    )
    
    effective_date = models.DateTimeField(
        verbose_name="Date d'effet"
    )
    
    # Traitement
    processed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Traité le"
    )
    
    new_license = models.OneToOneField(
        License,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='renewal_source',
        verbose_name="Nouvelle licence générée"
    )
    
    # Notes
    notes = models.TextField(
        blank=True,
        verbose_name="Notes"
    )

    class Meta:
        db_table = 'licensing_renewal'
        verbose_name = 'Renouvellement de licence'
        verbose_name_plural = 'Renouvellements de licence'
        ordering = ['-requested_at']


class LicenseMetrics(BaseModel):
    """
    Métriques des licences
    Statistiques globales du système de licence
    """
    # Période
    period_date = models.DateField(
        unique=True,
        verbose_name="Date de la période"
    )
    
    # Licences actives
    total_licenses = models.IntegerField(
        default=0,
        verbose_name="Total des licences"
    )
    
    active_licenses = models.IntegerField(
        default=0,
        verbose_name="Licences actives"
    )
    
    expired_licenses = models.IntegerField(
        default=0,
        verbose_name="Licences expirées"
    )
    
    suspended_licenses = models.IntegerField(
        default=0,
        verbose_name="Licences suspendues"
    )
    
    # Répartition par type
    starter_licenses = models.IntegerField(
        default=0,
        verbose_name="Licences Starter"
    )
    
    professional_licenses = models.IntegerField(
        default=0,
        verbose_name="Licences Professional"
    )
    
    enterprise_licenses = models.IntegerField(
        default=0,
        verbose_name="Licences Enterprise"
    )
    
    # Chiffre d'affaires
    daily_revenue = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        verbose_name="CA quotidien"
    )
    
    monthly_revenue = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        verbose_name="CA mensuel"
    )
    
    yearly_revenue = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        verbose_name="CA annuel"
    )
    
    # Violations
    total_violations = models.IntegerField(
        default=0,
        verbose_name="Total violations"
    )
    
    critical_violations = models.IntegerField(
        default=0,
        verbose_name="Violations critiques"
    )

    class Meta:
        db_table = 'licensing_metrics'
        verbose_name = 'Métriques de licence'
        verbose_name_plural = 'Métriques de licence'
        ordering = ['-period_date']