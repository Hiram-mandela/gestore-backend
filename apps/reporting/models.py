"""
Modèles de reporting et analytics pour GESTORE
Système de génération de rapports et tableaux de bord
"""
from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.contrib.auth import get_user_model
from apps.core.models import BaseModel, AuditableModel, NamedModel, ActivableModel

User = get_user_model()


class ReportCategory(BaseModel, NamedModel, ActivableModel):
    """
    Catégories de rapports
    Ex: Ventes, Stocks, Finance, etc.
    """
    icon = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Icône",
        help_text="Nom de l'icône pour l'interface"
    )
    
    color = models.CharField(
        max_length=7,
        default='#007bff',
        verbose_name="Couleur",
        help_text="Couleur d'affichage (format hexadécimal)"
    )
    
    order = models.IntegerField(
        default=0,
        verbose_name="Ordre d'affichage"
    )

    class Meta:
        db_table = 'reporting_category'
        verbose_name = 'Catégorie de rapport'
        verbose_name_plural = 'Catégories de rapport'
        ordering = ['order', 'name']


class ReportTemplate(AuditableModel, NamedModel, ActivableModel):
    """
    Modèles de rapports prédéfinis
    Templates configurables pour différents types de rapports
    """
    REPORT_TYPES = [
        ('table', 'Tableau'),
        ('chart', 'Graphique'),
        ('dashboard', 'Tableau de bord'),
        ('export', 'Export de données'),
        ('summary', 'Résumé'),
    ]
    
    CHART_TYPES = [
        ('line', 'Ligne'),
        ('bar', 'Barres'),
        ('pie', 'Secteurs'),
        ('area', 'Aires'),
        ('scatter', 'Nuage de points'),
        ('donut', 'Donut'),
    ]
    
    FREQUENCY_CHOICES = [
        ('manual', 'Manuel'),
        ('daily', 'Quotidien'),
        ('weekly', 'Hebdomadaire'),
        ('monthly', 'Mensuel'),
        ('quarterly', 'Trimestriel'),
        ('yearly', 'Annuel'),
    ]
    
    category = models.ForeignKey(
        ReportCategory,
        on_delete=models.PROTECT,
        verbose_name="Catégorie"
    )
    
    report_type = models.CharField(
        max_length=20,
        choices=REPORT_TYPES,
        verbose_name="Type de rapport"
    )
    
    chart_type = models.CharField(
        max_length=20,
        choices=CHART_TYPES,
        null=True,
        blank=True,
        verbose_name="Type de graphique"
    )
    
    # Configuration de la requête
    sql_query = models.TextField(
        blank=True,
        verbose_name="Requête SQL",
        help_text="Requête SQL personnalisée pour générer les données"
    )
    
    data_source = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Source de données",
        help_text="Nom de la vue ou fonction qui génère les données"
    )
    
    # Paramètres du rapport
    parameters = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Paramètres",
        help_text="Paramètres configurables du rapport (filtres, dates, etc.)"
    )
    
    # Configuration d'affichage
    layout_config = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Configuration layout",
        help_text="Configuration de mise en page et style"
    )
    
    # Génération automatique
    auto_generate = models.BooleanField(
        default=False,
        verbose_name="Génération automatique"
    )
    
    frequency = models.CharField(
        max_length=20,
        choices=FREQUENCY_CHOICES,
        default='manual',
        verbose_name="Fréquence de génération"
    )
    
    # Accès et permissions
    is_public = models.BooleanField(
        default=False,
        verbose_name="Rapport public",
        help_text="Accessible à tous les utilisateurs autorisés"
    )
    
    allowed_roles = models.ManyToManyField(
        'authentication.Role',
        blank=True,
        verbose_name="Rôles autorisés"
    )
    
    # Métadonnées
    tags = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Tags",
        help_text="Tags pour la recherche et l'organisation"
    )

    class Meta:
        db_table = 'reporting_template'
        verbose_name = 'Modèle de rapport'
        verbose_name_plural = 'Modèles de rapport'
        ordering = ['category__name', 'name']


class Report(AuditableModel):
    """
    Rapports générés
    Instances de rapports créées à partir des templates
    """
    REPORT_STATUS = [
        ('generating', 'En cours de génération'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
        ('expired', 'Expiré'),
    ]
    
    template = models.ForeignKey(
        ReportTemplate,
        on_delete=models.PROTECT,
        related_name='generated_reports',
        verbose_name="Modèle de rapport"
    )
    
    title = models.CharField(
        max_length=200,
        verbose_name="Titre du rapport"
    )
    
    status = models.CharField(
        max_length=20,
        choices=REPORT_STATUS,
        default='generating',
        verbose_name="Statut"
    )
    
    # Paramètres utilisés
    parameters_used = models.JSONField(
        default=dict,
        verbose_name="Paramètres utilisés",
        help_text="Paramètres utilisés pour générer ce rapport"
    )
    
    # Période couverte
    date_from = models.DateField(
        null=True,
        blank=True,
        verbose_name="Date de début"
    )
    
    date_to = models.DateField(
        null=True,
        blank=True,
        verbose_name="Date de fin"
    )
    
    # Données et résultats
    data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Données du rapport",
        help_text="Données générées pour ce rapport"
    )
    
    summary = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Résumé",
        help_text="Métriques et résumés calculés"
    )
    
    # Génération
    generation_started_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Génération démarrée à"
    )
    
    generation_completed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Génération terminée à"
    )
    
    generation_duration = models.DurationField(
        null=True,
        blank=True,
        verbose_name="Durée de génération"
    )
    
    # Erreurs
    error_message = models.TextField(
        blank=True,
        verbose_name="Message d'erreur"
    )
    
    # Partage et export
    is_shared = models.BooleanField(
        default=False,
        verbose_name="Rapport partagé"
    )
    
    shared_with = models.ManyToManyField(
        User,
        blank=True,
        related_name='shared_reports',
        verbose_name="Partagé avec"
    )
    
    # Export
    exported_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Exporté le"
    )
    
    export_format = models.CharField(
        max_length=10,
        blank=True,
        verbose_name="Format d'export"
    )
    
    def get_generation_time(self):
        """Retourne le temps de génération en secondes"""
        if self.generation_duration:
            return self.generation_duration.total_seconds()
        return None
    
    def is_recent(self, hours=24):
        """Vérifie si le rapport est récent"""
        if self.generation_completed_at:
            return (
                timezone.now() - self.generation_completed_at
            ).total_seconds() < (hours * 3600)
        return False
    
    def can_be_regenerated(self):
        """Vérifie si le rapport peut être régénéré"""
        return self.status in ['completed', 'failed', 'expired']

    class Meta:
        db_table = 'reporting_report'
        verbose_name = 'Rapport généré'
        verbose_name_plural = 'Rapports générés'
        ordering = ['-generation_completed_at', '-created_at']
        indexes = [
            models.Index(fields=['template', 'status']),
            models.Index(fields=['created_by', 'created_at']),
            models.Index(fields=['date_from', 'date_to']),
        ]


class Dashboard(AuditableModel, NamedModel, ActivableModel):
    """
    Tableaux de bord personnalisables
    Collection de widgets et rapports
    """
    DASHBOARD_TYPES = [
        ('personal', 'Personnel'),
        ('role_based', 'Basé sur le rôle'),
        ('public', 'Public'),
        ('admin', 'Administration'),
    ]
    
    dashboard_type = models.CharField(
        max_length=20,
        choices=DASHBOARD_TYPES,
        default='personal',
        verbose_name="Type de tableau de bord"
    )
    
    # Configuration
    layout = models.JSONField(
        default=dict,
        verbose_name="Configuration layout",
        help_text="Configuration de la mise en page et des widgets"
    )
    
    refresh_interval = models.IntegerField(
        default=300,  # 5 minutes
        validators=[MinValueValidator(30)],
        verbose_name="Intervalle de rafraîchissement (secondes)"
    )
    
    # Accès
    is_default = models.BooleanField(
        default=False,
        verbose_name="Tableau de bord par défaut"
    )
    
    target_role = models.ForeignKey(
        'authentication.Role',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        verbose_name="Rôle cible",
        help_text="Rôle pour lequel ce tableau de bord est conçu"
    )
    
    shared_with = models.ManyToManyField(
        User,
        blank=True,
        related_name='accessible_dashboards',
        verbose_name="Partagé avec"
    )

    class Meta:
        db_table = 'reporting_dashboard'
        verbose_name = 'Tableau de bord'
        verbose_name_plural = 'Tableaux de bord'
        ordering = ['dashboard_type', 'name']


class DashboardWidget(BaseModel):
    """
    Widgets de tableau de bord
    Composants individuels affichés sur les tableaux de bord
    """
    WIDGET_TYPES = [
        ('metric', 'Métrique simple'),
        ('chart', 'Graphique'),
        ('table', 'Tableau'),
        ('gauge', 'Jauge'),
        ('progress', 'Barre de progression'),
        ('list', 'Liste'),
        ('alert', 'Alerte'),
    ]
    
    dashboard = models.ForeignKey(
        Dashboard,
        on_delete=models.CASCADE,
        related_name='widgets',
        verbose_name="Tableau de bord"
    )
    
    title = models.CharField(
        max_length=100,
        verbose_name="Titre du widget"
    )
    
    widget_type = models.CharField(
        max_length=20,
        choices=WIDGET_TYPES,
        verbose_name="Type de widget"
    )
    
    # Positionnement
    position_x = models.IntegerField(
        default=0,
        verbose_name="Position X"
    )
    
    position_y = models.IntegerField(
        default=0,
        verbose_name="Position Y"
    )
    
    width = models.IntegerField(
        default=4,
        validators=[MinValueValidator(1), MaxValueValidator(12)],
        verbose_name="Largeur (colonnes)"
    )
    
    height = models.IntegerField(
        default=3,
        validators=[MinValueValidator(1)],
        verbose_name="Hauteur (lignes)"
    )
    
    # Configuration
    config = models.JSONField(
        default=dict,
        verbose_name="Configuration du widget"
    )
    
    # Source de données
    data_source = models.CharField(
        max_length=100,
        verbose_name="Source de données"
    )
    
    query_parameters = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Paramètres de requête"
    )
    
    # Mise à jour
    last_updated = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Dernière mise à jour"
    )
    
    cached_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Données en cache"
    )

    class Meta:
        db_table = 'reporting_dashboard_widget'
        verbose_name = 'Widget de tableau de bord'
        verbose_name_plural = 'Widgets de tableau de bord'
        ordering = ['dashboard', 'position_y', 'position_x']


class KPI(BaseModel, NamedModel, ActivableModel):
    """
    Indicateurs de performance clés (KPI)
    Métriques importantes suivies régulièrement
    """
    KPI_TYPES = [
        ('sales', 'Ventes'),
        ('inventory', 'Stock'),
        ('financial', 'Financier'),
        ('customer', 'Client'),
        ('operational', 'Opérationnel'),
    ]
    
    DATA_TYPES = [
        ('number', 'Nombre'),
        ('percentage', 'Pourcentage'),
        ('currency', 'Devise'),
        ('ratio', 'Ratio'),
    ]
    
    TREND_DIRECTIONS = [
        ('up', 'Hausse'),
        ('down', 'Baisse'),
        ('stable', 'Stable'),
    ]
    
    kpi_type = models.CharField(
        max_length=20,
        choices=KPI_TYPES,
        verbose_name="Type de KPI"
    )
    
    data_type = models.CharField(
        max_length=20,
        choices=DATA_TYPES,
        default='number',
        verbose_name="Type de données"
    )
    
    # Calcul
    calculation_method = models.TextField(
        verbose_name="Méthode de calcul",
        help_text="Description ou formule de calcul du KPI"
    )
    
    sql_query = models.TextField(
        blank=True,
        verbose_name="Requête SQL",
        help_text="Requête pour calculer la valeur du KPI"
    )
    
    # Objectifs
    target_value = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Valeur cible"
    )
    
    min_acceptable = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Minimum acceptable"
    )
    
    max_acceptable = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Maximum acceptable"
    )
    
    # Fréquence de calcul
    calculation_frequency = models.CharField(
        max_length=20,
        choices=[
            ('realtime', 'Temps réel'),
            ('hourly', 'Horaire'),
            ('daily', 'Quotidien'),
            ('weekly', 'Hebdomadaire'),
            ('monthly', 'Mensuel'),
        ],
        default='daily',
        verbose_name="Fréquence de calcul"
    )
    
    # Affichage
    unit = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Unité",
        help_text="Unité d'affichage (€, %, kg, etc.)"
    )
    
    decimal_places = models.IntegerField(
        default=2,
        validators=[MinValueValidator(0), MaxValueValidator(6)],
        verbose_name="Nombre de décimales"
    )
    
    color_good = models.CharField(
        max_length=7,
        default='#28a745',
        verbose_name="Couleur bon"
    )
    
    color_warning = models.CharField(
        max_length=7,
        default='#ffc107',
        verbose_name="Couleur avertissement"
    )
    
    color_danger = models.CharField(
        max_length=7,
        default='#dc3545',
        verbose_name="Couleur danger"
    )

    class Meta:
        db_table = 'reporting_kpi'
        verbose_name = 'KPI'
        verbose_name_plural = 'KPIs'
        ordering = ['kpi_type', 'name']


class KPIValue(BaseModel):
    """
    Valeurs historiques des KPIs
    Stockage des valeurs calculées dans le temps
    """
    kpi = models.ForeignKey(
        KPI,
        on_delete=models.CASCADE,
        related_name='values',
        verbose_name="KPI"
    )
    
    value = models.DecimalField(
        max_digits=15,
        decimal_places=6,
        verbose_name="Valeur"
    )
    
    # Période
    period_start = models.DateTimeField(
        verbose_name="Début de période"
    )
    
    period_end = models.DateTimeField(
        verbose_name="Fin de période"
    )
    
    # Contexte
    context = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Contexte",
        help_text="Données contextuelles utilisées pour le calcul"
    )
    
    # Comparaison
    previous_value = models.DecimalField(
        max_digits=15,
        decimal_places=6,
        null=True,
        blank=True,
        verbose_name="Valeur précédente"
    )
    
    change_percentage = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Pourcentage de changement"
    )
    
    def calculate_change(self):
        """Calcule le pourcentage de changement par rapport à la valeur précédente"""
        if self.previous_value and self.previous_value != 0:
            change = ((self.value - self.previous_value) / self.previous_value) * 100
            self.change_percentage = change
            self.save(update_fields=['change_percentage'])
    
    def get_status(self):
        """Retourne le statut du KPI (bon, avertissement, danger)"""
        if self.kpi.target_value:
            if self.value >= self.kpi.target_value:
                return 'good'
            elif self.kpi.min_acceptable and self.value >= self.kpi.min_acceptable:
                return 'warning'
            else:
                return 'danger'
        return 'neutral'

    class Meta:
        db_table = 'reporting_kpi_value'
        verbose_name = 'Valeur KPI'
        verbose_name_plural = 'Valeurs KPI'
        ordering = ['-period_end']
        unique_together = ['kpi', 'period_start', 'period_end']


class ScheduledReport(AuditableModel):
    """
    Rapports programmés
    Configuration pour la génération automatique de rapports
    """
    SCHEDULE_TYPES = [
        ('interval', 'Intervalle'),
        ('cron', 'Expression cron'),
        ('daily', 'Quotidien'),
        ('weekly', 'Hebdomadaire'),
        ('monthly', 'Mensuel'),
    ]
    
    template = models.ForeignKey(
        ReportTemplate,
        on_delete=models.CASCADE,
        related_name='schedules',
        verbose_name="Modèle de rapport"
    )
    
    schedule_type = models.CharField(
        max_length=20,
        choices=SCHEDULE_TYPES,
        verbose_name="Type de programmation"
    )
    
    # Configuration horaire
    cron_expression = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Expression cron",
        help_text="Expression cron pour la programmation (ex: 0 9 * * 1 pour chaque lundi à 9h)"
    )
    
    interval_minutes = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(5)],
        verbose_name="Intervalle en minutes"
    )
    
    run_time = models.TimeField(
        null=True,
        blank=True,
        verbose_name="Heure d'exécution",
        help_text="Heure d'exécution pour les rapports quotidiens/hebdomadaires/mensuels"
    )
    
    # Jours de la semaine (pour hebdomadaire)
    weekdays = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Jours de la semaine",
        help_text="Liste des jours (0=lundi, 6=dimanche)"
    )
    
    # Jour du mois (pour mensuel)
    day_of_month = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(31)],
        verbose_name="Jour du mois"
    )
    
    # Paramètres par défaut
    default_parameters = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Paramètres par défaut"
    )
    
    # Distribution
    recipients = models.ManyToManyField(
        User,
        blank=True,
        verbose_name="Destinataires",
        help_text="Utilisateurs qui recevront le rapport automatiquement"
    )
    
    email_enabled = models.BooleanField(
        default=False,
        verbose_name="Envoi par email"
    )
    
    # Statut
    is_enabled = models.BooleanField(
        default=True,
        verbose_name="Activé"
    )
    
    last_run = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Dernière exécution"
    )
    
    next_run = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Prochaine exécution"
    )
    
    run_count = models.IntegerField(
        default=0,
        verbose_name="Nombre d'exécutions"
    )

    class Meta:
        db_table = 'reporting_scheduled_report'
        verbose_name = 'Rapport programmé'
        verbose_name_plural = 'Rapports programmés'
        ordering = ['next_run']


class ReportExport(AuditableModel):
    """
    Exports de rapports
    Historique des exports en différents formats
    """
    EXPORT_FORMATS = [
        ('pdf', 'PDF'),
        ('excel', 'Excel (XLSX)'),
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('html', 'HTML'),
    ]
    
    EXPORT_STATUS = [
        ('processing', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    ]
    
    report = models.ForeignKey(
        Report,
        on_delete=models.CASCADE,
        related_name='exports',
        verbose_name="Rapport"
    )
    
    format = models.CharField(
        max_length=10,
        choices=EXPORT_FORMATS,
        verbose_name="Format"
    )
    
    status = models.CharField(
        max_length=20,
        choices=EXPORT_STATUS,
        default='processing',
        verbose_name="Statut"
    )
    
    file_path = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Chemin du fichier"
    )
    
    file_size = models.BigIntegerField(
        null=True,
        blank=True,
        verbose_name="Taille du fichier (octets)"
    )
    
    download_count = models.IntegerField(
        default=0,
        verbose_name="Nombre de téléchargements"
    )
    
    # Export automatique
    auto_delete_after_days = models.IntegerField(
        default=30,
        validators=[MinValueValidator(1)],
        verbose_name="Suppression automatique (jours)"
    )
    
    def get_file_size_mb(self):
        """Retourne la taille du fichier en MB"""
        if self.file_size:
            return round(self.file_size / (1024 * 1024), 2)
        return 0

    class Meta:
        db_table = 'reporting_export'
        verbose_name = 'Export de rapport'
        verbose_name_plural = 'Exports de rapport'
        ordering = ['-created_at']