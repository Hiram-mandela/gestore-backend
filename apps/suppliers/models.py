"""
Modèles de gestion des fournisseurs pour GESTORE
Version de base pour Phase 1 - sera étendue en Phase 3
"""
from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator, EmailValidator
from django.utils import timezone
from django.contrib.auth import get_user_model
from apps.core.models import (
    BaseModel, AuditableModel, NamedModel, 
    ActivableModel, CodedModel, PricedModel
)
from apps.inventory.models import Article

User = get_user_model()


class SupplierCategory(BaseModel, NamedModel, ActivableModel):
    """
    Catégories de fournisseurs
    Ex: Pharmaceutique, Alimentaire, Textile, etc.
    """
    color = models.CharField(
        max_length=7,
        default='#007bff',
        verbose_name="Couleur",
        help_text="Couleur d'affichage (format hexadécimal)"
    )

    class Meta:
        db_table = 'suppliers_category'
        verbose_name = 'Catégorie fournisseur'
        verbose_name_plural = 'Catégories fournisseur'
        ordering = ['name']


class Supplier(AuditableModel, CodedModel, NamedModel, ActivableModel):
    """
    Fournisseurs - Version complète
    Entreprises qui approvisionnent le magasin
    """
    SUPPLIER_TYPES = [
        ('manufacturer', 'Fabricant'),
        ('distributor', 'Distributeur'),
        ('wholesaler', 'Grossiste'),
        ('dropshipper', 'Dropshipper'),
        ('service', 'Prestataire de service'),
    ]
    
    PAYMENT_TERMS = [
        ('immediate', 'Comptant'),
        ('net_15', 'Net 15 jours'),
        ('net_30', 'Net 30 jours'),
        ('net_45', 'Net 45 jours'),
        ('net_60', 'Net 60 jours'),
        ('net_90', 'Net 90 jours'),
    ]
    
    supplier_type = models.CharField(
        max_length=20,
        choices=SUPPLIER_TYPES,
        default='distributor',
        verbose_name="Type de fournisseur"
    )
    
    category = models.ForeignKey(
        SupplierCategory,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name="Catégorie"
    )
    
    # Informations légales
    legal_name = models.CharField(
        max_length=200,
        verbose_name="Raison sociale"
    )
    
    tax_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro fiscal/TVA"
    )
    
    registration_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro d'enregistrement"
    )
    
    # Coordonnées
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
    
    phone = models.CharField(
        max_length=20,
        verbose_name="Téléphone principal"
    )
    
    fax = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Fax"
    )
    
    email = models.EmailField(
        verbose_name="Email principal",
        validators=[EmailValidator()]
    )
    
    website = models.URLField(
        blank=True,
        verbose_name="Site web"
    )
    
    # Contacts
    primary_contact = models.CharField(
        max_length=100,
        verbose_name="Contact principal"
    )
    
    primary_contact_phone = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Téléphone contact principal"
    )
    
    primary_contact_email = models.EmailField(
        blank=True,
        verbose_name="Email contact principal"
    )
    
    # Contact commercial
    sales_contact = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Contact commercial"
    )
    
    sales_contact_phone = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Téléphone commercial"
    )
    
    sales_contact_email = models.EmailField(
        blank=True,
        verbose_name="Email commercial"
    )
    
    # Conditions commerciales
    payment_terms = models.CharField(
        max_length=20,
        choices=PAYMENT_TERMS,
        default='net_30',
        verbose_name="Conditions de paiement"
    )
    
    credit_limit = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Limite de crédit"
    )
    
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(0)],
        verbose_name="Remise générale (%)"
    )
    
    minimum_order_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Montant minimum de commande"
    )
    
    # Délais
    lead_time_days = models.IntegerField(
        default=7,
        validators=[MinValueValidator(0)],
        verbose_name="Délai de livraison (jours)"
    )
    
    # Évaluation
    rating = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MinValueValidator(5)],
        verbose_name="Note (0-5 étoiles)"
    )
    
    # Statistiques
    total_orders = models.IntegerField(
        default=0,
        verbose_name="Nombre total de commandes"
    )
    
    total_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant total des achats"
    )
    
    last_order_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Dernière commande"
    )
    
    # Configuration
    auto_order_enabled = models.BooleanField(
        default=False,
        verbose_name="Commandes automatiques",
        help_text="Activer la génération automatique de commandes"
    )
    
    preferred_order_day = models.IntegerField(
        choices=[
            (0, 'Lundi'), (1, 'Mardi'), (2, 'Mercredi'),
            (3, 'Jeudi'), (4, 'Vendredi'), (5, 'Samedi'), (6, 'Dimanche')
        ],
        null=True,
        blank=True,
        verbose_name="Jour de commande préféré"
    )
    
    # Documents
    logo = models.ImageField(
        upload_to='suppliers/logos/',
        null=True,
        blank=True,
        verbose_name="Logo"
    )
    
    notes = models.TextField(
        blank=True,
        verbose_name="Notes internes"
    )
    
    def get_current_balance(self):
        """Retourne le solde actuel avec le fournisseur"""
        # Sera implémenté avec les factures fournisseurs
        return Decimal('0.00')
    
    def get_average_delivery_time(self):
        """Calcule le délai moyen de livraison basé sur l'historique"""
        # Sera implémenté avec l'historique des livraisons
        return self.lead_time_days
    
    def can_place_order(self, amount):
        """Vérifie si une commande peut être passée"""
        if not self.is_active:
            return False, "Fournisseur inactif"
        
        if self.minimum_order_amount and amount < self.minimum_order_amount:
            return False, f"Montant minimum: {self.minimum_order_amount}"
        
        if self.credit_limit:
            current_balance = self.get_current_balance()
            if current_balance + amount > self.credit_limit:
                return False, "Limite de crédit dépassée"
        
        return True, "OK"

    class Meta:
        db_table = 'suppliers_supplier'
        verbose_name = 'Fournisseur'
        verbose_name_plural = 'Fournisseurs'
        ordering = ['name']
        indexes = [
            models.Index(fields=['code']),
            models.Index(fields=['is_active', 'name']),
        ]


class SupplierArticle(BaseModel):
    """
    Articles proposés par un fournisseur
    Relation entre articles et fournisseurs avec conditions spécifiques
    """
    supplier = models.ForeignKey(
        Supplier,
        on_delete=models.CASCADE,
        related_name='articles',
        verbose_name="Fournisseur"
    )
    
    article = models.ForeignKey(
        Article,
        on_delete=models.CASCADE,
        related_name='suppliers',
        verbose_name="Article"
    )
    
    # Références fournisseur
    supplier_reference = models.CharField(
        max_length=50,
        verbose_name="Référence fournisseur"
    )
    
    supplier_barcode = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Code-barres fournisseur"
    )
    
    # Prix et conditions
    purchase_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        verbose_name="Prix d'achat"
    )
    
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(0)],
        verbose_name="Remise spécifique (%)"
    )
    
    minimum_quantity = models.IntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        verbose_name="Quantité minimum"
    )
    
    package_quantity = models.IntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        verbose_name="Quantité par colis",
        help_text="Nombre d'unités dans un colis fournisseur"
    )
    
    # Priorité
    is_preferred = models.BooleanField(
        default=False,
        verbose_name="Fournisseur préféré",
        help_text="Fournisseur préféré pour cet article"
    )
    
    priority = models.IntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        verbose_name="Priorité",
        help_text="1 = priorité maximale"
    )
    
    # Délais
    lead_time_days = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Délai spécifique (jours)",
        help_text="Délai spécifique pour cet article (sinon délai général du fournisseur)"
    )
    
    # Statut
    is_available = models.BooleanField(
        default=True,
        verbose_name="Disponible chez le fournisseur"
    )
    
    discontinued = models.BooleanField(
        default=False,
        verbose_name="Arrêté par le fournisseur"
    )
    
    last_price_update = models.DateTimeField(
        auto_now=True,
        verbose_name="Dernière mise à jour prix"
    )

    class Meta:
        db_table = 'suppliers_supplier_article'
        verbose_name = 'Article fournisseur'
        verbose_name_plural = 'Articles fournisseur'
        unique_together = ['supplier', 'article']
        ordering = ['supplier__name', 'article__name']


class PurchaseOrder(AuditableModel):
    """
    Commandes fournisseurs
    """
    ORDER_STATUS = [
        ('draft', 'Brouillon'),
        ('sent', 'Envoyée'),
        ('confirmed', 'Confirmée'),
        ('partially_received', 'Partiellement reçue'),
        ('received', 'Reçue'),
        ('cancelled', 'Annulée'),
        ('closed', 'Clôturée'),
    ]
    
    # Numérotation
    order_number = models.CharField(
        max_length=30,
        unique=True,
        verbose_name="Numéro de commande",
        help_text="Numéro unique généré automatiquement"
    )
    
    # Fournisseur
    supplier = models.ForeignKey(
        Supplier,
        on_delete=models.PROTECT,
        related_name='purchase_orders',
        verbose_name="Fournisseur"
    )
    
    # Statut et dates
    status = models.CharField(
        max_length=20,
        choices=ORDER_STATUS,
        default='draft',
        verbose_name="Statut"
    )
    
    order_date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Date de commande"
    )
    
    expected_delivery_date = models.DateField(
        null=True,
        blank=True,
        verbose_name="Date de livraison prévue"
    )
    
    # Référence fournisseur
    supplier_order_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro commande fournisseur"
    )
    
    # Montants
    subtotal = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0.00,
        verbose_name="Sous-total HT"
    )
    
    discount_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant remise"
    )
    
    tax_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant TVA"
    )
    
    shipping_cost = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Frais de port"
    )
    
    total_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant total TTC"
    )
    
    # Notes
    notes = models.TextField(
        blank=True,
        verbose_name="Notes internes"
    )
    
    delivery_instructions = models.TextField(
        blank=True,
        verbose_name="Instructions de livraison"
    )
    
    def save(self, *args, **kwargs):
        if not self.order_number:
            # Générer le numéro de commande
            today = timezone.now().date()
            prefix = f"CMD{today.strftime('%Y%m%d')}"
            
            last_order = PurchaseOrder.objects.filter(
                order_number__startswith=prefix
            ).order_by('order_number').last()
            
            if last_order and last_order.order_number:
                try:
                    last_number = int(last_order.order_number[-4:])
                    self.order_number = f"{prefix}{last_number + 1:04d}"
                except ValueError:
                    self.order_number = f"{prefix}0001"
            else:
                self.order_number = f"{prefix}0001"
        
        # Calculer la date de livraison prévue si pas définie
        if not self.expected_delivery_date and self.supplier:
            lead_time = self.supplier.lead_time_days
            self.expected_delivery_date = (
                self.order_date + timezone.timedelta(days=lead_time)
            ).date()
        
        super().save(*args, **kwargs)
    
    def calculate_totals(self):
        """Recalcule tous les totaux de la commande"""
        items = self.items.all()
        
        self.subtotal = sum(item.line_total for item in items)
        
        # Appliquer la remise générale du fournisseur
        if self.supplier.discount_percentage > 0:
            self.discount_amount = self.subtotal * (self.supplier.discount_percentage / 100)
        
        # Calculer les taxes (TVA à 18% par défaut en Côte d'Ivoire)
        taxable_amount = self.subtotal - self.discount_amount
        self.tax_amount = taxable_amount * Decimal('0.18')
        
        self.total_amount = taxable_amount + self.tax_amount + self.shipping_cost
        
        self.save()
    
    def can_be_cancelled(self):
        """Vérifie si la commande peut être annulée"""
        return self.status in ['draft', 'sent']
    
    def get_received_percentage(self):
        """Retourne le pourcentage de réception"""
        total_ordered = sum(item.quantity for item in self.items.all())
        total_received = sum(item.quantity_received for item in self.items.all())
        
        if total_ordered > 0:
            return (total_received / total_ordered) * 100
        return 0

    class Meta:
        db_table = 'suppliers_purchase_order'
        verbose_name = 'Commande fournisseur'
        verbose_name_plural = 'Commandes fournisseur'
        ordering = ['-order_date']
        indexes = [
            models.Index(fields=['order_number']),
            models.Index(fields=['supplier', 'order_date']),
            models.Index(fields=['status']),
        ]


class PurchaseOrderItem(BaseModel):
    """
    Lignes de commande fournisseur
    """
    purchase_order = models.ForeignKey(
        PurchaseOrder,
        on_delete=models.CASCADE,
        related_name='items',
        verbose_name="Commande"
    )
    
    article = models.ForeignKey(
        Article,
        on_delete=models.PROTECT,
        verbose_name="Article"
    )
    
    # Informations au moment de la commande
    article_name = models.CharField(
        max_length=200,
        verbose_name="Nom article"
    )
    
    supplier_reference = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Référence fournisseur"
    )
    
    # Quantités
    quantity = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        validators=[MinValueValidator(0.001)],
        verbose_name="Quantité commandée"
    )
    
    quantity_received = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        default=0,
        verbose_name="Quantité reçue"
    )
    
    # Prix
    unit_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        verbose_name="Prix unitaire"
    )
    
    line_total = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Total ligne"
    )
    
    # Dates
    expected_date = models.DateField(
        null=True,
        blank=True,
        verbose_name="Date prévue"
    )
    
    def save(self, *args, **kwargs):
        # Copier les informations de l'article
        if self.article:
            self.article_name = self.article.name
            # Chercher la référence fournisseur
            try:
                supplier_article = SupplierArticle.objects.get(
                    supplier=self.purchase_order.supplier,
                    article=self.article
                )
                self.supplier_reference = supplier_article.supplier_reference
                if not self.unit_price:
                    self.unit_price = supplier_article.purchase_price
            except SupplierArticle.DoesNotExist:
                if not self.unit_price:
                    self.unit_price = self.article.purchase_price
        
        # Calculer le total
        self.line_total = self.quantity * self.unit_price
        
        super().save(*args, **kwargs)
    
    def get_remaining_quantity(self):
        """Retourne la quantité restant à recevoir"""
        return self.quantity - self.quantity_received
    
    def is_fully_received(self):
        """Vérifie si la ligne est entièrement reçue"""
        return self.quantity_received >= self.quantity

    class Meta:
        db_table = 'suppliers_purchase_order_item'
        verbose_name = 'Ligne commande fournisseur'
        verbose_name_plural = 'Lignes commande fournisseur'
        ordering = ['purchase_order', 'created_at']


class Delivery(AuditableModel):
    """
    Livraisons fournisseurs
    Une commande peut avoir plusieurs livraisons (livraison partielle)
    """
    DELIVERY_STATUS = [
        ('pending', 'En attente'),
        ('in_transit', 'En transit'),
        ('delivered', 'Livrée'),
        ('partially_received', 'Partiellement réceptionnée'),
        ('received', 'Réceptionnée'),
        ('rejected', 'Refusée'),
    ]
    
    # Numérotation
    delivery_number = models.CharField(
        max_length=30,
        unique=True,
        verbose_name="Numéro de livraison"
    )
    
    # Commande liée
    purchase_order = models.ForeignKey(
        PurchaseOrder,
        on_delete=models.PROTECT,
        related_name='deliveries',
        verbose_name="Commande"
    )
    
    # Informations livraison
    supplier_delivery_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro livraison fournisseur"
    )
    
    carrier = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Transporteur"
    )
    
    tracking_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro de suivi"
    )
    
    # Statut et dates
    status = models.CharField(
        max_length=20,
        choices=DELIVERY_STATUS,
        default='pending',
        verbose_name="Statut"
    )
    
    shipped_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Date d'expédition"
    )
    
    delivered_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Date de livraison"
    )
    
    received_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Date de réception"
    )
    
    # Réception
    received_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='received_deliveries',
        verbose_name="Réceptionné par"
    )
    
    # Notes
    delivery_notes = models.TextField(
        blank=True,
        verbose_name="Notes de livraison"
    )
    
    reception_notes = models.TextField(
        blank=True,
        verbose_name="Notes de réception"
    )
    
    def save(self, *args, **kwargs):
        if not self.delivery_number:
            # Générer le numéro de livraison
            today = timezone.now().date()
            prefix = f"LIV{today.strftime('%Y%m%d')}"
            
            last_delivery = Delivery.objects.filter(
                delivery_number__startswith=prefix
            ).order_by('delivery_number').last()
            
            if last_delivery and last_delivery.delivery_number:
                try:
                    last_number = int(last_delivery.delivery_number[-4:])
                    self.delivery_number = f"{prefix}{last_number + 1:04d}"
                except ValueError:
                    self.delivery_number = f"{prefix}0001"
            else:
                self.delivery_number = f"{prefix}0001"
        
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'suppliers_delivery'
        verbose_name = 'Livraison'
        verbose_name_plural = 'Livraisons'
        ordering = ['-delivered_date', '-created_at']


class DeliveryItem(BaseModel):
    """
    Articles reçus dans une livraison
    """
    delivery = models.ForeignKey(
        Delivery,
        on_delete=models.CASCADE,
        related_name='items',
        verbose_name="Livraison"
    )
    
    purchase_order_item = models.ForeignKey(
        PurchaseOrderItem,
        on_delete=models.PROTECT,
        verbose_name="Ligne de commande"
    )
    
    quantity_delivered = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        validators=[MinValueValidator(0)],
        verbose_name="Quantité livrée"
    )
    
    quantity_accepted = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        validators=[MinValueValidator(0)],
        verbose_name="Quantité acceptée"
    )
    
    quantity_rejected = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        default=0,
        verbose_name="Quantité refusée"
    )
    
    # Traçabilité
    lot_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro de lot"
    )
    
    expiry_date = models.DateField(
        null=True,
        blank=True,
        verbose_name="Date de péremption"
    )
    
    # Qualité
    quality_check_passed = models.BooleanField(
        default=True,
        verbose_name="Contrôle qualité OK"
    )
    
    rejection_reason = models.TextField(
        blank=True,
        verbose_name="Motif de refus"
    )

    class Meta:
        db_table = 'suppliers_delivery_item'
        verbose_name = 'Article livré'
        verbose_name_plural = 'Articles livrés'