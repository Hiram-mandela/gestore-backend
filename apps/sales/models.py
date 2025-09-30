"""
Modèles de gestion des ventes pour GESTORE
Système complet de point de vente, transactions et paiements
"""
from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.contrib.auth import get_user_model
from apps.core.models import BaseModel, AuditableModel, NamedModel, ActivableModel
from apps.inventory.models import Article, Stock

User = get_user_model()


class Customer(BaseModel, NamedModel, ActivableModel):
    """
    Clients du magasin
    Gestion de la fidélité et historique d'achats
    """
    CUSTOMER_TYPES = [
        ('individual', 'Particulier'),
        ('company', 'Entreprise'),
        ('professional', 'Professionnel'),
    ]
    
    customer_type = models.CharField(
        max_length=20,
        choices=CUSTOMER_TYPES,
        default='individual',
        verbose_name="Type de client"
    )
    
    customer_code = models.CharField(
        max_length=20,
        unique=True,
        verbose_name="Code client",
        help_text="Code unique généré automatiquement"
    )
    
    # Informations de contact
    first_name = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Prénom"
    )
    
    last_name = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Nom de famille"
    )
    
    company_name = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Nom de l'entreprise"
    )
    
    email = models.EmailField(
        blank=True,
        verbose_name="Email"
    )
    
    phone = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Téléphone"
    )
    
    address = models.TextField(
        blank=True,
        verbose_name="Adresse"
    )
    
    city = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Ville"
    )
    
    postal_code = models.CharField(
        max_length=10,
        blank=True,
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
        verbose_name="Numéro fiscal/TVA"
    )
    
    # Fidélité
    loyalty_card_number = models.CharField(
        max_length=20,
        unique=True,
        null=True,
        blank=True,
        verbose_name="Numéro carte fidélité"
    )
    
    loyalty_points = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        verbose_name="Points fidélité"
    )
    
    # Statistiques
    total_purchases = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0.00,
        verbose_name="Total des achats"
    )
    
    purchase_count = models.IntegerField(
        default=0,
        verbose_name="Nombre d'achats"
    )
    
    last_purchase_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Dernier achat"
    )
    
    # Préférences
    preferred_payment_method = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Mode de paiement préféré"
    )
    
    marketing_consent = models.BooleanField(
        default=False,
        verbose_name="Consent marketing",
        help_text="Accepte de recevoir des communications marketing"
    )
    
    def save(self, *args, **kwargs):
        if not self.customer_code:
            # Générer le code client automatiquement
            last_customer = Customer.objects.filter(
                customer_code__isnull=False
            ).order_by('customer_code').last()
            
            if last_customer and last_customer.customer_code:
                try:
                    last_number = int(last_customer.customer_code.replace('CLI', ''))
                    self.customer_code = f'CLI{last_number + 1:06d}'
                except ValueError:
                    self.customer_code = 'CLI000001'
            else:
                self.customer_code = 'CLI000001'
        
        super().save(*args, **kwargs)
    
    def get_full_name(self):
        """Retourne le nom complet du client"""
        if self.customer_type == 'company':
            return self.company_name or self.name
        return f"{self.first_name} {self.last_name}".strip() or self.name
    
    def add_loyalty_points(self, points):
        """Ajoute des points de fidélité"""
        self.loyalty_points += points
        self.save(update_fields=['loyalty_points'])
    
    def can_use_loyalty_points(self, points):
        """Vérifie si le client peut utiliser des points"""
        return self.loyalty_points >= points

    class Meta:
        db_table = 'sales_customer'
        verbose_name = 'Client'
        verbose_name_plural = 'Clients'
        ordering = ['last_name', 'first_name', 'company_name']


class PaymentMethod(BaseModel, NamedModel, ActivableModel):
    """
    Moyens de paiement acceptés
    """
    PAYMENT_TYPES = [
        ('cash', 'Espèces'),
        ('card', 'Carte bancaire'),
        ('mobile_money', 'Mobile Money'),
        ('check', 'Chèque'),
        ('credit', 'Crédit'),
        ('voucher', 'Bon d\'achat'),
        ('loyalty_points', 'Points fidélité'),
    ]
    
    payment_type = models.CharField(
        max_length=20,
        choices=PAYMENT_TYPES,
        verbose_name="Type de paiement"
    )
    
    # Configuration
    requires_authorization = models.BooleanField(
        default=False,
        verbose_name="Nécessite autorisation",
        help_text="Nécessite une autorisation de supervision"
    )
    
    max_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Montant maximum",
        help_text="Montant maximum autorisé pour ce mode de paiement"
    )
    
    fee_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        verbose_name="Frais (%)",
        help_text="Pourcentage de frais pour ce mode de paiement"
    )
    
    # Configuration technique
    integration_config = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Configuration intégration",
        help_text="Configuration technique pour l'intégration"
    )

    class Meta:
        db_table = 'sales_payment_method'
        verbose_name = 'Moyen de paiement'
        verbose_name_plural = 'Moyens de paiement'
        ordering = ['payment_type', 'name']


class Sale(AuditableModel):
    """
    Vente/Transaction principale
    Représente une transaction complète
    """
    SALE_STATUS = [
        ('draft', 'Brouillon'),
        ('pending', 'En attente'),
        ('completed', 'Terminée'),
        ('cancelled', 'Annulée'),
        ('refunded', 'Remboursée'),
        ('partially_refunded', 'Partiellement remboursée'),
    ]
    
    SALE_TYPES = [
        ('regular', 'Vente normale'),
        ('return', 'Retour'),
        ('exchange', 'Échange'),
        ('quote', 'Devis'),
    ]
    
    # Identification
    sale_number = models.CharField(
        max_length=30,
        unique=True,
        verbose_name="Numéro de vente",
        help_text="Numéro unique généré automatiquement"
    )
    
    sale_type = models.CharField(
        max_length=20,
        choices=SALE_TYPES,
        default='regular',
        verbose_name="Type de vente"
    )
    
    status = models.CharField(
        max_length=20,
        choices=SALE_STATUS,
        default='draft',
        verbose_name="Statut"
    )
    
    # Client
    customer = models.ForeignKey(
        Customer,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='sales',
        verbose_name="Client"
    )
    
    # Vendeur/Caissier
    cashier = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='sales_as_cashier',
        verbose_name="Caissier"
    )
    
    # Dates
    sale_date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Date de vente"
    )
    
    # Montants
    subtotal = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Sous-total HT",
        help_text="Montant hors taxes avant remises"
    )
    
    discount_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant remise",
        help_text="Montant total des remises appliquées"
    )
    
    tax_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant TVA"
    )
    
    total_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant total TTC"
    )
    
    paid_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant payé"
    )
    
    change_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Monnaie rendue"
    )
    
    # Fidélité
    loyalty_points_earned = models.IntegerField(
        default=0,
        verbose_name="Points fidélité gagnés"
    )
    
    loyalty_points_used = models.IntegerField(
        default=0,
        verbose_name="Points fidélité utilisés"
    )
    
    # Vente liée (pour les retours/échanges)
    original_sale = models.ForeignKey(
        'self',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='related_sales',
        verbose_name="Vente d'origine"
    )
    
    # Notes
    notes = models.TextField(
        blank=True,
        verbose_name="Notes",
        help_text="Notes internes sur la vente"
    )
    
    customer_notes = models.TextField(
        blank=True,
        verbose_name="Notes client",
        help_text="Notes visibles sur le ticket"
    )
    
    # Configuration
    receipt_printed = models.BooleanField(
        default=False,
        verbose_name="Ticket imprimé"
    )
    
    receipt_emailed = models.BooleanField(
        default=False,
        verbose_name="Ticket envoyé par email"
    )
    
    def save(self, *args, **kwargs):
        if not self.sale_number:
            # Générer le numéro de vente
            today = timezone.now().date()
            prefix = f"VTE{today.strftime('%Y%m%d')}"
            
            last_sale = Sale.objects.filter(
                sale_number__startswith=prefix
            ).order_by('sale_number').last()
            
            if last_sale and last_sale.sale_number:
                try:
                    last_number = int(last_sale.sale_number[-4:])
                    self.sale_number = f"{prefix}{last_number + 1:04d}"
                except ValueError:
                    self.sale_number = f"{prefix}0001"
            else:
                self.sale_number = f"{prefix}0001"
        
        super().save(*args, **kwargs)
    
    def calculate_totals(self):
        """Recalcule tous les totaux de la vente"""
        from decimal import Decimal  # Ajouter l'import si nécessaire en haut du fichier
        
        items = self.items.all()
        
        # Utiliser Decimal pour les sommes
        self.subtotal = sum((item.line_total for item in items), Decimal('0.00'))
        self.tax_amount = sum((item.tax_amount for item in items), Decimal('0.00'))
        
        # S'assurer que discount_amount est un Decimal
        if not isinstance(self.discount_amount, Decimal):
            self.discount_amount = Decimal(str(self.discount_amount))
        
        self.total_amount = self.subtotal + self.tax_amount - self.discount_amount
        
        # Points fidélité (1 point par euro dépensé)
        if self.customer and self.total_amount > 0:
            self.loyalty_points_earned = int(self.total_amount)
        
        self.save()
    
    def is_paid(self):
        """Vérifie si la vente est entièrement payée"""
        return self.paid_amount >= self.total_amount
    
    def get_balance(self):
        """Retourne le solde restant à payer"""
        return self.total_amount - self.paid_amount
    
    def can_be_returned(self):
        """Vérifie si la vente peut être retournée"""
        return (
            self.status == 'completed' and
            self.sale_type == 'regular' and
            self.sale_date >= timezone.now() - timezone.timedelta(days=30)
        )

    class Meta:
        db_table = 'sales_sale'
        verbose_name = 'Vente'
        verbose_name_plural = 'Ventes'
        ordering = ['-sale_date']
        indexes = [
            models.Index(fields=['sale_number']),
            models.Index(fields=['sale_date']),
            models.Index(fields=['customer', 'sale_date']),
            models.Index(fields=['cashier', 'sale_date']),
        ]


class SaleItem(BaseModel):
    """
    Ligne de vente
    Article vendu dans une transaction
    """
    sale = models.ForeignKey(
        Sale,
        on_delete=models.CASCADE,
        related_name='items',
        verbose_name="Vente"
    )
    
    article = models.ForeignKey(
        Article,
        on_delete=models.PROTECT,
        verbose_name="Article"
    )
    
    # Informations au moment de la vente
    article_name = models.CharField(
        max_length=200,
        verbose_name="Nom article",
        help_text="Nom de l'article au moment de la vente"
    )
    
    article_code = models.CharField(
        max_length=50,
        verbose_name="Code article",
        help_text="Code de l'article au moment de la vente"
    )
    
    # Quantité et prix
    quantity = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        validators=[MinValueValidator(0.001)],
        verbose_name="Quantité"
    )
    
    unit_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name="Prix unitaire",
        help_text="Prix unitaire au moment de la vente"
    )
    
    # Remises
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        verbose_name="Remise (%)"
    )
    
    discount_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant remise"
    )
    
    # Totaux
    line_total = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Total ligne",
        help_text="Total de la ligne après remise"
    )
    
    # Taxes
    tax_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0.00,
        verbose_name="Taux de TVA (%)"
    )
    
    tax_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Montant TVA"
    )
    
    # Traçabilité stock
    stock_movement = models.ForeignKey(
        'inventory.StockMovement',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name="Mouvement de stock associé"
    )
    
    lot_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro de lot vendu"
    )
    
    def save(self, *args, **kwargs):
        from decimal import Decimal  # Ajouter l'import si nécessaire
        
        # Copier les informations de l'article
        if self.article:
            self.article_name = self.article.name
            self.article_code = self.article.code
            if not self.unit_price:
                self.unit_price = self.article.selling_price
            if not self.tax_rate:
                self.tax_rate = self.article.category.tax_rate
        
        # Calculer les montants
        gross_amount = self.quantity * self.unit_price
        
        # Forcer la conversion en Decimal
        if self.discount_percentage > 0:
            self.discount_amount = gross_amount * (self.discount_percentage / Decimal('100'))
        else:
            self.discount_amount = Decimal('0.00')  # Initialiser comme Decimal
        
        self.line_total = gross_amount - self.discount_amount
        self.tax_amount = self.line_total * (self.tax_rate / Decimal('100'))
        
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'sales_sale_item'
        verbose_name = 'Ligne de vente'
        verbose_name_plural = 'Lignes de vente'
        ordering = ['sale', 'created_at']


class Payment(AuditableModel):
    """
    Paiement d'une vente
    Une vente peut avoir plusieurs paiements (paiement mixte)
    """
    PAYMENT_STATUS = [
        ('pending', 'En attente'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
        ('cancelled', 'Annulé'),
        ('refunded', 'Remboursé'),
    ]
    
    sale = models.ForeignKey(
        Sale,
        on_delete=models.CASCADE,
        related_name='payments',
        verbose_name="Vente"
    )
    
    payment_method = models.ForeignKey(
        PaymentMethod,
        on_delete=models.PROTECT,
        verbose_name="Moyen de paiement"
    )
    
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0.01)],
        verbose_name="Montant"
    )
    
    status = models.CharField(
        max_length=20,
        choices=PAYMENT_STATUS,
        default='pending',
        verbose_name="Statut"
    )
    
    # Informations spécifiques au mode de paiement
    card_last_digits = models.CharField(
        max_length=4,
        blank=True,
        verbose_name="4 derniers chiffres carte"
    )
    
    authorization_code = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Code d'autorisation"
    )
    
    transaction_id = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="ID transaction externe"
    )
    
    mobile_money_number = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Numéro Mobile Money"
    )
    
    check_number = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Numéro de chèque"
    )
    
    # Espèces
    cash_received = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Espèces reçues"
    )
    
    cash_change = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Monnaie rendue"
    )
    
    # Métadonnées
    payment_date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Date de paiement"
    )
    
    notes = models.TextField(
        blank=True,
        verbose_name="Notes"
    )

    class Meta:
        db_table = 'sales_payment'
        verbose_name = 'Paiement'
        verbose_name_plural = 'Paiements'
        ordering = ['-payment_date']


class Discount(BaseModel, NamedModel, ActivableModel):
    """
    Remises et promotions
    """
    DISCOUNT_TYPES = [
        ('percentage', 'Pourcentage'),
        ('fixed_amount', 'Montant fixe'),
        ('buy_x_get_y', 'Achetez X obtenez Y'),
        ('loyalty_points', 'Points fidélité'),
    ]
    
    DISCOUNT_SCOPES = [
        ('sale', 'Sur la vente totale'),
        ('category', 'Sur une catégorie'),
        ('article', 'Sur un article spécifique'),
        ('customer', 'Pour un client spécifique'),
    ]
    
    discount_type = models.CharField(
        max_length=20,
        choices=DISCOUNT_TYPES,
        verbose_name="Type de remise"
    )
    
    scope = models.CharField(
        max_length=20,
        choices=DISCOUNT_SCOPES,
        verbose_name="Portée de la remise"
    )
    
    # Valeurs
    percentage_value = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        verbose_name="Valeur pourcentage"
    )
    
    fixed_value = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Valeur fixe"
    )
    
    # Conditions
    min_quantity = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        verbose_name="Quantité minimum"
    )
    
    min_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Montant minimum"
    )
    
    max_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Montant maximum"
    )
    
    # Cibles
    target_categories = models.ManyToManyField(
        'inventory.Category',
        blank=True,
        verbose_name="Catégories cibles"
    )
    
    target_articles = models.ManyToManyField(
        Article,
        blank=True,
        verbose_name="Articles cibles"
    )
    
    target_customers = models.ManyToManyField(
        Customer,
        blank=True,
        verbose_name="Clients cibles"
    )
    
    # Période de validité
    start_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Date de début"
    )
    
    end_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Date de fin"
    )
    
    # Limitations
    max_uses = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        verbose_name="Utilisations maximum"
    )
    
    max_uses_per_customer = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        verbose_name="Utilisations max par client"
    )
    
    current_uses = models.IntegerField(
        default=0,
        verbose_name="Utilisations actuelles"
    )
    
    # Autorisation
    requires_authorization = models.BooleanField(
        default=False,
        verbose_name="Nécessite autorisation"
    )
    
    def is_valid(self, customer=None, amount=None):
        """Vérifie si la remise est valide"""
        now = timezone.now()
        
        # Vérifier la période
        if self.start_date and now < self.start_date:
            return False
        if self.end_date and now > self.end_date:
            return False
        
        # Vérifier les utilisations
        if self.max_uses and self.current_uses >= self.max_uses:
            return False
        
        # Vérifier le montant minimum
        if self.min_amount and (not amount or amount < self.min_amount):
            return False
        
        return True
    
    def calculate_discount(self, amount, quantity=1):
        """Calcule le montant de la remise"""
        if not self.is_valid(amount=amount):
            return Decimal('0.00')
        
        if self.discount_type == 'percentage':
            discount = amount * (self.percentage_value / 100)
        elif self.discount_type == 'fixed_amount':
            discount = self.fixed_value
        else:
            discount = Decimal('0.00')
        
        # Limiter le montant maximum
        if self.max_amount and discount > self.max_amount:
            discount = self.max_amount
        
        return discount

    class Meta:
        db_table = 'sales_discount'
        verbose_name = 'Remise'
        verbose_name_plural = 'Remises'
        ordering = ['-start_date', 'name']


class SaleDiscount(BaseModel):
    """
    Remises appliquées à une vente
    """
    sale = models.ForeignKey(
        Sale,
        on_delete=models.CASCADE,
        related_name='applied_discounts',
        verbose_name="Vente"
    )
    
    discount = models.ForeignKey(
        Discount,
        on_delete=models.PROTECT,
        verbose_name="Remise"
    )
    
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name="Montant de la remise"
    )
    
    authorized_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name="Autorisée par"
    )

    class Meta:
        db_table = 'sales_sale_discount'
        verbose_name = 'Remise appliquée'
        verbose_name_plural = 'Remises appliquées'


class Receipt(BaseModel):
    """
    Tickets de caisse
    Configuration et historique des impressions
    """
    sale = models.OneToOneField(
        Sale,
        on_delete=models.CASCADE,
        related_name='receipt',
        verbose_name="Vente"
    )
    
    receipt_number = models.CharField(
        max_length=30,
        unique=True,
        verbose_name="Numéro de ticket"
    )
    
    # Configuration d'impression
    header_text = models.TextField(
        blank=True,
        verbose_name="Texte d'en-tête"
    )
    
    footer_text = models.TextField(
        blank=True,
        verbose_name="Texte de pied de page"
    )
    
    # Impression
    printed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Imprimé le"
    )
    
    print_count = models.IntegerField(
        default=0,
        verbose_name="Nombre d'impressions"
    )
    
    emailed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Envoyé par email le"
    )

    class Meta:
        db_table = 'sales_receipt'
        verbose_name = 'Ticket de caisse'
        verbose_name_plural = 'Tickets de caisse'