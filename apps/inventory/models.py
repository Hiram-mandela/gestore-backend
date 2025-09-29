"""
Modèles de gestion des stocks et inventaire pour GESTORE
Système complet de gestion des articles, stocks, et mouvements
"""
from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.contrib.auth import get_user_model
from apps.core.models import (
    BaseModel, AuditableModel, NamedModel, 
    ActivableModel, CodedModel, PricedModel, OrderedModel
)

User = get_user_model()


class UnitOfMeasure(BaseModel, NamedModel, ActivableModel):
    """
    Unités de mesure pour les articles
    Ex: pièce, kg, litre, boîte, etc.
    """
    symbol = models.CharField(
        max_length=10,
        unique=True,
        verbose_name="Symbole",
        help_text="Symbole ou abréviation de l'unité (ex: kg, L, pcs)"
    )
    
    is_decimal = models.BooleanField(
        default=False,
        verbose_name="Décimale autorisée",
        help_text="Permet les quantités décimales pour cette unité"
    )

    class Meta:
        db_table = 'inventory_unit_of_measure'
        verbose_name = 'Unité de mesure'
        verbose_name_plural = 'Unités de mesure'
        ordering = ['name']


class UnitConversion(BaseModel):
    """
    Conversions entre unités de mesure
    Ex: 1 kg = 1000 g, 1 boîte = 12 pièces
    """
    from_unit = models.ForeignKey(
        UnitOfMeasure,
        on_delete=models.CASCADE,
        related_name='conversions_from',
        verbose_name="Unité source"
    )
    
    to_unit = models.ForeignKey(
        UnitOfMeasure,
        on_delete=models.CASCADE,
        related_name='conversions_to',
        verbose_name="Unité cible"
    )
    
    conversion_factor = models.DecimalField(
        max_digits=15,
        decimal_places=6,
        validators=[MinValueValidator(Decimal('0.000001'))],
        verbose_name="Facteur de conversion",
        help_text="Multiplicateur pour convertir de l'unité source vers l'unité cible"
    )
    
    def __str__(self):
        return f"1 {self.from_unit.symbol} = {self.conversion_factor} {self.to_unit.symbol}"

    class Meta:
        db_table = 'inventory_unit_conversion'
        verbose_name = 'Conversion d\'unité'
        verbose_name_plural = 'Conversions d\'unités'
        unique_together = ['from_unit', 'to_unit']


class Category(BaseModel, NamedModel, ActivableModel, OrderedModel):
    """
    Catégories et sous-catégories d'articles
    Structure hiérarchique illimitée
    """
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='children',
        verbose_name="Catégorie parent",
        help_text="Catégorie parent pour créer une hiérarchie"
    )
    
    code = models.CharField(
        max_length=20,
        unique=True,
        verbose_name="Code catégorie",
        help_text="Code unique de la catégorie"
    )
    
    # Configuration fiscale
    tax_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        verbose_name="Taux de TVA (%)",
        help_text="Taux de TVA par défaut pour cette catégorie"
    )
    
    # Configuration métier
    requires_prescription = models.BooleanField(
        default=False,
        verbose_name="Nécessite ordonnance",
        help_text="Articles de cette catégorie nécessitent une ordonnance"
    )
    
    requires_lot_tracking = models.BooleanField(
        default=False,
        verbose_name="Traçabilité lot obligatoire",
        help_text="Suivi obligatoire des lots pour cette catégorie"
    )
    
    requires_expiry_date = models.BooleanField(
        default=False,
        verbose_name="Date de péremption obligatoire",
        help_text="Date de péremption obligatoire pour cette catégorie"
    )
    
    # Alertes
    default_min_stock = models.IntegerField(
        default=5,
        validators=[MinValueValidator(0)],
        verbose_name="Stock minimum par défaut",
        help_text="Stock minimum par défaut pour les articles de cette catégorie"
    )
    
    # Couleur pour l'interface
    color = models.CharField(
        max_length=7,
        default='#007bff',
        verbose_name="Couleur",
        help_text="Couleur d'affichage (format hexadécimal)"
    )
    
    def get_level(self):
        """Retourne le niveau dans la hiérarchie"""
        level = 0
        parent = self.parent
        while parent:
            level += 1
            parent = parent.parent
        return level
    
    def get_full_path(self):
        """Retourne le chemin complet de la catégorie"""
        path = []
        current = self
        while current:
            path.insert(0, current.name)
            current = current.parent
        return ' > '.join(path)
    
    def get_children_recursive(self):
        """Retourne tous les enfants de manière récursive"""
        children = list(self.children.all())
        for child in list(children):
            children.extend(child.get_children_recursive())
        return children

    class Meta:
        db_table = 'inventory_category'
        verbose_name = 'Catégorie'
        verbose_name_plural = 'Catégories'
        ordering = ['parent__name', 'order', 'name']


class Brand(BaseModel, NamedModel, ActivableModel):
    """
    Marques des articles
    """
    logo = models.ImageField(
        upload_to='brands/',
        null=True,
        blank=True,
        verbose_name="Logo"
    )
    
    website = models.URLField(
        blank=True,
        verbose_name="Site web"
    )

    class Meta:
        db_table = 'inventory_brand'
        verbose_name = 'Marque'
        verbose_name_plural = 'Marques'
        ordering = ['name']


class Supplier(BaseModel, NamedModel, ActivableModel, CodedModel):
    """
    Fournisseurs - Version simplifiée pour inventory
    Version complète dans l'app suppliers
    """
    contact_person = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Personne de contact"
    )
    
    phone = models.CharField(
        max_length=20,
        blank=True,
        verbose_name="Téléphone"
    )
    
    email = models.EmailField(
        blank=True,
        verbose_name="Email"
    )

    class Meta:
        db_table = 'inventory_supplier'
        verbose_name = 'Fournisseur'
        verbose_name_plural = 'Fournisseurs'
        ordering = ['name']


class Article(AuditableModel, CodedModel, NamedModel, ActivableModel):
    """
    Articles du magasin
    Modèle principal pour tous les produits vendus
    """
    ARTICLE_TYPES = [
        ('product', 'Produit'),
        ('service', 'Service'),
        ('bundle', 'Pack/Bundle'),
        ('variant', 'Variante'),
    ]
    
    # Identification
    article_type = models.CharField(
        max_length=20,
        choices=ARTICLE_TYPES,
        default='product',
        verbose_name="Type d'article"
    )
    
    # Références
    barcode = models.CharField(
        max_length=50,
        unique=True,
        null=True,
        blank=True,
        verbose_name="Code-barres principal",
        help_text="Code-barres EAN13, UPC ou autre"
    )
    
    internal_reference = models.CharField(
        max_length=50,
        unique=True,
        null=True,
        blank=True,
        verbose_name="Référence interne",
        help_text="Référence interne du magasin"
    )
    
    supplier_reference = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Référence fournisseur",
        help_text="Référence chez le fournisseur principal"
    )
    
    # Classification
    category = models.ForeignKey(
        Category,
        on_delete=models.PROTECT,
        verbose_name="Catégorie"
    )
    
    brand = models.ForeignKey(
        Brand,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name="Marque"
    )
    
    # Informations générales
    short_description = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Description courte",
        help_text="Description affichée en caisse"
    )
    
    # Prix
    purchase_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(0)],
        verbose_name="Prix d'achat HT",
        help_text="Prix d'achat hors taxes"
    )
    
    selling_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(0)],
        verbose_name="Prix de vente TTC",
        help_text="Prix de vente toutes taxes comprises"
    )
    
    # Unité
    unit_of_measure = models.ForeignKey(
        UnitOfMeasure,
        on_delete=models.PROTECT,
        verbose_name="Unité de mesure"
    )
    
    # Gestion des stocks
    manage_stock = models.BooleanField(
        default=True,
        verbose_name="Gérer le stock",
        help_text="Activer la gestion de stock pour cet article"
    )
    
    min_stock_level = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        verbose_name="Stock minimum",
        help_text="Seuil d'alerte stock bas"
    )
    
    max_stock_level = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        verbose_name="Stock maximum",
        help_text="Stock maximum recommandé"
    )
    
    # Fournisseur principal
    main_supplier = models.ForeignKey(
        Supplier,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name="Fournisseur principal"
    )
    
    # Traçabilité
    requires_lot_tracking = models.BooleanField(
        default=False,
        verbose_name="Traçabilité des lots",
        help_text="Suivi obligatoire des numéros de lot"
    )
    
    requires_expiry_date = models.BooleanField(
        default=False,
        verbose_name="Date de péremption",
        help_text="Gestion des dates de péremption"
    )
    
    # Configuration vente
    is_sellable = models.BooleanField(
        default=True,
        verbose_name="Vendable",
        help_text="Article disponible à la vente"
    )
    
    is_purchasable = models.BooleanField(
        default=True,
        verbose_name="Achetable",
        help_text="Article peut être acheté auprès des fournisseurs"
    )
    
    allow_negative_stock = models.BooleanField(
        default=False,
        verbose_name="Autoriser stock négatif",
        help_text="Permet les ventes même sans stock"
    )
    
    # Article parent pour les variantes
    parent_article = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='variants',
        verbose_name="Article parent",
        help_text="Article parent pour les variantes (taille, couleur, etc.)"
    )
    
    # Attributs des variantes
    variant_attributes = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Attributs variante",
        help_text="Attributs spécifiques de la variante (taille, couleur, etc.)"
    )
    
    # Images
    image = models.ImageField(
        upload_to='articles/',
        null=True,
        blank=True,
        verbose_name="Image principale"
    )
    
    # Poids et dimensions
    weight = models.DecimalField(
        max_digits=8,
        decimal_places=3,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Poids (kg)"
    )
    
    length = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Longueur (cm)"
    )
    
    width = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Largeur (cm)"
    )
    
    height = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        verbose_name="Hauteur (cm)"
    )
    
    # Méta-données
    tags = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Tags",
        help_text="Mots-clés pour la recherche"
    )
    
    notes = models.TextField(
        blank=True,
        verbose_name="Notes internes",
        help_text="Notes internes non visibles en caisse"
    )
    
    def get_current_stock(self):
        """Retourne le stock actuel de l'article"""
        return self.stock_entries.aggregate(
            total=models.Sum('quantity_on_hand')
        )['total'] or 0
    
    def get_available_stock(self):
        """Retourne le stock disponible (non réservé)"""
        return self.stock_entries.aggregate(
            available=models.Sum('quantity_available')
        )['available'] or 0
    
    def is_low_stock(self):
        """Vérifie si le stock est bas"""
        if not self.manage_stock:
            return False
        return self.get_current_stock() <= self.min_stock_level
    
    def get_margin_percent(self):
        """Calcule le pourcentage de marge"""
        if self.purchase_price > 0:
            return ((self.selling_price - self.purchase_price) / self.purchase_price) * 100
        return 0
    
    def get_all_barcodes(self):
        """Retourne tous les codes-barres de l'article"""
        barcodes = []
        if self.barcode:
            barcodes.append(self.barcode)
        barcodes.extend([ab.barcode for ab in self.additional_barcodes.all()])
        return barcodes

    class Meta:
        db_table = 'inventory_article'
        verbose_name = 'Article'
        verbose_name_plural = 'Articles'
        ordering = ['category__name', 'name']
        indexes = [
            models.Index(fields=['barcode']),
            models.Index(fields=['internal_reference']),
            models.Index(fields=['category', 'is_active']),
            models.Index(fields=['is_sellable', 'is_active']),
        ]


class ArticleBarcode(BaseModel):
    """
    Codes-barres additionnels pour un article
    Un article peut avoir plusieurs codes-barres
    """
    article = models.ForeignKey(
        Article,
        on_delete=models.CASCADE,
        related_name='additional_barcodes',
        verbose_name="Article"
    )
    
    barcode = models.CharField(
        max_length=50,
        unique=True,
        verbose_name="Code-barres"
    )
    
    barcode_type = models.CharField(
        max_length=20,
        choices=[
            ('EAN13', 'EAN-13'),
            ('UPC', 'UPC'),
            ('CODE128', 'Code 128'),
            ('INTERNAL', 'Code interne'),
            ('SUPPLIER', 'Code fournisseur'),
        ],
        default='EAN13',
        verbose_name="Type de code-barres"
    )
    
    is_primary = models.BooleanField(
        default=False,
        verbose_name="Code principal"
    )

    class Meta:
        db_table = 'inventory_article_barcode'
        verbose_name = 'Code-barres article'
        verbose_name_plural = 'Codes-barres articles'


class ArticleImage(BaseModel, OrderedModel):
    """
    Images additionnelles pour un article
    Gestion de multiples images par article
    """
    article = models.ForeignKey(
        Article,
        on_delete=models.CASCADE,
        related_name='images',
        verbose_name="Article"
    )
    
    image = models.ImageField(
        upload_to='articles/images/',
        verbose_name="Image"
    )
    
    alt_text = models.CharField(
        max_length=200,
        blank=True,
        verbose_name="Texte alternatif",
        help_text="Description de l'image pour l'accessibilité"
    )
    
    is_primary = models.BooleanField(
        default=False,
        verbose_name="Image principale"
    )
    
    caption = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Légende"
    )

    class Meta:
        db_table = 'inventory_article_image'
        verbose_name = 'Image d\'article'
        verbose_name_plural = 'Images d\'articles'
        ordering = ['article', 'order', '-is_primary']


class PriceHistory(AuditableModel):
    """
    Historique des modifications de prix
    Traçabilité complète des changements de tarifs
    """
    PRICE_CHANGE_REASONS = [
        ('cost_increase', 'Augmentation coût fournisseur'),
        ('cost_decrease', 'Diminution coût fournisseur'),
        ('margin_adjustment', 'Ajustement marge'),
        ('promotion', 'Promotion'),
        ('market_adjustment', 'Ajustement marché'),
        ('currency_change', 'Variation devise'),
        ('bulk_update', 'Mise à jour en masse'),
        ('manual', 'Modification manuelle'),
    ]
    
    article = models.ForeignKey(
        Article,
        on_delete=models.CASCADE,
        related_name='price_history',
        verbose_name="Article"
    )
    
    # Prix avant modification
    old_purchase_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name="Ancien prix d'achat"
    )
    
    old_selling_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name="Ancien prix de vente"
    )
    
    # Nouveaux prix
    new_purchase_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name="Nouveau prix d'achat"
    )
    
    new_selling_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name="Nouveau prix de vente"
    )
    
    # Métadonnées du changement
    reason = models.CharField(
        max_length=20,
        choices=PRICE_CHANGE_REASONS,
        verbose_name="Raison du changement"
    )
    
    notes = models.TextField(
        blank=True,
        verbose_name="Notes"
    )
    
    effective_date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Date d'effet"
    )
    
    def get_purchase_change_percent(self):
        """Calcule le pourcentage de variation du prix d'achat"""
        if self.old_purchase_price > 0:
            return ((self.new_purchase_price - self.old_purchase_price) / self.old_purchase_price) * 100
        return 0
    
    def get_selling_change_percent(self):
        """Calcule le pourcentage de variation du prix de vente"""
        if self.old_selling_price > 0:
            return ((self.new_selling_price - self.old_selling_price) / self.old_selling_price) * 100
        return 0

    class Meta:
        db_table = 'inventory_price_history'
        verbose_name = 'Historique de prix'
        verbose_name_plural = 'Historiques de prix'
        ordering = ['-effective_date']


class Location(BaseModel, NamedModel, ActivableModel, CodedModel):
    """
    Emplacements de stockage
    Hiérarchie: Magasin > Zone > Rayon > Étagère > Casier
    """
    LOCATION_TYPES = [
        ('store', 'Magasin'),
        ('zone', 'Zone'),
        ('aisle', 'Rayon'),
        ('shelf', 'Étagère'),
        ('bin', 'Casier'),
    ]
    
    location_type = models.CharField(
        max_length=20,
        choices=LOCATION_TYPES,
        verbose_name="Type d'emplacement"
    )
    
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='children',
        verbose_name="Emplacement parent"
    )
    
    barcode = models.CharField(
        max_length=50,
        unique=True,
        null=True,
        blank=True,
        verbose_name="Code-barres emplacement"
    )

    class Meta:
        db_table = 'inventory_location'
        verbose_name = 'Emplacement'
        verbose_name_plural = 'Emplacements'
        ordering = ['location_type', 'code', 'name']


class Stock(BaseModel):
    """
    Stock physique d'un article dans un emplacement
    """
    article = models.ForeignKey(
        Article,
        on_delete=models.CASCADE,
        related_name='stock_entries',
        verbose_name="Article"
    )
    
    location = models.ForeignKey(
        Location,
        on_delete=models.CASCADE,
        verbose_name="Emplacement"
    )
    
    lot_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name="Numéro de lot",
        help_text="Numéro de lot du fournisseur"
    )
    
    expiry_date = models.DateField(
        null=True,
        blank=True,
        verbose_name="Date de péremption"
    )
    
    quantity_on_hand = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        default=0,
        verbose_name="Quantité en stock"
    )
    
    quantity_reserved = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        default=0,
        verbose_name="Quantité réservée"
    )
    
    quantity_available = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        default=0,
        verbose_name="Quantité disponible"
    )
    
    # Coûts
    unit_cost = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Coût unitaire",
        help_text="Coût unitaire d'achat de ce lot"
    )
    
    def save(self, *args, **kwargs):
        # Calculer la quantité disponible
        self.quantity_available = self.quantity_on_hand - self.quantity_reserved
        super().save(*args, **kwargs)
    
    def is_expired(self):
        """Vérifie si le lot est périmé"""
        if self.expiry_date:
            return self.expiry_date <= timezone.now().date()
        return False
    
    def days_until_expiry(self):
        """Retourne le nombre de jours avant péremption"""
        if self.expiry_date:
            delta = self.expiry_date - timezone.now().date()
            return delta.days
        return None

    class Meta:
        db_table = 'inventory_stock'
        verbose_name = 'Stock'
        verbose_name_plural = 'Stocks'
        unique_together = ['article', 'location', 'lot_number', 'expiry_date']
        ordering = ['article__name', 'location__name', 'expiry_date']


class StockMovement(AuditableModel):
    """
    Mouvements de stock
    Trace tous les mouvements d'entrée et de sortie
    """
    MOVEMENT_TYPES = [
        ('in', 'Entrée'),
        ('out', 'Sortie'),
        ('adjustment', 'Ajustement'),
        ('transfer', 'Transfert'),
        ('return', 'Retour'),
        ('loss', 'Perte'),
        ('found', 'Trouvé'),
    ]
    
    MOVEMENT_REASONS = [
        ('purchase', 'Achat fournisseur'),
        ('sale', 'Vente client'),
        ('return_supplier', 'Retour fournisseur'),
        ('return_customer', 'Retour client'),
        ('inventory', 'Inventaire'),
        ('damage', 'Dommage'),
        ('theft', 'Vol'),
        ('expiry', 'Péremption'),
        ('transfer', 'Transfert'),
        ('adjustment', 'Ajustement'),
        ('production', 'Production'),
        ('consumption', 'Consommation'),
    ]
    
    article = models.ForeignKey(
        Article,
        on_delete=models.CASCADE,
        related_name='movements',
        verbose_name="Article"
    )
    
    stock = models.ForeignKey(
        Stock,
        on_delete=models.CASCADE,
        related_name='movements',
        verbose_name="Stock concerné"
    )
    
    movement_type = models.CharField(
        max_length=20,
        choices=MOVEMENT_TYPES,
        verbose_name="Type de mouvement"
    )
    
    reason = models.CharField(
        max_length=20,
        choices=MOVEMENT_REASONS,
        verbose_name="Raison du mouvement"
    )
    
    quantity = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        verbose_name="Quantité"
    )
    
    unit_cost = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Coût unitaire"
    )
    
    reference_document = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Document de référence",
        help_text="Numéro de facture, bon de livraison, etc."
    )
    
    notes = models.TextField(
        blank=True,
        verbose_name="Notes"
    )
    
    # Stock avant et après le mouvement
    stock_before = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        verbose_name="Stock avant"
    )
    
    stock_after = models.DecimalField(
        max_digits=10,
        decimal_places=3,
        verbose_name="Stock après"
    )

    class Meta:
        db_table = 'inventory_stock_movement'
        verbose_name = 'Mouvement de stock'
        verbose_name_plural = 'Mouvements de stock'
        ordering = ['-created_at']


class StockAlert(BaseModel):
    """
    Alertes de stock
    Notifications automatiques pour stock bas, péremption, etc.
    """
    ALERT_TYPES = [
        ('low_stock', 'Stock bas'),
        ('out_of_stock', 'Rupture de stock'),
        ('expiry_soon', 'Péremption proche'),
        ('expired', 'Périmé'),
        ('overstock', 'Surstock'),
    ]
    
    ALERT_LEVELS = [
        ('info', 'Information'),
        ('warning', 'Avertissement'),
        ('critical', 'Critique'),
    ]
    
    article = models.ForeignKey(
        Article,
        on_delete=models.CASCADE,
        related_name='alerts',
        verbose_name="Article"
    )
    
    stock = models.ForeignKey(
        Stock,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        verbose_name="Stock concerné"
    )
    
    alert_type = models.CharField(
        max_length=20,
        choices=ALERT_TYPES,
        verbose_name="Type d'alerte"
    )
    
    alert_level = models.CharField(
        max_length=20,
        choices=ALERT_LEVELS,
        verbose_name="Niveau d'alerte"
    )
    
    message = models.TextField(
        verbose_name="Message d'alerte"
    )
    
    is_acknowledged = models.BooleanField(
        default=False,
        verbose_name="Acquittée"
    )
    
    acknowledged_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Acquittée par"
    )
    
    acknowledged_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Acquittée le"
    )

    class Meta:
        db_table = 'inventory_stock_alert'
        verbose_name = 'Alerte de stock'
        verbose_name_plural = 'Alertes de stock'
        ordering = ['-created_at', 'alert_level']