"""
Serializers pour l'application inventory - GESTORE
Gestion complète des articles, stocks et mouvements avec optimisations
"""
from rest_framework import serializers
from django.db.models import Sum, Q, F
from django.utils import timezone
from decimal import Decimal
from apps.core.serializers import (
    BaseModelSerializer, AuditableSerializer, NamedModelSerializer, 
    ActivableModelSerializer, CodedModelSerializer, OrderedModelSerializer,
    PricedModelSerializer, BulkOperationSerializer
)
from .models import (
    UnitOfMeasure, UnitConversion, Category, Brand, Supplier,
    Article, ArticleBarcode, ArticleImage, PriceHistory,
    Location, Stock, StockMovement, StockAlert
)


# ========================
# UNITÉS ET CONVERSIONS
# ========================

class UnitOfMeasureSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer):
    """
    Serializer pour les unités de mesure
    """
    symbol = serializers.CharField(max_length=10)
    is_decimal = serializers.BooleanField(default=False)
    
    # Champs calculés
    articles_count = serializers.SerializerMethodField()
    conversion_count = serializers.SerializerMethodField()
    
    class Meta:
        model = UnitOfMeasure
        fields = [
            'id', 'name', 'description', 'symbol', 'is_decimal', 'is_active',
            'status_display', 'articles_count', 'conversion_count',
            'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
    
    def get_articles_count(self, obj):
        """Nombre d'articles utilisant cette unité"""
        return getattr(obj, 'articles_count', 0)
    
    def get_conversion_count(self, obj):
        """Nombre de conversions configurées"""
        return getattr(obj, 'conversion_count', 0)


class UnitConversionSerializer(BaseModelSerializer):
    """
    Serializer pour les conversions d'unités
    """
    from_unit = UnitOfMeasureSerializer(read_only=True)
    from_unit_id = serializers.CharField(write_only=True)
    to_unit = UnitOfMeasureSerializer(read_only=True)
    to_unit_id = serializers.CharField(write_only=True)
    conversion_factor = serializers.DecimalField(max_digits=15, decimal_places=6)
    
    # Champ calculé pour l'affichage
    conversion_display = serializers.SerializerMethodField()
    
    class Meta:
        model = UnitConversion
        fields = [
            'id', 'from_unit', 'from_unit_id', 'to_unit', 'to_unit_id',
            'conversion_factor', 'conversion_display',
            'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
    
    def get_conversion_display(self, obj):
        """Affichage de la conversion"""
        return f"1 {obj.from_unit.symbol} = {obj.conversion_factor} {obj.to_unit.symbol}"
    
    def validate(self, attrs):
        """Validation globale de la conversion"""
        from_unit_id = attrs.get('from_unit_id')
        to_unit_id = attrs.get('to_unit_id')
        
        if from_unit_id == to_unit_id:
            raise serializers.ValidationError("L'unité source et l'unité cible doivent être différentes.")
        
        return attrs


# ========================
# CLASSIFICATION
# ========================

class CategorySerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer, 
                        CodedModelSerializer, OrderedModelSerializer):
    """
    Serializer pour les catégories avec hiérarchie
    """
    parent = serializers.CharField(source='parent.id', read_only=True, allow_null=True)
    parent_id = serializers.CharField(write_only=True, allow_null=True, required=False)
    parent_name = serializers.CharField(source='parent.name', read_only=True)
    
    # Configuration métier
    tax_rate = serializers.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    requires_prescription = serializers.BooleanField(default=False)
    requires_lot_tracking = serializers.BooleanField(default=False)
    requires_expiry_date = serializers.BooleanField(default=False)
    default_min_stock = serializers.IntegerField(default=5)
    color = serializers.CharField(max_length=7, default='#007bff')
    
    # Champs calculés
    level = serializers.SerializerMethodField()
    full_path = serializers.SerializerMethodField()
    children_count = serializers.SerializerMethodField()
    articles_count = serializers.SerializerMethodField()
    has_children = serializers.SerializerMethodField()
    
    class Meta:
        model = Category
        fields = [
            'id', 'name', 'description', 'code', 'parent', 'parent_id', 'parent_name',
            'tax_rate', 'requires_prescription', 'requires_lot_tracking', 
            'requires_expiry_date', 'default_min_stock', 'color', 'order', 'is_active',
            'level', 'full_path', 'children_count', 'articles_count', 'has_children',
            'status_display', 'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
    
    def get_level(self, obj):
        """Niveau dans la hiérarchie"""
        return obj.get_level()
    
    def get_full_path(self, obj):
        """Chemin complet de la catégorie"""
        return obj.get_full_path()
    
    def get_children_count(self, obj):
        """Nombre d'enfants directs"""
        return getattr(obj, 'children_count', 0)
    
    def get_articles_count(self, obj):
        """Nombre d'articles dans cette catégorie"""
        return getattr(obj, 'articles_count', 0)
    
    def get_has_children(self, obj):
        """Indique si la catégorie a des enfants"""
        return self.get_children_count(obj) > 0


class CategoryTreeSerializer(CategorySerializer):
    """
    Serializer pour l'arborescence complète des catégories
    """
    children = serializers.SerializerMethodField()
    
    class Meta(CategorySerializer.Meta):
        fields = CategorySerializer.Meta.fields + ['children']
    
    def get_children(self, obj):
        """Récupère les enfants récursivement"""
        if hasattr(obj, 'children'):
            children = obj.children.filter(is_active=True).order_by('order', 'name')
            return CategoryTreeSerializer(children, many=True, context=self.context).data
        return []


class BrandSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer):
    """
    Serializer pour les marques
    """
    logo = serializers.ImageField(required=False, allow_null=True)
    logo_url = serializers.SerializerMethodField()
    website = serializers.URLField(required=False, allow_blank=True)
    
    # Champs calculés
    articles_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Brand
        fields = [
            'id', 'name', 'description', 'logo', 'logo_url', 'website', 'is_active',
            'status_display', 'articles_count',
            'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
    
    def get_logo_url(self, obj):
        """URL complète du logo"""
        if obj.logo:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.logo.url)
            return obj.logo.url
        return None
    
    def get_articles_count(self, obj):
        """Nombre d'articles de cette marque"""
        return getattr(obj, 'articles_count', 0)


class SupplierSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer, CodedModelSerializer):
    """
    Serializer pour les fournisseurs (version simplifiée)
    """
    contact_person = serializers.CharField(max_length=100, required=False, allow_blank=True)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    
    # Champs calculés
    articles_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Supplier
        fields = [
            'id', 'name', 'description', 'code', 'contact_person', 'phone', 'email',
            'is_active', 'status_display', 'articles_count',
            'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
    
    def get_articles_count(self, obj):
        """Nombre d'articles de ce fournisseur"""
        return getattr(obj, 'articles_count', 0)


# ========================
# ARTICLES
# ========================

class ArticleImageSerializer(BaseModelSerializer, OrderedModelSerializer):
    """
    Serializer pour les images d'articles
    """
    image = serializers.ImageField()
    image_url = serializers.SerializerMethodField()
    alt_text = serializers.CharField(max_length=200, required=False, allow_blank=True)
    caption = serializers.CharField(max_length=255, required=False, allow_blank=True)
    is_primary = serializers.BooleanField(default=False)
    
    class Meta:
        model = ArticleImage
        fields = [
            'id', 'image', 'image_url', 'alt_text', 'caption', 'is_primary', 'order',
            'created_at', 'updated_at'
        ]
    
    def get_image_url(self, obj):
        """URL complète de l'image"""
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None


class ArticleBarcodeSerializer(BaseModelSerializer):
    """
    Serializer pour les codes-barres d'articles
    """
    barcode = serializers.CharField(max_length=50)
    barcode_type = serializers.ChoiceField(choices=[
        ('EAN13', 'EAN-13'),
        ('UPC', 'UPC'),
        ('CODE128', 'Code 128'),
        ('INTERNAL', 'Code interne'),
        ('SUPPLIER', 'Code fournisseur'),
    ], default='EAN13')
    is_primary = serializers.BooleanField(default=False)
    
    class Meta:
        model = ArticleBarcode
        fields = [
            'id', 'barcode', 'barcode_type', 'is_primary',
            'created_at', 'updated_at'
        ]


# REMARQUE: ArticleSupplierSerializer supprimé car on utilise
# SupplierArticleSerializer de l'app suppliers pour les relations article-fournisseur


class PriceHistorySerializer(AuditableSerializer):
    """
    Serializer pour l'historique des prix
    """
    article_name = serializers.CharField(source='article.name', read_only=True)
    old_purchase_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    old_selling_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    new_purchase_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    new_selling_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    reason = serializers.ChoiceField(choices=[
        ('cost_increase', 'Augmentation coût fournisseur'),
        ('cost_decrease', 'Diminution coût fournisseur'),
        ('margin_adjustment', 'Ajustement marge'),
        ('promotion', 'Promotion'),
        ('market_adjustment', 'Ajustement marché'),
        ('currency_change', 'Variation devise'),
        ('bulk_update', 'Mise à jour en masse'),
        ('manual', 'Modification manuelle'),
    ])
    notes = serializers.CharField(required=False, allow_blank=True)
    effective_date = serializers.DateTimeField(default=timezone.now)
    
    # Champs calculés
    purchase_change_percent = serializers.SerializerMethodField()
    selling_change_percent = serializers.SerializerMethodField()
    
    class Meta:
        model = PriceHistory
        fields = [
            'id', 'article_name', 'old_purchase_price', 'old_selling_price',
            'new_purchase_price', 'new_selling_price', 'reason', 'notes',
            'effective_date', 'purchase_change_percent', 'selling_change_percent',
            'created_by', 'created_at'
        ]
    
    def get_purchase_change_percent(self, obj):
        """Pourcentage de variation du prix d'achat"""
        return obj.get_purchase_change_percent()
    
    def get_selling_change_percent(self, obj):
        """Pourcentage de variation du prix de vente"""
        return obj.get_selling_change_percent()


class ArticleListSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer, CodedModelSerializer):
    """
    Serializer optimisé pour les listes d'articles
    """
    article_type = serializers.CharField()
    barcode = serializers.CharField(max_length=50, required=False, allow_null=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    category_color = serializers.CharField(source='category.color', read_only=True)
    brand_name = serializers.CharField(source='brand.name', read_only=True)
    unit_symbol = serializers.CharField(source='unit_of_measure.symbol', read_only=True)
    
    # Prix
    purchase_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    selling_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    
    # Image principale
    image_url = serializers.SerializerMethodField()
    
    # Champs calculés pour performance
    current_stock = serializers.SerializerMethodField()
    available_stock = serializers.SerializerMethodField()
    is_low_stock = serializers.SerializerMethodField()
    margin_percent = serializers.SerializerMethodField()
    
    class Meta:
        model = Article
        fields = [
            'id', 'name', 'code', 'article_type', 'barcode', 'category_name', 'category_color',
            'brand_name', 'unit_symbol', 'purchase_price', 'selling_price', 'image_url',
            'current_stock', 'available_stock', 'is_low_stock', 'margin_percent',
            'is_sellable', 'is_active', 'status_display',
            'created_at', 'updated_at'
        ]
    
    def get_image_url(self, obj):
        """URL de l'image principale"""
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None
    
    def get_current_stock(self, obj):
        """Stock actuel (préchargé si disponible)"""
        return getattr(obj, 'current_stock', 0)
    
    def get_available_stock(self, obj):
        """Stock disponible (préchargé si disponible)"""
        return getattr(obj, 'available_stock', 0)
    
    def get_is_low_stock(self, obj):
        """Indicateur stock bas"""
        current_stock = self.get_current_stock(obj)
        # Gérer le cas où current_stock ou min_stock_level est None
        if current_stock is None or obj.min_stock_level is None:
            return False
        return obj.manage_stock and current_stock <= obj.min_stock_level
    
    def get_margin_percent(self, obj):
        """Pourcentage de marge"""
        return obj.get_margin_percent()


class ArticleDetailSerializer(AuditableSerializer, NamedModelSerializer, ActivableModelSerializer, CodedModelSerializer):
    """
    Serializer complet pour les articles avec toutes les relations
    """
    article_type = serializers.CharField()
    
    # Références
    barcode = serializers.CharField(max_length=50, required=False, allow_null=True)
    internal_reference = serializers.CharField(max_length=50, required=False, allow_null=True)
    supplier_reference = serializers.CharField(max_length=50, required=False, allow_blank=True)
    
    # Relations avec expansion
    category = CategorySerializer(read_only=True)
    category_id = serializers.CharField(write_only=True)
    brand = BrandSerializer(read_only=True)
    brand_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    unit_of_measure = UnitOfMeasureSerializer(read_only=True)
    unit_of_measure_id = serializers.CharField(write_only=True)
    main_supplier = SupplierSerializer(read_only=True)
    main_supplier_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    
    # Informations générales
    short_description = serializers.CharField(max_length=100, required=False, allow_blank=True)
    
    # Prix
    purchase_price = serializers.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    selling_price = serializers.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    # Configuration stock
    manage_stock = serializers.BooleanField(default=True)
    min_stock_level = serializers.IntegerField(default=0)
    max_stock_level = serializers.IntegerField(default=0)
    
    # Configuration métier
    requires_lot_tracking = serializers.BooleanField(default=False)
    requires_expiry_date = serializers.BooleanField(default=False)
    is_sellable = serializers.BooleanField(default=True)
    is_purchasable = serializers.BooleanField(default=True)
    allow_negative_stock = serializers.BooleanField(default=False)
    
    # Variantes
    parent_article = ArticleListSerializer(read_only=True)
    parent_article_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    variant_attributes = serializers.JSONField(default=dict, required=False)
    
    # Image principale
    image = serializers.ImageField(required=False, allow_null=True)
    image_url = serializers.SerializerMethodField()
    
    # Dimensions
    weight = serializers.DecimalField(max_digits=8, decimal_places=3, required=False, allow_null=True)
    length = serializers.DecimalField(max_digits=8, decimal_places=2, required=False, allow_null=True)
    width = serializers.DecimalField(max_digits=8, decimal_places=2, required=False, allow_null=True)
    height = serializers.DecimalField(max_digits=8, decimal_places=2, required=False, allow_null=True)
    
    # Métadonnées
    tags = serializers.JSONField(default=list, required=False)
    notes = serializers.CharField(required=False, allow_blank=True)
    
    # Relations multiples
    additional_barcodes = ArticleBarcodeSerializer(many=True, read_only=True)
    images = ArticleImageSerializer(many=True, read_only=True)
    # suppliers -> Utiliser SupplierArticle de l'app suppliers (related_name='suppliers')
    price_history = PriceHistorySerializer(many=True, read_only=True)
    variants = ArticleListSerializer(many=True, read_only=True)
    
    # Champs calculés
    current_stock = serializers.SerializerMethodField()
    available_stock = serializers.SerializerMethodField()
    reserved_stock = serializers.SerializerMethodField()
    is_low_stock = serializers.SerializerMethodField()
    margin_percent = serializers.SerializerMethodField()
    all_barcodes = serializers.SerializerMethodField()
    variants_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Article
        fields = [
            'id', 'name', 'description', 'code', 'article_type', 'barcode',
            'internal_reference', 'supplier_reference', 'category', 'category_id',
            'brand', 'brand_id', 'unit_of_measure', 'unit_of_measure_id',
            'main_supplier', 'main_supplier_id', 'short_description',
            'purchase_price', 'selling_price', 'manage_stock', 'min_stock_level',
            'max_stock_level', 'requires_lot_tracking', 'requires_expiry_date',
            'is_sellable', 'is_purchasable', 'allow_negative_stock',
            'parent_article', 'parent_article_id', 'variant_attributes',
            'image', 'image_url', 'weight', 'length', 'width', 'height',
            'tags', 'notes', 'is_active', 'status_display',
            'additional_barcodes', 'images', 'price_history', 'variants',
            'current_stock', 'available_stock', 'reserved_stock', 'is_low_stock',
            'margin_percent', 'all_barcodes', 'variants_count',
            'created_by', 'created_at', 'updated_by', 'updated_at',
            'sync_status', 'needs_sync'
        ]
    
    def get_image_url(self, obj):
        """URL de l'image principale"""
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None
    
    def get_current_stock(self, obj):
        """Stock actuel total"""
        return obj.get_current_stock()
    
    def get_available_stock(self, obj):
        """Stock disponible total"""
        return obj.get_available_stock()
    
    def get_reserved_stock(self, obj):
        """Stock réservé total"""
        return obj.stock_entries.aggregate(
            total=Sum('quantity_reserved')
        )['total'] or 0
    
    def get_is_low_stock(self, obj):
        """Indicateur stock bas"""
        return obj.is_low_stock()
    
    def get_margin_percent(self, obj):
        """Pourcentage de marge"""
        return obj.get_margin_percent()
    
    def get_all_barcodes(self, obj):
        """Tous les codes-barres de l'article"""
        return obj.get_all_barcodes()
    
    def get_variants_count(self, obj):
        """Nombre de variantes"""
        return getattr(obj, 'variants_count', 0)


# ========================
# EMPLACEMENTS ET STOCKS
# ========================

class LocationSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer, CodedModelSerializer):
    """
    Serializer pour les emplacements
    """
    location_type = serializers.ChoiceField(choices=[
        ('store', 'Magasin'),
        ('zone', 'Zone'),
        ('aisle', 'Rayon'),
        ('shelf', 'Étagère'),
        ('bin', 'Casier'),
    ])
    parent = serializers.CharField(source='parent.id', read_only=True, allow_null=True)
    parent_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    parent_name = serializers.CharField(source='parent.name', read_only=True)
    barcode = serializers.CharField(max_length=50, required=False, allow_null=True)
    
    # Champs calculés
    children_count = serializers.SerializerMethodField()
    stocks_count = serializers.SerializerMethodField()
    full_path = serializers.SerializerMethodField()
    
    class Meta:
        model = Location
        fields = [
            'id', 'name', 'description', 'code', 'location_type', 'parent', 'parent_id',
            'parent_name', 'barcode', 'is_active', 'status_display',
            'children_count', 'stocks_count', 'full_path',
            'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
    
    def get_children_count(self, obj):
        """Nombre d'emplacements enfants"""
        return getattr(obj, 'children_count', 0)
    
    def get_stocks_count(self, obj):
        """Nombre de stocks dans cet emplacement"""
        return getattr(obj, 'stocks_count', 0)
    
    def get_full_path(self, obj):
        """Chemin complet de l'emplacement"""
        path = []
        current = obj
        while current:
            path.insert(0, current.name)
            current = current.parent
        return ' > '.join(path)


class StockSerializer(BaseModelSerializer):
    """
    Serializer pour les stocks
    """
    article = ArticleListSerializer(read_only=True)
    article_id = serializers.CharField(write_only=True)
    location = LocationSerializer(read_only=True)
    location_id = serializers.CharField(write_only=True)
    
    lot_number = serializers.CharField(max_length=50, required=False, allow_blank=True)
    expiry_date = serializers.DateField(required=False, allow_null=True)
    
    quantity_on_hand = serializers.DecimalField(max_digits=10, decimal_places=3, default=0)
    quantity_reserved = serializers.DecimalField(max_digits=10, decimal_places=3, default=0)
    quantity_available = serializers.DecimalField(max_digits=10, decimal_places=3, read_only=True)
    unit_cost = serializers.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    # Champs calculés
    is_expired = serializers.SerializerMethodField()
    days_until_expiry = serializers.SerializerMethodField()
    stock_value = serializers.SerializerMethodField()
    
    class Meta:
        model = Stock
        fields = [
            'id', 'article', 'article_id', 'location', 'location_id',
            'lot_number', 'expiry_date', 'quantity_on_hand', 'quantity_reserved',
            'quantity_available', 'unit_cost', 'is_expired', 'days_until_expiry',
            'stock_value', 'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
    
    def get_is_expired(self, obj):
        """Vérifie si le stock est périmé"""
        return obj.is_expired()
    
    def get_days_until_expiry(self, obj):
        """Jours avant péremption"""
        return obj.days_until_expiry()
    
    def get_stock_value(self, obj):
        """Valeur du stock"""
        return float(obj.quantity_on_hand * obj.unit_cost)


class StockMovementSerializer(AuditableSerializer):
    """
    Serializer pour les mouvements de stock
    """
    article = ArticleListSerializer(read_only=True)
    article_id = serializers.CharField(write_only=True)
    stock = StockSerializer(read_only=True)
    stock_id = serializers.CharField(write_only=True)
    
    movement_type = serializers.ChoiceField(choices=[
        ('in', 'Entrée'),
        ('out', 'Sortie'),
        ('adjustment', 'Ajustement'),
        ('transfer', 'Transfert'),
        ('return', 'Retour'),
        ('loss', 'Perte'),
        ('found', 'Trouvé'),
    ])
    
    reason = serializers.ChoiceField(choices=[
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
    ])
    
    quantity = serializers.DecimalField(max_digits=10, decimal_places=3)
    unit_cost = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    reference_document = serializers.CharField(max_length=100, required=False, allow_blank=True)
    notes = serializers.CharField(required=False, allow_blank=True)
    stock_before = serializers.DecimalField(max_digits=10, decimal_places=3)
    stock_after = serializers.DecimalField(max_digits=10, decimal_places=3)
    
    # Champs calculés
    movement_value = serializers.SerializerMethodField()
    
    class Meta:
        model = StockMovement
        fields = [
            'id', 'article', 'article_id', 'stock', 'stock_id', 'movement_type',
            'reason', 'quantity', 'unit_cost', 'reference_document', 'notes',
            'stock_before', 'stock_after', 'movement_value',
            'created_by', 'created_at'
        ]
    
    def get_movement_value(self, obj):
        """Valeur du mouvement"""
        if obj.unit_cost:
            return float(obj.quantity * obj.unit_cost)
        return 0


class StockAlertSerializer(BaseModelSerializer):
    """
    Serializer pour les alertes de stock
    """
    article = ArticleListSerializer(read_only=True)
    article_id = serializers.CharField(write_only=True)
    stock = StockSerializer(read_only=True)
    stock_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    
    alert_type = serializers.ChoiceField(choices=[
        ('low_stock', 'Stock bas'),
        ('out_of_stock', 'Rupture de stock'),
        ('expiry_soon', 'Péremption proche'),
        ('expired', 'Périmé'),
        ('overstock', 'Surstock'),
    ])
    
    alert_level = serializers.ChoiceField(choices=[
        ('info', 'Information'),
        ('warning', 'Avertissement'),
        ('critical', 'Critique'),
    ])
    
    message = serializers.CharField()
    is_acknowledged = serializers.BooleanField(default=False)
    acknowledged_by = serializers.CharField(source='acknowledged_by.get_full_name', read_only=True)
    acknowledged_at = serializers.DateTimeField(read_only=True)
    
    class Meta:
        model = StockAlert
        fields = [
            'id', 'article', 'article_id', 'stock', 'stock_id', 'alert_type',
            'alert_level', 'message', 'is_acknowledged', 'acknowledged_by',
            'acknowledged_at', 'created_at', 'updated_at'
        ]


# ========================
# OPÉRATIONS EN MASSE
# ========================

class ArticleBulkUpdateSerializer(BulkOperationSerializer):
    """
    Serializer pour les opérations en masse sur les articles
    """
    action = serializers.ChoiceField(choices=[
        ('activate', 'Activer'),
        ('deactivate', 'Désactiver'),
        ('delete', 'Supprimer'),
        ('update_prices', 'Modifier prix'),
        ('update_category', 'Changer catégorie'),
        ('update_supplier', 'Changer fournisseur'),
        ('generate_barcodes', 'Générer codes-barres'),
    ])


class StockAdjustmentSerializer(serializers.Serializer):
    """
    Serializer pour les ajustements de stock
    """
    article_id = serializers.CharField()
    location_id = serializers.CharField()
    new_quantity = serializers.DecimalField(max_digits=10, decimal_places=3)
    reason = serializers.ChoiceField(choices=[
        ('inventory', 'Inventaire'),
        ('damage', 'Dommage'),
        ('theft', 'Vol'),
        ('expiry', 'Péremption'),
        ('correction', 'Correction'),
    ])
    notes = serializers.CharField(required=False, allow_blank=True)
    reference_document = serializers.CharField(max_length=100, required=False, allow_blank=True)


class StockTransferSerializer(serializers.Serializer):
    """
    Serializer pour les transferts de stock
    """
    article_id = serializers.CharField()
    from_location_id = serializers.CharField()
    to_location_id = serializers.CharField()
    quantity = serializers.DecimalField(max_digits=10, decimal_places=3)
    notes = serializers.CharField(required=False, allow_blank=True)
    reference_document = serializers.CharField(max_length=100, required=False, allow_blank=True)
    
    def validate(self, attrs):
        """Validation du transfert"""
        if attrs['from_location_id'] == attrs['to_location_id']:
            raise serializers.ValidationError("L'emplacement source et l'emplacement cible doivent être différents.")
        
        if attrs['quantity'] <= 0:
            raise serializers.ValidationError("La quantité doit être positive.")
        
        return attrs