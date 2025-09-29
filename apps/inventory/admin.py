"""
Configuration de l'interface d'administration pour inventory - GESTORE
"""
from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Sum
from .models import (
    UnitOfMeasure, UnitConversion, Category, Brand, Supplier,
    Article, ArticleBarcode, ArticleImage, PriceHistory,
    Location, Stock, StockMovement, StockAlert
)


@admin.register(UnitOfMeasure)
class UnitOfMeasureAdmin(admin.ModelAdmin):
    list_display = ['name', 'symbol', 'is_decimal', 'is_active', 'created_at']
    list_filter = ['is_active', 'is_decimal']
    search_fields = ['name', 'symbol']
    ordering = ['name']


@admin.register(UnitConversion)
class UnitConversionAdmin(admin.ModelAdmin):
    list_display = ['from_unit', 'to_unit', 'conversion_factor', 'created_at']
    list_filter = ['from_unit', 'to_unit']
    search_fields = ['from_unit__name', 'to_unit__name']
    raw_id_fields = ['from_unit', 'to_unit']


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'parent', 'color_badge', 'tax_rate', 'is_active', 'order']
    list_filter = ['is_active', 'requires_prescription', 'requires_lot_tracking', 'parent']
    search_fields = ['name', 'code', 'description']
    ordering = ['parent__name', 'order', 'name']
    raw_id_fields = ['parent']
    
    def color_badge(self, obj):
        return format_html(
            '<span style="background-color: {}; padding: 5px 10px; border-radius: 3px; color: white;">{}</span>',
            obj.color, obj.name
        )
    color_badge.short_description = 'Couleur'


@admin.register(Brand)
class BrandAdmin(admin.ModelAdmin):
    list_display = ['name', 'website', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name', 'website']
    ordering = ['name']


@admin.register(Supplier)
class SupplierAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'contact_person', 'phone', 'email', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code', 'contact_person', 'email']
    ordering = ['name']


class ArticleBarcodeInline(admin.TabularInline):
    model = ArticleBarcode
    extra = 1
    fields = ['barcode', 'barcode_type', 'is_primary']


class ArticleImageInline(admin.TabularInline):
    model = ArticleImage
    extra = 1
    fields = ['image', 'alt_text', 'is_primary', 'order']


# REMARQUE: ArticleSupplierInline supprimé
# Utiliser SupplierArticleInline de l'app suppliers à la place


@admin.register(Article)
class ArticleAdmin(admin.ModelAdmin):
    list_display = [
        'code', 'name', 'category', 'brand', 'purchase_price', 'selling_price',
        'margin_display', 'stock_status', 'is_active'
    ]
    list_filter = [
        'is_active', 'article_type', 'category', 'brand', 
        'is_sellable', 'manage_stock'
    ]
    search_fields = ['name', 'code', 'barcode', 'internal_reference', 'description']
    ordering = ['category__name', 'name']
    raw_id_fields = ['category', 'brand', 'unit_of_measure', 'main_supplier', 'parent_article']
    inlines = [ArticleBarcodeInline, ArticleImageInline]  # ArticleSupplierInline retiré
    
    fieldsets = (
        ('Identification', {
            'fields': ('name', 'code', 'article_type', 'description', 'short_description')
        }),
        ('Références', {
            'fields': ('barcode', 'internal_reference', 'supplier_reference')
        }),
        ('Classification', {
            'fields': ('category', 'brand', 'unit_of_measure', 'main_supplier')
        }),
        ('Prix', {
            'fields': ('purchase_price', 'selling_price')
        }),
        ('Gestion des stocks', {
            'fields': (
                'manage_stock', 'min_stock_level', 'max_stock_level',
                'requires_lot_tracking', 'requires_expiry_date', 'allow_negative_stock'
            )
        }),
        ('Configuration', {
            'fields': ('is_sellable', 'is_purchasable', 'is_active')
        }),
        ('Variantes', {
            'fields': ('parent_article', 'variant_attributes'),
            'classes': ('collapse',)
        }),
        ('Dimensions', {
            'fields': ('weight', 'length', 'width', 'height', 'image'),
            'classes': ('collapse',)
        }),
        ('Métadonnées', {
            'fields': ('tags', 'notes'),
            'classes': ('collapse',)
        }),
    )
    
    def margin_display(self, obj):
        margin = obj.get_margin_percent()
        color = 'green' if margin > 20 else 'orange' if margin > 10 else 'red'
        return format_html(
            '<span style="color: {};">{:.1f}%</span>',
            color, margin
        )
    margin_display.short_description = 'Marge'
    
    def stock_status(self, obj):
        if not obj.manage_stock:
            return format_html('<span style="color: gray;">Non géré</span>')
        
        stock = obj.get_current_stock()
        if stock <= 0:
            return format_html('<span style="color: red;">Rupture</span>')
        elif stock <= obj.min_stock_level:
            return format_html('<span style="color: orange;">{}</span>', stock)
        else:
            return format_html('<span style="color: green;">{}</span>', stock)
    stock_status.short_description = 'Stock'


@admin.register(PriceHistory)
class PriceHistoryAdmin(admin.ModelAdmin):
    list_display = [
        'article', 'old_selling_price', 'new_selling_price', 
        'change_display', 'reason', 'created_by', 'effective_date'
    ]
    list_filter = ['reason', 'effective_date']
    search_fields = ['article__name', 'article__code', 'notes']
    raw_id_fields = ['article', 'created_by']
    date_hierarchy = 'effective_date'
    
    def change_display(self, obj):
        change = obj.get_selling_change_percent()
        color = 'red' if change > 0 else 'green'
        arrow = '↑' if change > 0 else '↓'
        return format_html(
            '<span style="color: {};">{} {:.1f}%</span>',
            color, arrow, abs(change)
        )
    change_display.short_description = 'Variation'


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'location_type', 'parent', 'barcode', 'is_active']
    list_filter = ['is_active', 'location_type', 'parent']
    search_fields = ['name', 'code', 'barcode']
    ordering = ['location_type', 'code', 'name']
    raw_id_fields = ['parent']


@admin.register(Stock)
class StockAdmin(admin.ModelAdmin):
    list_display = [
        'article', 'location', 'quantity_on_hand', 'quantity_available',
        'quantity_reserved', 'lot_number', 'expiry_status', 'unit_cost'
    ]
    list_filter = ['location', 'expiry_date']
    search_fields = ['article__name', 'article__code', 'location__name', 'lot_number']
    raw_id_fields = ['article', 'location']
    date_hierarchy = 'expiry_date'
    
    def expiry_status(self, obj):
        if not obj.expiry_date:
            return '-'
        
        if obj.is_expired():
            return format_html('<span style="color: red;">Expiré</span>')
        
        days = obj.days_until_expiry()
        if days <= 30:
            return format_html('<span style="color: orange;">{} jours</span>', days)
        else:
            return format_html('<span style="color: green;">{} jours</span>', days)
    expiry_status.short_description = 'Expiration'


@admin.register(StockMovement)
class StockMovementAdmin(admin.ModelAdmin):
    list_display = [
        'article', 'movement_type', 'reason', 'quantity', 
        'stock_before', 'stock_after', 'created_by', 'created_at'
    ]
    list_filter = ['movement_type', 'reason', 'created_at']
    search_fields = ['article__name', 'article__code', 'reference_document', 'notes']
    raw_id_fields = ['article', 'stock', 'created_by']
    date_hierarchy = 'created_at'
    readonly_fields = ['created_by', 'created_at', 'updated_by', 'updated_at']


@admin.register(StockAlert)
class StockAlertAdmin(admin.ModelAdmin):
    list_display = [
        'article', 'alert_type', 'alert_level', 'message',
        'is_acknowledged', 'acknowledged_by', 'created_at'
    ]
    list_filter = ['alert_type', 'alert_level', 'is_acknowledged', 'created_at']
    search_fields = ['article__name', 'article__code', 'message']
    raw_id_fields = ['article', 'stock', 'acknowledged_by']
    date_hierarchy = 'created_at'
    
    actions = ['mark_as_acknowledged']
    
    def mark_as_acknowledged(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(
            is_acknowledged=True,
            acknowledged_by=request.user,
            acknowledged_at=timezone.now()
        )
        self.message_user(request, f'{updated} alertes acquittées.')
    mark_as_acknowledged.short_description = 'Acquitter les alertes sélectionnées'