from django.contrib import admin
from .models import (
    Property, 
    PropertyCategory, 
    PropertyType, 
    Customer, 
    Agreement, 
    Payment,
    UtilityBill
)

@admin.register(Property)
class PropertyAdmin(admin.ModelAdmin):
  list_display = ('title', 'price', 'address','latitude', 'longitude', 'status', 'property_category', 'property_type', 'created_at', 'updated_at')
  list_filter = ('status', 'property_category', 'property_type')
  search_fields = ('title', 'address', 'description')

@admin.register(PropertyCategory)
class PropertyCategoryAdmin(admin.ModelAdmin):
  list_display = ('name',)
  search_fields = ('name',)

@admin.register(PropertyType)
class PropertyTypeAdmin(admin.ModelAdmin):
  list_display = ('name', 'category')
  list_filter = ('category',)
  search_fields = ('name',)

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
  list_display = ('user', 'cnic', 'phone_number', 'address')
  search_fields = ('cnic', 'phone_number', 'address')

@admin.register(Agreement)
class AgreementAdmin(admin.ModelAdmin):
  list_display = ('property', 'customer', 'status', 'created_at')
  list_filter = ('status', 'property')
  search_fields = ('property__title', 'customer__cnic')

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = (
        'agreement',
        'amount',
        'method',
        'status',
        'date',
        'created_at'
    )
    list_filter = ('status', 'method', 'date')
    search_fields = (
        'agreement__property__title',
        'agreement__customer__user__name',
        'agreement__customer__cnic'
    )
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)

@admin.register(UtilityBill)
class UtilityBillAdmin(admin.ModelAdmin):
    list_display = (
        'agreement',
        'bill_type',
        'bill_amount',
        'paid_amount',
        'bill_date',
        'due_date',
        'paid_date',
        'created_at'
    )
    list_filter = (
        'bill_type',
        'bill_date',
        'due_date',
        'paid_date'
    )
    search_fields = (
        'agreement__property__title',
        'agreement__customer__user__name',
        'agreement__customer__cnic'
    )
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-bill_date',)

    def get_paid_status(self, obj):
        return "Paid" if obj.paid_date else "Unpaid"
    get_paid_status.short_description = "Payment Status"
