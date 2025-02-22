from rest_framework import serializers
from .models import Property, PropertyCategory, PropertyType, Agreement, Customer, PropertyImage, Payment, UtilityBill, Account, Ledger, Transaction
from account.models import User
from django.core.files.base import ContentFile
import base64

class PropertySerializer(serializers.ModelSerializer):
  property_category_name = serializers.SerializerMethodField()
  property_type_name = serializers.SerializerMethodField()
  images = serializers.SerializerMethodField()
  uploaded_images = serializers.ListField(
    child=serializers.ImageField(),
    write_only=True,
    required=False
  )

  class Meta:
    model = Property
    fields = [
      'id', 'title', 'description', 'price', 'address', 'latitude', 'longitude','city', 'status', 'rent_or_buy',
      'bedroom', 'washroom', 'area', 'property_category', 'property_type',
      'property_category_name', 'property_type_name', 'created_at', 'updated_at',
      'images', 'uploaded_images'
    ]

  def get_property_category_name(self, obj):
    return obj.property_category.name if obj.property_category else None

  def get_property_type_name(self, obj):
    return obj.property_type.name if obj.property_type else None

  def get_images(self, obj):
    return PropertyImageSerializer(obj.property_images.all(), many=True).data

  def create(self, validated_data):
    uploaded_images = validated_data.pop('uploaded_images', [])
    property_instance = Property.objects.create(**validated_data)
    
    for image in uploaded_images:
      PropertyImage.objects.create(
        property=property_instance,
        image=image
      )
    
    return property_instance

  def update(self, instance, validated_data):
    uploaded_images = validated_data.pop('uploaded_images', [])
    
    # Update the property instance
    for attr, value in validated_data.items():
      setattr(instance, attr, value)
    instance.save()
    
    # Add new images
    for image in uploaded_images:
      PropertyImage.objects.create(
        property=instance,
        image=image
      )
    
    return instance


class PropertyCategorySerializer(serializers.ModelSerializer):
  class Meta:
    model = PropertyCategory
    fields = '__all__'

class PropertyTypeSerializer(serializers.ModelSerializer):
  class Meta:
    model = PropertyType
    fields = '__all__'
class CustomerSerializer(serializers.ModelSerializer):
  user = serializers.SerializerMethodField(read_only=True)
  user_id = serializers.PrimaryKeyRelatedField(
    queryset=User.objects.all(),
    source='user',
    write_only=True
  )
  agreements = serializers.SerializerMethodField(read_only=True)

  class Meta:
    model = Customer
    fields = '__all__'

  def get_user(self, obj):
    user = obj.user
    return {
      'id': user.id,
      'email': user.email,
      'name': user.name
    }

  def get_agreements(self, obj):
    try:
      agreements = obj.agreements.all()
      return [{
        'id': agreement.id,
        'customer_note': agreement.customer_note,
        'details': agreement.details,
        'rent_amount': agreement.rent_amount,
        'rent_start_date': agreement.rent_start_date,
        'rent_end_date': agreement.rent_end_date,
        'purchase_amount': agreement.purchase_amount,
        'purchase_date': agreement.purchase_date,
        'security_amount': agreement.security_amount,
        'status': agreement.status,
        'created_at': agreement.created_at,
        'updated_at': agreement.updated_at,
        'property': {
          'id': agreement.property.id,
          'title': agreement.property.title,
          'rent_or_buy': agreement.property.rent_or_buy
        }
      } for agreement in agreements]
    except Exception:
      return []

class AgreementSerializer(serializers.ModelSerializer):
  # Nested serializers for related fields
  property = PropertySerializer(read_only=True)
  property_id = serializers.PrimaryKeyRelatedField(
    queryset=Property.objects.all(),
    source='property',
    write_only=True
  )

  user_details = serializers.SerializerMethodField(read_only=True)

  def get_user_details(self, obj):
    user = obj.customer.user
    return {
      'id': user.id,
      'email': user.email,
      'name': user.name
    }

  customer = CustomerSerializer(read_only=True)
  customer_id = serializers.PrimaryKeyRelatedField(
    queryset=Customer.objects.all(),
    source='customer',
    write_only=True
  )

  class Meta:
    model = Agreement
    fields = '__all__'

  def get_customer(self, obj):
    customer = obj.customer
    return {
      'id': customer.id,
      'cnic': customer.cnic,
      'phone_number': customer.phone_number,
      'address': customer.address
    }

class PropertyImageSerializer(serializers.ModelSerializer):
  class Meta:
    model = PropertyImage
    fields = ['id', 'image', 'created_at']

class PaymentSerializer(serializers.ModelSerializer):
    agreement_details = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Payment
        fields = [
            'id', 'agreement', 'status', 'method', 
            'amount', 'date', 'created_at', 'updated_at',
            'agreement_details'
        ]
        read_only_fields = ['date']  # Date is set automatically when status changes

    def get_agreement_details(self, obj):
        return {
            'id': obj.agreement.id,
            'property': {
                'id': obj.agreement.property.id,
                'title': obj.agreement.property.title,
                'rent_or_buy': obj.agreement.property.rent_or_buy
            },
            'customer': {
                'id': obj.agreement.customer.id,
                'name': obj.agreement.customer.user.name,
                'email': obj.agreement.customer.user.email
            }
        }

class UtilityBillSerializer(serializers.ModelSerializer):
    agreement_details = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = UtilityBill
        fields = [
            'id', 'agreement', 'bill_type', 'bill_amount',
            'paid_amount', 'bill_date', 'due_date', 'paid_date',
            'bill_image', 'payment_receipt', 'created_at', 'updated_at', 
            'agreement_details'
        ]

    def get_agreement_details(self, obj):
        return {
            'id': obj.agreement.id,
            'property': {
                'id': obj.agreement.property.id,
                'title': obj.agreement.property.title,
                'rent_or_buy': obj.agreement.property.rent_or_buy
            },
            'customer': {
                'id': obj.agreement.customer.id,
                'name': obj.agreement.customer.user.name,
                'email': obj.agreement.customer.user.email
            }
        }

class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['id', 'name', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

class LedgerSerializer(serializers.ModelSerializer):
    account_name = serializers.CharField(source='account.name', read_only=True)

    class Meta:
        model = Ledger
        fields = [
            'id', 'account', 'account_name', 'title',
            'debit_total', 'credit_total', 'balance',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'debit_total', 'credit_total', 'balance',
            'created_at', 'updated_at'
        ]

class TransactionSerializer(serializers.ModelSerializer):
    ledger_title = serializers.CharField(source='ledger.title', read_only=True)
    account_name = serializers.CharField(source='ledger.account.name', read_only=True)

    class Meta:
        model = Transaction
        fields = [
            'id', 'ledger', 'ledger_title', 'account_name',
            'detail', 'date', 'amount', 'type', 'balance',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['balance', 'created_at', 'updated_at']

    def validate(self, data):
        # Ensure amount is positive
        if data.get('amount', 0) <= 0:
            raise serializers.ValidationError({
                "amount": "Amount must be greater than zero"
            })
        return data