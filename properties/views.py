from rest_framework import viewsets, filters
from rest_framework.pagination import PageNumberPagination
from .models import Property, PropertyCategory, PropertyType, Customer, Agreement, PropertyImage, Payment, UtilityBill, Account, Ledger, Transaction
from .serializers import PropertySerializer, PropertyCategorySerializer, PropertyTypeSerializer, CustomerSerializer, PaymentSerializer, UtilityBillSerializer, AccountSerializer, LedgerSerializer, TransactionSerializer
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from .serializers import AgreementSerializer
from rest_framework import status
from django.utils import timezone
from rest_framework.permissions import IsAdminUser

class GeneralPagination(PageNumberPagination):
  page_size = 10  # Default page size
  page_size_query_param = 'page_size'
  max_page_size = 100000

class PropertyViewSet(viewsets.ModelViewSet):
  queryset = Property.objects.all()
  serializer_class = PropertySerializer
  filter_backends = [filters.OrderingFilter, filters.SearchFilter]
  ordering_fields = ['created_at']
  search_fields = ['title', 'description', 'address']
  pagination_class = GeneralPagination

  def get_queryset(self):
    queryset = Property.objects.all()
    category_id = self.request.query_params.get('category_id')
    type_id = self.request.query_params.get('type_id')
    rent_or_buy = self.request.query_params.get('type')
    filter_type = self.request.query_params.get('filter_type')
    
    if category_id:
      queryset = queryset.filter(property_category_id=category_id)
    if type_id:
      queryset = queryset.filter(property_type_id=type_id)
    if rent_or_buy in ['rent', 'buy']:
      queryset = queryset.filter(rent_or_buy=rent_or_buy)
      
    # Handle dashboard filters
    if not filter_type:
        # Show only available properties (not sold or rented)
        queryset = queryset.exclude(
            agreements__status='active'
        )
    elif filter_type == 'all':
        pass
    elif filter_type == 'sold':
        queryset = queryset.filter(
            agreements__status='active',
            rent_or_buy='buy'
        )
    elif filter_type == 'rent':
        queryset = queryset.filter(
            agreements__status='active',
            rent_or_buy='rent'
        )
    elif filter_type == 'hold':
        queryset = queryset.filter(status='inactive')
    elif filter_type == 'pending':
        queryset = queryset.filter(agreements__status='pending')
    
    queryset = queryset.order_by('-created_at')
    return queryset.distinct()

  @action(detail=True, methods=['delete'])
  def delete_image(self, request, pk=None):
    try:
      image_id = request.data.get('image_id')
      if not image_id:
        return Response(
          {'error': 'image_id is required'}, 
          status=status.HTTP_400_BAD_REQUEST
        )
      
      image = PropertyImage.objects.get(
        id=image_id, 
        property_id=pk
      )
      image.delete()
      
      return Response(
        {'message': 'Image deleted successfully'}, 
        status=status.HTTP_200_OK
      )
    except PropertyImage.DoesNotExist:
      return Response(
        {'error': 'Image not found'}, 
        status=status.HTTP_404_NOT_FOUND
      )

class PropertyCategoryViewSet(viewsets.ModelViewSet):
  queryset = PropertyCategory.objects.all()
  serializer_class = PropertyCategorySerializer

  @action(detail=True, methods=['get'], url_path='types', url_name='property_types')
  def get_types(self, request, pk=None):
    category = self.get_object()
    property_types = PropertyType.objects.filter(category=category)
    serializer = PropertyTypeSerializer(property_types, many=True)
    return Response(serializer.data)

class PropertyTypeViewSet(viewsets.ModelViewSet):
  queryset = PropertyType.objects.all()
  serializer_class = PropertyTypeSerializer

class CustomerViewSet(viewsets.ModelViewSet):
  queryset = Customer.objects.all()
  serializer_class = CustomerSerializer
  pagination_class = GeneralPagination

  @action(detail=False, methods=['get'], url_path='get', url_name='get_customer')
  def get_customer(self, request):
    user = request.user
    customer = Customer.objects.filter(user=user).first()  # Check if customer exists for the logged-in user
    if customer:
      serializer = self.get_serializer(customer)
      return Response({'customer': serializer.data}) 
    return Response({'customer': False})  # Return false if no customer is found
  
  @action(detail=False, methods=['get'], url_path='active_customers', url_name='active_customers')
  def get_active_customers(self, request):
    # Get all customers who have at least one agreement
    customers_with_agreements = Customer.objects.filter(
      agreements__isnull=False  # Ensure customer has at least one agreement
    ).distinct()
    
    serializer = self.get_serializer(customers_with_agreements, many=True)
    return Response({'results': serializer.data})


class AgreementViewSet(viewsets.ModelViewSet):
  def get_queryset(self):
    user = self.request.user
    if user.is_admin:
      return Agreement.objects.all().order_by('-created_at')
    else:
      return Agreement.objects.filter(customer__user=user).order_by('-created_at')

  queryset = Agreement.objects.all()
  serializer_class = AgreementSerializer
  pagination_class = GeneralPagination

class PaymentViewSet(viewsets.ModelViewSet):
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer
    pagination_class = GeneralPagination

    @action(detail=False, methods=['get'])
    def user(self, request):
        # Get payments where the agreement's customer's user matches the current user
        payments = Payment.objects.filter(
            agreement__customer__user=request.user
        ).order_by('-created_at')
        
        page = self.paginate_queryset(payments)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(payments, many=True)
        return Response(serializer.data)

    def get_queryset(self):
        queryset = Payment.objects.all()
        
        # If user is not admin, only show their own payments
        if not self.request.user.is_admin:
            queryset = queryset.filter(agreement__customer__user=self.request.user)
        
        # Filter by agreement if provided
        agreement_id = self.request.query_params.get('agreement')
        if agreement_id:
            queryset = queryset.filter(agreement_id=agreement_id)
        
        # Filter by customer if provided
        customer_id = self.request.query_params.get('customer')
        if customer_id:
            queryset = queryset.filter(agreement__customer_id=customer_id)
        
        return queryset.order_by('-created_at')

    def partial_update(self, request, *args, **kwargs):
        payment = self.get_object()
        
        # If payment is not pending, don't allow updates
        if payment.status != 'pending':
            return Response(
                {'error': 'Only pending payments can be updated'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # If status is being changed from pending
        new_status = request.data.get('status')
        if new_status and new_status != 'pending':
            # Use the date from frontend if provided, otherwise use current date
            payment_date = request.data.get('date')
            if payment_date:
                request.data['date'] = payment_date
            else:
                request.data['date'] = timezone.now().date()
        elif new_status == 'pending':
            # If status is being set back to pending, remove the date
            request.data['date'] = None
        
        return super().partial_update(request, *args, **kwargs)

class UtilityBillViewSet(viewsets.ModelViewSet):
    queryset = UtilityBill.objects.all()
    serializer_class = UtilityBillSerializer
    pagination_class = GeneralPagination

    @action(detail=False, methods=['get'])
    def user(self, request):
        # Get bills where the agreement's customer's user matches the current user
        bills = UtilityBill.objects.filter(
            agreement__customer__user=request.user
        ).order_by('-bill_date')
        
        page = self.paginate_queryset(bills)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(bills, many=True)
        return Response(serializer.data)

    def get_queryset(self):
        queryset = UtilityBill.objects.all()
        
        # If user is not admin, only show their own bills
        if not self.request.user.is_admin:
            queryset = queryset.filter(agreement__customer__user=self.request.user)
        
        # Filter by agreement if provided
        agreement_id = self.request.query_params.get('agreement')
        if agreement_id:
            queryset = queryset.filter(agreement_id=agreement_id)
        
        # Filter by customer if provided
        customer_id = self.request.query_params.get('customer')
        if customer_id:
            queryset = queryset.filter(agreement__customer_id=customer_id)
        
        return queryset.order_by('-bill_date')

    def partial_update(self, request, *args, **kwargs):
        bill = self.get_object()
        
        # If bill is already paid, don't allow updates
        if bill.paid_date:
            return Response(
                {'error': 'Bill is already paid'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # If paid_amount is being set, set the paid_date
        if 'paid_amount' in request.data:
            request.data['paid_date'] = timezone.now().date()
            
            # Handle payment receipt if provided
            if 'payment_receipt' in request.FILES:
                request.data['payment_receipt'] = request.FILES['payment_receipt']
        
        return super().partial_update(request, *args, **kwargs)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_dashboard_stats(request):
    # Get total properties
    total_properties = Property.objects.count()
    
    # Get properties by status
    sold_properties = Agreement.objects.filter(
        status='active',
        property__rent_or_buy='buy'
    ).count()
    
    on_rent = Agreement.objects.filter(
        status='active',
        property__rent_or_buy='rent'
    ).count()
    
    on_hold = Property.objects.filter(status='inactive').count()
    
    # Get pending requests (agreements)
    pending_requests = Agreement.objects.filter(status='pending').count()

    return Response({
        'total_properties': total_properties,
        'sold_properties': sold_properties,
        'on_rent': on_rent,
        'on_hold': on_hold,
        'pending_requests': pending_requests
    })

class AccountViewSet(viewsets.ModelViewSet):
    queryset = Account.objects.all()
    serializer_class = AccountSerializer
    http_method_names = ['get', 'post', 'put', 'patch']  # Exclude delete

    def get_queryset(self):
        queryset = Account.objects.all()
        name = self.request.query_params.get('name', None)
        if name:
            queryset = queryset.filter(name__icontains=name)
        return queryset.order_by('name')

class LedgerViewSet(viewsets.ModelViewSet):
    queryset = Ledger.objects.all()
    serializer_class = LedgerSerializer
    filterset_fields = ['account']

    def get_queryset(self):
        queryset = Ledger.objects.all()
        account_id = self.request.query_params.get('account_id', None)
        if account_id:
            queryset = queryset.filter(account_id=account_id)
        return queryset.order_by('-created_at')

class TransactionViewSet(viewsets.ModelViewSet):
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    filterset_fields = ['ledger', 'type', 'date']

    def get_queryset(self):
        queryset = Transaction.objects.all()
        ledger_id = self.request.query_params.get('ledger_id', None)
        if ledger_id:
            queryset = queryset.filter(ledger_id=ledger_id)
        return queryset.order_by('-date', '-created_at')
