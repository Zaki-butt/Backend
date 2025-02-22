from django.db import models
from django.core.validators import MinValueValidator, MaxLengthValidator
from account.models import User
class PropertyCategory(models.Model):
  name = models.CharField(max_length=100, unique=True)

  class Meta:
      verbose_name_plural = "Property Categories"

  def __str__(self):
    return self.name

class PropertyType(models.Model):
  category = models.ForeignKey(
    PropertyCategory, 
    on_delete=models.CASCADE, 
    related_name='types'
  )
  name = models.CharField(max_length=100)

  def __str__(self):
    return self.name

class Property(models.Model):
  STATUS_CHOICES = (
    ('active', 'Active'),
    ('inactive', 'Inactive')
  )

  RENT_OR_BUY_CHOICES = (
    ('rent', 'Rent'),
    ('buy', 'Buy')
  )

  title = models.CharField(
    max_length=200,
    validators=[MaxLengthValidator(200)],
    blank=False,
    null=False
  )
  description = models.TextField(
    blank=False,
    null=False
  )
  price = models.TextField(
     blank=False,
    null=False
   # max_digits=10,
   # decimal_places=2,
    #validators=[MinValueValidator(0.01)],
    #blank=False,
    #null=False
  )
  address = models.CharField(
    max_length=255,
    validators=[MaxLengthValidator(255)],
    blank=False,
    null=False
  )
  latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
  longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
  city = models.CharField(
    max_length=100,
    validators=[MaxLengthValidator(100)],
    blank=False,
    null=False,
    default='Sialkot'
  )
  status = models.CharField(
    max_length=30,
    choices=STATUS_CHOICES,
    default='active'
  )
  bedroom = models.IntegerField(
    validators=[MinValueValidator(0)],
    blank=True,
    null=True
  )
  washroom = models.IntegerField(
    validators=[MinValueValidator(0)],
    blank=True,
    null=True
  )
  area = models.DecimalField(
    max_digits=10,
    decimal_places=2,
    validators=[MinValueValidator(0)],
    blank=True,
    null=True
  )
  property_category = models.ForeignKey(
    PropertyCategory,
    on_delete=models.SET_NULL,
    related_name='properties',
    blank=True,
    null=True
  )
  property_type = models.ForeignKey(
    PropertyType,
    on_delete=models.SET_NULL,
    related_name='properties',
    blank=True,
    null=True
  )
  rent_or_buy = models.CharField(
    max_length=10,
    choices=RENT_OR_BUY_CHOICES,
    default='buy'
  )
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)


  class Meta:
    verbose_name_plural = "Properties"

  def __str__(self):
    return self.title


class Customer(models.Model):
  user = models.ForeignKey(
    'account.User',
    on_delete=models.CASCADE,
    related_name='customers'
  )

  cnic = models.CharField(
    max_length=15,
    unique=True,
    blank=False,
    null=False
  )
  phone_number = models.CharField(
    max_length=15,
    unique=True,
    blank=False,
    null=False
  )
  address = models.CharField(
    max_length=255,
    blank=False,
    null=False
  )

  class Meta:
    verbose_name_plural = "Customers"
    unique_together = ('user',)

  def __str__(self):
    return self.cnic


class Agreement(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled')
    )

    property = models.ForeignKey(
        Property,
        on_delete=models.CASCADE,
        related_name='agreements'
    )

    customer = models.ForeignKey(
      Customer,
      on_delete=models.CASCADE,
      related_name='agreements',
    )

    customer_note = models.TextField(
        blank=True,
        null=True
    )

    image = models.ImageField(
        upload_to='agreements/',
        blank=True,
        null=True
    )
    details = models.TextField(
        blank=True,
        null=True
    )
    rent_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        blank=True,
        null=True
    )
    rent_start_date = models.DateField(
        blank=True,
        null=True
    )
    rent_end_date = models.DateField(
        blank=True,
        null=True
    )
    purchase_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        blank=True,
        null=True
    )
    purchase_date = models.DateField(
        blank=True,
        null=True
    )
    security_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        blank=True,
        null=True
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Agreements"

    def __str__(self):
        return f"Agreement for {self.property.title}"

class Payment(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed')
    )

    METHOD_CHOICES = (
        ('cash', 'Cash'),
        ('bank_transfer', 'Bank Transfer'),
        ('cheque', 'Cheque'),
        ('other', 'Other')
    )

    agreement = models.ForeignKey(
        Agreement,
        on_delete=models.CASCADE,
        related_name='payments'
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )

    method = models.CharField(
        max_length=20,
        choices=METHOD_CHOICES,
        default='cash'
    )

    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        blank=False,
        null=False
    )

    date = models.DateField(
        auto_now_add=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Payments"

    def __str__(self):
        return f"Payment of {self.amount} for {self.agreement}"

class PropertyImage(models.Model):
    property = models.ForeignKey(
        Property,
        on_delete=models.CASCADE,
        related_name='property_images'
    )
    image = models.ImageField(
        upload_to='properties/',
        blank=True,
        null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image for {self.property.title}"

class UtilityBill(models.Model):
    BILL_TYPE_CHOICES = (
        ('electricity', 'Electricity'),
        ('gas', 'Gas'),
        ('water', 'Water'),
        ('other', 'Other')
    )

    agreement = models.ForeignKey(
        Agreement,
        on_delete=models.CASCADE,
        related_name='utility_bills'
    )
    bill_type = models.CharField(
        max_length=20,
        choices=BILL_TYPE_CHOICES
    )
    bill_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)]
    )
    paid_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        null=True,
        blank=True
    )
    bill_date = models.DateField()
    due_date = models.DateField()
    paid_date = models.DateField(null=True, blank=True)
    bill_image = models.ImageField(
        upload_to='bills/',
        null=True,
        blank=True
    )
    payment_receipt = models.ImageField(
        upload_to='bills/receipts/',
        null=True,
        blank=True,
        help_text='Payment receipt image'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-bill_date']

    def __str__(self):
        return f"{self.bill_type} bill for {self.agreement}"

class Account(models.Model):
    name = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']

class Ledger(models.Model):
    account = models.ForeignKey(
        Account,
        on_delete=models.CASCADE,
        related_name='ledgers'
    )
    title = models.CharField(max_length=200)
    debit_total = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=0
    )
    credit_total = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=0
    )
    balance = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=0
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.account.name} - {self.title}"

    class Meta:
        ordering = ['-created_at']

class Transaction(models.Model):
    TRANSACTION_TYPES = (
        ('debit', 'Debit'),
        ('credit', 'Credit')
    )

    ledger = models.ForeignKey(
        Ledger,
        on_delete=models.CASCADE,
        related_name='transactions'
    )
    detail = models.TextField()
    date = models.DateField()
    amount = models.DecimalField(
        max_digits=15,
        decimal_places=2
    )
    type = models.CharField(
        max_length=6,
        choices=TRANSACTION_TYPES
    )
    balance = models.DecimalField(
        max_digits=15,
        decimal_places=2
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ledger.title} - {self.type} - {self.amount}"

    class Meta:
        ordering = ['-date', '-created_at']

    def save(self, *args, **kwargs):
        is_new = self._state.adding  # Check if this is a new transaction
        
        if not is_new:
            # If updating, first reverse the previous transaction's effect
            old_transaction = Transaction.objects.get(pk=self.pk)
            if old_transaction.type == 'debit':
                self.ledger.debit_total -= old_transaction.amount
                self.ledger.balance -= old_transaction.amount
            else:
                self.ledger.credit_total -= old_transaction.amount
                self.ledger.balance += old_transaction.amount

        # Apply the new transaction
        if self.type == 'debit':
            self.ledger.debit_total += self.amount
            self.ledger.balance += self.amount
        else:
            self.ledger.credit_total += self.amount
            self.ledger.balance -= self.amount
        
        # Update the balance for this transaction
        self.balance = self.ledger.balance
        
        # Save the ledger first
        self.ledger.save()
        
        # Then save the transaction
        super().save(*args, **kwargs)

        # If this is not a new transaction, recalculate balances for all subsequent transactions
        if not is_new:
            subsequent_transactions = Transaction.objects.filter(
                ledger=self.ledger,
                date__gte=self.date,
                created_at__gt=self.created_at
            ).order_by('date', 'created_at')
            
            current_balance = self.balance
            for trans in subsequent_transactions:
                if trans.id != self.id:  # Skip the current transaction
                    if trans.type == 'debit':
                        current_balance += trans.amount
                    else:
                        current_balance -= trans.amount
                    trans.balance = current_balance
                    Transaction.objects.filter(id=trans.id).update(balance=current_balance)

