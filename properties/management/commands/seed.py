from django.core.management.base import BaseCommand
from account.models import User 
from properties.models import PropertyCategory, PropertyType, Property, Customer, Agreement
import random
from datetime import date

class Command(BaseCommand):
    help = "Seed the database with initial data"

    def handle(self, *args, **kwargs):
        self.stdout.write("Seeding database...")
        self.create_users()
        self.create_categories_and_types()
        self.create_properties()
        self.create_agreement()
        self.stdout.write("Database seeding completed.")

    def create_categories_and_types(self):
        categories_and_types = {
            "Residential": ["Apartment", "House", "Villa"],
            "Commercial": ["Office", "Shop", "Warehouse"],
            "Land": ["Plot", "Agricultural Land", "Industrial Land"],
        }

        self.categories = []
        self.types = []

        for category_name, type_names in categories_and_types.items():
            category, _ = PropertyCategory.objects.get_or_create(name=category_name)
            self.categories.append(category)
            for type_name in type_names:
                property_type, _ = PropertyType.objects.get_or_create(
                    name=type_name, category=category
                )
                self.types.append(property_type)

    def create_properties(self):
        titles = [
            "Spacious Apartment in Downtown",
            "Modern House with Garden View",
            "Luxury Villa near the Lake",
            "Central Office Space with City View",
            "Prime Location Shop for Rent",
            "Large Warehouse for Storage",
            "Scenic Plot of Land with Mountain Views",
            "Fertile Agricultural Land for Sale",
            "Industrial Land for Development",
        ]

        descriptions = [
            "A spacious and modern apartment located in the heart of the city.",
            "A cozy house with a beautiful garden, perfect for a family.",
            "A luxurious villa offering stunning views of the nearby lake.",
            "Modern office space strategically located with panoramic city views.",
            "Prime retail space in a bustling commercial area, ideal for businesses.",
            "Large warehouse facility suitable for various storage needs.",
            "Scenic plot of land offering breathtaking mountain views, ideal for a vacation home.",
            "Fertile agricultural land suitable for farming and cultivation.",
            "Industrial land strategically positioned for business expansion and development.",
        ]

        prices = [
            150000.00,
            200000.00,
            250000.00,
            300000.00,
            350000.00,
            400000.00,
            450000.00,
            500000.00,
            550000.00,
        ]
        addresses = [
            "123 Main St",
            "456 Oak St",
            "789 Pine St",
            "101 Maple Ave",
            "202 Birch Ave",
            "303 Cedar Ave",
            "404 Elm St",
            "505 Ash St",
            "606 Willow St",
        ]

        # Ensure there are categories and types created before creating properties
        if not PropertyCategory.objects.exists() or not PropertyType.objects.exists():
            self.stdout.write(
                self.style.ERROR("No property categories or types available.")
            )
            return

        for _ in range(200):
            Property.objects.create(
                title=random.choice(titles),
                description=random.choice(descriptions),
                price=random.choice(prices),
                address=random.choice(addresses),
                # latitude=random.uniform(24.396308, 49.384358),  # Random lat for USA
                # longitude=random.uniform(-125.000000, -66.934570),  # Random lng for USA
                latitude = random.uniform(27.6350, 32.7500), # Random latitude for Punjab, Pakistan
                longitude = random.uniform(69.6500, 75.4500),  # Random longitude for Punjab, Pakistan
                status=random.choice(["active", "inactive"]),
                property_category=random.choice(PropertyCategory.objects.all()),
                property_type=random.choice(PropertyType.objects.all()),
            )
        self.stdout.write(self.style.SUCCESS("200 Properties created."))

    def create_customer(self, user = User.objects.filter(is_admin=False).first()):
        # Create a new customer and reference the first non-admin user
        if user:  
            customer = Customer.objects.create(
                user=user, 
                cnic='12345-6789012-3',  
                phone_number='1234567890',  
                address='123 Street Name, City'  
            )
            self.stdout.write(self.style.SUCCESS(f"Customer created with ID: {customer.id}"))
        else:
            self.stdout.write(self.style.ERROR("No users found in the database."))

    def create_users(self):
        # Creating two users - one admin and one non-admin
        admin_user = User.objects.create_user(
            name='Admin User',
            email='admin@email.com',
            password='admin123',  # Use a secure password in production
        )
        admin_user.is_admin=True # Set to True for admin user
        admin_user.save()
        self.stdout.write(self.style.SUCCESS(f"Admin user created with ID: {admin_user.id}"))

        non_admin_user = User.objects.create_user(
            name='Non Admin User',
            email='nonadmin@email.com',
            password='nonadmin123',  # Use a secure password in production
        )
        non_admin_user.is_admin=False  # Set to False for non-admin user
        non_admin_user.save()
        self.stdout.write(self.style.SUCCESS(f"Non-admin user created with ID: {non_admin_user.id}"))

        self.create_customer(user=non_admin_user)

    def create_agreement(self):
        property_instance = Property.objects.first()
        customer_instance = Customer.objects.first()

        # Check if we have a property and customer, then create the agreement
        if property_instance and customer_instance:
            agreement = Agreement.objects.create(
                property=property_instance,               # Associate the first property
                customer=customer_instance,               # Associate the first customer
                rent_start_date=date(2024, 11, 21),        # Set rent start date
                rent_end_date=date(2025, 11, 21),          # Set rent end date
                details="This is the agreement for renting the property.",  # Optional: any additional details
                security_amount=5000.00,                  # Optional: security amount for the rental agreement
                status='pending'                           # Default status (can be 'pending', 'active', etc.)
            )
            self.stdout.write(self.style.SUCCESS(f"Agreement created with ID: {agreement.id}"))
        else:
            self.stdout.write(self.style.ERROR("Either property or customer not found."))

