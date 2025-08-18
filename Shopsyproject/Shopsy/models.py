from django.db import models
from django.contrib.auth.models import User
import string
import random
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from decimal import Decimal


class User(models.Model):
    ROLE_CHOICES = [
        ('user', 'Regular User'),
        ('admin', 'Administrator')
    ]
    
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    mobile = models.CharField(max_length=15, unique=True)
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    last_login = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        
    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def update_last_login(self):
        self.last_login = timezone.now()
        self.save(update_fields=['last_login'])

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_regular_user(self):
        return self.role == 'user'


class Product(models.Model):
    productname = models.CharField(max_length=100)
    productprice = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    description = models.CharField(max_length=500)
    discount = models.IntegerField(default=0)
    image = models.ImageField(upload_to='products/', null=True, blank=True)
    create_date = models.DateField(auto_now=True)
    create_by = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.productname

    @property
    def final_price(self):
        try:
            if self.discount:
                # Convert all values to Decimal to ensure proper calculation
                price = Decimal(str(self.productprice))
                discount = Decimal(str(self.discount))
                discount_multiplier = Decimal('1.0') - (discount / Decimal('100.0'))
                return price * discount_multiplier
            return self.productprice
        except (TypeError, ValueError):
            return self.productprice  # Return original price if calculation fails


class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('canceled', 'Canceled'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    delivery_charge = models.DecimalField(max_digits=6, decimal_places=2, default=50.00)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    order_date = models.DateTimeField(auto_now_add=True)

    # Address Details
    full_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    house_no = models.CharField(max_length=255)
    landmark = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=255)
    state = models.CharField(max_length=255)
    pincode = models.CharField(max_length=10)

    def save(self, *args, **kwargs):
        self.total_price = (self.price * self.quantity) 
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Order {self.id} by {self.user.name if self.user else 'Guest'}"

