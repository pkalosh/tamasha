from enum import auto
from unittest.util import _MAX_LENGTH
from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager
from phonenumber_field.modelfields import PhoneNumberField
from shortuuid.django_fields import ShortUUIDField
import uuid
from django.db.models.signals import m2m_changed , post_save,pre_save
from django.dispatch import receiver
import qrcode
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
from django.core.files import File
import uuid
from decimal import Decimal

class UserManager(BaseUserManager):
    def create_user(self, email,first_name,last_name,password=None):
        """
        Creates and saves a User with the given email, first_name,last_name and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name,last_name ,password=None):
        """
        Creates and saves a superuser with the given email, first_name,last_name and password.
        """
        user = self.create_user(
            email,
            
            first_name=first_name,
            last_name=last_name,
            password=password
        )
        # user.is_staff =True
        user.is_admin = True
        user.save(using=self._db)
        return user

# Create your models here.
class  User(AbstractUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    mobile = models.CharField(max_length=255, null=True, blank=True)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_event_admin = models.BooleanField(default=False)
    is_event_scanner = models.BooleanField(default=False)
    
    username = None

    objects = UserManager()

    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['first_name', 'last_name',]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
    class  Meta:
        db_table = 'Users'
        managed = True
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        app_label = 'api'


class UserToken(models.Model):
    user_id=models.IntegerField()
    token=models.CharField(max_length=255)
    created_at=models.DateTimeField(auto_now_add=True)
    expired_at=models.DateTimeField()

    class Meta:
        db_table = 'UserTokens'
        managed = True
        verbose_name = 'UserToken'
        verbose_name_plural = 'UserTokens'
        app_label = 'api'
    def __str__(self) -> str:
        return self.token
    
class EventsToScan(models.Model):
    event_id=models.ForeignKey('Event',on_delete=models.CASCADE)
    user_id=models.ForeignKey(User,on_delete=models.CASCADE)
    created_at=models.DateTimeField(auto_now_add=True)
    assigned_by=models.ForeignKey(User,on_delete=models.CASCADE, related_name='assigned_by')
    updated_at=models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'EventsToScan'
        managed = True
        verbose_name = 'EventsToScan'
        verbose_name_plural = 'EventsToScan'
        app_label = 'api'
    def __str__(self) -> str:
        return f'EventID:{self.event_id}-UserID:{self.user_id}'

class Reset(models.Model):
    email=models.CharField(max_length=255) 
    token=models.CharField(max_length=255,unique=True)   

    class Meta:
        db_table = 'Resets'
        managed = True
        verbose_name = 'Reset'
        verbose_name_plural = 'Reset'
        app_label = 'api'

    def __str__(self) -> str:
        return self.email
class AbstractBaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class MpesaResponseBody(AbstractBaseModel):
    body = models.JSONField()
    class Meta:
        db_table = 'MpesaResponseBodies'
        managed = True
        verbose_name = 'MpesaResponseBody'
        verbose_name_plural = 'MpesaResponseBodies'
        app_label = 'api'

        
STATUS = ( (0, "Complete"),(1, "Pending"), (2, "Cancelled"))


class Transaction(models.Model):
    transaction_no = models.CharField(default=uuid.uuid4, max_length=50, unique=True)
    phone_number = PhoneNumberField(null=False, blank=False)
    checkout_request_id = models.CharField(max_length=200)
    reference = models.CharField(max_length=40, blank=True)
    description = models.TextField(null=True, blank=True)
    amount = models.CharField(max_length=10)
    status = models.CharField(max_length=15, choices=STATUS, default=1)
    event_no = models.CharField(max_length=200, blank=True, null=True)
    ticket_id = models.CharField(max_length=200, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(blank=True, null=True)
    ip = models.CharField(max_length=200, blank=True, null=True)

    date = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now_add=False, null=True, blank=True)


    class Meta:
        db_table = 'Transactions'
        managed = True
        verbose_name = 'Transaction'
        verbose_name_plural = 'Transactions'
        app_label = 'api'
    def __str__(self) -> str:
        return self.transaction_no

class Subscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField()
    amount = models.IntegerField()
    amount_paid = models.IntegerField()
    mpesa_trn_id = models.ForeignKey(Transaction, on_delete=models.CASCADE, blank=True, null=True)

    class Meta:
        db_table = 'Subscriptions'
        managed = True
        verbose_name = 'Subscription'
        verbose_name_plural = 'Subscriptions'
        app_label = 'api'
    def __str__(self) -> str:
        return self.user.email
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization_name = models.CharField(max_length=255, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=255, blank=True, null=True)
    county = models.CharField(max_length=255, blank=True, null=True)
    constituency = models.CharField(max_length=255, blank=True, null=True)
    ward = models.CharField(max_length=255, blank=True, null=True)
    postcode = models.CharField(max_length=255, blank=True, null=True)
    country = models.CharField(max_length=255, blank=True, null=True)
    phone = models.CharField(max_length=255, blank=True, null=True)
    logo = models.ImageField(upload_to ="profilelogo", blank=True, null=True)
    status = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    verification_statement = models.CharField(max_length=255, blank=True, null=True)
    subscription_status = models.BooleanField(default=False)
    kra_certificate = models.FileField(upload_to ="kra_certificate", blank=True, null=True)
    incorporation_certficate = models.FileField(upload_to ="incorporation_certificate", blank=True, null=True)
    cr_12 = models.FileField(upload_to ="cr_12", blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated_at = models.DateTimeField(auto_now_add=False, null=True, blank=True)
    subscription = models.ForeignKey('Subscription', on_delete=models.CASCADE, blank=True, null=True)
    
    class Meta:
        db_table = 'Profiles'
        managed = True
        verbose_name = 'Profile'
        verbose_name_plural = 'Profiles'
        app_label = 'api'    
    def __str__(self) -> str:
        return self.user.email

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        if not hasattr(instance, 'profile'):
            Profile.objects.create(user=instance)


class Role(models.Model):
    """
    Custom Role Model for Granular Permissions with permission management
    """
    ROLE_CHOICES = (
        ('organization_admin', 'Organization Admin'),
        ('staff', 'Staff'),
    )
    
    name = models.CharField(max_length=50, choices=ROLE_CHOICES)
    description = models.TextField(blank=True)
    profile = models.ForeignKey(Profile, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['name']),
        ]
        unique_together = ['name', 'profile']
        
    def __str__(self):
        return f"{self.get_name_display()}"

    def __str__(self):
        return self.get_name_display()

class Staff(models.Model):
    """
    Staff Member Model with Detailed Access Control 
    """
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('suspended', 'Suspended'),
        ('inactive', 'Inactive'),
    )
    
    user = models.OneToOneField(User, on_delete=models.PROTECT, related_name='staff_profile')
    employee_id = models.CharField(max_length=50, unique=True)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, related_name='staff_members')
    organization = models.ForeignKey(Profile, on_delete=models.PROTECT, related_name='staff')
    
    # Additional Staff Details
    date_joined = models.DateField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')

    last_activity = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['employee_id']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.role.get_name_display() if self.role else 'No Role'}"


class Tag(models.Model):
    tag = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.tag
    
    class Meta:
        verbose_name = 'Tag'
        verbose_name_plural = 'Tags'
        app_label = 'api'


class Event(models.Model):
    title = models.CharField(max_length=255)
    organization = models.ForeignKey(Profile, on_delete=models.CASCADE)
    description = models.TextField()
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    location = models.CharField(max_length=255,blank=True, null=True)
    latitude = models.CharField(max_length=255,blank=True, null=True)
    longitude = models.CharField(max_length=255,blank=True, null=True)
    tags = models.ManyToManyField(Tag)
    banner = models.ImageField(upload_to="events",blank=True, null=True)
    floor_plan = models.ImageField(upload_to="floor_plan",blank=True, null=True)
    instagram_url = models.CharField(max_length=255, blank=True, null=True)
    x_url = models.CharField(max_length=255, blank=True, null=True)
    meta_url = models.CharField(max_length=255, blank=True, null=True)
    updated_at  = models.DateTimeField(blank=True, null=True)
    created_at  = models.DateTimeField(auto_now_add =True)
    venue= models.CharField(max_length=255,blank=True, null=True)
    is_active=models.BooleanField(default=True)
    
    def __str__(self):
        return self.title

    class Meta:
        verbose_name = 'Event'
        verbose_name_plural = 'Events'
        app_label = 'api'



class TicketType(models.Model):
    title = models.CharField(max_length=255)
    event = models.ForeignKey(Event, blank=True, null=True, on_delete=models.CASCADE)
    price = models.DecimalField(default=0.00, max_digits=65, decimal_places=2)
    available_tickets = models.IntegerField(default=0)
    ticket_type_banner = models.ImageField(upload_to="tickect_banner", blank=True, null=True)
    is_active=models.BooleanField(default=True)
    start_date = models.DateTimeField(blank=True, null=True)
    end_date = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f'{self.event}-{self.title}'
    class Meta:
        verbose_name = 'TicketType'
        verbose_name_plural = 'TicketTypes'
        app_label = 'api'

    def get_discount_price(self):
        active_discount = Discount.objects.filter(ticket_type=self, is_active=True).order_by('-timestamp').first()
        if active_discount: 
            discount_rate = Decimal(active_discount.discount_rate) / Decimal(100)
            return self.price * (Decimal(1) - discount_rate)
        return 0.0
class Discount(models.Model):
    title = models.CharField(max_length=255)
    coupon = models.CharField(max_length=255)
    ticket_type = models.ForeignKey(TicketType, on_delete=models.CASCADE)
    discount_rate = models.FloatField()
    is_active = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    start_date  = models.DateTimeField(blank=True, null=True)
    end_date  = models.DateTimeField(blank=True, null=True)
    created_by = models.ForeignKey(User,on_delete =models.CASCADE)

    class Meta:
        verbose_name = 'Discount'
        verbose_name_plural = 'Discounts'
        app_label = 'api'
    def __str__(self):
        return self.title

class Invoice(models.Model):
    invoice_number = models.CharField(max_length=20, unique=True, blank=True)
    data = models.JSONField()
    is_paid=models.BooleanField(default=False)
    generated_at=models.DateTimeField(auto_now_add=True)
    paid_at=models.DateTimeField(blank=True,null=True)
    mpesa_receipt= models.CharField(max_length=255,blank=True,null=True)
    invoice_amount=models.FloatField(blank=True,null=True)
    ticket_quantity=models.PositiveBigIntegerField(default=0)
    is_complementary=models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.invoice_number:
            last_invoice = Invoice.objects.all().order_by('id').last()
            if not last_invoice:
                new_number = 1
            else:
                new_number = last_invoice.id + 1
            self.invoice_number = f"INV{new_number:06d}"
        super(Invoice, self).save(*args, **kwargs)

    def __str__(self):
        return f"{ self.invoice_number}-{str(self.is_paid)}"

    class Meta:
        verbose_name = 'Invoice'
        verbose_name_plural = 'Invoices'
        app_label = 'api'

class Ticket(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    ticket_type = models.ForeignKey(TicketType, on_delete=models.CASCADE)
    invoice_number = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField()
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    amount_paid = models.DecimalField(default=0.00, max_digits=65, decimal_places=2)
    # txn_id = models.ForeignKey(Transaction, on_delete=models.CASCADE)
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    RF_id = models.CharField(max_length=255, blank=True, null=True)
    qr_code = models.ImageField(upload_to="Tickets", blank=True, null=True)
    invoice_id= models.ForeignKey( Invoice ,null=True, blank=True, on_delete=models.DO_NOTHING)
    ticket_code = models.CharField(max_length=255, unique=True, blank=True, null=True)
    email_to= models.EmailField(blank=True, null=True)
    mpesa_receipt=models.CharField(max_length=255, blank=True, null=True)
    pdf_path = models.CharField(max_length=255, blank=True, null=True)
    is_complementary=models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Ticket'
        verbose_name_plural = 'Tickets'
        app_label = 'api'
    def generate_ticket_code(self):
        return str(uuid.uuid4()).replace("-", "").upper()[:10]

    def save(self, *args, **kwargs):
        if not self.ticket_code:
            self.ticket_code = self.generate_ticket_code()

        # Generate the QR code using the ticket_code
        qrcode_img = qrcode.make(f'{self.ticket_code}')
        canvas = Image.new('RGB', (280, 280), 'white')
        draw = ImageDraw.Draw(canvas)
        canvas.paste(qrcode_img)
        fname = f'qr_code_{self.ticket_code}.png'
        buffer = BytesIO()
        canvas.save(buffer, 'PNG')
        self.qr_code.save(fname, File(buffer), save=False)
        canvas.close()

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.id}-{self.event}-{self.email}-{self.invoice_number}{self.ticket_type}{self.event}"

class CustomerEmail(models.Model):
    ticket_type = models.ForeignKey(Ticket, on_delete=models.CASCADE, blank=True, null=True)
    event =  models.ForeignKey(Event, on_delete=models.CASCADE, blank=True, null=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    receiver = models.EmailField()
    sender = models.EmailField()


    def __str__(self):
        return self.receiver

    class Meta:
        verbose_name = 'CustomerEmail'
        verbose_name_plural = 'CustomerEmails'
        app_label = 'api'

class Ad(models.Model):
    title = models.CharField(max_length=255)
    image = models.ImageField(upload_to="ads")
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
    class Meta:
        verbose_name = 'Ad'
        verbose_name_plural = 'Ads'
        app_label = 'api'


class Blog(models.Model):
    title = models.CharField(max_length=255)
    image = models.ImageField(upload_to="blogs")
    description = models.TextField(blank=True, null=True)
    source = models.CharField(max_length=255, blank=True, null=True)
    link = models.CharField(max_length=255, blank=True, null=True)
    author = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
    class Meta:
        verbose_name = 'Blog'
        verbose_name_plural = 'Blogs'
        app_label = 'api'


class Gallery(models.Model):
    image = models.ImageField(upload_to="gallery")
    event = models.ForeignKey(Event, on_delete=models.CASCADE, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
    
    class Meta:
        verbose_name = 'Gallery'
        verbose_name_plural = 'Galleries'
        app_label = 'api'
    
class MpesaStkPushRequestResponse(models.Model):
    merchant_request_id = models.CharField(max_length=100)
    checkout_request_id = models.CharField(max_length=100)
    response_code = models.CharField(max_length=10)
    response_description = models.CharField(max_length=255)
    customer_message = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    invoice_number=models.CharField(max_length=20, blank=True)
    is_paid=models.BooleanField(default=False)
    #device requesting payment
    fcm_token = models.CharField(max_length=255,blank=True,null=True)
    primary_email= models.EmailField(max_length=254, blank=True,null=True)
    amount=models.FloatField( blank=True,null=True)

    class Meta:
        verbose_name = 'MpesaStkPushRequestResponse'
        verbose_name_plural = 'MpesaStkPushRequestResponses'
        app_label = 'api'
        

    def __str__(self):
        return f"STK Request For {self.invoice_number} Amount:{self.amount}"
    
class MpesaCallback(models.Model):
    body=models.TextField(blank=True,null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return str(self.created_at)
    class Meta:
        verbose_name = 'MpesaCallback'
        verbose_name_plural = 'MpesaCallbacks'
        app_label = 'api'
class MpesaPayment(models.Model):
    merchant_request_id = models.CharField(max_length=255)
    checkout_request_id = models.CharField(max_length=255)
    result_code = models.IntegerField()
    result_desc = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    mpesa_receipt_number = models.CharField(max_length=255, unique=True)
    balance = models.CharField(max_length=255, null=True, blank=True)
    transaction_date = models.BigIntegerField()
    phone_number = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    invoice_number=models.ForeignKey(Invoice,on_delete=models.CASCADE,blank=True,null=True)

    def __str__(self):
        return f'{self.phone_number} | {self.mpesa_receipt_number} | {self.amount} | {self.invoice_number} |Tickets:{self.ticket_quantity}'
    
    @property
    def ticket_quantity(self):
        if self.invoice_number:
            return self.invoice_number.ticket_quantity
        return None
    class Meta:
        verbose_name = 'MpesaPayment'
        verbose_name_plural = 'MpesaPayments'
        app_label = 'api'
    
    
class TransactionStatus(models.Model):
    result = models.TextField()

    def __str__(self):
        return f'TransactionStatus(id={self.id}, result={self.result[:50]})'
    class Meta:
        verbose_name = 'TransactionStatus'
        verbose_name_plural = 'TransactionStatuses'
        app_label = 'api'
    
    
class DispatchComplemetaryTickets(models.Model):
    invoice_number=models.ForeignKey(Invoice, on_delete=models.DO_NOTHING)
    ticket=models.ForeignKey(Ticket,on_delete=models.DO_NOTHING)
    is_emailed=models.BooleanField(default=False)
    sent_at=models.DateTimeField(blank=True,null=True)
    created_at=models.DateTimeField(blank=True,null=True)
    file_path=models.CharField(max_length=255)

    class Meta:
        verbose_name = 'DispatchComplemetaryTickets'
        verbose_name_plural = 'DispatchComplemetaryTicketss'
        app_label = 'api'   
    
    
class ComplementaryTicketDispatch(models.Model):
    invoice_number = models.ForeignKey(Invoice, on_delete=models.DO_NOTHING)
    ticket = models.ForeignKey(Ticket, on_delete=models.DO_NOTHING)
    is_emailed = models.BooleanField(default=False)
    sent_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set the timestamp when the object is created
    file_path = models.CharField(max_length=255)

    def __str__(self):
        return f"Ticket {self.ticket} for Invoice {self.invoice_number}"
    class Meta:
        verbose_name = 'ComplementaryTicketDispatch'
        verbose_name_plural = 'ComplementaryTicketDispatches'
        app_label = 'api'
    
class TicketCheckInLogger(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.DO_NOTHING)
    scan_in_at = models.DateTimeField(blank=True, null=True)
    scan_out_at = models.DateTimeField(blank=True, null=True)
    scanned_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"TicketCheckInLogger(ticket={self.ticket}, scanned_by={self.scanned_by})"
    class Meta:
        verbose_name = 'TicketCheckInLogger'
        verbose_name_plural = 'TicketCheckInLoggers'
        app_label = 'api'