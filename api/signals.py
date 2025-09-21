from django.db.models.signals import post_save
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.conf import settings
from django.http import HttpResponse
from weasyprint import HTML
import os
from django.db.models.signals import pre_delete, post_delete, pre_save, post_save
from .models import *
from django.dispatch import receiver
from firebase_admin.messaging import Message, Notification
from fcm_django.models import FCMDevice
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from rest_framework.exceptions import ValidationError
from firebase_admin.messaging import Message, Notification
from django.shortcuts import get_object_or_404
from rest_framework.test import APIRequestFactory
from rest_framework.test import force_authenticate
from django.urls import resolve

from .utils import send_email_with_attachment
@receiver(post_save, sender=Ticket)  # Replace 'Invoice' with your model name
def generate_ticket_pdf(sender, instance, created, **kwargs):
    if created:
        host=settings.HOST_URL
        ticket_data = {
            'event':instance.event.title,
            'event_banner':f'{host}{instance.event.banner.url}',
            'ticket_type':instance.ticket_type.title,
            'name':f"{instance.first_name} {instance.last_name}",
            'ticket_id':instance.ticket_code,
            'qr_code':f'{host}{instance.qr_code.url}',
            'price':instance.ticket_type.price,
            'ticket_type_banner':instance.ticket_type.ticket_type_banner,
            'location':instance.event.location,
            'start_date': instance.event.start_date.date(),
            'start_time': instance.event.start_date.time()
        }
        
        context = {"ticket_data": ticket_data}

        # Render the HTML template with the combined context
        html_string = render_to_string("api/ticket_doc.html", context)

        # Generate the PDF file
        html = HTML(string=html_string)
        pdf_file = html.write_pdf()

        # Define the file path
        file_path = os.path.join(
            settings.MEDIA_ROOT, "ticket_documents", f"{instance.ticket_code}.pdf"
        )

        # Ensure the directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Save the PDF to the file path
        with open(file_path, "wb") as f:
            f.write(pdf_file)
            
        instance.pdf_path = file_path
        instance.save(update_fields=['pdf_path'])
        event=instance.event.title
        email=instance.email
        if not instance.is_complementary:
            send_email_with_attachment(email,file_path,event)
        if  instance.is_complementary:
            download_url = f"{host}/media/ticket_documents/{instance.ticket_code}.pdf"
            ComplementaryTicketDispatch.objects.create(invoice_number=instance.invoice_id,ticket=instance,is_emailed=False,file_path=download_url)
        
@receiver(post_save, sender=Invoice)
def update_invoice_amount_and_quantity(sender, instance, **kwargs):
    data = instance.data.get("attendeeInfo", [])
    
    total_amount = 0
    ticket_quantity = 0
    
    for attendee in data:
        ticket_type_id = attendee.get("ticket_type")
        try:
            ticket_type = TicketType.objects.get(id=ticket_type_id)
            total_amount += ticket_type.price
            ticket_quantity += 1
        except TicketType.DoesNotExist:
            # Log the error or handle it as necessary
            pass

    # Only update fields if there is a change
    if instance.invoice_amount != total_amount or instance.ticket_quantity != ticket_quantity:
        instance.invoice_amount = total_amount
        instance.ticket_quantity = ticket_quantity
        instance.save(update_fields=['invoice_amount', 'ticket_quantity'])
        
        