

from mailjet_rest import Client
from datetime import datetime
from django.conf import settings

api_key = settings.MAIL_JET_API_KEY
api_secret = settings.MAIL_JET_API_SECRET
mailjet = Client(auth=(api_key, api_secret), version="v3.1")

from mailjet_rest import Client
from django.core.mail import EmailMultiAlternatives
import json

import os
import base64

# Initialize Mailjet Client

mailjet = Client(auth=(api_key, api_secret), version="v3.1")
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.views.decorators.http import require_POST



def send_email_with_attachment(email, attachment_path, event):
    # Prepare the email message
    sender_email = "marketing@rahafest.com"
    subject = "Ticket"
    text_content = f"""We are pleased to inform you that your ticket purchase was successful. You can find the ticket details attached to this email.

Thank you for choosing {event}. We look forward to seeing you at the event!"""

    # Prepare the message data
    email_data = {
        "Messages": [
            {
                "From": {"Email": sender_email, "Name": "TicketRaha"},
                "To": [{"Email": email, "Name": "Recipient"}],
                "Subject": subject,
                "TextPart": text_content,
                "Attachments": [
                    {
                        "ContentType": "application/pdf",
                        "Filename": os.path.basename(attachment_path),
                        "Base64Content": base64.b64encode(
                            open(attachment_path, "rb").read()
                        ).decode("utf-8"),
                    }
                ],
            }
        ]
    }

    # Send the email
    try:
        result = mailjet.send.create(data=email_data)
        print(result.status_code)
        print(result.json())
        return True
    except Exception as e:
        print(str(e))
        return False


def parse_mpesa_callback(callback_body):
    callback_data = json.loads(callback_body)
    stk_callback = callback_data['Body']['stkCallback']
    merchant_request_id = stk_callback['MerchantRequestID']
    checkout_request_id = stk_callback['CheckoutRequestID']
    result_code = stk_callback['ResultCode']
    result_desc = stk_callback['ResultDesc']
    
    # Extracting the metadata
    metadata = stk_callback.get('CallbackMetadata', {}).get('Item', [])
    data = {item['Name']: item.get('Value') for item in metadata}
    
    amount = data.get('Amount')
    mpesa_receipt_number = data.get('MpesaReceiptNumber')
    transaction_date = data.get('TransactionDate')
    phone_number = data.get('PhoneNumber')
    
    return {
        'merchant_request_id': merchant_request_id,
        'checkout_request_id': checkout_request_id,
        'result_code': result_code,
        'result_desc': result_desc,
        'amount': amount,
        'mpesa_receipt_number': mpesa_receipt_number,
        'transaction_date': transaction_date,
        'phone_number': phone_number,
    }

def get_mpesa_payment(merchant_request_id, checkout_request_id):
    return get_object_or_404(
        MpesaPayment,
        merchant_request_id=merchant_request_id,
        checkout_request_id=checkout_request_id
    )

def update_invoice_with_payment(invoice_number, amount, mpesa_receipt_number):
    invoice = get_object_or_404(Invoice, invoice_number=invoice_number)
    
    invoice.is_paid = True
    invoice.mpesa_receipt = mpesa_receipt_number
    invoice.paid_at = timezone.now()
    invoice.invoice_amount = amount  # Assuming amount is the same as invoice amount or update logic as needed
    invoice.save()

    return invoice

def get_stk_push_request(merchant_request_id, checkout_request_id):
    return get_object_or_404(
        MpesaStkPushRequestResponse,
        merchant_request_id=merchant_request_id,
        checkout_request_id=checkout_request_id
    )

def update_mpesa_payment(payment, data, invoice):
    payment.result_code = data['result_code']
    payment.result_desc = data['result_desc']
    payment.amount = data['amount']
    payment.mpesa_receipt_number = data['mpesa_receipt_number']
    payment.transaction_date = data['transaction_date']
    payment.phone_number = data['phone_number']
    payment.invoice_number = invoice
    payment.save()

@csrf_exempt
@require_POST
def mpesa_callback_view(request):
    callback_body = request.body.decode('utf-8')
    data = parse_mpesa_callback(callback_body)
    
    # Retrieve the corresponding stk push request
    stk_push_request = get_stk_push_request(
        data['merchant_request_id'],
        data['checkout_request_id']
    )
    
    # Retrieve the existing mpesa payment record
    payment = get_mpesa_payment(
        data['merchant_request_id'],
        data['checkout_request_id']
    )
    
    # Update the invoice
    invoice = update_invoice_with_payment(
        stk_push_request.invoice_number,
        data['amount'],
        data['mpesa_receipt_number']
    )
    
    # Update the existing MpesaPayment
    update_mpesa_payment(payment, data, invoice)
    
    # Save the callback data in MpesaCallback
    MpesaCallback.objects.create(body=callback_body)
    

def send_complementary_tickets(email, html_str):
    email_data = {
        'Messages': [
            {
                "From": {
                    "Email": "marketing@rahafest.com",
                    "Name": "Raha Rave"
                },
                "To": [
                    {
                        "Email": email,
                        "Name": "You"
                    }
                ],
                "Subject": f"Complementary Tickets",
                "TextPart": "",
                "HTMLPart":html_str # Pass the rendered HTML template
            }
        ]}
    resu = mailjet.send.create(data=email_data)
    print(resu.status_code)
    print(resu.json())

    return JsonResponse({'status': 'success'})

