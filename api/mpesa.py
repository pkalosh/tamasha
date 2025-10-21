import base64
import json
import requests
from datetime import datetime
from django.conf import settings
from .models import MpesaStkPushRequestResponse
from .serializers import MpesaStkPushRequestResponseSerializer


class Mpesa:
    """
    M-Pesa integration class for setup and STK push initiation.
    Handles access token generation, password generation, and payment requests.
    Loads all parameters from Django settings.
    """

    def __init__(self):
        self.consumer_key = settings.CONSUMER_KEY
        self.consumer_secret = settings.CONSUMER_SECRET
        self.passkey = settings.PASSKEY
        self.api_url = settings.API_URL
        self.business_short_code = settings.BUSINESS_SHORT_CODE
        self.host_url = settings.HOST_URL
        self.callback_url = settings.MPESA_CALLBACK_URL

        # Dynamic setup
        self.timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        self.password = self._generate_password()
        self.access_token = self._get_or_refresh_access_token()

        self.stkpush_endpoint = f"{self.api_url}/mpesa/stkpush/v1/processrequest"

    def _generate_password(self):
        """Generate Lipa na M-Pesa password: base64(Shortcode + Passkey + Timestamp)."""
        data = f"{self.business_short_code}{self.passkey}{self.timestamp}"
        return base64.b64encode(data.encode()).decode()

    def _get_or_refresh_access_token(self):
        """
        Fetch or refresh M-Pesa access token using Consumer Key and Secret.
        Caches in a simple variable; for production, use a model or Redis for persistence.
        """
        # For simplicity, fetch every time; add caching logic if needed
        auth_string = f"{self.consumer_key}:{self.consumer_secret}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        headers = {"Authorization": f"Basic {auth_b64}"}
        token_url = f"{self.api_url}/oauth/v1/generate?grant_type=client_credentials"

        try:
            response = requests.get(token_url, headers=headers)
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get('access_token', '')
            else:
                raise ValueError(f"Failed to fetch access token: {response.text}")
        except Exception as e:
            raise ValueError(f"Access token error: {str(e)}")

    def initiate_stk_push(self, invoice_number, total_amount, phone, fcm_token=None, primary_email=None, invoice_id=None):
        """
        Initiate STK push payment. Returns dict: {'success': bool, 'data': dict or 'error': str}.
        Saves response to MpesaStkPushRequestResponse if successful.
        """
        headers = {"Authorization": f"Bearer {self.access_token}"}
        request_payload = {
            "BusinessShortCode": self.business_short_code,
            "Password": self.password,
            "Timestamp": self.timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": total_amount if not settings.IS_TEST_ENV else 1,  # Toggle for test env
            "PartyA": phone,
            "PartyB": self.business_short_code,
            "PhoneNumber": phone,
            "CallBackURL": self.callback_url,
            "AccountReference": invoice_number,
            "TransactionDesc": f"Payment for: {invoice_number}",
        }

        try:
            response = requests.post(self.stkpush_endpoint, json=request_payload, headers=headers)
            response_data = response.json() if response.status_code == 200 else {"error": response.text}

            if response.status_code == 200:
                merchant_request_id = response_data.get("MerchantRequestID", "")
                checkout_request_id = response_data.get("CheckoutRequestID", "")
                response_code = response_data.get("ResponseCode", "")
                response_description = response_data.get("ResponseDescription", "")
                customer_message = response_data.get("CustomerMessage", "")

                mpesa_stk_push_data = {
                    "merchant_request_id": merchant_request_id,
                    "checkout_request_id": checkout_request_id,
                    "response_code": response_code,
                    "response_description": response_description,
                    "customer_message": customer_message,
                    "invoice_number": invoice_number,
                    "is_paid": False,
                    "fcm_token": fcm_token,
                    "primary_email": primary_email,
                    "amount": total_amount,
                }
                serializer = MpesaStkPushRequestResponseSerializer(data=mpesa_stk_push_data)
                if serializer.is_valid():
                    serializer.save()
                    return {"success": True, "data": response_data}
                else:
                    return {"success": False, "error": serializer.errors}
            else:
                return {"success": False, "error": response_data}

        except Exception as e:
            return {"success": False, "error": str(e)}