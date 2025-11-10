import base64
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
        raw_api_url = settings.API_URL  # Raw from config('API_URL')
        print(f"DEBUG - Raw loaded API_URL from settings: '{raw_api_url}'")  # Keep for now
        
        self.consumer_key = settings.CONSUMER_KEY
        self.consumer_secret = settings.CONSUMER_SECRET
        self.passkey = settings.PASSKEY
        # FIXED: Only strip trailing '/' (common for base URLs); no query param stripping needed
        self.api_url = raw_api_url.rstrip('/')
        
        # FIXED: Check raw for typo warning (before any stripping)
        if 'safaricom' in raw_api_url.lower() and not raw_api_url.rstrip('/').endswith('.co.ke'):
            print(f"WARNING: Raw API_URL '{raw_api_url}' may have a domain typo. Expected '.co.ke' for Kenya.")
        
        print(f"DEBUG - Normalized API_URL: '{self.api_url}'")  # Should now be correct
        
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
        
        # Debug logs (remove or use proper logger in production)
        print(f"Debug - API Base: {self.api_url}")
        print(f"Debug - Token URL: {token_url}")
        
        try:
            response = requests.get(token_url, headers=headers, timeout=30)  # Added timeout
            response.raise_for_status()  # Raises HTTPError for bad status codes
            token_data = response.json()
            token = token_data.get('access_token', '')
            if not token:
                raise ValueError("No access token in response")
            print(f"Debug - Token fetched successfully (expires in {token_data.get('expires_in', 'unknown')}s)")
            return token
        except requests.exceptions.ConnectionError as e:
            if "NameResolutionError" in str(e):
                raise ValueError(f"DNS resolution failed: Check raw API_URL loading (printed above). Full error: {str(e)}")
            raise ValueError(f"Connection error fetching token: {str(e)}")
        except requests.exceptions.HTTPError as e:
            raise ValueError(f"HTTP error fetching token ({e.response.status_code}): {e.response.text}")
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
            response = requests.post(self.stkpush_endpoint, json=request_payload, headers=headers, timeout=30)
            response.raise_for_status()  # Raises for non-200
            response_data = response.json()
            
            merchant_request_id = response_data.get("MerchantRequestID", "")
            checkout_request_id = response_data.get("CheckoutRequestID", "")
            response_code = response_data.get("ResponseCode", "")
            response_description = response_data.get("ResponseDescription", "")
            customer_message = response_data.get("CustomerMessage", "")
            
            print("Merchant Request ID:", merchant_request_id)
            print("Checkout Request ID:", checkout_request_id)
            print("Response Code:", response_code)
            print("Response Description:", response_description)
            print("Customer Message:", customer_message)
            
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
        except requests.exceptions.ConnectionError as e:
            return {"success": False, "error": f"Connection error during STK push: {str(e)}"}
        except requests.exceptions.HTTPError as e:
            error_text = e.response.text if e.response else str(e)
            return {"success": False, "error": error_text}
        except Exception as e:
            return {"success": False, "error": str(e)}