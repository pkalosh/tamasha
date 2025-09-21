from django.shortcuts import render

# Create your views here.
from asyncio import exceptions
from cgitb import reset
import email
from lib2to3.pgen2 import token
from os import access
from random import random
import string
from urllib import response
from webbrowser import get
from django.core.mail import send_mail
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header
import random
from django.contrib.auth.decorators import login_required
from .serializers import *
from .authentication import *
import time
from rest_framework import generics, status, viewsets
from django.core.paginator import Paginator
from django.core.mail import send_mail
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.decorators import action
import os
import json
import requests
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, get_object_or_404, get_list_or_404
from fcm_django.models import FCMDevice
from firebase_admin.messaging import Message, Notification
from .utils import send_email_with_attachment,send_complementary_tickets
from django.utils import timezone
from weasyprint import HTML
from django.conf import settings
from django.template.loader import render_to_string
from django.db.models import Count,F
from django.http import Http404
from django.db.models import Count, Sum, F, Q
import pandas as pd
from django.http import HttpResponse



from rest_framework.decorators import throttle_classes
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle

from django.db.models import Count, Sum, F, Q


# Create your views here.
class RegisterApiView(APIView):
    # authentication_classes = [JWTAuthentication]

    def post(self, request):
        data = request.data
        serializer = UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Send email
        # subject = "Welcome to Tamasha Website"
        # message = f"Dear {user.username},\n\nWelcome to Tamasha website! Thank you for registering."
        # from_email = "Tamasha@gmail.com"
        # to_email = user.email
        # send_mail(subject, message, from_email, [to_email])

        return Response(serializer.data)


class LoginApiView(APIView):
    
    def get_user_roles_and_details(self, user):
        """
        Get user roles and related details with clear role hierarchy
        """
        roles = []
        user_details = {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
        }
        
        # Check for staff profile first (takes priority)
        staff_data = None
        has_staff_role = False
        
        try:
            staff = user.staff_profile
            if staff and staff.status == 'active':
                staff_data = {
                    'employee_id': staff.employee_id,
                    'organization': self.get_organization_data(staff.organization),
                    'role': self.get_role_data(staff.role),
                    'status': staff.status,
                    'date_joined': staff.date_joined.isoformat() if staff.date_joined else None,
                    'last_activity': staff.last_activity.isoformat() if staff.last_activity else None,
                }
                
                # Add staff role (this takes priority over profile-based roles)
                if staff.role:
                    roles.append(staff.role.name)
                    has_staff_role = True
                    
        except AttributeError:
            # User doesn't have staff_profile relationship
            pass
        
        # Check if user is an event admin (independent role)
        if hasattr(user, 'is_event_admin') and user.is_event_admin:
            if 'event_admin' not in roles:
                roles.append('event_admin')
        
        # Check if user has a profile - only add organization_admin if no staff role exists
        if hasattr(user, 'profile') and user.profile:
            user_details['profile_id'] = user.profile.id
            # Only add organization_admin role if user doesn't have a staff-based role
            if not has_staff_role:
                roles.append('organization_admin')
        
        # Add basic user role if no other roles found
        if not roles:
            roles.append('user')
        
        return roles, user_details, staff_data
    
    def get_organization_data(self, organization):
        """
        Get organization data safely
        """
        if not organization:
            return None
            
        return {
            'id': organization.id,
            'name': getattr(organization, 'organization_name', ''),
            'address': getattr(organization, 'address', ''),
            'city': getattr(organization, 'city', ''),
            'phone': getattr(organization, 'phone', ''),
            'status': getattr(organization, 'status', ''),
        }
    
    def get_role_data(self, role):
        """
        Get role data safely
        """
        if not role:
            return None
            
        return {
            'name': role.name,
            'display_name': role.get_name_display(),
            'description': role.description,
        }

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        
        if not email or not password:
            raise exceptions.ValidationError("Email and password are required")
        
        user = User.objects.filter(email=email).first()
        if user is None:
            raise exceptions.AuthenticationFailed("Invalid Credentials!")
            
        if not user.check_password(password):
            raise exceptions.AuthenticationFailed("Invalid Credentials")
        
        # Get user roles and details
        roles, user_details, staff_data = self.get_user_roles_and_details(user)
        
        # Create tokens
        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)
        
        UserToken.objects.create(
            user_id=user.id,
            token=refresh_token,
            expired_at=datetime.datetime.utcnow() + datetime.timedelta(days=7),
        )
        
        # Update staff last_login if applicable
        if staff_data:
            try:
                staff = user.staff_profile
                staff.last_login = datetime.datetime.now()
                staff.save(update_fields=['last_login'])
            except AttributeError:
                pass
        
        response = Response()
        response.set_cookie(
            key="refresh_token", 
            value=refresh_token, 
            httponly=True, 
            secure=True
        )
        
        response_data = {
            "token": access_token,
            "roles": roles,
            "user": user_details,
        }
        
        # Add staff data if available
        if staff_data:
            response_data["staff"] = staff_data
            
        response.data = response_data
        return response


class UserApiView(APIView):
    authentication_classes = [JWTAuthentication]

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get(self, request):
        return Response(UserSerializer(request.user).data)


class RefreshApiView(APIView):
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get(self, request):
        print(request.data)
        
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            raise exceptions.AuthenticationFailed("Refresh token not provided")
        
        try:
            user_id = decode_refresh_token(refresh_token)
        except Exception:
            raise exceptions.AuthenticationFailed("Invalid refresh token")
        
        # Check if refresh token is valid and not expired
        if not UserToken.objects.filter(
            user_id=user_id, 
            token=refresh_token,
            expired_at__gt=datetime.datetime.now(tz=datetime.timezone.utc)
        ).exists():
            raise exceptions.AuthenticationFailed("Refresh token expired or invalid")
        
        # Get user object
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed("User not found")
        
        # Create new access token
        access_token = create_access_token(user_id)
        
        # Use UserSerializer to get consistent user data with staff details
        serializer = UserSerializer(
            user, 
            context={
                'include_staff': True, 
                'include_roles': True
            }
        )
        
        response_data = {
            "token": access_token,
            **serializer.data  # Includes user data, roles, and staff details
        }
        
        return Response(response_data)


class LogoutApiView(APIView):
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        UserToken.objects.filter(token=refresh_token).delete()
        response = Response()
        response.delete_cookie(key="refresh_token")

        response.data = {"message": "logout success"}

        return response


class ForgotPasswordApiView(APIView):
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def post(self, request):
        email = request.data["email"]
        token = "".join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
        )
        Reset.objects.create(email=request.data["email"], token=token)
        url = "http://localhost:8000/reset/" + token
        try:
            send_mail(
                subject="Reset Your Password",
                message='Click <a href="%s">here<a/> to reset your password' % url,
                from_email="tickets@tamashalink.com",
                recipient_list=[email],
            )
        except Exception as e:
            print(e)
        return Response({"message": "success"})


class ResetPasswordApiView(APIView):

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def post(self, request):
        data = request.data
        if data["password"] != data["confirm_password"]:
            raise exceptions.APIException("Password do not match!")
        reset_password = Reset.objects.filter(token=data["token"]).first()
        if not reset_password:
            raise exceptions.APIException("Invalid Link!")

        user = User.objects.filter(email=reset_password.email).first()
        if not user:
            raise exceptions.APIException("User Not Found!")
        user.set_password(data["password"])
        user.save()
        return Response({"message": "success"})


class EventOrganizationKYCApiView(APIView):
    authentication_classes = [JWTAuthentication]
    parser_classes = (MultiPartParser, FormParser)

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get(self, request):
        user = request.user

        if not user:
            raise exceptions.AuthenticationFailed("User not authenticated")

        if not user.is_event_admin:
            raise exceptions.AuthenticationFailed(
                "User not permitted to access this resource"
            )

        try:
            profile = Profile.objects.get(user=user)
        except Profile.DoesNotExist:
            raise exceptions.NotFound("Profile not found")

        serializer = KYCSerializer(profile)
        return Response(serializer.data)

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def post(self, request):
        org_data = request.data
        user = request.user

        if not user:
            raise exceptions.AuthenticationFailed("User not authenticated")
        if not user.is_event_admin:
            raise exceptions.AuthenticationFailed(
                "User not permitted to access this resource"
            )
        try:
            profile = Profile.objects.get(user=user)
        except Profile.DoesNotExist:
            raise exceptions.NotFound("Profile not found")

        serializer = KYCSerializer(instance=profile, data=org_data)
        if serializer.is_valid():
            serializer.save()

            return Response({"message": "success"})
        else:
            return Response(serializer.errors, status=400)

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def patch(self, request, profile_id):
        user = request.user
        if not user:
            raise exceptions.AuthenticationFailed("User not authenticated")
        if not user.is_event_admin:
            raise exceptions.AuthenticationFailed(
                "User not permitted to access this resource"
            )
        try:
            profile = Profile.objects.get(id=profile_id)
        except Profile.DoesNotExist:
            raise exceptions.NotFound("Profile not found")

        serializer = KYCSerializer(instance=profile, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=400)


class ProfileAPIView(generics.ListCreateAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer


class ProfileDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer


class CreateEventAPIView(generics.CreateAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Event.objects.all()
    serializer_class = EventSerializer


class EventPatchView(APIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def patch(self, request, pk):
        try:
            event = Event.objects.get(pk=pk)
        except Event.DoesNotExist:
            return Response(
                {"error": "Event not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # Remove 'id' from request data to prevent updating it
        if "id" in request.data:
            del request.data["id"]
        if "organization" in request.data:
            del request.data["organization"]
        serializer = EventSerializer(event, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ListEventAPIView(generics.ListAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer


class OrgEventListAPIView(generics.RetrieveAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Event.objects.all()
    serializer_class = EventSerializer

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)


class EventListByOrganizationView(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    serializer_class = EventSerializer

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get_queryset(self):
        organization_id = self.kwargs["organization_id"]
        return Event.objects.filter(organization_id=organization_id)


# class EventDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
#     queryset = Event.objects.all()
#     serializer_class = EventSerializer


class TagAPIView(generics.ListCreateAPIView):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer

    def post(self, request, *args, **kwargs):
        # Reject POST requests with MethodNotAllowed exception
        raise MethodNotAllowed("POST")


class TagDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer


class TicketTypeAPIView(generics.ListCreateAPIView):
    authentication_classes = [JWTAuthentication]
    serializer_class = TicketTypeSerializer

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get_queryset(self):
        # Retrieve the event_id from the URL parameters
        event_id = self.kwargs.get("event_id")
        # Filter ticket types based on the event_id
        return TicketType.objects.filter(event_id=event_id)


class TicketTypeListAPIView(generics.ListAPIView):
    serializer_class = TicketTypeSerializer

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get_queryset(self):
        # Retrieve the event_id from the URL parameters
        event_id = self.kwargs.get("event_id")
        # Filter ticket types based on the event_id
        return TicketType.objects.filter(event_id=event_id)


class TicketTypeUpdateAPIView(generics.UpdateAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = TicketType.objects.all()
    serializer_class = TicketTypeSerializer

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)


class TicketTypeDeleteAPIView(generics.DestroyAPIView):
    queryset = TicketType.objects.all()

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"detail": "Ticket type deleted successfully."}, status=status.HTTP_200_OK
        )


class TicketListView(generics.ListCreateAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Ticket.objects.all()
    serializer_class = BulkTicketCreateSerializer

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.save()
        tickets_data = [
            TicketCreateSerializer(ticket).data for ticket in data["tickets"]
        ]
        # payment_data = PaymentSerializer(data['payment']).data
        response_data = {
            "attendeeInfo": tickets_data,
        }
        return Response(response_data, status=status.HTTP_201_CREATED)

    def get(self, request, *args, **kwargs):
        raise MethodNotAllowed("GET")


# Blog API VIEWS


class BlogAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get(self, request):
        blog = Blog.objects.all()
        serializer = BlogSerializer(blog, many=True)
        return Response(serializer.data)

    # post
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def post(self, request):
        serializer = BlogSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # edit
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def put(self, request, blog_id):
        blog = Blog.objects.get(id=blog_id)
        serializer = BlogSerializer(blog, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # delete
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def delete(self, request, blog_id):
        blog = Blog.objects.get(id=blog_id)
        blog.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdsAPIView(APIView):
    # authentication_classes = [JWTAuthentication]

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get(self, request):
        ad = Ad.objects.all()
        serializer = AdSerializer(ad, many=True)
        return Response(serializer.data)

    # post
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def post(self, request):
        serializer = AdSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # edit
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def put(self, request, ad_id):
        ad = Ad.objects.get(id=ad_id)
        serializer = AdSerializer(ad, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # delete
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def delete(self, request, ad_id):
        ad = Ad.objects.get(id=ad_id)
        ad.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)



class TicketsByOrganizationView(APIView):
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get(self, request, organization_id):
        try:
            profile = Profile.objects.get(id=organization_id)
        except Profile.DoesNotExist:
            return Response(
                {"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND
            )

        tickets = Ticket.objects.filter(event__organization=profile)
        serializer = TicketSerializer(tickets, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TicketTypeListView(APIView):
    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def get(self, request, organization_id):
        try:
            organization = Profile.objects.get(id=organization_id)
        except Profile.DoesNotExist:
            return Response(
                {"detail": "Organization not found."}, status=status.HTTP_404_NOT_FOUND
            )

        ticket_types = TicketType.objects.filter(event__organization=organization)
        serializer = TicketTypeSerializer(ticket_types, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class MpesaCallBackUrlAPIView(APIView):

    def post(self, request, format=None):
        body = request.data
        if not body:
            return Response(
                {"error": "No callback data received"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if body:
            mpesa = MpesaResponseBody.objects.create(body=body)

            mpesa_body = mpesa.body
            print(mpesa_body)

            try:
                result_code = mpesa_body["Body"]["stkCallback"]["ResultCode"]
                result_desc = mpesa_body["Body"]["stkCallback"]["ResultDesc"]
                checkout_request_id = mpesa_body["Body"]["stkCallback"][
                    "CheckoutRequestID"
                ]
                merchant_request_id = mpesa_body["Body"]["stkCallback"][
                    "MerchantRequestID"
                ]
                amount = mpesa_body["Body"]["stkCallback"]["CallbackMetadata"]["Item"][
                    0
                ]["Value"]
                mpesa_receipt_number = mpesa_body["Body"]["stkCallback"][
                    "CallbackMetadata"
                ]["Item"][1]["Value"]
                print(mpesa_receipt_number)
                transaction_date = mpesa_body["Body"]["stkCallback"][
                    "CallbackMetadata"
                ]["Item"][3]["Value"]
                phone_number = mpesa_body["Body"]["stkCallback"]["CallbackMetadata"][
                    "Item"
                ][4]["Value"]
                try:
                    txn = Transaction.objects.get(
                        checkout_request_id=checkout_request_id
                    )
                    txn.receipt_no = mpesa_receipt_number
                    txn.amount = amount
                    txn.updated = datetime.strptime(
                        str(transaction_date), "%Y%m%d%H%M%S"
                    )

                    txn.status = "Complete"
                    txn.save()
                except Transaction.DoesNotExist:
                    return Response(
                        {"error": "Transaction does not exist."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                try:
                    bill = Bill.objects.get(bill_number=txn.bill_no)
                    bill_transactions = Transaction.objects.filter(bill_no=bill.id)
                    total_amount_paid = sum(
                        transaction.amount for transaction in bill_transactions
                    )
                    if float(total_amount_paid) != float(bill.total_amount):
                        bill.bill_status = "Active"
                        bill.bill_payment_status = "Unpaid"
                        bill.amount_paid += float(amount)
                    else:
                        bill.amount_paid = total_amount_paid
                        # bill.bill_payment_id = txn.id
                        bill.payment_confirmed = True
                        bill.bill_payment_status = "Paid"
                        bill.bill_status = "Closed"
                    bill.save()
                except Bill.DoesNotExist:
                    return Response(
                        {"error": "Bill not found."}, status=status.HTTP_400_BAD_REQUEST
                    )

                return Response(
                    {"message": "Callback received and processed successfully."}
                )
            except KeyError:
                return Response(
                    {"error": "Invalid callback data format."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

    def get(self, request, format=None):
        response_bodies = MpesaResponseBody.objects.all()
        serializer = MpesaResponseBodySerializer(response_bodies, many=True)
        return Response({"responses": serializer.data})


class InvoiceCreateView(generics.CreateAPIView):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def create(self, request, *args, **kwargs):
        data = request.data
        attendee_info = data.get("data", {}).get("attendeeInfo", [])

        # Calculate total amount
        total_amount = 0
        for attendee in attendee_info:
            ticket_type_id = attendee.get("ticket_type")
            try:
                ticket_type = TicketType.objects.get(id=ticket_type_id)
                total_amount += ticket_type.price
            except TicketType.DoesNotExist:
                return Response(
                    {"error": f"TicketType with id {ticket_type_id} does not exist."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Create invoice
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        # Include total amount in the response
        response_data = serializer.data
        response_data["total_amount"] = total_amount

        headers = self.get_success_headers(serializer.data)
        return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)


class InitiatePayment(APIView):

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def post(self, request, *args, **kwargs):
        try:
            data = request.data

            invoice_number = data.get("invoice_number")
            phone = data.get("phone")
            fcm_token = data.get("fcm_token")
            primary_email = data.get("primary_email")

            # Retrieve the Invoice instance
            try:
                invoice = Invoice.objects.get(invoice_number=invoice_number)
                total_amount = invoice.invoice_amount
                invoice_id = invoice.id
            except Invoice.DoesNotExist:
                return Response(
                    {"error": "Invoice not found"}, status=status.HTTP_404_NOT_FOUND
                )

            response_data = {
                "id": invoice_id,
                "invoice_number": invoice_number,
                "total_amount": total_amount,
                "phone": phone,
                "fcm_token": fcm_token,
                "payment_status": "Pending",
                "primary_email": primary_email,
            }

            try:
                lipa_na_mpesa_online(
                    invoice_id,
                    invoice_number,
                    total_amount,
                    phone,
                    fcm_token,
                    primary_email,
                )
                return Response(response_data, status=status.HTTP_200_OK)
            except Exception as e:
                print(e)
                return Response(
                    {"error": "Payment initiation failed", "details": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
def mpesa_callback(request):
    try:
        if request.method == "POST":
            print("CALLBACK RECIEVED")
            # Parse the JSON data from the request body
            stk_callback_response = json.loads(request.body.decode("utf-8"))
            print(stk_callback_response)

            mpesa_callback = MpesaCallback.objects.create(
                body=json.dumps(stk_callback_response)
            )

            if mpesa_callback:
                print("MpesaCallbacks object created successfully.")

                body = stk_callback_response.get("Body", {})
                stk_callback = body.get("stkCallback", {})
                print(body)
                print("stk callback")
                print(stk_callback)

                merchant_request_id = stk_callback.get("MerchantRequestID", "")
                checkout_request_id = stk_callback.get("CheckoutRequestID", "")
                result_code = stk_callback.get("ResultCode", "")
                result_desc = stk_callback.get("ResultDesc", "")

                if result_code == 0:

                    try:
                        callback_metadata = stk_callback.get("CallbackMetadata", {})

                        items = callback_metadata.get("Item", [])

                        amount = next(
                            (
                                item["Value"]
                                for item in items
                                if item["Name"] == "Amount"
                            ),
                            None,
                        )

                        mpesa_receipt_number = next(
                            (
                                item["Value"]
                                for item in items
                                if item["Name"] == "MpesaReceiptNumber"
                            ),
                            None,
                        )
                        transaction_date = next(
                            (
                                item["Value"]
                                for item in items
                                if item["Name"] == "TransactionDate"
                            ),
                            None,
                        )
                        phone_number = next(
                            (
                                item["Value"]
                                for item in items
                                if item["Name"] == "PhoneNumber"
                            ),
                            None,
                        )

                        current_invoice_stkpush_request = get_object_or_404(
                            MpesaStkPushRequestResponse,
                            checkout_request_id=checkout_request_id,
                            merchant_request_id=merchant_request_id,
                        )
                        print("CURRENT OBJ")
                        print(current_invoice_stkpush_request)
                        print(
                            current_invoice_stkpush_request.invoice_number,
                            current_invoice_stkpush_request.fcm_token,
                        )

                        current_invoice = get_object_or_404(
                            Invoice,
                            invoice_number=current_invoice_stkpush_request.invoice_number,
                        )
                        tickets = current_invoice.data
                        current_invoice.is_paid = True
                        current_invoice.paid_at = timezone.now()
                        current_invoice.mpesa_receipt = mpesa_receipt_number
                        current_invoice.save()

                        print("TICKETS JSON")
                        print(tickets)
                        email_to = current_invoice.data["payment"]["email_to"]
                        print(email_to)
                        try:
                            serializer = BulkTicketCreateSerializer(
                                data=tickets,
                                context={
                                    "email_to": email_to,
                                    "invoice_number": get_object_or_404(
                                        Invoice,
                                        invoice_number=current_invoice.invoice_number,
                                    ),
                                    "mpesa_receipt": mpesa_receipt_number,
                                },
                            )
                            if serializer.is_valid():
                                try:
                                    serializer.save()
                                    print(serializer.data)
                                except Exception as e:
                                    print("TICKET CREATION FAILED")
                                    print(e)

                                # "send push notification"
                                # try:

                                #     tkn="cC4X15yUcilSnIJFwSvYAe:APA91bEe1IMpSs8noBuL5gGi74Y38GJ9XKc8gtoRSetiQN0E27tuSPQ0Ij8zl0u_vFBnHEHY5Vsu42rvTwqzpTo6yt6RklShSYW-8LwTaFZ0Y_h1uGa67nIQecr5HzDiI5YyNOqFAhSE"
                                #     device, created = FCMDevice.objects.get_or_create(registration_id=tkn)
                                #     device = FCMDevice.objects.filter(registration_id=tkn)
                                #     device.send_message(Message(
                                #     notification=Notification(title="Payment COnfimed", body=f"SOme", image="url"),
                                #     data={
                                #         "is_paid" : True,
                                #         },

                                #     ) )

                                # except Exception as e:
                                #     print(e)

                                # send emails to customer

                            else:
                                print("Failed Serializer")
                                print(serializer)
                        except Exception as e:
                            print("BUlk Serializer Exception")
                            print(e)

                        mpesa_payment = MpesaPayment.objects.create(
                            merchant_request_id=merchant_request_id,
                            checkout_request_id=checkout_request_id,
                            result_code=result_code,
                            result_desc=result_desc,
                            amount=amount,
                            mpesa_receipt_number=mpesa_receipt_number,
                            transaction_date=transaction_date,
                            phone_number=phone_number,
                            invoice_number=get_object_or_404(
                                Invoice, invoice_number=current_invoice.invoice_number
                            ),
                        )
                    except Exception as e:
                        print(e)
                        print(" ERROR SAVING MPESA PAYMENTS")

        return HttpResponse("success", status=200)

    except Exception as e:
        print(f"Error: {e}")
        return JsonResponse({"error": str(e)}, status=500)


def lipa_na_mpesa_online(
    invoice_id, invoice_number, total_amount, phone, fcm_token, primary_email
):

    # is_test_env = settings.IS_TEST_ENV
    # if is_test_env==True:
    #     total_amount = 1
    # else:
    #     total_amount = total_amount

    access_token = MpesaAccessToken.validated_mpesa_access_token
    print(access_token)
    # api_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    api_url = "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    headers = {"Authorization": "Bearer %s" % access_token}
    request = {
        "BusinessShortCode": LipanaMpesaPpassword.Business_short_code,
        "Password": LipanaMpesaPpassword.decode_password,
        "Timestamp": LipanaMpesaPpassword.lipa_time,
        "TransactionType": "CustomerPayBillOnline",
        # "Amount": 1,
        "Amount": total_amount,
        "PartyA": phone,
        # "PartyA": 254700494222,
        "PartyB": LipanaMpesaPpassword.Business_short_code,
        "PhoneNumber": phone,
        # "PhoneNumber": 254700494222,
        "CallBackURL": settings.MPESA_CALLBACK_URL,
        "AccountReference": f"{invoice_number}",
        "TransactionDesc": f"Payment for: {invoice_number}",
    }

    response = requests.post(api_url, json=request, headers=headers)
    print(json.loads(response.text))
    if response.status_code == 200:
        response_data = response.json()
        print("Response Data:", response_data)
        merchant_request_id = response_data.get("MerchantRequestID", "")
        checkout_request_id = response_data.get("CheckoutRequestID", "")
        response_code = response_data.get("ResponseCode", "")
        response_description = response_data.get("ResponseDescription", "")
        customer_message = response_data.get("CustomerMessage", "")
        # print("Merchant Request ID:", merchant_request_id)
        # print("Checkout Request ID:", checkout_request_id)
        # print("Response Code:", response_code)
        # print("Response Description:", response_description)
        # print("Customer Message:", customer_message)
        print("HERE")
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
        print("LL")
        serializer = MpesaStkPushRequestResponseSerializer(data=mpesa_stk_push_data)
        if serializer.is_valid():
            serializer.save()
            return HttpResponse("Success", status=200)
        else:
            print(serializer)
            return HttpResponse("Failed to save data", status=400)

    try:
        pass

    except Exception as e:
        print(e)
    return HttpResponse("SOme stuff", status=200)


def generate_invoice_pdf(
    request,
):
    invoice_number = "INV000010"
    try:
        # Retrieve the invoice from the database
        invoice = Invoice.objects.get(invoice_number=invoice_number)

        # Render the HTML template with the invoice data
        html_string = render_to_string("api/sample.html", {"invoice": invoice})

        # Generate the PDF file
        html = HTML(string=html_string)
        pdf_file = html.write_pdf()

        # Define the file path
        file_path = os.path.join(
            settings.MEDIA_ROOT, "invoices", f"{invoice_number}.pdf"
        )

        # Ensure the directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Save the PDF to the file path
        with open(file_path, "wb") as f:
            f.write(pdf_file)

        return HttpResponse(
            f"PDF generated and saved to {file_path}", content_type="text/plain"
        )
    except Invoice.DoesNotExist:
        return HttpResponse("Invoice not found", status=404)


# #Ticket analytics

class TicketCountView(APIView):
    authentication_classes = [JWTAuthentication]
    throttle_classes = [UserRateThrottle, AnonRateThrottle]
    # permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
        except Profile.DoesNotExist:
            raise Http404("Profile not found")

        events = Event.objects.filter(organization=profile.id)
        
        if not events.exists():
            return Response({"error": "No events found for this organization"}, status=status.HTTP_404_NOT_FOUND)

        response_data = []
        
        for event in events:
            event_data = EventStatsSerializer(event).data
            ticket_types = TicketType.objects.filter(event=event)
            ticks_data = TicketTypeSerializer(ticket_types, many=True).data
            
            event_response = {
                'id': event_data['id'],
                'title': event_data['title'],
                'is_active': event_data['is_active'],
                'ticket_types': ticks_data
            }
            
            response_data.append(event_response)

        return Response({'events': response_data}, status=status.HTTP_200_OK)


class ClientTotalAnalysis(APIView):
    authentication_classes = [JWTAuthentication]
    throttle_classes = [UserRateThrottle, AnonRateThrottle]

    def get(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
        except Profile.DoesNotExist:
            raise Http404("Profile not found")

        events = Event.objects.filter(organization=profile)

        total_events = events.count()




class SendComplementaryTickets(APIView):
    authentication_classes=[JWTAuthentication]
    def post(self, request):
        serializer = InvoiceNumberSerializer(data=request.data)
        if serializer.is_valid():
            invoice_number = serializer.validated_data['invoice_number']
            tickets_dispatch = ComplementaryTicketDispatch.objects.filter(invoice_number__invoice_number=invoice_number)
            if not tickets_dispatch.exists():
                return Response({'error': 'No tickets found for the given invoice number'}, status=status.HTTP_404_NOT_FOUND)

            download_links = []
            for dispatch in tickets_dispatch:
                download_url = f"{dispatch.file_path}"
                # print(download_url)
                download_links.append(f'<a href="{download_url}">Ticket for { dispatch.ticket.first_name} { dispatch.ticket.last_name}</a>')
            
            email_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Invoice Tickets</title>
            </head>
            <body>
                <p>Dear Customer,</p>
                <p>Please find your tickets attached. You can download them using the following links:</p>
                <ul>
                    {'<br>'.join(download_links)}
                </ul>
                <p>Best regards,</p>
                <p>Tamasha Link Team</p>
            </body>
            </html>
            """
            # print(email_body)
            email = tickets_dispatch.first().ticket.email

            try:
                send_complementary_tickets(email,email_body)
                
                return Response({'message': 'Email sent successfully'}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class TicketCheckInLoggerCreateView(generics.CreateAPIView):
    authentication_classes=[JWTAuthentication]
    queryset = TicketCheckInLogger.objects.all()
    serializer_class = TicketCheckInLoggerSerializer
    

    def post(self, request, *args, **kwargs):
        ticket_code = request.data.get('ticket_code')
        
        if not ticket_code:
            return Response({"error": "ticket_code is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            ticket = Ticket.objects.get(ticket_code=ticket_code)
        except Ticket.DoesNotExist:
            return Response({"error": "Invalid Ticket."}, status=status.HTTP_404_NOT_FOUND)

        # Count existing records for the ticket
        check_in_count = TicketCheckInLogger.objects.filter(ticket=ticket).count()

        ticket_check_in_logger = TicketCheckInLogger(
            ticket=ticket,
            scan_in_at=timezone.now(),
            scanned_by=request.user
        )
        ticket_check_in_logger.save()

        # Get the history of check-ins for the ticket
        history = TicketCheckInLogger.objects.filter(ticket=ticket)
        history_serializer = self.get_serializer(history, many=True)

        # Prepare response data
        response_data = {
            "new_record": self.get_serializer(ticket_check_in_logger).data,
            "check_in_count": check_in_count + 1,  # Including the new record
            "history": history_serializer.data
        }

        return Response(response_data, status=status.HTTP_201_CREATED)


class InvoiceUpdateView(generics.UpdateAPIView):
    authentication_classes=[JWTAuthentication]
    queryset = Invoice.objects.all()
    serializer_class = InvoiceUpdateSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'  # Default is 'pk' which is the primary key

    def get_object(self):
        invoice_id = self.kwargs.get('pk')
        return Invoice.objects.get(id=invoice_id)




class InvoiceDetailView(generics.RetrieveAPIView):
    authentication_classes=[JWTAuthentication]
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
    lookup_field = 'pk'  # Default is 'pk', which refers to the primary key

    def get_object(self):
        invoice_id = self.kwargs.get('pk')
        return Invoice.objects.get(id=invoice_id)


@csrf_exempt
def query_transaction(request):
    print("------------------/")
    try:
        if request.method == "POST":
            print("QUERY CALLBACK RECIEVED")
            # Parse the JSON data from the request body
            callback_response = json.loads(request.body.decode("utf-8"))
            print(callback_response)

            mpesa_callback = TransactionStatus.objects.create(
                body=json.dumps(callback_response)
            )

            # Define your access credentials and endpoints
        
        api_url = "https://sandbox.safaricom.co.ke/mpesa/transactionstatus/v1/query"

        # Step 1: Obtain the OAuth Token
        # oauth_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        # response = requests.get(oauth_url, auth=(consumer_key, consumer_secret))
        oauth_token = MpesaAccessToken.validated_mpesa_access_token
        print("**************")
        print(oauth_token)
        print("**************")

        # Step 2: Prepare the request payload
        payload = {
            "Initiator": "testapiuser",
            "SecurityCredential": "0350e85bcb0368d621c1882961cbd93a3eaaa0d82851ff97393ea14a7cf3f1a5",
            "Command ID": "TransactionStatusQuery",
            "Transaction ID": "SFT32XH6YL",
            "OriginatorConversationID": "AG_20190826_0000777ab7d848b9e721",
            "PartyA": "4137255",
            "IdentifierType": "4",
            "ResultURL": "https://tickoh.stackthon.com/api/query-status",
            "QueueTimeOutURL": "http://myservice:8080/timeout",
            "Remarks": "OK",
            "Occasion": "OK",
        }

        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "Content-Type": "application/json",
        }

        # Step 3: Send the request to the Transaction Status API
        response = requests.post(api_url, headers=headers, json=payload)
        response_data = response.json()
        print("*******--*******")
        print(response_data)
        print("**************")

        # Step 4: Save the response data to the database
        transaction_status = TransactionStatus(result=json.dumps(response_data))
        transaction_status.save()

        return transaction_status

    except Exception as e:
        print(e)


class TicketCountView(APIView):
    authentication_classes = [JWTAuthentication]
    throttle_classes = [UserRateThrottle, AnonRateThrottle]
    # permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
        except Profile.DoesNotExist:
            raise Http404("Profile not found")

        events = Event.objects.filter(organization=profile.id)
        
        if not events.exists():
            return Response({"error": "No events found for this organization"}, status=status.HTTP_404_NOT_FOUND)

        response_data = []
        
        for event in events:
            event_data = EventStatsSerializer(event).data
            ticket_types = TicketType.objects.filter(event=event)
            ticks_data = TicketTypeSerializer(ticket_types, many=True).data
            
            event_response = {
                'id': event_data['id'],
                'title': event_data['title'],
                'is_active': event_data['is_active'],
                'ticket_types': ticks_data
            }
            
            response_data.append(event_response)

        return Response({'events': response_data}, status=status.HTTP_200_OK)


class ClientTotalAnalysis(APIView):
    authentication_classes = [JWTAuthentication]
    throttle_classes = [UserRateThrottle, AnonRateThrottle]

    def get(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
        except Profile.DoesNotExist:
            raise Http404("Profile not found")

        events = Event.objects.filter(organization=profile)

        total_events = events.count()

        total_tickets_created = TicketType.objects.filter(event__in=events).aggregate(total_created=Sum('available_tickets'))['total_created'] or 0

        total_tickets_sold = 0
        total_revenue = 0.00

        tickets_with_invoices = Ticket.objects.filter(event__in=events, invoice_number__isnull=False)

        for ticket in tickets_with_invoices:
            try:
                invoice = Invoice.objects.get(invoice_number=ticket.invoice_number)
                if invoice.is_paid:
                    total_tickets_sold += invoice.ticket_quantity
                    if invoice.invoice_amount is not None:
                        total_revenue += float(invoice.invoice_amount)
            except Invoice.DoesNotExist:
                pass

        dashboard_data = {
            "total_events": total_events,
            "total_revenue": total_revenue,
            "total_tickets_sold": total_tickets_sold,
            "total_tickets_created": total_tickets_created
        }
        print(dashboard_data)
        return Response(dashboard_data, status=status.HTTP_200_OK)
    
    
class TicketStatisticsView(APIView):

    def get(self, request):
        # Get distinct ticket IDs from TicketCheckInLogger
        distinct_tickets = TicketCheckInLogger.objects.values('ticket').distinct()

        # Extract distinct ticket IDs
        ticket_ids = [ticket['ticket'] for ticket in distinct_tickets]

        # Get ticket types for the distinct ticket IDs
        tickets = Ticket.objects.filter(id__in=ticket_ids)
        ticket_type_counts = tickets.values('ticket_type').annotate(count=Count('id'))

        # Create a dictionary to hold ticket_type and their counts
        ticket_type_stats = {}
        total_count = 0
        for ticket_type in ticket_type_counts:
            ticket_type_id = ticket_type['ticket_type']
            count = ticket_type['count']
            ticket_type_name = TicketType.objects.get(id=ticket_type_id).title
            ticket_type_stats[ticket_type_name] = count
            total_count += count

        # Prepare data for the response
        data = {
            'ticket_type_counts': ticket_type_stats,
            'total_count': total_count
        }

        return Response(data)

    
    
    
class TicketCountView(APIView):

    def get(self, request, *args, **kwargs):
        ticket_counts = (
            Ticket.objects
            .values(
                event_title=F('event__title'),  # Include event title
                ticket_type_title=F('ticket_type__title')
            )
            .annotate(count=Count('ticket_type'))
        )
        serializer = TicketCountSerializer(ticket_counts, many=True)
        return Response(serializer.data)

class EventTicketsView(APIView):

    def get(self, request, event_id, *args, **kwargs):
        try:
            # Ensure the event exists
            event = Event.objects.get(id=event_id)

            # Get all tickets related to this event
            tickets = Ticket.objects.filter(event=event)

            # Serialize the tickets
            serializer = TicketSerializer(tickets, many=True)

            # Return the serialized data
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Event.DoesNotExist:
            return Response({"error": "Event not found"}, status=status.HTTP_404_NOT_FOUND)
        
def export_mpesa_payments_to_excel(request):
    # Query the MpesaPayment data
    payments = MpesaPayment.objects.all()

    # Convert queryset to a DataFrame
    df = pd.DataFrame(list(payments.values(
        'merchant_request_id',
        'checkout_request_id',
        'result_code',
        'result_desc',
        'amount',
        'mpesa_receipt_number',
        'balance',
        'transaction_date',
        'phone_number',
        'created_at',
        'invoice_number',
    )))

    # Convert the 'amount' column to float
    if 'amount' in df.columns:
        df['amount'] = df['amount'].astype(float)

    # Convert timezone-aware datetimes to timezone-naive
    if 'created_at' in df.columns:
        df['created_at'] = df['created_at'].apply(lambda x: x.astimezone(None) if pd.notna(x) and x.tzinfo is not None else x)

    # Create an HttpResponse object to serve as the file
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=mpesa_payments.xlsx'

    # Use the pandas Excel writer to save the DataFrame to the response
    with pd.ExcelWriter(response, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Payments')

    return response