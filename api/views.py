import json
import logging
# Create your views here.
from asyncio import exceptions
from cgitb import reset
import email
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
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAdminUser
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
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
from rest_framework.generics import ListAPIView, RetrieveUpdateAPIView
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
from django.views.decorators.http import require_http_methods
from rest_framework.decorators import throttle_classes
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from .mpesa import Mpesa
import re
from django.db.models import Count, Sum, F, Q
logger = logging.getLogger(__name__)

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


# class CreateEventAPIView(generics.CreateAPIView):
#     authentication_classes = [JWTAuthentication]
#     queryset = Event.objects.all()
#     serializer_class = EventSerializer


# class EventPatchView(APIView):
#     authentication_classes = [JWTAuthentication]
#     # permission_classes = [IsAuthenticated]

#     @throttle_classes([UserRateThrottle, AnonRateThrottle])
#     def patch(self, request, pk):
#         try:
#             event = Event.objects.get(pk=pk)
#         except Event.DoesNotExist:
#             return Response(
#                 {"error": "Event not found"}, status=status.HTTP_404_NOT_FOUND
#             )

#         # Remove 'id' from request data to prevent updating it
#         if "id" in request.data:
#             del request.data["id"]
#         if "organization" in request.data:
#             del request.data["organization"]
#         serializer = EventSerializer(event, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class ListEventAPIView(generics.ListAPIView):
#     queryset = Event.objects.all()
#     serializer_class = EventSerializer


class EventListCreateAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        events = Event.objects.all().prefetch_related("tags", "schedules")
        serializer = EventSerializer(events, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = EventSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EventRetrieveAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request, pk):
        event = get_object_or_404(Event.objects.prefetch_related("schedules", "tags"), pk=pk)
        serializer = EventSerializer(event)
        return Response(serializer.data)


class EventUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def patch(self, request, pk):
        event = get_object_or_404(Event, pk=pk)
        serializer = EventSerializer(event, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EventDeleteAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def delete(self, request, pk):
        event = get_object_or_404(Event, pk=pk)
        event.delete()
        return Response({"detail": "Event deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


class PublicEventListView(APIView):

    def get(self, request):
        events = Event.objects.filter(is_active=True)
        serializer = EventSerializer(events, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# ------------------ SCHEDULE CRUD ------------------

class ScheduleListCreateAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request, event_id):
        event = get_object_or_404(Event, pk=event_id)
        schedules = event.schedules.all().order_by("start_time")
        serializer = ScheduleSerializer(schedules, many=True)
        return Response(serializer.data)

    def post(self, request, event_id):
        event = get_object_or_404(Event, pk=event_id)
        data = request.data.copy()
        data["event"] = event.id
        serializer = ScheduleSerializer(data=data)
        if serializer.is_valid():
            serializer.save(event=event)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScheduleRetrieveAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request, pk):
        schedule = get_object_or_404(Schedule, pk=pk)
        serializer = ScheduleSerializer(schedule)
        return Response(serializer.data)


class ScheduleUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def patch(self, request, pk):
        schedule = get_object_or_404(Schedule, pk=pk)
        serializer = ScheduleSerializer(schedule, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScheduleDeleteAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def delete(self, request, pk):
        schedule = get_object_or_404(Schedule, pk=pk)
        schedule.delete()
        return Response({"detail": "Schedule deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


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


class TagListCreateAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user = request.user
        if hasattr(user, "profile"):
            tags = Tag.objects.filter(profile=user.profile)
        else:
            return Response({"detail": "User has no associated profile."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = TagSerializer(tags, many=True)
        return Response(serializer.data)

    def post(self, request):
        user = request.user
        if not hasattr(user, "profile"):
            return Response({"detail": "User has no associated profile."}, status=status.HTTP_400_BAD_REQUEST)

        data = request.data.copy()
        data["profile"] = user.profile.id  # auto-assign organization

        serializer = TagSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#  Retrieve
class TagRetrieveAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request, pk):
        user = request.user
        tag = get_object_or_404(Tag, pk=pk, profile=user.profile)
        serializer = TagSerializer(tag)
        return Response(serializer.data)


#  Update
class TagUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def put(self, request, pk):
        user = request.user
        tag = get_object_or_404(Tag, pk=pk, profile=user.profile)
        serializer = TagSerializer(tag, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        user = request.user
        tag = get_object_or_404(Tag, pk=pk, profile=user.profile)
        serializer = TagSerializer(tag, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#  Delete
class TagDeleteAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def delete(self, request, pk):
        user = request.user
        tag = get_object_or_404(Tag, pk=pk, profile=user.profile)
        tag.delete()
        return Response({"detail": "Tag deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


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
    authentication_classes = [JWTAuthentication]

    queryset = TicketType.objects.all()

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"detail": "Ticket type deleted successfully."}, status=status.HTTP_200_OK
        )


class TicketListView(generics.ListCreateAPIView):
    # authentication_classes = [JWTAuthentication]
    queryset = Ticket.objects.all()
    serializer_class = BulkTicketCreateSerializer

    @throttle_classes([UserRateThrottle, AnonRateThrottle])
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        print("Creating tickets with data:", serializer.validated_data)
        print(f"valid serializer: {serializer.is_valid()}")
        data = serializer.save()
        tickets_data = [
            TicketCreateSerializer(ticket).data for ticket in data["tickets"]
        ]
        # payment_data = PaymentSerializer(data['payment']).data
        print(f"Tickets data: {tickets_data}")
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

class InitiatePayment(APIView):
    throttle_classes = [UserRateThrottle, AnonRateThrottle]

    def post(self, request, *args, **kwargs):
        try:
            data = request.data
            invoice_number = data.get("invoice_number")
            phone = data.get("phone")
            fcm_token = data.get("fcm_token")
            primary_email = data.get("primary_email")

            # Validate required fields early
            if not invoice_number:
                return Response(
                    {
                        "success": False,
                        "message": "Invoice number is required",
                        "data": None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate and normalize phone number (Kenyan M-Pesa format)
            if not phone:
                return Response(
                    {
                        "success": False,
                        "message": "Phone number is required",
                        "data": None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            def normalize_kenyan_phone(phone_str):
                phone_str = re.sub(r'[^\d]', '', phone_str)  # Strip non-digits
                if phone_str.startswith('0'):
                    phone_str = '254' + phone_str[1:]  # 07xx -> 2547xx
                elif phone_str.startswith('7') and len(phone_str) == 9:
                    phone_str = '254' + phone_str  # 7xx -> 2547xx
                elif phone_str.startswith('254') and len(phone_str) == 12:
                    pass  # Already correct
                elif phone_str.startswith('+254') and len(phone_str) == 13:
                    phone_str = phone_str[1:]  # +254 -> 254
                else:
                    raise ValueError("Invalid phone number format. Use 2547xxxxxxxx, 07xxxxxxxxx, or +2547xxxxxxxx.")
                return phone_str

            try:
                phone = normalize_kenyan_phone(phone)
            except ValueError as ve:
                return Response(
                    {
                        "success": False,
                        "message": str(ve),
                        "data": None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Retrieve the Invoice instance
            try:
                invoice = Invoice.objects.get(invoice_number=invoice_number)
            except Invoice.DoesNotExist:
                return Response(
                    {
                        "success": False,
                        "message": "Invoice not found",
                        "data": None
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            # Validate invoice amount
            if invoice.invoice_amount is None:
                return Response(
                    {
                        "success": False,
                        "message": "Invoice amount is not set or invalid",
                        "data": None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                total_amount = float(invoice.invoice_amount)
                if total_amount <= 0:
                    return Response(
                        {
                            "success": False,
                            "message": "Invoice amount must be greater than zero",
                            "data": None
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except (ValueError, TypeError) as e:
                return Response(
                    {
                        "success": False,
                        "message": "Invalid invoice amount format",
                        "details": str(e),
                        "data": None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            invoice_id = invoice.id

            # Instantiate Mpesa (this triggers token/password generation)
            mpesa = Mpesa()

            # Call with correct order: invoice_number, total_amount, phone, fcm_token, primary_email, invoice_id
            stk_response = mpesa.initiate_stk_push(
                invoice_number=invoice_number,  # str
                total_amount=total_amount,  # float/int
                phone=phone,  # normalized: "2547xxxxxxxx"
                fcm_token=fcm_token,
                primary_email=primary_email,
                invoice_id=invoice_id  # int (now last, as per signature)
            )

            if stk_response["success"]:
                response_data = {
                    "id": invoice_id,
                    "invoice_number": invoice_number,
                    "total_amount": total_amount,
                    "phone": phone,  # Normalized phone returned for confirmation
                    "fcm_token": fcm_token,
                    "payment_status": "Pending",
                    "primary_email": primary_email,
                    "merchant_request_id": stk_response["data"].get("MerchantRequestID"),
                    "checkout_request_id": stk_response["data"].get("CheckoutRequestID"),
                }
                return Response(
                    {
                        "success": True,
                        "message": "Payment initiation successful. Please check your phone for the M-Pesa prompt.",
                        "data": response_data
                    },
                    status=status.HTTP_200_OK
                )
            else:
                # M-Pesa-specific failures return 400 (client error) instead of 500 for better semantics
                return Response(
                    {
                        "success": False,
                        "message": "Payment initiation failed",
                        "details": stk_response.get("error"),
                        "data": None
                    },
                    status=status.HTTP_400_BAD_REQUEST  # Changed from 500 to 400
                )
        except Exception as e:
            print(f"Unexpected error in InitiatePayment: {e}")  # Server-side log
            return Response(
                {
                    "success": False,
                    "message": "An unexpected error occurred during payment initiation",
                    "details": str(e),
                    "data": None
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR  # Truly unexpected -> 500
            )

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



# Public API View: POST for Contact Form Submission
class ContactAPIView(APIView):
    
    def post(self, request):
        serializer = SupportTicketSerializer(data=request.data)
        if serializer.is_valid():
            ticket = serializer.save()
            return Response({
                'success': True,
                'message': 'Your enquiry has been submitted successfully. We will get back to you soon.',
                'data': SupportTicketSerializer(ticket).data
            }, status=status.HTTP_201_CREATED)
        return Response({
            'success': False,
            'message': 'Please correct the errors below.',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

# Admin API Views (Staff-only)
class TicketListAPIView(ListAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = SupportTicket.objects.all()
    serializer_class = SupportTicketSerializer

class TicketDetailAPIView(RetrieveUpdateAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = SupportTicket.objects.all()
    serializer_class = SupportTicketSerializer
    lookup_field = 'pk'
    
    def perform_update(self, serializer):
        # Allow status updates (e.g., to 'closed')
        if 'status' in serializer.validated_data:
            serializer.validated_data['updated_at'] = timezone.now()
        serializer.save()


@api_view(['POST'])
@permission_classes([IsAdminUser])
@authentication_classes([SessionAuthentication, TokenAuthentication])
def mark_ticket_closed(request, pk):
    ticket = get_object_or_404(SupportTicket, pk=pk)
    ticket.status = 'closed'
    ticket.save()
    return Response({
        'success': True,
        'message': f'Ticket {ticket.subject} marked as closed.',
        'data': SupportTicketSerializer(ticket).data
    })


class VerifyTicketAPIView(APIView):    
    def post(self, request):
        serializer = VerifyTicketSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid ticket code provided.",
                "errors": serializer.errors,
                "data": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        ticket_code = serializer.validated_data['ticket_code']
        ticket = get_object_or_404(Ticket, ticket_code=ticket_code)
        
        # Check 2: Confirm invoice is paid (via is_paid or linked Invoice)
        if not ticket.is_paid:
            if ticket.invoice_id and hasattr(ticket.invoice_id, 'is_paid') and ticket.invoice_id.is_paid:
                ticket.is_paid = True  # Sync if needed
                ticket.save(update_fields=['is_paid'])
            else:
                return Response({
                    "success": False,
                    "message": "Ticket is not paid. Please complete payment first.",
                    "data": None
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check 3: Confirm no check-in logs (scan_in_at not null)
        has_checkin = TicketCheckInLogger.objects.filter(
            ticket=ticket, 
            scan_in_at__isnull=False
        ).exists()
        
        if has_checkin:
            return Response({
                "success": False,
                "message": "This ticket has already been checked in.",
                "data": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # All checks passed
        response_data = {
            "ticket_code": ticket.ticket_code,
            "first_name": ticket.first_name,
            "last_name": ticket.last_name,
            "event": str(ticket.event),  # Assuming Event has __str__
            "ticket_type": str(ticket.ticket_type),  # Assuming TicketType has __str__
            "is_paid": ticket.is_paid,
            "created_at": ticket.created_at.isoformat() if ticket.created_at else None,
            "status": "Ticket is Valid - Ready for check-in",
        }
        
        return Response({
            "success": True,
            "message": "Ticket verified successfully. Ready for check-in.",
            "data": response_data
        }, status=status.HTTP_200_OK)