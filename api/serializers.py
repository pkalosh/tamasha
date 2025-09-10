from dataclasses import fields
from pyexpat import model
from signal import valid_signals
from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from django.shortcuts import render, get_object_or_404, get_list_or_404


from .models import *


class UserSerializer(ModelSerializer):
    profile_id = serializers.PrimaryKeyRelatedField(source='profile', read_only=True)
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "password", "id","is_event_admin","profile_id"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class KYCSerializer(ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            "organization_name",
            "address",
            "city",
            "county",
            "constituency",
            "ward",
            "postcode",
            "country",
            "phone",
            "logo",
            "status",
            "kra_certificate",
            "incorporation_certficate",
            "cr_12",
        ]


class ProfileSerializer(ModelSerializer):
    class Meta:
        model = Profile
        fields = "__all__"


class TagSerializer(ModelSerializer):
    class Meta:
        model = Tag
        fields = ["id", "tag"]


class EventSerializer(ModelSerializer):
    tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True)

    class Meta:
        model = Event
        fields = [
            "id",
            "title",
            "organization",
            "description",
            "start_date",
            "end_date",
            "location",
            "latitude",
            "longitude",
            "tags",
            "banner",
            "floor_plan",
            "instagram_url",
            "x_url",
            "meta_url",
            "updated_at",
            "created_at",
            "is_active"
        ]

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        # Convert organization to dictionary
        representation["organization"] = {
            "organization_name": instance.organization.organization_name,
            "id": instance.organization.id,
            # Add more organization data if needed
        }
        # Serialize tags to a list of tag IDs
        representation["tags"] = [
            {"id": tag.id, "tag": tag.tag} for tag in instance.tags.all()
        ]        
        return representation


    def create(self, validated_data):
        tags_data = validated_data.pop("tags")  # Remove tags data from validated data
        event = Event.objects.create(**validated_data)  # Create the event object

        # Create tags and associate them with the event
        for tag_data in tags_data:
            print(tag_data)
            tag = Tag.objects.get(id = tag_data.id)
            event.tags.add(tag)

        return event

    def update(self, instance, validated_data):
        tags_data = validated_data.pop("tags", None)
        tags = instance.tags.all()
        instance = super().update(instance, validated_data)

        if tags_data is not None:
            instance.tags.clear()
            for tag_data in tags_data:
                tag, _ = Tag.objects.get_or_create(**tag_data)
                instance.tags.add(tag)

        return instance


class TicketTypeSerializer(ModelSerializer):
    class Meta:
        model = TicketType
        fields = "__all__"


from rest_framework import serializers
from .models import Ticket

class TicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket
        fields = [
            "event",
            "ticket_type",
            "email",
            "first_name",
            "last_name",
            "phone",
            "amount_paid",
            "RF_id",
            "qr_code"
        ]

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        request = self.context.get('request', None)  # Use default None if 'request' is not in context

        # Convert ticket_type to dictionary
        ticket_type_data = instance.ticket_type
        if ticket_type_data:
            representation["ticket_type"] = {
                "title": ticket_type_data.title,
                "id": ticket_type_data.id,
            }
        else:
            representation["ticket_type"] = None

        # Convert event to dictionary
        event_data = instance.event
        if event_data:
            organization_data = event_data.organization
            if request:
                banner_url = f"{request.scheme}://{request.get_host()}{event_data.banner.url}" if event_data.banner else None
            else:
                banner_url = event_data.banner.url if event_data.banner else None

            representation["event"] = {
                "title": event_data.title,
                "id": event_data.id,
                "banner": banner_url,
                "organization": {
                    "organization_name": organization_data.organization_name if organization_data else None,
                    "id": organization_data.id if organization_data else None,
                },
                # Add more event data if needed
            }
        else:
            representation["event"] = None

        return representation


class BlogSerializer(ModelSerializer):
    class Meta:
        model = Blog
        fields = "__all__"


class AdSerializer(ModelSerializer):
    class Meta:
        model = Ad
        fields = "__all__"

        
        
class TicketCreateSerializer(ModelSerializer):
    class Meta:
        model = Ticket
        fields = [
            "event",
            "ticket_type",
            "email",
            "first_name",
            "last_name",
            "phone",
            "RF_id",
            "invoice_number",
            "mpesa_receipt",
            "is_complementary",
            "invoice_id",
        ]

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['amount', 'method', 'phone']
class BulkTicketCreateSerializer(serializers.Serializer):
    attendeeInfo = TicketCreateSerializer(many=True)
    # payment = PaymentSerializer()
    def validate(self, data):
        email_to = self.context.get('email_to')
        # invoice_number=self.context.get('invoice_number')
        if email_to:
            pass
            
            
        return data

    def create(self, validated_data):
        invoice_number = self.context.get('invoice_number')
        mpesa_receipt = self.context.get('mpesa_receipt')
        
        tickets_data = validated_data.pop('attendeeInfo')
        
        tickets = []
        print(tickets_data)
        for ticket_data in tickets_data:
            ticket_data['invoice_number'] = invoice_number
            ticket_data['mpesa_receipt']=mpesa_receipt
            ticket = Ticket.objects.create(**ticket_data)
            
            tickets.append(ticket)
            print(ticket)
        
        return {'tickets': tickets}



    def to_representation(self, instance):
        representation = super().to_representation(instance)
        
        # Query events related to the rahafest instance
        events = Event.objects.filter(organization=instance.rahafest.id)
        
        # Serialize the related events
        event_serializer = EventSerializer(events, many=True)
        
        # Assuming 'organization_name' and 'id' are fields in the related Profile model
        representation["Profile"] = {
            "organization_name": instance.rahafest.organization_name,
            "organization_id": instance.rahafest.id,
            "events": event_serializer.data  # Serialize the events
        }
        
        return representation

    
class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ['id', 'invoice_number', 'data']
        read_only_fields = ['id', 'invoice_number']
        
class MpesaStkPushRequestResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = MpesaStkPushRequestResponse
        fields = '__all__'

        
        
class TicketCountSerializer(serializers.Serializer):
    event = serializers.SerializerMethodField()
    ticket_type = serializers.SerializerMethodField()
    count = serializers.IntegerField()

    def get_event(self, obj):
        event = Event.objects.get(id=obj['event_id'])
        return EventSerializer(event).data

    def get_ticket_type(self, obj):
        ticket_type = TicketType.objects.get(id=obj['ticket_type_id'])
        return TicketTypeSerializer(ticket_type).data
    
    
class InvoiceNumberSerializer(serializers.Serializer):
    invoice_number = serializers.CharField(max_length=20)
    
    
class TicketCheckInLoggerSerializer(serializers.ModelSerializer):
    scanned_by = UserSerializer(read_only=True)
    class Meta:
        model = TicketCheckInLogger
        fields = '__all__'
    
class InvoiceUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ['data','is_complementary']
        
    

class EventStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = ["id", "title","is_active"]
        
        
class TicketCountSerializer(serializers.Serializer):
    ticket_type_title = serializers.CharField()
    count = serializers.IntegerField()
    event_title=serializers.CharField()

from decimal import Decimal
class TicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket
        fields = [
            "event",
            "ticket_type",
            "email",
            "first_name",
            "last_name",
            "phone",
            "amount_paid",
            "RF_id",
            "qr_code"
        ]

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        request = self.context.get('request', None)  # Use default None if 'request' is not in context

        # Convert ticket_type to dictionary
        ticket_type_data = instance.ticket_type
        if ticket_type_data:
            representation["ticket_type"] = {
                "title": ticket_type_data.title,
                "id": ticket_type_data.id,
            }
        else:
            representation["ticket_type"] = None

        # Convert event to dictionary
        event_data = instance.event
        if event_data:
            organization_data = event_data.organization
            if request:
                banner_url = f"{request.scheme}://{request.get_host()}{event_data.banner.url}" if event_data.banner else None
            else:
                banner_url = event_data.banner.url if event_data.banner else None

            representation["event"] = {
                "title": event_data.title,
                "id": event_data.id,
                "banner": banner_url,
                "organization": {
                    "organization_name": organization_data.organization_name if organization_data else None,
                    "id": organization_data.id if organization_data else None,
                },
                # Add more event data if needed
            }
        else:
            representation["event"] = None

        return representation

