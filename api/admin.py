from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(User)
admin.site.register(UserToken)
admin.site.register(Role)
admin.site.register(Staff)
admin.site.register(Reset)
admin.site.register(Transaction)
admin.site.register(Subscription)
admin.site.register(Profile)
admin.site.register(Tag)
admin.site.register(Event)
admin.site.register(TicketType)
admin.site.register(Ticket)
admin.site.register(CustomerEmail)
admin.site.register(Ad)
admin.site.register(Blog)
admin.site.register(Gallery)
admin.site.register(Invoice)
admin.site.register(MpesaStkPushRequestResponse)
admin.site.register(MpesaCallback)
admin.site.register(MpesaPayment)
admin.site.register(ComplementaryTicketDispatch)
admin.site.register(EventsToScan)


admin.site.register(Discount)
admin.site.register(TicketCheckInLogger)


