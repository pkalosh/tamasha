from django import views
from django.urls import path, include

# from backend.api.models import Reset
from . import views
from .views import *


urlpatterns = [
    #Accounts/Profile endpoints
    path('register', RegisterApiView.as_view()),
    path('login',LoginApiView.as_view(),),
    path('user',UserApiView.as_view(),),
    path('refresh',RefreshApiView.as_view(),),
    path('logout',LogoutApiView.as_view(), ),
    path('forgot',ForgotPasswordApiView.as_view(),),
    path('reset',ResetPasswordApiView.as_view(),),
    

    #Event Endpoints
    path('tickets-by-org/<int:organization_id>', TicketsByOrganizationView.as_view(), name='tickets-by-org'),
    path('create-event', CreateEventAPIView.as_view(), name='create-event'),
    path('list-events',ListEventAPIView.as_view(), name='list-events'),
    path('ticket-type', TicketTypeAPIView.as_view(), name='ticket-type'),
    path('events/<int:pk>/update-event', EventPatchView.as_view(), name='update-event'),
    path('org/<int:pk>/org-event',OrgEventListAPIView.as_view(),name='org-event'),
    path('events/<int:event_id>/event-ticket-type',TicketTypeListAPIView.as_view(), name='event-ticket-type'),
    path('create-invoice', InvoiceCreateView.as_view(), name='create-invoice'),
    path('ticket',TicketListView.as_view(),name='ticket'),
    path('update-ticket-type/<int:pk>',TicketTypeUpdateAPIView.as_view(), name='update-ticket-type'),
    path('delete-ticket-type/<int:pk>', TicketTypeDeleteAPIView.as_view(), name='delete-ticket-type'),
    path('complementary', SendComplementaryTickets.as_view(), name='send_invoice_tickets_email'),
    path('ticket-check-in', TicketCheckInLoggerCreateView.as_view(), name='ticket-check-in'),
    path('tags', TagAPIView.as_view(), name='tags'),
    path('mpesa',views.lipa_na_mpesa_online, name="mpesa"),
    path('mpesa_callback',views.mpesa_callback,name="mpesa_callback"),
    path('initiate-payment', InitiatePayment.as_view(), name='initiate-payment'),
    path('mpesa_stk_push', MpesaCallBackUrlAPIView.as_view(), name='mpesa_stk_push_callback_url'),
    # path('pdf',views.generate_invoice_pdf,name='pdf'),

    path('tickets/count', TicketCountView.as_view(), name='ticket-count'),
    path('query-status',views.query_transaction,name='query-status'),
    path('events/tickets/stats', TicketCountView.as_view(), name='ticket-stats'),
    path('organization-analysis', ClientTotalAnalysis.as_view(), name='client-analysis'),

    #Client Dashboard
    path('events/org-events/<int:organization_id>', EventListByOrganizationView.as_view(), name='org-events'),
    path('events/tickets/stats', TicketCountView.as_view(), name='ticket-stats'),
    path('organization-analysis', ClientTotalAnalysis.as_view(), name='client-analysis'),
    path('organizations/<int:organization_id>/ticket-types', TicketTypeListView.as_view(), name='ticket-types-list'),
    path('kyc',EventOrganizationKYCApiView.as_view(),),
    path('kyc/<int:profile_id>',EventOrganizationKYCApiView.as_view(),),


    #Blog Endpoints
    path('blog', BlogAPIView.as_view(), name='blog'),
    path('blog/edit/<int:blog_id>', BlogAPIView.as_view(), name='edit-blog'),
    path('blog/delete/<int:blog_id>', BlogAPIView.as_view(), name='delete-blog'),

    #Ad Endpoints
    path('ads', AdsAPIView.as_view(), name='ads'),
    path('ads/edit/<int:ad_id>', AdsAPIView.as_view(), name='edit-ad'),
    path('ads/delete/<int:ad_id>', AdsAPIView.as_view(), name='delete-ad'),
    path('invoice-update/<int:pk>', InvoiceUpdateView.as_view(), name='invoice-update'),
    path('invoices/<int:pk>', InvoiceDetailView.as_view(), name='invoice-detail'),
    path('ticket-statistics', TicketStatisticsView.as_view(), name='ticket-statistics'),
    path('ticket-type-count', TicketCountView.as_view(), name='ticket-type-count'),
    
    path('events/<int:event_id>/tickets/', EventTicketsView.as_view(), name='event-tickets'),
    path('export-mpesa-payments/', export_mpesa_payments_to_excel, name='export_mpesa_payments'),

]
