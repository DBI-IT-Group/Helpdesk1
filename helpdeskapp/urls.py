from django.urls import path
from . import views 
from django.conf import settings
from django.conf.urls.static import static 

urlpatterns = [
    # Authentication & User Management
    path('', views.user_login, name='home'),  
    path('register/', views.register, name='register'),  
    path('login/', views.user_login, name='login'),  
    path('logout/', views.user_logout, name='logout'),  

    # User Dashboards
    path('dashboard/', views.dashboard, name='dashboard'),  
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),  
    path('technician-dashboard/', views.technician_dashboard, name='technician_dashboard'),  
    path('l2-technician-dashboard/', views.l2_technician_dashboard, name='l2_technician_dashboard'),  
    path('l1/tickets/', views.l1_technicians_tickets, name='l1_technicians_tickets'),
    path('notes/', views.notes, name='notes'),
    path("users/", views.user_management, name="user_management"),





    # Ticket Management
    path('add_ticket/', views.add_ticket, name='add_ticket'),  
    path('add-ticket/', views.add_ticket_view, name='add_ticket'),

    path('my_tickets/', views.my_tickets, name='my_tickets'),  
    path('tickets/', views.view_tickets, name='view_tickets'),  

    path('escalated-tickets/', views.escalated_tickets, name='escalated_tickets'),
    path('completed-tickets/', views.completed_tickets, name='completed_tickets'),

    #CAB
    path('reports/', views.reports_view, name='reports'),
    path("roles_management/", views.roles_management_view, name="roles_management"),
    path('roles/list/', views.user_roles_list_view, name='user_role_list'),
    path("cab-requests/", views.cab_requests_view, name="cab_requests"),
    path('user/settings/', views.settings_page, name='settings-page'),
    path('manage_tickets/', views.manage_tickets, name='manage_tickets'),
    path('cab/requests/', views.cab_requests_list, name='cab_requests_list'),
    path("cab/requests/", views.cab_requests_list, name="cab_requests_list"),
    path("cab/requests/<int:pk>/", views.cab_request_detail, name="cab_request_detail"),
    path("cab/", views.cab_dashboard, name="cab"),
    path("cab_stats/", views.cab_stats_view, name="cab_stats"),
    path("cab/requests/table/", views.cab_requests_table_view, name="cab_requests_table"),
    
 



    # Ticket Actions
    path('ticket/<int:id>/accept/', views.accept_ticket, name='accept_ticket'),
    path('accept-ticket/<int:id>/', views.accept_ticket_l2_escalated, name='accept_ticket_l2_escalated'),
    path('accept-completed/<int:id>/', views.accept_ticket_l2_completed, name='accept_ticket_l2_completed'),

    #path('ticket/<int:id>/request-info/', views.request_info, name='request_info'),
    path('ticket/<int:id>/escalate/', views.escalate_ticket, name='escalate_ticket'),
    path('ticket/<int:id>/complete/', views.complete_ticket, name='complete_ticket'),
    path('close-ticket-escalated/<int:id>/', views.close_ticket_ecalated, name='close_ticket_escalated'),
    path('close-ticket-resolved/<int:id>/', views.close_ticket_completed, name='close_ticket_completed'),
    path('user/settings/', views.settings_page, name='settings-page'),

    #Bot
    path('chat-bot/', views.chat_with_bot, name='chat_bot'),
    #L2 Technicians CAB Requests
    path('technician/requests/', views.technician_requests, name='technician_requests'),
    path('technician/requestslist/', views.technician_requestslist, name='technician_requestslist'),

    # Data
    path("metrics/", views.metrics_view, name="metrics"),



]
# This serves media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

