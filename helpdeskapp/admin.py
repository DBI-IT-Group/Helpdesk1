from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.core.mail import send_mail
from .models import CustomUser, Ticket

class TicketAdmin(admin.ModelAdmin):
    list_display = ('ticket_number', 'ticket_title', 'department', 'priority_level', 'status', 'date_created_on', 'user')
    list_filter = ('department', 'priority_level', 'status', 'date_created_on')
    search_fields = ('ticket_number', 'ticket_title', 'problem_description', 'user__email')
    ordering = ('-date_created_on',)

    fieldsets = (
        (None, {'fields': ('ticket_number', 'ticket_title', 'user')}),
        ('Details', {'fields': ('department', 'contact_info', 'problem_description', 'priority_level', 'preferred_contact_method')}),
        ('Attachments', {'fields': ('attachment',)}),
        ('Status & Dates', {'fields': ('status', 'date_created_on')}),
    )

    readonly_fields = ('ticket_number', 'date_created_on')

admin.site.register(Ticket, TicketAdmin)


class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('id', 'full_name', 'email', 'role', 'is_active', 'is_staff')
    list_filter = ('role', 'is_active', 'is_staff')
    search_fields = ('full_name', 'email')
    ordering = ('id',)
    
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('full_name',)}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'full_name', 'role', 'password1', 'password2'),
        }),
    )

    def save_model(self, request, obj, form, change):
        # Check if the user is being created, not updated
        is_new = obj.pk is None
        
        # Get the raw password before the parent save_model hashes and saves it
        raw_password = form.cleaned_data.get('password1')
        
        # Call the parent save_model to handle the hashing of the password and saving the user object
        super().save_model(request, obj, form, change)

        # Only send the email if a new user was created and a password was provided
        if is_new and raw_password:
            # Send email with credentials
            send_mail(
                subject='Your Account Credentials',
                message=f'Hello {obj.full_name},\n\nYour account has been created.\nUsername: {obj.username}\nPassword: {raw_password}\n\nPlease change your password after first login.',
                from_email='Services@dbi-itgroup.co.za',
                recipient_list=[obj.email],
                fail_silently=False,
            )

admin.site.register(CustomUser, CustomUserAdmin)




