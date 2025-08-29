from django.contrib.auth.models import Permission
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser

@receiver(post_save, sender=CustomUser)
def assign_permissions(sender, instance, created, **kwargs):
    if created:
        if instance.role == 'L1_Technician':
            permission = Permission.objects.get(codename='view_pending_tickets')
            instance.user_permissions.add(permission)

        elif instance.role == 'L2_Technician':
            permissions = Permission.objects.filter(codename__in=['view_escalated_tickets', 'view_completed_tickets'])
            instance.user_permissions.add(*permissions)

        elif instance.role == 'Administrator':
            # Assign specific permissions required for administrators
            permissions = Permission.objects.filter(codename__in=['view_pending_tickets', 'view_escalated_tickets', 'view_completed_tickets'])
            instance.user_permissions.add(*permissions)
