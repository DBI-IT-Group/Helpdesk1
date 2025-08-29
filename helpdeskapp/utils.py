from django.db.models import Count
from .models import CustomUser
import random
from django.core.mail import send_mail
from django.conf import settings

def get_least_busy_l1_technician():
    """
    Finds the L1 Technician with the least number of assigned tickets.
    """
    l1_technicians = CustomUser.objects.filter(role="L1_Technician") \
        .annotate(assigned_tickets_count=Count('directly_assigned_tickets')) \
        .order_by('assigned_tickets_count')

    if not l1_technicians.exists():
        return None

    least_tickets = l1_technicians.first().assigned_tickets_count
    least_busy_techs = [tech for tech in l1_technicians if tech.assigned_tickets_count == least_tickets]

    return random.choice(least_busy_techs) if least_busy_techs else None


def get_least_busy_l2_technician():
    """
    Finds the L2 Technician with the least number of assigned completed tickets.
    """
    l2_technicians = CustomUser.objects.filter(role="L2_Technician") \
        .annotate(assigned_tickets_count=Count('directly_assigned_tickets')) \
        .order_by('assigned_tickets_count')

    if not l2_technicians.exists():
        return None

    least_tickets = l2_technicians.first().assigned_tickets_count
    least_busy_techs = [tech for tech in l2_technicians if tech.assigned_tickets_count == least_tickets]

    return random.choice(least_busy_techs) if least_busy_techs else None

def send_notification_email(subject, message, recipient_email):
    """
    Sends a notification email using Django's send_mail utility.
    Raises an exception if the email could not be sent.

    Args:
        subject (str): Subject line of the email.
        message (str): Plain text message body.
        recipient_email (str): Recipient's email address.
    """
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [recipient_email],
        fail_silently=False,  # Let exceptions bubble up for visibility
    )

