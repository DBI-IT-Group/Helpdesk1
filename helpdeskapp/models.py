import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, Permission
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count
from django.utils import timezone


class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('End-User', 'End-User'),
        ('Technician', 'Technician'),
        ('Administrator', 'Administrator'),
        ('L1_Technician', 'L1_Technician'),
        ('L2_Technician', 'L2_Technician'),
        ('CAB', 'CAB'),
    ]
    
    full_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'full_name', 'role']
    
    def __str__(self):
        return f"{self.full_name} ({self.role})"


class Ticket(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('In Progress', 'In Progress'),
        ('Escalated', 'Escalated'),
        ('Completed', 'Completed'),  
    ]

    PRIORITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    ]

    CONTACT_METHOD_CHOICES = [
        ('Email', 'Email'),
        ('Phone', 'Phone'),
    ]

    DEPARTMENT_CHOICES = [
        ('IT', 'IT'),
        ('HR', 'HR'),
        ('Finance', 'Finance'),
    ]

    id = models.AutoField(primary_key=True)
    ticket_number = models.CharField(max_length=20, unique=True, blank=True)
    ticket_title = models.CharField(max_length=255)
    department = models.CharField(max_length=100, choices=DEPARTMENT_CHOICES)
    contact_info = models.CharField(max_length=255)
    problem_description = models.TextField()
    priority_level = models.CharField(max_length=50, choices=PRIORITY_CHOICES)
    preferred_contact_method = models.CharField(max_length=50, choices=CONTACT_METHOD_CHOICES)
    attachment = models.FileField(upload_to='attachments/', blank=True, null=True)
    date_created_on = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    accepted_by_l2 = models.BooleanField(default=False)
    assigned_technician = models.ForeignKey( settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_tickets')

    assigned_technician = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name="directly_assigned_tickets"
    )

    # New fields to track time
    assigned_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    escalated_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)


    class Meta:
        permissions = [
            ("view_pending_tickets", "Can view pending tickets"),
            ("view_escalated_tickets", "Can view escalated tickets"),
        ]

    def assign_technician(self):
        """Automatically assign the ticket to the least busy L1 or L2 Technician."""
        if not self.assigned_technician:
            from helpdeskapp.models import CustomUser  # Avoid circular import

            if self.status == "Escalated":
                least_busy_technician = CustomUser.objects.filter(role="L2_Technician") \
                    .annotate(ticket_count=Count('directly_assigned_tickets')) \
                    .order_by('ticket_count') \
                    .first()
            else:
                least_busy_technician = CustomUser.objects.filter(role="L1_Technician") \
                    .annotate(ticket_count=Count('directly_assigned_tickets')) \
                    .order_by('ticket_count') \
                    .first()
            
            if least_busy_technician:
                self.assigned_technician = least_busy_technician
                self.assigned_at = timezone.now()  # Set assignment time

    def save(self, *args, **kwargs):
        if not self.ticket_number:
            self.ticket_number = str(uuid.uuid4())[:8].upper()

        # Set completion timestamp if just completed
        if self.status == "Completed" and self.completed_at is None:
            self.completed_at = timezone.now()

        self.assign_technician()  # Assign technician if not assigned
        super().save(*args, **kwargs)

    def time_taken(self):
        if self.assigned_at and self.completed_at:
            return self.completed_at - self.assigned_at
        return None

    def __str__(self):
        assigned_to = self.assigned_technician.full_name if self.assigned_technician else "Unassigned"
        return f"{self.ticket_number} - {self.ticket_title} (Assigned to: {assigned_to}) {self.id}"


class CABRequest(models.Model):
    CHANGE_TYPE_CHOICES = [
        ("Normal Change", "Normal Change"),
        ("Standard Change", "Standard Change"),
        ("Emergency Change", "Emergency Change"),
    ]
    
    STATUS_CHOICES = [
        ('in_progress', 'In Progress'),
        ('approved', 'Approved'),
        ('rejected','Rejected'),
    ]
    
    REJECTION_REASONS = [
    ("insufficient_info", "Insufficient Information"),
    ("high_risk", "High Risk"),
    ("no_business_justification", "No Business Justification"),
    ("incomplete_rollback_plan", "Incomplete Rollback Plan"),
    ("resource_constraints", "Resource Constraints"),
]

    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL,  
        on_delete=models.CASCADE,
        related_name="cab_requests"
    )
    change_type = models.CharField(max_length=20, choices=CHANGE_TYPE_CHOICES)
    title = models.CharField(max_length=255)
    description = models.TextField()
    risk_assessment = models.TextField()
    implementation_plan = models.TextField()
    rollback_plan = models.TextField()  

    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='in_progress')
    rejection_reason = models.CharField(max_length=50,choices=REJECTION_REASONS,blank=True,null=True,help_text="Applicable only if status is 'rejected'"
    )
    attachment = models.FileField(upload_to='cab_attachments/', null=True, blank=True)

    def __str__(self):
        return f"{self.change_type} - {self.title} ({self.requester.full_name})"
    
class TicketAssignment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='assignments')
    technician = models.ForeignKey(
    CustomUser,
    on_delete=models.CASCADE,
    limit_choices_to={'groups__name': 'Technician'},
    related_name='assigned_ticket_entries'
)
    assigned_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='tickets_assigned_by')
    assigned_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('ticket', 'technician')  
        ordering = ['-assigned_at']

    def __str__(self):
        return f"Ticket #{self.ticket.id} assigned to {self.technician.get_full_name()}"

class EscalationNote(models.Model):
    ticket = models.ForeignKey('Ticket', on_delete=models.CASCADE, related_name='escalation_notes')
    note = models.TextField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Note for Ticket {self.ticket.ticket_number} by {self.created_by}"    