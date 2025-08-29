from django import forms
from .models import Ticket, CustomUser,CABRequest

from django import forms
from .models import CustomUser

class CustomUserRegistrationForm(forms.ModelForm):
    
    full_name = forms.CharField(
        max_length=50, required=True, 
        widget=forms.TextInput(attrs={'placeholder': 'katlego James'})
    )
    email = forms.EmailField(
        required=True, 
        widget=forms.EmailInput(attrs={'placeholder': 'example@gmail.com'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(), 
        required=True
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(), 
        required=True
    )
    role = forms.CharField(
        initial='End-User', 
        widget=forms.HiddenInput(), 
        required=True
    )

    class Meta:
        model = CustomUser
        fields = ['full_name', 'email', 'password', 'role']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():  # Fixed incorrect field
            raise forms.ValidationError("Email Already Exists")
        return email 

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")
        
        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match!")

        return cleaned_data

    def save(self, commit=True):
     user = super().save(commit=False)
     user.username = self.cleaned_data["email"]  # Assign email as username
     user.role = "End-User"
     user.set_password(self.cleaned_data["password"])

     if commit:
        user.save()

     return user



class CustomLoginForm(forms.Form):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'placeholder': 'example@gmail.com'}))
    password = forms.CharField(widget=forms.PasswordInput(), required=True)

class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = [
            'ticket_title', 'department', 'contact_info', 
            'problem_description', 'priority_level', 
            'preferred_contact_method', 'attachment'
        ]
        widgets = {
            'ticket_title': forms.TextInput(attrs={
                'class': 'mt-1 block w-full border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500',
                'placeholder': 'Enter ticket title'
            }),
            'contact_info': forms.TextInput(attrs={
                'class': 'mt-1 block w-full border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500',
                'placeholder': 'Email or phone number'
            }),
            'problem_description': forms.Textarea(attrs={
                'class': 'mt-1 block w-full border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500',
                'rows': 4,
                'placeholder': 'Describe the issue...'
            }),
            'priority_level': forms.Select(attrs={
                'class': 'mt-1 block w-full border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500'
            }),
            'department': forms.Select(attrs={
                'class': 'mt-1 block w-full border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500'
            }),
            'preferred_contact_method': forms.Select(attrs={
                'class': 'mt-1 block w-full border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500'
            }),
            'attachment': forms.ClearableFileInput(attrs={
                'class': 'mt-1 block w-full text-gray-700'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['attachment'].required = False  
        

class CustomUserSettingsForm(forms.ModelForm):
    full_name = forms.CharField(
        max_length=50, required=True,
        widget=forms.TextInput(attrs={
            'placeholder': 'Full Name',
            'class': 'form-control'
        })
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }), 
        required=False
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }), 
        required=False
    )

    class Meta:
        model = CustomUser
        fields = ['full_name']

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and new_password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")
            

        return cleaned_data

    
class CABRequestForm(forms.ModelForm):
    class Meta:
        model = CABRequest
        fields = [
                  'change_type',
                  'title',
                  'description',
                  'risk_assessment',
                  'implementation_plan',
                  'rollback_plan',
                   'attachment',
                  ]

        widgets = {
            'field_name': forms.TextInput(attrs={'class': 'border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500'}),
            'change_type': forms.Select(attrs={'class': 'form-control'}),
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'risk_assessment': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'implementation_plan': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'rollback_plan': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'status': forms.Select(attrs={'class': 'form-control'}),
            'rejection_reason': forms.Select(attrs={'class': 'form-control'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get("status")
        rejection_reason = cleaned_data.get("rejection_reason")

        if status == "rejected" and not rejection_reason:
            self.add_error('rejection_reason', "This field is required when status is 'rejected'.")
        return cleaned_data