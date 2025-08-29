import ssl
from django.core.mail import get_connection, EmailMessage

# SSL port 465, use_ssl=True
ssl_context = ssl._create_unverified_context()

connection = get_connection(
    host='smtp.gmail.com',
    port=465,
    username='luthongwala100@gmail.com',
    password='fmbfctzqisfflnrk',  # Gmail app password
    use_ssl=True,
    fail_silently=False,
    ssl_context=ssl_context
)

email = EmailMessage(
    subject='Test subject',
    body='Test message',
    from_email='luthongwala100@gmail.com',
    to=['lutho.ngwala@dbi-itgroup.co.za'],
    connection=connection
)

email.send()
print("Email sent!")
