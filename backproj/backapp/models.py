from django.db import models
from django.contrib.auth.models import AbstractUser
from phonenumber_field.modelfields import PhoneNumberField
UTTARAKHAND_CITIES = [
    ("Dehradun", "Dehradun"),
    ("Haridwar", "Haridwar"),
    ("Rishikesh", "Rishikesh"),
    ("Nainital", "Nainital"),
    ("Almora", "Almora"),
    ("Mussoorie", "Mussoorie"),
    ("Ranikhet", "Ranikhet"),
    ("Kedarnath", "Kedarnath"),
    ("Badrinath", "Badrinath"),
    ("Gangotri", "Gangotri"),
    ("Yamunotri", "Yamunotri"),
    ("Pithoragarh", "Pithoragarh"),
    ("Champawat", "Champawat"),
    ("Tehri", "Tehri"),
    ("Joshimath", "Joshimath"),
    ("Kotdwar", "Kotdwar"),
    ("Haldwani", "Haldwani"),
    ("Roorkee", "Roorkee"),
]
class HimUser(AbstractUser):
    mobile_no = PhoneNumberField(blank=True, null=True, unique=True)
    location = models.CharField(
        max_length=255,
        choices=UTTARAKHAND_CITIES,
        blank=True,
        null=True
    )
    def __str__(self):
        return self.username
