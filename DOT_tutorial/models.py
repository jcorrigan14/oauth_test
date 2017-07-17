from django.db import models
from django.contrib.auth.models import Group

from oauth2_provider.models import AbstractApplication, Application

class CustomApplication(AbstractApplication):
    """
    This model extends the base AbstractApplication model provided by OAuth2.0
    """
    # add custom fields here
    persistent = models.BooleanField(verbose_name='Mobile Application')


    # Some permissions are predefined and may be enough. If you want custom permissions, add them here
    class Meta:
        permissions = (
            ('change_Application' , 'Change Application details'),
            ('change_registration', 'Change Registration Setup'),
            ('change_submission', 'Change Submission Setup'),
            ('view_registration_admin', 'View Registration Admin'),
            ('add_users', 'Add New Users'),
            ('read', 'Read'),
            ('write', 'write'),
            ('groups', 'Access to groups'),
            ('super_powers', 'Super Powers!')
        )

    def __str__(self):
        return self.name

    def get_persistent(self):
        return self.persistent

