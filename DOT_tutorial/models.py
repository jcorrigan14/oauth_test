from django.db import models
from django.contrib.auth.models import Group

from oauth2_provider.models import AbstractApplication, Application

class CustomApplication(AbstractApplication):
    # add custom fields here
    Persistent = models.BooleanField()


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






class ApplicationGroup(models.Model):
    '''
    This model associates a permissions group with an Application.
    Allows for easy retrieval of Group (Role Name) per Application
    '''
    group = models.ForeignKey(Group)
    application = models.ForeignKey(CustomApplication)
    # modified = models.DateTimeField(auto_now=True)
    # created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.group.__str__()
    #
    # class Meta:
    #     unique_together = ['group', 'event']

