from django.contrib import admin

from DOT_tutorial.models import *

from guardian.admin import GuardedModelAdmin


class ApplicationGroupAdmin(GuardedModelAdmin): # Admin.ModelAdmin or GuardedModelAdmin
    pass
admin.site.register(ApplicationGroup, ApplicationGroupAdmin)



