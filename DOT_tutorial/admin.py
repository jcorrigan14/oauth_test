from django.contrib import admin

from DOT_tutorial.models import *

from guardian.admin import GuardedModelAdmin


class ApplicationAdmin(GuardedModelAdmin):
    pass
admin.site.register(Application, ApplicationAdmin)


class ApplicationGroupAdmin(GuardedModelAdmin): # Admin.ModelAdmin or GuardedModelAdmin
    pass
admin.site.register(ApplicationGroup, ApplicationAdmin)



