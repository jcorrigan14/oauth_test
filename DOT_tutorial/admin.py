from django.contrib import admin

from DOT_tutorial.models import ApplicationGroup, CustomApplication

from guardian.admin import GuardedModelAdmin

from oauth2_provider.admin import ApplicationAdmin


class ApplicationGroupAdmin(GuardedModelAdmin): # Admin.ModelAdmin or GuardedModelAdmin
    pass
admin.site.register(ApplicationGroup, ApplicationGroupAdmin)

class CustomApplicationAdmin(ApplicationAdmin):
    list_display = ("name", "user", "client_type", "authorization_grant_type", "persistent")
admin.site.unregister(CustomApplication)
admin.site.register(CustomApplication, CustomApplicationAdmin)

