from django.contrib import admin

from DOT_tutorial.models import CustomApplication, GeniusUser, Genders, UsersGroup, Salutations, Languages,\
    Grades, ModeMessages, Introductions, LearningTracks

from guardian.admin import GuardedModelAdmin

from oauth2_provider.admin import ApplicationAdmin


class ApplicationGroupAdmin(GuardedModelAdmin): # Admin.ModelAdmin or GuardedModelAdmin
    pass

class CustomApplicationAdmin(ApplicationAdmin):
    list_display = ("name", "user", "client_type", "authorization_grant_type", "persistent")
admin.site.unregister(CustomApplication)
admin.site.register(CustomApplication, CustomApplicationAdmin)
admin.site.register(GeniusUser)
admin.site.register(Genders)
admin.site.register(UsersGroup)
admin.site.register(Salutations)
admin.site.register(Languages)
admin.site.register(Grades)
admin.site.register(ModeMessages)
admin.site.register(Introductions)
admin.site.register(LearningTracks)


