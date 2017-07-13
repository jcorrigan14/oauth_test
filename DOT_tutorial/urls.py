from django.conf.urls import url, include
from django.contrib import admin
admin.autodiscover()
from django.contrib import admin
from DOT_tutorial.views import *

urlpatterns = [
    url(r'^o/applications/register/', CustomApplicationRegistration.as_view()),
    url(r'^o/applications/(?P<pk>[\w-]+)/update/$', CustomApplicationUpdate.as_view(), name="update"),
    url(r'^o/applications/(?P<pk>[\w-]+)/$', CustomApplicationDetail.as_view(), name="detail"),
    url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    url(r'^admin/', admin.site.urls),
    url(r'^login/', LoginView.as_view()),
    url(r'^refresh/', RefreshView.as_view()),
    url(r'^logout/', logoutView.as_view()),
    url(r'^us/', userView.as_view()),
    url(r'^valid/', Validate.as_view()),
    url(r'^signup/', SignupView.as_view()),
]


