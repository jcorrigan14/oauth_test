from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import Group, User
from django.core.exceptions import ValidationError
from django.db import models, router
from django.db.models.deletion import Collector
from oauth2_provider.models import AbstractApplication, Application

from DOT_tutorial.values import *


class CustomApplication(AbstractApplication):
    """
    This model extends the base AbstractApplication model provided by OAuth2.0
    Applications for Genius Plaza would be Web, iOS Mobile, Android Mobile, and hopefully more!
    """
    # add custom fields here

    #
    # The persistent field determines whether Access Tokens are persistent or not. Only mobile apps should
    # have this set to "True". This determines what tokens to revoke when logging out.
    # Check docs for further detail
    #
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

class BaseModel(models.Model):
    """
        Parent model
        :model:`djangoplaza.BaseModel`
    """
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)

    def can_delete(self):
        """
            Selects which fields of the base model can be deleted
        """
        if self._get_pk_val():
            seen_objs = Collector(router.db_for_write(self.__class__, instance=self))
            seen_objs.collect([self])
            if len(seen_objs.data) > 1:
                raise ValidationError("Sorry, cannot be deleted.")

    def delete(self, **kwargs):
        """
            Deletes fields from base model
        """
        assert self._get_pk_val() is not None, "Object %s cannot be deleted because %s is null." % (
            self._meta.object_name, self._meta.pk.attname)
        seen_objs = Collector(router.db_for_write(self.__class__, instance=self))
        seen_objs.collect([self])
        self.can_delete()
        seen_objs.delete()

    def save(self, **kwargs):
        """
            Saves fields
        """
        models.Model.save(self)

    class Meta:
        abstract = True


class UsersGroup(BaseModel):
    """
        This is depricated! no point to recreate a UsersGroup model when Django has a built in auth_group model.
        We now create these groups in the roles_init(app) function in views.py
    
        Determines the type of user: Either school, student, teacher, parent, etc
    """
    name = models.CharField(max_length=100)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Users Group'
        verbose_name_plural = 'Users Group'
        db_table = 'users_group'
        unique_together = ('name',)

    def get_price(self):
        if self.usersgroupssignupprices_set.exists():
            return self.usersgroupssignupprices_set.all()[0].amount
        return 0

    def get_amount_users(self):
        return self.users_set.count()

    def get_my_chart_color(self):
        if self.id == USERS_GROUPS_STUDENT_ID:
            return "#FF0F00"
        if self.id == USERS_GROUPS_PARENT_ID:
            return "#FF6600"
        if self.id == USERS_GROUPS_TEACHER_ID:
            return "#CD0D74"
        if self.id == USERS_GROUPS_PRINCIPAL_ID:
            return "#FCD202"
        if self.id == USERS_GROUPS_DISTRICT_ID:
            return "#04D215"
        if self.id == USERS_GROUPS_STATE_ID:
            return "#B0DE09"
        if self.id == USERS_GROUPS_COUNTRY_ID:
            return "#04D215"
        if self.id == USERS_GROUPS_CHAMPION_ID:
            return "#2A0CD0"
        if self.id == USERS_GROUPS_ADMIN_ID:
            return "#333333"
        return "#DDDDDD"

class AccessTypes(BaseModel):
    """
        Defines the type of access
    """
    name = models.CharField(max_length=100)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Access Type'
        verbose_name_plural = 'Access Types'
        db_table = 'access _types'
        unique_together = ('name',)


class RepresentsOrganizations(BaseModel):
    """
        Defines the type of User representation
    """
    name = models.CharField(max_length=100)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Represent Organization'
        verbose_name_plural = 'Represents Organizations'
        db_table = 'represents_organizations'
        unique_together = ('name',)

class Languages(BaseModel):
    """
        Determines the user's language of preference
    """
    name = models.CharField(max_length=100)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Language'
        verbose_name_plural = 'Languages'
        db_table = 'languages'
        unique_together = ('name',)


class Genders(BaseModel):
    """
        Model that identifies the user's gender
    """
    name = models.CharField(max_length=50)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Gender'
        verbose_name_plural = 'Genders'
        db_table = 'genders'
        unique_together = ('name',)
        ordering = ('name', )


class Salutations(BaseModel):
    """
        Model that identifies the user's salutation preference
    """
    name = models.CharField(max_length=20)
    language = models.ForeignKey(Languages, blank=True, null=True)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Salutations'
        verbose_name_plural = 'Salutations'
        db_table = 'salutations'
        unique_together = ('name',)


class ModeMessages(BaseModel):
    """
        Model used to contact site. Either by message, email, etc.
    """
    name = models.CharField(max_length=100)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Mode Message'
        verbose_name_plural = 'Modes Messages'
        db_table = 'modes_messages'
        unique_together = ('name',)


class Introductions(BaseModel):
    """
        How did the user heard about the Genius Plaza
    """
    name = models.CharField(max_length=100)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Introduction'
        verbose_name_plural = 'Introductions'
        db_table = 'introductions'
        unique_together = ('name',)


class Grades(BaseModel):
    """
        Stores the user's grades
    """
    name = models.CharField(max_length=100)
    name_spanish = models.CharField(max_length=100, blank=True, null=True)
    language = models.ForeignKey(Languages, blank=True, null=True)
    old_id = models.IntegerField(default=0)
    order = models.IntegerField(default=0)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Grades'
        verbose_name_plural = 'Grades'
        db_table = 'grades'
        ordering = ('order',)
        unique_together = ('name',)

    def get_my_standards_by_curriculums(self):
        return [x.standard for x in self.curriculumsrelations_set.filter(standard__isnull=False).distinct('standard')]

    def get_standards(self, domain, subject, curriculum):
        return [x.standard for x in self.curriculumsrelations_set.filter(standard__isnull=False, curriculum=curriculum, subject=subject, domain=domain).distinct('standard')]

    def number_standards_by_curriculums(self):
        return self.curriculumsrelations_set.filter(standard__isnull=False).count()

class LearningTracks(BaseModel):
    """
        Determines the learning track for the user
    """
    name = models.CharField(max_length=100)

    def __str__(self):
        return "{}".format(self.name)

    class Meta:
        verbose_name = 'Learning Track'
        verbose_name_plural = 'Learning Tracks'
        db_table = 'learning_tracks'
        unique_together = ('name',)

    def get_languages_list(self):
        return_list = []

        if self.id == LEARNING_TRACK_BILINGUAL:
            return_list.append(LANGUAGE_ENGLISH_ID)
            return_list.append(LANGUAGE_SPANISH_ID)

        if self.id == LEARNING_TRACK_ENGLISH:
            return_list.append(LANGUAGE_ENGLISH_ID)

        if self.id == LEARNING_TRACK_SPANISH:
            return_list.append(LANGUAGE_SPANISH_ID)

        return return_list
#
#
# Goodbye Users :"(  you will be missed
#
#
# class Users(BaseModel):
#     """
#         Model used to define a user according to the following fields:
#     """
#     user = models.OneToOneField(User)
#     group = models.ForeignKey(UsersGroup, blank=True, null=True)
#     salutation = models.ForeignKey(Salutations, blank=True, null=True)
#     gender = models.ForeignKey(Genders, blank=True, null=True)
#     mobile_country_phone_id = models.CharField(max_length=10, blank=True, null=True)
#     mobile = models.CharField(max_length=20, blank=True, null=True)
#     contactme_by = models.ForeignKey(ModeMessages, blank=True, null=True)
#     birth_year = models.IntegerField(default=0, blank=True, null=True)
#     birth_day = models.DateField(blank=True, null=True)
#     language = models.ForeignKey(Languages, blank=True, null=True)
#     referral = models.ForeignKey(Introductions, blank=True, null=True)
#     grade = models.ForeignKey(Grades, blank=True, null=True)
#     track = models.ForeignKey(LearningTracks, blank=True, null=True)
#     avatar = models.FileField(upload_to='images/', max_length=100, blank=True, null=True)
#     cover = models.FileField(upload_to='images/', max_length=100, blank=True, null=True)
#     access_type = models.ForeignKey(AccessTypes, blank=True, null=True)
#     representing_organization = models.ForeignKey(RepresentsOrganizations, blank=True, null=True)
#     organization = models.CharField(max_length=300, blank=True, null=True)
#     why_interested = models.TextField(blank=True, null=True)
#     bio = models.TextField(blank=True, null=True)
#     message_to_learners = models.TextField(blank=True, null=True)
#     title = models.TextField(blank=True, null=True)
#     old_id = models.IntegerField(default=0)
#     old_group_name = models.CharField(max_length=20, blank=True, null=True)


class GeniusUser(AbstractUser):
    """
    A new User model that combines the Django User and the Users model that previously existed. 
    Fields such as last_name and password are inherited from AbstractUser (Django User)
    
    Check the documentation for the migration script and workflow that combined these two models
    into one new model
    """
    first_name = models.CharField(max_length=30)
    email = models.EmailField(blank=True, unique=True, null=True)
    # No more custom group! We are now using Django's built in auth_groups
    # We now create these groups in the roles_init(app) function in views.py
    #group = models.ForeignKey(UsersGroup, blank=True, null=True, related_name='genius_users')
    salutation = models.ForeignKey(Salutations, blank=True, null=True, related_name='genius_users')
    gender = models.ForeignKey(Genders,blank=True, null=True, related_name='genius_users')
    mobile_country_phone_id = models.CharField(max_length=10, blank=True, null=True)
    mobile = models.CharField(max_length=20, blank=True, null=True)
    contactme_by = models.ForeignKey(ModeMessages, blank=True, null=True, related_name='genius_users')
    birth_year = models.IntegerField(default=0, blank=True, null=True)
    birth_day = models.DateField(blank=True, null=True)
    language = models.ForeignKey(Languages, blank=True, null=True, related_name='genius_users')
    referral = models.ForeignKey(Introductions, blank=True, null=True, related_name='genius_users')
    grade = models.ForeignKey(Grades, blank=True, null=True, related_name='genius_users')
    track = models.ForeignKey(LearningTracks, blank=True, null=True, related_name='genius_users')
    avatar = models.FileField(upload_to='images/', max_length=100, blank=True, null=True)
    cover = models.FileField(upload_to='images/', max_length=100, blank=True, null=True)
    access_type = models.ForeignKey(AccessTypes, blank=True, null=True, related_name='genius_users')
    representing_organization = models.ForeignKey(RepresentsOrganizations, blank=True, null=True, related_name='genius_users')
    organization = models.CharField(max_length=300, blank=True, null=True)
    why_interested = models.TextField(blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    message_to_learners = models.TextField(blank=True, null=True)
    title = models.TextField(blank=True, null=True)
    old_id = models.IntegerField(default=0)
    old_group_name = models.CharField(max_length=20, blank=True, null=True)

    class Meta:
        verbose_name = 'Genius User'
        verbose_name_plural = 'Genius Users'
        db_table = 'genius_user'