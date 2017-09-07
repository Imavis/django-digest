from django.conf import settings
from django.db import models


class UserNonce(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    nonce = models.CharField(max_length=100, unique=True, db_index=True)
    count = models.IntegerField(null=True)
    last_used_at = models.DateTimeField(null=False)
    class Meta:
        app_label = 'django_digest'
        ordering = ('last_used_at',)

class PartialDigest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    login = models.CharField(max_length=128, db_index=True)
    partial_digest = models.CharField(max_length=100)
    confirmed = models.BooleanField(default=True)
    class Meta:
        app_label = 'django_digest'
