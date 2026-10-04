import base64
import hashlib
import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


def server_id():
    return uuid.uuid4().hex


class Server(models.Model):
    id = models.CharField(primary_key=True, max_length=32, default=server_id, editable=False)
    name = models.CharField(max_length=80)
    host = models.CharField(max_length=253)
    mode = models.CharField(max_length=8, choices=[('demo', 'Demo'), ('local', 'Local'), ('ssh', 'SSH')])
    is_default = models.BooleanField(default=False)
    port = models.PositiveIntegerField(default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    username = models.CharField(max_length=64, default='root')
    auth_method = models.CharField(max_length=8, default='key', choices=[('key', 'SSH key'), ('password', 'Password'), ('agent', 'SSH agent')])
    key_path = models.CharField(max_length=500, blank=True)
    fingerprint = models.CharField(max_length=100, blank=True)
    encrypted_secret = models.TextField(blank=True)
    nginx_root = models.CharField(max_length=500, default='/etc/nginx')
    log_root = models.CharField(max_length=500, default='/var/log/nginx')
    interface = models.CharField(max_length=64, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_default', 'name', 'id']

    def cipher(self):
        from cryptography.fernet import Fernet
        key = hashlib.sha256(('snc-ssh:' + settings.SECRET_KEY).encode()).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    def set_secret(self, value):
        self.encrypted_secret = self.cipher().encrypt(value.encode()).decode() if value else ''

    def get_secret(self):
        return self.cipher().decrypt(self.encrypted_secret.encode()).decode() if self.encrypted_secret else ''


class AuditEvent(models.Model):
    server = models.ForeignKey(Server, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=150)
    action = models.CharField(max_length=50)
    target = models.CharField(max_length=255, blank=True)
    success = models.BooleanField(default=True)
    detail = models.TextField(blank=True)

    class Meta:
        ordering = ['-id']


class LoginAttempt(models.Model):
    key = models.CharField(max_length=64, unique=True)
    failures = models.PositiveIntegerField(default=0)
    window = models.DateTimeField()


class MetricSample(models.Model):
    server = models.ForeignKey(Server, null=True, blank=True, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    cpu = models.FloatField()
    memory = models.FloatField()
    rx_rate = models.FloatField()
    tx_rate = models.FloatField()
    rx_mb = models.FloatField()
    tx_mb = models.FloatField()
    uptime = models.FloatField()

    class Meta:
        ordering = ['-id']