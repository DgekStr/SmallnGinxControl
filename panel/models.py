import base64
import hashlib
import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from .transactions import ACCESS_LOG_SAMPLE_DEFAULT_BYTES, ACCESS_LOG_SAMPLE_MAX_BYTES


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
    traffic_blocked = models.BooleanField(default=False)
    maintenance_page_path = models.CharField(max_length=1000, default='/var/www/html/maitenance.html')
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
    disk_used_bytes = models.PositiveBigIntegerField(default=0)
    disk_total_bytes = models.PositiveBigIntegerField(default=0)
    rx_rate = models.FloatField()
    tx_rate = models.FloatField()
    rx_mb = models.FloatField()
    tx_mb = models.FloatField()
    uptime = models.FloatField()

    class Meta:
        ordering = ['-id']


class TwoFactorCredential(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='two_factor_credential')
    encrypted_secret = models.TextField(blank=True, default='')
    encrypted_pending_secret = models.TextField(blank=True, default='')
    enabled = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    @staticmethod
    def cipher():
        from cryptography.fernet import Fernet
        key = hashlib.sha256(('snc-2fa:' + settings.SECRET_KEY).encode()).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    def get_secret(self, *, pending=False):
        encrypted = self.encrypted_pending_secret if pending else self.encrypted_secret
        return self.cipher().decrypt(encrypted.encode()).decode() if encrypted else ''

    def set_secret(self, value, *, pending=False):
        encrypted = self.cipher().encrypt(value.encode()).decode() if value else ''
        if pending:
            self.encrypted_pending_secret = encrypted
        else:
            self.encrypted_secret = encrypted


class ServiceSetting(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    log_retention_days = models.PositiveSmallIntegerField(default=30, validators=[MinValueValidator(1), MaxValueValidator(3650)])
    session_timeout_hours = models.PositiveSmallIntegerField(default=24, validators=[MinValueValidator(1), MaxValueValidator(720)])
    access_log_sample_bytes = models.PositiveIntegerField(default=ACCESS_LOG_SAMPLE_DEFAULT_BYTES, validators=[MinValueValidator(1), MaxValueValidator(ACCESS_LOG_SAMPLE_MAX_BYTES)])
    updated_at = models.DateTimeField(auto_now=True)

    @classmethod
    def get_solo(cls):
        return cls.objects.get_or_create(pk=1)[0]


class DomainExpiry(models.Model):
    domain = models.CharField(max_length=253, primary_key=True)
    expires_on = models.DateField(null=True, blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, default='pending', choices=[('pending', 'Pending'), ('checking', 'Checking'), ('ready', 'Ready'), ('unavailable', 'Unavailable')])

    class Meta:
        ordering = ['domain']