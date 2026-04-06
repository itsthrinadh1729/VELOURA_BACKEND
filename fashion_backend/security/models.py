from django.db import models


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address


class ThreatLog(models.Model):
    ip = models.CharField(max_length=100)
    attack_type = models.CharField(max_length=20)
    endpoint = models.CharField(max_length=255)
    payload = models.TextField(blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    ignored = models.BooleanField(default=False)
    target = models.CharField(max_length=255, default="unknown")


    def __str__(self):
        return f"{self.ip} - {self.attack_type}"