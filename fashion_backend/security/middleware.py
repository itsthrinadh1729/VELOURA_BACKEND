import time
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

from .models import BlockedIP
from .detectors import detect_sql_injection,detect_xss
from .logger import ThreatLogger


class SecurityMiddleware(MiddlewareMixin):
    request_log = {}
    attack_counter = {}

    def process_request(self, request):
        ip = self.get_client_ip(request)

        # ✅ Blocked IP check
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return JsonResponse({"error": "Your IP is blocked"}, status=403)

        # ✅ DDoS detection
        if self.is_ddos(ip):
            ThreatLogger.log(request, "DDOS")
            self.auto_block_ip(ip)
            return JsonResponse({"error": "Too many requests"}, status=429)

        payload = self.get_payload(request)

        # ✅ SQL Injection
        if detect_sql_injection(payload):
            ThreatLogger.log(request, "SQL Injection", payload)
            self.auto_block_ip(ip)
            return JsonResponse({"error": "SQL Injection detected"}, status=403)

        # ✅ XSS
        if detect_xss(payload):
            ThreatLogger.log(request, "XSS", payload)
            self.auto_block_ip(ip)
            return JsonResponse({"error": "XSS detected"}, status=403)

        # ✅ Brute force
        if request.path.endswith("/login") and request.method == "POST":
            if self.is_bruteforce(ip):
                ThreatLogger.log(request, "Brute Force")
                self.auto_block_ip(ip)
                return JsonResponse({"error": "Too many login attempts"}, status=429)

        return None

    # -------------------------
    # Helpers
    # -------------------------

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")

    def get_payload(self, request):
        data = ""

        if request.GET:
            data += str(request.GET.dict())

        if request.POST:
            data += str(request.POST.dict())

        try:
            if request.body:
                data += request.body.decode("utf-8", errors="ignore")
        except Exception:
            pass

        return data

    # -------------------------
    # DDoS detection
    # -------------------------

    def is_ddos(self, ip):
        now = time.time()
        window = 10
        limit = 30

        if ip not in self.request_log:
            self.request_log[ip] = []

        self.request_log[ip] = [
            t for t in self.request_log[ip] if now - t < window
        ]

        self.request_log[ip].append(now)

        return len(self.request_log[ip]) > limit

    # -------------------------
    # Brute force detection
    # -------------------------

    def is_bruteforce(self, ip):
        limit = 5
        self.attack_counter[ip] = self.attack_counter.get(ip, 0) + 1
        return self.attack_counter[ip] > limit

    # -------------------------
    # Auto block (NO DB dependency)
    # -------------------------

    def auto_block_ip(self, ip):
        self.attack_counter[ip] = self.attack_counter.get(ip, 0) + 1

        if self.attack_counter[ip] >= 10:
            BlockedIP.objects.get_or_create(
                ip_address=ip,
                defaults={"reason": "Multiple attacks detected"}
            )