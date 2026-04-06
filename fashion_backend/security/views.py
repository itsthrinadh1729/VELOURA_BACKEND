from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Count

from .models import ThreatLog, BlockedIP


# ===============================
# 🔐 LOGS (Protected with JWT)
# ===============================
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import ThreatLog


class ThreatLogView(APIView):

    def get_permissions(self):
        if self.request.method == 'POST':
            return [AllowAny()]
        return [IsAuthenticated()]

    def get(self, request):
        logs = ThreatLog.objects.all().order_by("-timestamp")

        data = [
            {
                "id": str(log.id),
                "ip": log.ip,
                "attack_type": log.attack_type,
                "payload": log.payload,
                "severity": self.get_severity(log.attack_type),
                "time": log.timestamp.strftime("%I:%M:%S %p"),
                "status": "ACTIVE" if not log.resolved else "RESOLVED",
                "target": getattr(log, "target", "unknown")
            }
            for log in logs
        ]

        return Response({"data": data})

    def post(self, request):
        data = request.data

        ThreatLog.objects.create(
            ip=data.get("ip"),
            attack_type=data.get("attack_type"),
            endpoint=data.get("endpoint", "unknown"),
            payload=data.get("payload", ""),
            user_agent=data.get("user_agent", ""),
            target=data.get("target", "unknown")
        )

        return Response({"message": "Log received"})

    def get_severity(self, attack_type):
        return {
            "SQL Injection": "CRITICAL",
            "XSS": "HIGH",
            "DDOS": "CRITICAL",
            "Brute Force": "HIGH"
        }.get(attack_type, "LOW")


# ===============================
# 📊 STATS (Protected)
# ===============================
class AttackStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        total_logs = ThreatLog.objects.count()
        blocked_ips = BlockedIP.objects.count()
        active_threats = ThreatLog.objects.filter(resolved=False, ignored=False).count()

        return Response({
            "data": {
                "totalLogs": total_logs,
                "totalAttacks": total_logs,
                "activeThreats": active_threats,
                "blockedIPs": blocked_ips
            }
        })


# ===============================
# 📈 ATTACK TYPES (Charts)
# ===============================
class AttackTypeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        types = ThreatLog.objects.values("attack_type").annotate(count=Count("attack_type"))

        return Response({
            item["attack_type"]: item["count"] for item in types
        })


# ===============================
# 🌍 TOP IPs
# ===============================
class TopIPView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ips = (
            ThreatLog.objects.values("ip")
            .annotate(attack_count=Count("ip"))
            .order_by("-attack_count")[:5]
        )

        return Response(list(ips))


# ===============================
# 🔥 ACTION APIs
# ===============================

# 🚫 BLOCK IP
class BlockIPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ip = request.data.get("ip")

        if not ip:
            return Response({"error": "IP required"}, status=400)

        BlockedIP.objects.get_or_create(
            ip_address=ip,
            defaults={"reason": "Manually blocked"}
        )

        return Response({"message": "IP blocked successfully"})


# ✅ RESOLVE INCIDENT
class ResolveIncidentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        log_id = request.data.get("id")

        try:
            log = ThreatLog.objects.get(id=log_id)
            log.resolved = True
            log.save()

            return Response({"message": "Incident resolved"})
        except ThreatLog.DoesNotExist:
            return Response({"error": "Log not found"}, status=404)


# 🚮 IGNORE INCIDENT
class IgnoreIncidentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        log_id = request.data.get("id")

        try:
            log = ThreatLog.objects.get(id=log_id)
            log.ignored = True
            log.save()

            return Response({"message": "Incident ignored"})
        except ThreatLog.DoesNotExist:
            return Response({"error": "Log not found"}, status=404)