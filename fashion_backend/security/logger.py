import requests


class ThreatLogger:
    MONITORING_URL = "http://127.0.0.1:8008/api/security/logs/"

    @staticmethod
    def log(request, attack_type, payload=""):
        try:
            ip = ThreatLogger.get_client_ip(request)
            endpoint = request.path
            user_agent = request.META.get("HTTP_USER_AGENT", "")

            log_data = {
                "ip": ip,
                "attack_type": attack_type,
                "endpoint": endpoint,
                "payload": payload,
                "user_agent": user_agent,
                "target": "electronics"  # 🔥 important
            }

            try:
                requests.post(ThreatLogger.MONITORING_URL, json=log_data, timeout=2)
            except Exception as e:
                print("Monitoring server not reachable:", e)

        except Exception as e:
            print(f"[ThreatLogger Error]: {e}")

    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")