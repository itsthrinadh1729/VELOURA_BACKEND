import time
from collections import defaultdict

request_log = defaultdict(list)
failed_logins = defaultdict(int)

class RateLimiter:

    @staticmethod
    def is_ddos(ip):
        now = time.time()
        request_log[ip].append(now)

        # last 10 sec window
        request_log[ip] = [t for t in request_log[ip] if now - t < 10]

        return len(request_log[ip]) > 30

    @staticmethod
    def is_bruteforce(ip, failed=False):
        if failed:
            failed_logins[ip] += 1

        return failed_logins[ip] > 5