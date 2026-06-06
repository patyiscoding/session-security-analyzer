from log import log

class Helpers():
    def vulnerabilityFound(message):
        log.critical(f"[⚠️] VULNERABILITY FOUND: {message}")