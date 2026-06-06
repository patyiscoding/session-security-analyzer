from mitmproxy import http
import re
from JWTAnalyzer import JWTAnalyzer
from log import log
from CookiesAnalyzer import CookiesAnalyzer

class SessionAnalyzer:
    def request(self, flow: http.HTTPFlow):
        if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
            return

        CORS = flow.request.headers.get("Access-Control-Allow-Origin")
        if CORS is not None:
            log.info(f"CORS headers {CORS}")


    def response(self, flow):
        if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
            return

        log.info(f"{flow.request.method} request to {flow.request.url}. ({flow.response.status_code}) {flow.response.headers.get("Content-Type", "")} response")

        # ---------------------------------SETCOOKIES ANALYSIS---------------------------------
        SETCOOKIES = flow.response.headers.get_all("Set-Cookie")
        if len(SETCOOKIES) != 0:
            CookiesAnalyzer.evaluateSETCOOKIES(SETCOOKIES)
        
        # ---------------------------------JWT ANALYSIS----------------------------------------
        AUTHORIZATION = flow.request.headers.get("Authorization", "")
        JWTAnalyzerInstance = JWTAnalyzer()

        # From Authorization header
        if AUTHORIZATION and AUTHORIZATION.startswith("Bearer "):
            log.debug("Evaluating JWT from the Authorization header")
            JWTAnalyzerInstance.evaluateJWT(AUTHORIZATION.split(" ")[1], flow)

        # From Cookie header
        matches = re.findall("token=((?:[a-zA-Z0-9_-]+\\.){2}[a-zA-Z0-9_-]+)", flow.request.headers.get("Cookie", ""))
        if len(matches) != 0 and matches[0] is not None:
            log.debug("Evaluating JWT from the Cookie header")
            JWTAnalyzerInstance.evaluateJWT(matches[0], flow)



addons = [SessionAnalyzer()]