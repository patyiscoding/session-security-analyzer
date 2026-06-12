from mitmproxy import http
import re
from project.modules.JWTAnalyzer import JWTAnalyzer
from project.helpers.log import log
from project.modules.CookiesAnalyzer import CookiesAnalyzer
from project.helpers.helpers import Helpers
from project.modules.SecretsScanner import SecretsScanner
from project.modules.HeadersAnalyzer import HeaderAnalyzer
from project.modules.WebStorageAnalyzer import LocalStorageAnalyzer

class SessionAnalyzer:
    def request(self, flow: http.HTTPFlow):
        if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
            return

    
    def response(self, flow):
        if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
            return

        print("") # for newline before each new request/response log
        log.metadata(f"{flow.request.method} request to {flow.request.url}. ({flow.response.status_code}) {flow.response.headers.get("Content-Type", "")} response")

        # ---------------------------------SETCOOKIES ANALYSIS---------------------------------
        SETCOOKIES = flow.response.headers.get_all("Set-Cookie")
        if len(SETCOOKIES) != 0:
            CookiesAnalyzer.evaluateSETCOOKIES(SETCOOKIES)
        
       
        AUTHORIZATION = flow.request.headers.get("Authorization", "")
        # if flow.request.scheme == "http" and (AUTHORIZATION != "" or flow.request.headers.get("Cookie", "") != ""):
        #     Helpers.vulnerabilityFound(f'Sensitive data ({flow.request.headers.get("Authorization", "")} {flow.request.headers.get("Cookie", "")}) being sent over the insecure HTTP protocol')
        
        # ---------------------------------JWT ANALYSIS----------------------------------------
        

        # From Authorization header
        if AUTHORIZATION and AUTHORIZATION.startswith("Bearer "):
            log.debug("Evaluating JWT from the Authorization header")
            JWTAnalyzer.evaluateJWT(AUTHORIZATION.split(" ")[1], flow)

        # From Cookie header
        matches = re.findall("token=((?:[a-zA-Z0-9_-]+\\.){2}[a-zA-Z0-9_-]+)", flow.request.headers.get("Cookie", ""))
        if len(matches) != 0 and matches[0] is not None:
            log.debug("Evaluating JWT from the Cookie header")
            JWTAnalyzer.evaluateJWT(matches[0], flow)
        
        # ---------------------------------SECRETS SCAN----------------------------------------
        content = flow.response.content.decode("utf-8")
        print(content)
        # SecretsScanner.lookForSecretsWithGitLeaks(content)

        
        HeaderAnalyzer.analyzeHeaders(flow.response.headers, flow.request.url, flow)



# def __init__():
    # SecretsScanner()

addons = [SessionAnalyzer()]