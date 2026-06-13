from mitmproxy import http
import re
from modules.JWTAnalyzer import JWTAnalyzer
from helpers.log import log
from modules.CookiesAnalyzer import CookiesAnalyzer
from helpers.helpers import Helpers
from modules.SecretsScanner import SecretsScanner
from modules.HeadersAnalyzer import HeaderAnalyzer
from modules.WebStorageAnalyzer import WebStorageAnalyzer
import json

class SessionAnalyzer:
    def request(self, flow: http.HTTPFlow):
        # if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
        #     return

        if WebStorageAnalyzer.webStorageEndpoint in flow.request.path:
            if flow.request.method == "OPTIONS":
                flow.response = http.Response.make(
                    204,
                    b"",
                    {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type"
                    }
                )
                return
            
            if flow.request.method == "POST":
                log.info("Received web storage dump")
                try:
                    rawPayload = flow.request.get_text()
                    jsonParsed = json.loads(rawPayload)
                    host = flow.request.host
                    
                    log.info(f"Dumped web storage for {host}")
                    print(json.dumps(jsonParsed, indent=4))
                    
                    flow.response = http.Response.make(
                        200, 
                        b"Response", 
                        {   
                            "Content-Type": "text/plain", 
                            "Access-Control-Allow-Origin": "*"
                        }
                    )
                except Exception as e:
                    log.error(f"Failed to process web storage dump: {e}")
                return

        return

    
    def response(self, flow: http.HTTPFlow):
        # if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
        #     return

        WebStorageAnalyzer.analyzeWebStorage(flow)

        print("") # for newline before each new request/response log
        log.metadata(f"[{flow.request.method}] ({flow.response.status_code}) {flow.request.url} {flow.response.headers.get("Content-Type", "")}")

        # ---------------------------------SETCOOKIES ANALYSIS---------------------------------
        SETCOOKIES = flow.response.headers.get_all("Set-Cookie")
        if len(SETCOOKIES) != 0:
            CookiesAnalyzer.evaluateSETCOOKIES(SETCOOKIES)
        
       
        AUTHORIZATION = flow.request.headers.get("Authorization", "")
        # if flow.request.scheme == "http" and (AUTHORIZATION != "" or flow.request.headers.get("Cookie", "") != ""):
        #     Helpers.vulnerabilityFound(f'Sensitive data ({flow.request.headers.get("Authorization", "")} {flow.request.headers.get("Cookie", "")}) being sent over the insecure HTTP protocol')
        
        # ---------------------------------JWT ANALYSIS----------------------------------------
        

        # # From Authorization header
        # if AUTHORIZATION and AUTHORIZATION.startswith("Bearer "):
        #     log.debug("Evaluating JWT from the Authorization header")
        #     JWTAnalyzer.evaluateJWT(AUTHORIZATION.split(" ")[1], flow)

        # # From Cookie header
        # matches = re.findall("token=((?:[a-zA-Z0-9_-]+\\.){2}[a-zA-Z0-9_-]+)", flow.request.headers.get("Cookie", ""))
        # if len(matches) != 0 and matches[0] is not None:
        #     log.debug("Evaluating JWT from the Cookie header")
        #     JWTAnalyzer.evaluateJWT(matches[0], flow)
        
        # ---------------------------------SECRETS SCAN----------------------------------------
        content = flow.response.text
        # print(content)
        # SecretsScanner.lookForSecretsWithGitLeaks(content)

        
        # HeaderAnalyzer.analyzeHeaders(flow, flow.response.headers, flow.request.url)
        


# def __init__():
    # SecretsScanner()

addons = [SessionAnalyzer()]