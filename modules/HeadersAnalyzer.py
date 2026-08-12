from helpers.log import log
import re
from datetime import timedelta
from helpers.helpers import Helpers
import time
class HeadersAnalyzer:
    def __init__(self, Helpers, SessionAnalyzer):
        self.Helpers = Helpers
        self.SessionAnalyzer = SessionAnalyzer

    def analyzeHeaders(self, flow):
        log.debug("EVALUATING HEADERS")
        headers = flow.response.headers
        path = flow.request.url

        self.analyzeSTS(flow, headers, path)
        self.analyzeCORS(flow, headers, path)
        self.analyzeURL(flow, path)

    def analyzeSTS(self, flow, headers, path):
        STS = headers.get("Strict-Transport-Security", "")
        
        if STS == "":
            self.Helpers.logWarning(flow, f"Missing Strict-Transport-Security header", path)
        else:
            match = re.search(r"max-age=(\d+)", STS)    
            if match:
                maxAge = int(match.group(1))
                maxAgeConverted = str(timedelta(seconds=maxAge))
                log.warning(f"Strict-Transport-Security max-age: {maxAgeConverted} at path {path}")
            else:
                log.warning(f"Found Strict-Transport-Security header, but couldn't extract max-age at path {path}")


    def analyzeCORS(self, flow, responseHeaders, path):
        CORSCredentials = responseHeaders.get("Access-Control-Allow-Credentials")
        if CORSCredentials and CORSCredentials.lower() == "true":
            incomingOrigin = flow.request.headers.get('Origin')
            CORSOrigin = responseHeaders.get("Access-Control-Allow-Origin", "")
            if CORSOrigin == "*" or CORSOrigin == incomingOrigin:
                self.Helpers.logWarning(flow, f"Access-Control-Allow-Credentials header set to 'true', but Access-Control-Allow-Origin set to *. Any origin is allowed to access the resource.", path)
    
    def analyzeURL(self, flow, path):
        if any(param in flow.request.url.lower() for param in ["sid=", "session_id=", "token=", "jwt=", "sessionid="]):
            self.Helpers.logWarning(flow, "Potential Session Fixation risk due to a session token found in URL", path)