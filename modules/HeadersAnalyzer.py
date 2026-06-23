from helpers.log import log
import re
from datetime import timedelta
from helpers.helpers import Helpers


class HeadersAnalyzer:
    def analyzeHeaders(flow):
        log.debug("EVALUATING HEADERS")
        headers = flow.response.headers
        path = flow.request.url

        HeadersAnalyzer.analyzeSTS(flow, headers, path)
        HeadersAnalyzer.analyzeNoSniff(flow, headers, path)
        HeadersAnalyzer.analyzeCORS(flow, headers, path)
        HeadersAnalyzer.analyzeURL(flow, path)

    def analyzeSTS(flow, headers, path):
        STS = headers.get("Strict-Transport-Security", "")
        
        if STS == "":
            Helpers.logWarning(flow, f"Missing Strict-Transport-Security header", path)
        else:
            match = re.search(r"max-age=(\d+)", STS)    
            if match:
                maxAge = int(match.group(1))
                maxAgeConverted = str(timedelta(seconds=maxAge))
                Helpers.logVulnerability(flow, f"Strict-Transport-Security max-age: {maxAgeConverted}", path)
            else:
                Helpers.logWarning(flow, f"Found Strict-Transport-Security header, but couldn't extract max-age", path)

    def analyzeNoSniff(flow, headers, path):
        XCONTENT = headers.get("X‐Content‐Type‐Options", None)

        if XCONTENT is None:
            Helpers.logWarning(flow, f"Missing X‐Content‐Type‐Options: no-sniff header", path)
        else:
            if "no-sniff" not in XCONTENT:
                Helpers.logWarning(flow, f"X‐Content‐Type‐Options header not set to 'no-sniff' value", path)

    def analyzeCORS(flow, responseHeaders, path):
        CORSCredentials = responseHeaders.get("Access-Control-Allow-Credentials")
        if CORSCredentials and CORSCredentials.lower() == "true":
            incomingOrigin = flow.request.headers.get('Origin')
            CORSOrigin = responseHeaders.get("Access-Control-Allow-Origin", "")
            if CORSOrigin == "*" or CORSOrigin == incomingOrigin:
                Helpers.logWarning(flow, f"Access-Control-Allow-Credentials header set to 'true', but Access-Control-Allow-Origin set to. Any origin is allowed to access the resource.", path)
    
    def analyzeURL(flow, path):
        if any(param in flow.request.url.lower() for param in ["sid=", "session_id=", "token="]):
            Helpers.logWarning(flow, "Potential Session Fixation risk due to a session token found in URL", path)