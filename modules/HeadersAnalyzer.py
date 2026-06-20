from helpers.log import log
import re
from datetime import timedelta
from helpers.helpers import Helpers


class HeadersAnalyzer:
    # def __init__(self):
    #         self.fuzzedJWTs = set()

  
    def analyzeHeaders(flow):
        log.debug("EVALUATING HEADERS")
        headers = flow.response.headers
        path = flow.request.url

        HeadersAnalyzer.analyzeSTS(flow, headers, path)
        HeadersAnalyzer.analyzeNoSniff(flow, headers, path)
        HeadersAnalyzer.analyzeCORS(flow, headers)

    def analyzeSTS(flow, headers, path):
        STS = headers.get("Strict-Transport-Security", "")
        
        if STS == "":
            Helpers.logWarning(flow, f"Missing Strict-Transport-Security header on request {path}", path)
        else:
            match = re.search(r"max-age=(\d+)", STS)    
            if match:
                maxAge = int(match.group(1))
                maxAgeConverted = str(timedelta(seconds=maxAge))
                Helpers.logVulnerability(flow, f"Max age: {maxAgeConverted}", path)
            else:
                Helpers.logWarning(flow, f"Found Strict-Transport-Security header, but couldn't extract max-age at {path}")

    def analyzeNoSniff(flow, headers, path):
        XCONTENT = headers.get("X‐Content‐Type‐Options", None)

        if XCONTENT is None:
            Helpers.logWarning(flow, f"Missing X‐Content‐Type‐Options: no-sniff header", path)
        else:
            if "no-sniff" not in XCONTENT:
                Helpers.logWarning(flow, f"X‐Content‐Type‐Options header not set to 'no-sniff' value", path)

    def analyzeCORS(flow, responseHeaders):
        CORS = flow.request.headers.get("Access-Control-Allow-Origin")
        if CORS is not None:
            log.info(f"CORS headers {CORS}")