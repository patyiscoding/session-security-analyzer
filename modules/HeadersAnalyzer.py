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

        HeadersAnalyzer.analyzeSTS(headers, path)
        HeadersAnalyzer.analyzeNoSniff(headers, path)
        HeadersAnalyzer.analyzeCORS(headers, flow)

    def analyzeSTS(headers, path):
        STS = headers.get("Strict-Transport-Security", "")
        
        if STS == "":
            Helpers.logWarning(f"Missing Strict-Transport-Security header on request {path}", path)
        else:
            match = re.search(r"max-age=(\d+)", STS)    
            if match:
                maxAge = int(match.group(1))
                maxAgeConverted = str(timedelta(seconds=maxAge))
                Helpers.logVulnerability(f"Max age: {maxAgeConverted}", path)
            else:
                Helpers.logWarning(f"Found Strict-Transport-Security header, but couldn't extract max-age at {path}")

    def analyzeNoSniff(headers, path):
        XCONTENT = headers.get("X‐Content‐Type‐Options", None)

        if XCONTENT is None:
            Helpers.logWarning(f"Missing X‐Content‐Type‐Options: no-sniff header at path {path}", path)
        else:
            if "no-sniff" not in XCONTENT:
                Helpers.logWarning(f"X‐Content‐Type‐Options header not set to 'no-sniff' value at path {path}", path)

    def analyzeCORS(headers, flow):
        CORS = flow.request.headers.get("Access-Control-Allow-Origin")
        if CORS is not None:
            log.info(f"CORS headers {CORS}")