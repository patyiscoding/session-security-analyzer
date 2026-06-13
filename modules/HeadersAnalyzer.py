from helpers.log import log
import re

class HeaderAnalyzer:
    # def __init__(self):
    #         self.fuzzedJWTs = set()

  
    def analyzeHeaders(flow, headers, path):
        HeaderAnalyzer.analyzeSTS(headers, path)
        HeaderAnalyzer.analyzeNoSniff(headers, path)
        HeaderAnalyzer.analyzeCORS(headers, flow)

    def analyzeSTS(headers, path):
        STS = headers.get("Strict-Transport-Security", "")
        
        if STS == "":
            log.warning(f"Missing strict-transport-security header on request {path}")
        else:
            match = re.search(r"max-age=(\d+)", STS)    
            if match:
                max_age = int(match.group(1))
                log.critical(max_age)

    def analyzeNoSniff(headers, path):
        XCONTENT = headers.get("X‐Content‐Type‐Options", None)

        if XCONTENT is None:
            log.warning(f"Missing X‐Content‐Type‐Options: no-sniff header at path {path}")
        else:
            if "no-sniff" not in XCONTENT:
                log.warning(f"X‐Content‐Type‐Options header not set to 'no-sniff' value at path {path}")

    def analyzeCORS(headers, flow):
        CORS = flow.request.headers.get("Access-Control-Allow-Origin")
        if CORS is not None:
            log.info(f"CORS headers {CORS}")