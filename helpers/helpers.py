from helpers.log import log
from dashboardServer import vulnerabilityQueue
import re
import http
import copy
import json

class Helpers():
    def __init__(self, SessionAnalyzer):
        self.SessionAnalyzer = SessionAnalyzer

    def printResponse(self, flow):
        print("")
        print("") # for newlines before each new request/response log

        try:
            statusText = http.HTTPStatus(flow.response.status_code).phrase
        except ValueError:
            statusText = "Unknown"
        
        BOLD = "\x1b[1m"
        BLUE = "\x1b[34m"
        GREEN = "\x1b[32m"
        RESET_COLOR = "\x1b[39m"
        RESET_ALL = "\x1b[0m"

        if(flow.response.status_code == 200):
            statusCodeString = f"{GREEN}{flow.response.status_code} {statusText}{RESET_COLOR}"
        else:
            statusCodeString = f"{BLUE}{flow.response.status_code} {statusText}{RESET_COLOR}"

        log.metadata(f"{BOLD}{flow.request.method} {statusCodeString} {flow.request.url} {flow.response.headers.get('Content-Type', '')}{RESET_ALL}")

    def logWarning(self, flow, contents, path):
        self.addToResults(flow, contents, path, "Warning")
        log.warning(f"{contents} at path {path}")
    
    def logVulnerability(self, flow, contents, path):
        self.addToResults(flow, contents, path, "Vulnerability")
        log.critical(f"POTENTIAL VULNERABILITY FOUND: {contents} at path {path}")


    def addToResults(self, flow, contents, url, level):
        # split by / but ignore the ones in https:// or http://
        pathElements = re.split(r'(?<!https:/)(?<!https:)(?<!http:)(?<!http:/)[/]', url)
        parts = [p for p in pathElements if p and p != "https:" and p!= "http:"]
        
        parts = []
        for p in pathElements:
            # if query params are present, ignore the rest of the path
            if "?" in p or "&" in p:
                break

            if p and p != "https:" and p!= "http:":
                parts.append(p)

        currentNode = self.SessionAnalyzer.vulnerabilityScanResultsJSON["data"].setdefault(parts[0], {})

        for token in parts[1:-1]:
            if token not in currentNode:
                currentNode[token] = {}
            
            if isinstance(currentNode[token], list):
                currentNode[token] = {}
            
            currentNode = currentNode[token]

        lastToken = parts[-1] if len(parts) > 1 else "/" 

        convertedContents = contents.encode('ascii', 'ignore').decode('ascii') # convert Unicode characters

        leaf = {
            "level": level,
            "contents": convertedContents, 
            "url": url,
            "severity": "unknown",
            "request": {    
                            "method": flow.request.method,
                            "statusCode": "",
                            "contents": flow.request.get_text(strict=False).replace("\"", "'"),
                            "headers": dict(flow.request.headers.items())
                        },
            "response": {
                            "statusCode": flow.response.status_code,
                            "contents": flow.response.get_text(strict=False).replace("\"", "'"),
                            "headers": dict(flow.request.headers.items())
                        }
        }

        if lastToken not in currentNode or not isinstance(currentNode[lastToken], list):
            currentNode[lastToken] = []

        doesLeafExistAlready = any(l.get("contents", "") == convertedContents for l in currentNode[lastToken])
    
        if doesLeafExistAlready:
            log.debug(f"Skipped adding a {level} due to a duplicate")
            return

        currentNode[lastToken].append(leaf)

        if level == "Warning":
            self.SessionAnalyzer.vulnerabilityScanResultsJSON["metadata"]["warnings"] += 1
        elif level == "Vulnerability":
            self.SessionAnalyzer.vulnerabilityScanResultsJSON["metadata"]["vulnerabilities"] += 1
        else:
            return

        log.info(f"ADDITION {convertedContents}, warnings: {self.SessionAnalyzer.vulnerabilityScanResultsJSON["metadata"]["warnings"]}, vulns: {self.SessionAnalyzer.vulnerabilityScanResultsJSON["metadata"]["vulnerabilities"]}")

        vulnerabilityQueue.put(json.dumps(self.SessionAnalyzer.vulnerabilityScanResultsJSON))