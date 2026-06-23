from helpers.log import log
from dashboardServer import telemetryQueue
import re
import json

class Helpers():
    vulnerabilities = 0
    warnings = 0

    def printResponse(flow):
        print("")
        print("") # for newlines before each new request/response log
        log.metadata(f"[{flow.request.method}] ({flow.response.status_code}) {flow.request.url} {flow.response.headers.get("Content-Type", "")}")

    def logWarning(flow, contents, path):
        Helpers.warnings += 1
        Helpers.addToResults(flow, contents, path, "Warning")
        log.warning(contents)
    
    def logVulnerability(flow, contents, path):
        Helpers.vulnerabilities += 1
        Helpers.addToResults(flow, contents, path, "Vulnerability")
        log.critical(f"POTENTIAL VULNERABILITY FOUND: {contents} at path {path}")


    def addToResults(flow, contents, url, level):
        from sessionAnalyzer import SessionAnalyzer

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

        currentNode = SessionAnalyzer.vulnerabilityScanResultsJSON["data"].setdefault(parts[0], {})
        SessionAnalyzer.vulnerabilityScanResultsJSON["metadata"]["vulnerabilities"] = Helpers.vulnerabilities
        SessionAnalyzer.vulnerabilityScanResultsJSON["metadata"]["warnings"] = Helpers.warnings

        for token in parts[1:-1]:
            if token not in currentNode:
                currentNode[token] = {}
            
            if isinstance(currentNode[token], list):
                currentNode[token] = {}
            
            currentNode = currentNode[token]

        lastToken = parts[-1] if len(parts) > 1 else "/" 

        convertedContents = contents.encode('ascii','ignore').decode('ascii') # convert Unicode characters

        leaf = {
            "level": level,
            "contents": convertedContents, 
            "url": url,
            "severity": "unknown",
            "request": flow.request.get_text(strict=False).replace("\"", "'"),
            "response": flow.response.get_text(strict=False).replace("\"", "'")
        }

        
        if currentNode.get(lastToken) is None:
            currentNode[lastToken] = [leaf]
        if isinstance(currentNode[lastToken], list):
            doesLeafExistAlready = any(leaf.get("contents", "") == convertedContents for leaf in currentNode[lastToken])
        
            if doesLeafExistAlready:
                log.debug(f"Skipped adding a {level} due to a duplicate")
                return

            currentNode[lastToken].append(leaf)
        else:
            currentNode[lastToken] = [leaf]

        telemetryQueue.put(json.dumps(SessionAnalyzer.vulnerabilityScanResultsJSON))