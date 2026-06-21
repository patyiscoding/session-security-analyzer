from helpers.log import log
import logging
from urllib.parse import urlparse
from dashboardServer import telemetryQueue
import re
import json

class Helpers():
    vulnerabilities = 0
    warnings = 0

    def printResponse(flow):
        print("") # for newline before each new request/response log
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
        parsedURL = urlparse(url)
        host = parsedURL.netloc

        pathElements = re.split(r'(?<!https:/)(?<!https:)(?<!http:)(?<!http:/)[/]', url)
        parts = [p for p in pathElements if p and p != "https:" and p!= "http:"]
        # pathElements = [elem for elem in parsedURL.path.split('/') if elem]

        from SessionAnalyzer import SessionAnalyzer
        currentNode = SessionAnalyzer.vulnerabilityScanResultsJSON["data"].setdefault(parts[0], {})
        SessionAnalyzer.vulnerabilityScanResultsJSON["metadata"]["vulnerabilities"] = Helpers.vulnerabilities
        SessionAnalyzer.vulnerabilityScanResultsJSON["metadata"]["warnings"] = Helpers.warnings


        for token in parts[1:-1]:
            if token not in currentNode:
                currentNode[token] = {}
            
            # If the token points to a list (a leaf node), we can't traverse further
            # Create a new branch by converting it to a dict
            if isinstance(currentNode[token], list):
                # This path was previously a leaf, now we need it to be a branch
                currentNode[token] = {}
            
            currentNode = currentNode[token]

        lastToken = parts[-1] if len(parts) > 1 else "/" 

        leaf = {
                'level': level,
                'contents': contents.encode('ascii','ignore').decode('ascii'), # convert Unicode characters
                'url': url,
                'severity': 'unknown',
                'request': flow.request.get_text(strict=False),
                'response': flow.response.get_text(strict=False)
            }
        
        # Ensure currentNode is a dict
        if not isinstance(currentNode, dict):
            currentNode = {}
        
        if currentNode.get(lastToken) is None:
            currentNode[lastToken] = [leaf]
        elif isinstance(currentNode[lastToken], list):
            currentNode[lastToken].append(leaf)
        else:
            # If it's not a list, convert it
            currentNode[lastToken] = [leaf]
        
        telemetryQueue.put(json.dumps(SessionAnalyzer.vulnerabilityScanResultsJSON))

        # print(type(SessionAnalyzer.vulnerabilityScanResultsJSON))
        # print(json.dumps(SessionAnalyzer.vulnerabilityScanResultsJSON, indent=4))