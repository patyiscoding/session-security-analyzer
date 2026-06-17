from helpers.log import log
import logging
from urllib.parse import urlparse
from dashboardServer import telemetryQueue

class Helpers():
    def logWarning(contents, path):
        Helpers.addToResults(contents, path, logging.WARNING)
        log.warning(contents)
    
    def logVulnerability(contents, path):
        Helpers.addToResults(contents, path, logging.WARNING)
        log.critical(f"[⚠️] POTENTIAL VULNERABILITY FOUND: {contents} at path {path}")


    def addToResults(contents, url, level):
        parsedURL = urlparse(url)
        host = parsedURL.netloc

        pathElements = [elem for elem in parsedURL.path.split('/') if elem]

        from SessionAnalyzer import SessionAnalyzer
        currentNode = SessionAnalyzer.vulnerabilityScanResultsJSON[host]

        lastToken = None
        for token in pathElements:
            currentNode = currentNode[token]
            lastToken = token
        
        currentNode[lastToken] = {
                                    'metadata_level': level,
                                    'metadata_contents': contents.encode('ascii','ignore'), # convert Unicode characters
                                    'url': url,
                                    'severity': 'unknown'
                                }
        
        telemetryQueue.put(SessionAnalyzer.vulnerabilityScanResultsJSON)

        # print(type(SessionAnalyzer.vulnerabilityScanResultsJSON))
        # print(json.dumps(SessionAnalyzer.vulnerabilityScanResultsJSON, indent=4))