from mitmproxy import http
import re

from modules.JWTAnalyzer import JWTAnalyzer
from helpers.log import log
from modules.CookiesAnalyzer import CookiesAnalyzer
from helpers.helpers import Helpers
from modules.SecretsScanner import SecretsScanner
from modules.HeadersAnalyzer import HeadersAnalyzer
from modules.WebStorageAnalyzer import WebStorageAnalyzer
import json
from collections import defaultdict
from dashboardServer import startDashboardServer, telemetryQueue
from multiprocessing import Process, Queue, current_process
from mitmproxy.addonmanager import Loader

SERVERSTARTED = False

def trie():
    return defaultdict(trie)


class SessionAnalyzer:
    def __init__(self):
        self.vulnerabilityServerProcess = None
        self.activeGitLeaksProcesses = set()
        self.vulnerabilityScanResultsJSON = trie()

    def load(self, loader: Loader):
        global SERVERSTARTED

        if current_process().name == 'MainProcess' and not SERVERSTARTED:
            print("TWICE?")
            self.vulnerabilityServerProcess = Process(target=startDashboardServer, args=(telemetryQueue,))
            self.vulnerabilityServerProcess.start()
            SERVERSTARTED = True
            print("Vulnerability Dashboard Server started on http://localhost:9999")

    

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
                        b"true", 
                        {   
                            "Content-Type": "text/plain", 
                            "Access-Control-Allow-Origin": "*"
                        }
                    )

                    if WebStorageAnalyzer.lastWebStorageDump == None:
                        WebStorageAnalyzer.lastWebStorageDump = jsonParsed
                    elif WebStorageAnalyzer.lastWebStorageDump == jsonParsed: # if the storage dump is the same as the last one, don't run the secrets scan
                        log.debug("Skipping secrets evaluation")
                        return


                    safeswitch = 0
                    for webStorageType in jsonParsed:
                        safeswitch += 1
                        log.debug(f"EVALUATING {webStorageType}")
                        
                        webStorageDumpItem = json.dumps(dict(jsonParsed[webStorageType].items()))
                        SecretsScanner.lookForSecrets(flow, webStorageDumpItem)
                        #     if safeswitch > 200:
                        #         break
                        # if safeswitch > 200:
                        #         break

                except Exception as e:
                    log.error(f"Failed to process web storage dump: {e}")

        return

    
    def response(self, flow: http.HTTPFlow):
        # if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
        #     return

        print("") # for newline before each new request/response log
        log.metadata(f"[{flow.request.method}] ({flow.response.status_code}) {flow.request.url} {flow.response.headers.get("Content-Type", "")}")

        CookiesAnalyzer.evaluateSETCOOKIES(flow)
        HeadersAnalyzer.analyzeHeaders(flow)
        WebStorageAnalyzer.analyzeWebStorage(flow)
        SecretsScanner.lookForSecrets(flow)

        # ---------------------------------JWT ANALYSIS----------------------------------------
        # From Authorization header
        AUTHORIZATION = flow.request.headers.get("Authorization", "")
        if AUTHORIZATION.startswith("Bearer "):
            log.debug("Evaluating JWT from the Authorization header")
            JWTAnalyzer.evaluateJWT(AUTHORIZATION.split(" ")[1], flow)

        # From Cookie header
        matches = re.findall("token=((?:[a-zA-Z0-9_-]+\\.){2}[a-zA-Z0-9_-]+)", flow.request.headers.get("Cookie", ""))
        if len(matches) != 0 and matches[0] is not None:
            log.debug("Evaluating JWT from the Cookie header")
            JWTAnalyzer.evaluateJWT(matches[0], flow)

    def done(self):
        if current_process().name == 'MainProcess' and self.server_process:
            self.server_process.terminate()
            self.server_process.join()

        if self.activeGitLeaksProcesses:
            for process in list(self.activeGitLeaksProcesses):
                if process.returncode is None:  # if still running
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass



























        # if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
        #     return
        # for runningHashcat in JWTAnalyzer.runningHashcats:
        #     if runningHashcat["isRunning"] == 0:
        #         continue

        #     return_code = runningHashcat["process"].poll()

        #     if return_code is None:
        #         print("Still running...")
        #     else:
        #         # stdout, stderr = runningHashcat["process"].communicate()
        #         print("Finished with code:", return_code)

        #         print(runningHashcat["process"].stdout.read())
        #         # if "Cracked" in stdout:
        #         #     print("HURRAYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY")
        #         runningHashcat["isRunning"] = 0

        
        # if flow.request.scheme == "http" and (AUTHORIZATION != "" or flow.request.headers.get("Cookie", "") != ""):
        #     Helpers.vulnerabilityFound(f'Sensitive data ({flow.request.headers.get("Authorization", "")} {flow.request.headers.get("Cookie", "")}) being sent over the insecure HTTP protocol')
        
       
        


addons = [SessionAnalyzer()]