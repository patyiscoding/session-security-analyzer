from mitmproxy import http, ctx
from helpers.log import log
import json
from collections import defaultdict
from dashboardServer import startDashboardServer, telemetryQueue
from multiprocessing import Process, Queue, current_process
from mitmproxy.addonmanager import Loader
import signal
import os
import threading
import time
from helpers.helpers import Helpers
from modules.CookiesAnalyzer import CookiesAnalyzer
from modules.HeadersAnalyzer import HeadersAnalyzer
from modules.JWTAnalyzer import JWTAnalyzer
from modules.WebStorageAnalyzer import WebStorageAnalyzer
import statistics
from modules.SecretsScanner import SecretsScanner

SERVERSTARTED = False
_analyzer_instance = None

class SessionAnalyzer:
    def __init__(self):
        self.Helpers = Helpers(SessionAnalyzer=self)
        self.CookiesAnalyzer = CookiesAnalyzer(Helpers=self.Helpers, SessionAnalyzer=self)
        self.HeadersAnalyzer = HeadersAnalyzer(Helpers=self.Helpers, SessionAnalyzer=self)
        self.JWTAnalyzer = JWTAnalyzer(Helpers=self.Helpers, SessionAnalyzer=self)
        self.SecretsScanner = SecretsScanner(Helpers=self.Helpers, SessionAnalyzer=self)
        self.WebStorageAnalyzer = WebStorageAnalyzer(SessionAnalyzer=self)
        

    activeGitLeaksProcesses = set()
    activeTasks = set()
    vulnerabilityScanResultsJSON = {
        "metadata": {},
        "data": {}
    }
    vulnerabilityServerProcess = None
    # timings = {
    #     "cookies": {"time": []},
    #     "headers": {"time": []},
    #     "jwt": {"time": []},
    #     "secrets": {"time": []},
    #     "webstorage": {"time": []}
    #     }
    

    def load(self, loader: Loader):
        global SERVERSTARTED, _analyzer_instance
        _analyzer_instance = self

        loader.add_option(
            name="useAttackMode",
            typespec=bool,
            default=False,
            help="Whether the script is to be run in attack mode",
        )

        if current_process().name == 'MainProcess' and not SERVERSTARTED:
            SessionAnalyzer.vulnerabilityServerProcess = Process(target=startDashboardServer, args=(telemetryQueue,))
            SessionAnalyzer.vulnerabilityServerProcess.start()
            SERVERSTARTED = True
            log.info("Vulnerability Dashboard Server started on http://localhost:9998")

        try:
            def signal_handler(signum, frame):
                log.info("Received interrupt signal, shutting down...")
                if _analyzer_instance:
                    _analyzer_instance.done()
            
            signal.signal(signal.SIGINT, signal_handler)
        except Exception as e:
            log.warning(f"Failed to set up signal handler: {e}")
    
    def configure(self, options):
        if "useAttackMode" in options:
            ctx.log.info(f"Use Attack mode?: {ctx.options.useAttackMode}")

    def request(self, flow: http.HTTPFlow):
        # if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
        #     return
        
        # Skip WebSocket upgrade requests and CONNECT tunnels (for proxied WebSocket connections)
        if flow.request.method == "CONNECT" or flow.request.headers.get("Upgrade", "").lower() == "websocket":
            log.debug(f"Skipping {flow.request.method} request to {flow.request.url}")
            return
        
        # if ":5173" in flow.request.url or ":8080" in flow.request.url or ":9998" in flow.request.url or ":9999" in flow.request.url: # if the request is coming from the dashboard frontend, ignore it
        #     return
        
        start = time.perf_counter()

        if self.WebStorageAnalyzer.webStorageEndpoint in flow.request.url:
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
                    
                    flow.response = http.Response.make(
                        200, 
                        b"true", 
                        {   
                            "Content-Type": "text/plain", 
                            "Access-Control-Allow-Origin": "*"
                        }
                    )

                    if self.WebStorageAnalyzer.lastWebStorageDump == None:
                        self.WebStorageAnalyzer.lastWebStorageDump = jsonParsed
                    elif self.WebStorageAnalyzer.lastWebStorageDump == jsonParsed: # if the storage dump is the same as the last one, don't run the secrets scan
                        log.debug("Skipping secrets evaluation")
                        return

                    for webStorageType in jsonParsed:
                        log.debug(f"EVALUATING {webStorageType}")
                        
                        webStorageDumpItem = json.dumps(dict(jsonParsed[webStorageType].items()))
                        self.SecretsScanner.lookForSecrets(flow, webStorageDumpItem)

                except Exception as e:
                    log.error(f"Failed to process web storage dump: {e}")

        elapsed = time.perf_counter() - start
        if elapsed > 0.05: # slower than 50ms
            print(f"SLOW REQUEST: {flow.request.method} {flow.request.url}")
            print(f"Time: {elapsed*1000:.1f}ms")

    
    def response(self, flow: http.HTTPFlow):
        # if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
        #     return
        
        if ":5173" in flow.request.url or ":8080" in flow.request.url or ":9998" in flow.request.url or ":9999" in flow.request.url: # if the response is coming from the dashboard frontend, ignore it
            return
        
        start = time.perf_counter()

  

        self.Helpers.printResponse(flow)

        self.CookiesAnalyzer.evaluateSetCookies(flow)
        self.HeadersAnalyzer.analyzeHeaders(flow)
        self.WebStorageAnalyzer.analyzeWebStorage(flow)
        self.SecretsScanner.lookForSecrets(flow)
        self.JWTAnalyzer.lookForJWTS(flow)

        elapsed = time.perf_counter() - start
        if elapsed > 0.05: # slower than 50ms
            print(f"SLOW RESPONSE: {flow.request.method} {flow.request.url}")
            print(f"Time: {elapsed * 1000:.1f}ms")
    
        # print("")
        # print(f"REQUESTS ANALYZED: {len(self.timings.get("headers").get("time", 0))}")
        # print(f"WEBSTORAGE AVERAGE: {statistics.mean(self.timings.get("webstorage").get("time", 0))}")
        # print(f"JWT AVERAGE: {statistics.mean(self.timings.get("jwt").get("time"))}")
        # print(f"HEADERS AVERAGE: {statistics.mean(self.timings.get("headers").get("time"))}")
        # print(f"SECRETS AVERAGE: {statistics.mean(self.timings.get("secrets").get("time"))}")
        # print(f"COOKIES AVERAGE: {statistics.mean(self.timings.get("cookies").get("time", 0))}")

        

    def done(self):
        def force_exit_timeout():
            time.sleep(5)
            log.warning("Force exiting")
            os._exit(1)
        
        failsafe_thread = threading.Thread(target=force_exit_timeout, daemon=True)
        failsafe_thread.start()
        
        for task in list(SessionAnalyzer.activeTasks):
            if not task.done():
                log.debug(f"Cancelling task: {task}")
                task.cancel()
        
        if current_process().name == 'MainProcess' and SessionAnalyzer.vulnerabilityServerProcess:
            log.debug("Terminating dashboard server process")
            SessionAnalyzer.vulnerabilityServerProcess.terminate()
            try:
                SessionAnalyzer.vulnerabilityServerProcess.join(timeout=1)
            except Exception as e:
                log.error(f"Error joining server process: {e}")

        # Kill all active GitLeaks asyncio subprocesses
        if SessionAnalyzer.activeGitLeaksProcesses:
            log.debug("Killing GitLeaks processes")
            for process in list(SessionAnalyzer.activeGitLeaksProcesses):
                try:
                    if process.returncode is None:
                        process.kill()
                except Exception as e:
                    log.debug(f"Error killing gitleaks process: {e}")
        
        # Kill all active Hashcat subprocesses
        for hashcat_entry in self.JWTAnalyzer.runningHashcats:
            if hashcat_entry["isRunning"] == 1:
                process = hashcat_entry["process"]
                try:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=1)
                except Exception as e:
                    log.debug(f"Error killing hashcat process: {e}")
        
        log.info("Shutdown complete, force exiting")

        os._exit(0)



























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