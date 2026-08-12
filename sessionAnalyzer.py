from mitmproxy import http, ctx
from helpers.log import log
import json
from dashboardServer import startDashboardServer, vulnerabilityQueue
from multiprocessing import Process, current_process
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
from modules.SecretsScanner import SecretsScanner

SERVERSTARTED = False
analyzerInstance = None

class SessionAnalyzer:
    def __init__(self):
        self.Helpers = Helpers(SessionAnalyzer=self)
        self.CookiesAnalyzer = CookiesAnalyzer(Helpers=self.Helpers, SessionAnalyzer=self)
        self.HeadersAnalyzer = HeadersAnalyzer(Helpers=self.Helpers, SessionAnalyzer=self)
        self.JWTAnalyzer = JWTAnalyzer(Helpers=self.Helpers, SessionAnalyzer=self)
        self.SecretsScanner = SecretsScanner(Helpers=self.Helpers, SessionAnalyzer=self)
        self.WebStorageAnalyzer = WebStorageAnalyzer(SessionAnalyzer=self)
        

        self.activeGitLeaksProcesses = set()
        self.activeTasks = set()
        self.vulnerabilityScanResultsJSON = {"metadata": {"warnings": 0, "vulnerabilities": 0}, "data": {}}
        self.vulnerabilityServerProcess = None


    def load(self, loader: Loader):
        global SERVERSTARTED, analyzerInstance
        analyzerInstance = self

        loader.add_option(name="useAttackMode", typespec=bool, default=False, help="Whether the script is to be run in attack mode")
        loader.add_option(name="localhostOnly", typespec=bool, default=True, help="Whether the script is to be run against localhost only")

        if current_process().name == 'MainProcess' and not SERVERSTARTED:
            self.vulnerabilityServerProcess = Process(target=startDashboardServer, args=(vulnerabilityQueue,))
            self.vulnerabilityServerProcess.start()
            SERVERSTARTED = True
            log.info("Vulnerability Dashboard Server started on http://localhost:9999")

        try:
            def signal_handler(signum, frame):
                log.info("Received interrupt signal, shutting down...")
                if analyzerInstance:
                    analyzerInstance.done()
            
            signal.signal(signal.SIGINT, signal_handler)
        except Exception as e:
            log.warning(f"Failed to set up signal handler: {e}")
    
    def configure(self, options):
        log.info(f"Use Attack mode?: {ctx.options.useAttackMode}")
        log.info(f"localhost only?: {ctx.options.localhostOnly}")

    def server_connect(self, data):
        if os.environ.get("RUNNING_IN_DOCKER") != "true":
            return

        host, port = data.server.address
        if host in ("localhost", "127.0.0.1", "::1"):
            data.server.address = ("host.docker.internal", port)

    def request(self, flow: http.HTTPFlow):
        if ctx.options.localhostOnly == True and "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
            return
        
        # skip WebSocket upgrade requests and CONNECT
        if flow.request.method == "CONNECT" or flow.request.headers.get("Upgrade", "").lower() == "websocket":
            log.debug(f"Skipping {flow.request.method} request to {flow.request.url}")
            return
        
        if ":5173" in flow.request.url or ":5174" in flow.request.url or ":8080" in flow.request.url or ":9999" in flow.request.url: # if the request is coming from the dashboard frontend, ignore it
            return

        # disable cache
        if "If-None-Match" in flow.request.headers:
            del flow.request.headers["If-None-Match"]
            
        if "If-Modified-Since" in flow.request.headers:
            del flow.request.headers["If-Modified-Since"]
            
        flow.request.headers["Cache-Control"] = "no-cache"
        flow.request.headers["Pragma"] = "no-cache"


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
                        log.debug("Skipping Web Storage secrets evaluation")
                        return

                    for webStorageType in jsonParsed:
                        log.debug(f"Evaluating Web Storage Type {webStorageType}")
                        
                        webStorageDumpItem = json.dumps(dict(jsonParsed[webStorageType].items()))
                        self.SecretsScanner.lookForSecrets(flow, webStorageDumpItem, webStorageType)

                except Exception as e:
                    log.error(f"Failed to process web storage dump: {e}")

        
        if flow and flow.response and flow.request:
            flow.response.content = b"" 
            flow.request.content = b""
 
    def response(self, flow: http.HTTPFlow):
        if ctx.options.localhostOnly == True and "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
            return
        
        if ":5173" in flow.request.url or ":5174" in flow.request.url or ":8080" in flow.request.url or ":9999" in flow.request.url: # if the request is coming from the dashboard frontend, ignore it
            return

        if "Active-Attack" in flow.request.headers.get("X-Attack", ""):
            self.JWTAnalyzer.evaluateAttackResponse(flow, flow.request.headers.get("X-Attack"))
            return

        self.Helpers.printResponse(flow)
        self.CookiesAnalyzer.evaluateSetCookies(flow)
        self.HeadersAnalyzer.analyzeHeaders(flow)
        self.WebStorageAnalyzer.analyzeWebStorage(flow)
        self.SecretsScanner.lookForSecrets(flow)
        self.JWTAnalyzer.lookForJWTs(flow)


    def done(self):
        def force_exit_timeout():
            time.sleep(5)
            log.warning("Force exiting")
            os._exit(1)
        
        failsafeThread = threading.Thread(target=force_exit_timeout, daemon=True)
        failsafeThread.start()
        
        for task in list(self.activeTasks):
            if not task.done():
                log.debug(f"Cancelling task: {task}")
                task.cancel()
        
        if current_process().name == 'MainProcess' and self.vulnerabilityServerProcess:
            log.debug("Terminating dashboard server process")
            self.vulnerabilityServerProcess.terminate()
            try:
                self.vulnerabilityServerProcess.join(timeout=1)
            except Exception as e:
                log.error(f"Error joining server process: {e}")

        # kill all active GitLeaks subprocesses
        if self.activeGitLeaksProcesses:
            log.debug("Killing GitLeaks processes")
            for process in list(self.activeGitLeaksProcesses):
                if process.returncode is None:
                    process.kill()
        
        # kill all active Hashcat subprocesses
        for hashcat_entry in self.JWTAnalyzer.runningHashcats:
            if hashcat_entry["isRunning"] == 1:
                process = hashcat_entry["process"]
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=1)
        
        log.info("Shutdown complete, force exiting")

        os._exit(0)


addons = [SessionAnalyzer()]