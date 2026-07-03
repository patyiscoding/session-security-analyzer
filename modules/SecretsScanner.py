# import whispers
import yaml
import logging
from helpers.log import log
import re
from helpers.helpers import Helpers
import tempfile
import subprocess
import json
from pathlib import Path
import asyncio
import os
import time
import uuid

class SecretsScanner():
    def __init__(self, Helpers, SessionAnalyzer):
        self.SessionAnalyzer = SessionAnalyzer
        self.Helpers = Helpers

    secretsPatterns = []

    SCRIPTDIR = Path(__file__).resolve().parent
    yamlPath = SCRIPTDIR / ".." / "third-party" / "awesome-regex-list" / "regexes.yml"

    with open(yamlPath) as stream:
        try:
            secretsPatterns = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logging.exception(exc)

    def lookForSecrets(self, flow, content=None):
        # start_time = time.time()

        log.debug("EVALUATING SECRETS")
        if content:
            text = content
        else:
            text = flow.response.get_text(strict=False)
            ct = flow.response.headers.get("Content-Type", "")

            contentType = ct.lower() if ct else ""

            isJSPath = hasattr(flow.response, "path") and str(flow.response.path).endswith(".js")

            allowedTypes = ["text/html", "application/json", "text/plain", "text/javascript", "application/javascript"]

            if isJSPath or (any(t in contentType for t in allowedTypes) and len(text) > 0) or ct is None:
                pass 
            else:
                return
            
        if not text:
            log.debug("Contents for secrets scanning are empty")
            return

        if len(text) > 5_000_000: # around 5MB
            log.warning(f"Skipping secrets scan: response too large ({len(text)/1024/1024:.1f}MB)")
            return


        self.lookForSecretsWithRegexes(flow, text)
        
        try:
            task = asyncio.create_task(self.lookForSecretsWithGitLeaks(flow, text))
            self.SessionAnalyzer.activeTasks.add(task)
            task.add_done_callback(lambda t: self.SessionAnalyzer.activeTasks.discard(t))
        except RuntimeError as e:
            log.error(f"Failed to create GitLeaks task: {e}")
        
        # print("SECRETSSCANNER, LOOKFORSECRETS: --- %s seconds ---" % (time.time() - start_time))
        # self.SessionAnalyzer.timings["secrets"]["time"].append(time.time() - start_time)

        
    def lookForSecretsWithRegexes(self, flow, text):
        log.debug("Starting regex secrets scan")
        matches = []

        for patternObj in SecretsScanner.secretsPatterns:
            for regex in patternObj.get('regexes', []):
                finds = re.findall(regex, str(text))
                matches.extend(finds)
        
        if len(matches) > 0:
            for match in matches:
                if len(match) > 700:
                    log.info("Skipping match found by SecretsScanner; length too big")
                    continue
                self.Helpers.logVulnerability(flow, f"Found potentially sensitive string: {match}", flow.request.url)
        log.debug(f"Finished regex secrets scan with {len(matches)} matches")


    async def lookForSecretsWithGitLeaks(self, flow, text):
        process = None
        try:
            log.debug("Starting GitLeaks secrets scan")
            reportPath = f"gitleaks_{uuid.uuid4().hex}.json"

            process = await asyncio.create_subprocess_exec(
                "./third-party/gitleaks.exe", "stdin", "--report-format=json", f"--report-path={reportPath}",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            self.SessionAnalyzer.activeGitLeaksProcesses.add(process)
            log.info(f"Active GitLeaks processes: {len(self.SessionAnalyzer.activeGitLeaksProcesses)}")

            # timeout to prevent hanging indefinitely
            try:
                await asyncio.wait_for(
                    process.communicate(input=text.encode('utf-8')),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                log.warning("GitLeaks scan timed out after 10 seconds")
                process.kill()
                await process.wait()
                return

            if not os.path.exists(reportPath):
                return
            
            with open(reportPath, "r", encoding="utf-8") as f:
                leaks = json.load(f)

                for leak in leaks:
                    secretValue = leak.get("Secret", "")
                    description = leak.get("Description", "")
                    
                    self.Helpers.logVulnerability(flow, f"(GitLeaks) {description} {secretValue}", flow.request.url)
              
        except asyncio.CancelledError:
            log.debug("GitLeaks scan cancelled")
            if process and process.returncode is None:
                try:
                    process.kill()
                    await process.wait()
                except OSError:
                    pass
        except Exception as e:
            log.error(f"GitLeaks scan error: {e}")
        finally:
            if process and process in self.SessionAnalyzer.activeGitLeaksProcesses:
                    self.SessionAnalyzer.activeGitLeaksProcesses.remove(process)
            try:
                if os.path.exists(reportPath):
                    os.remove(reportPath)
            except OSError:
                pass