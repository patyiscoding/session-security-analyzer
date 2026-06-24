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
            if (("text/html" in ct or "application/json" in ct or "text/plain" in ct or "text/javascript") and len(text) > 0):
                pass
            elif hasattr(flow.response, "path") and str(flow.response.path).endswith(".js"):
                pass
            elif ct is None:
                pass
            else:
                return
            
        if not text:
            log.debug("Contents for secrets scanning are empty")
            return

        if len(text) > 5_000_000:
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
                if len(match) > 500:
                    log.info("Skipping match found by SecretsScanner; length too big")
                    continue
                self.Helpers.logVulnerability(flow, f"Found potentially sensitive string: {match}", flow.request.url)


    async def lookForSecretsWithGitLeaks(self, flow, text):
        process = None
        try:
            log.debug("Starting GitLeaks secrets scan")

            process = await asyncio.create_subprocess_exec(
                "./third-party/gitleaks.exe", "stdin", "-f", "json",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            self.SessionAnalyzer.activeGitLeaksProcesses.add(process)
            log.info(f"Active GitLeaks processes: {len(self.SessionAnalyzer.activeGitLeaksProcesses)}")

            # Timeout to prevent hanging indefinitely
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=text.encode('utf-8')),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                log.warning("GitLeaks scan timed out after 10 seconds")
                process.kill()
                await process.wait()
                return

            if stdout.strip():
                try:
                    leaks = json.loads(stdout)
                    for leak in leaks:
                        secretValue = leak.get("Secret", "")
                        if len(secretValue) > 500:
                            log.info("Skipping match found by SecretsScanner; length too big")
                            continue
                        
                    self.Helpers.logVulnerability(flow, f"(GitLeaks) Found potentially sensitive string: {json.loads(stdout)}")
                except json.JSONDecodeError:
                    log.error("Failed to parse GitLeaks output JSON")
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
            if process:
                if process in self.SessionAnalyzer.activeGitLeaksProcesses:
                    self.SessionAnalyzer.activeGitLeaksProcesses.remove(process)