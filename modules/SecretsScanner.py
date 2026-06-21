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

class SecretsScanner():
    secretsPatterns = []

    SCRIPT_DIR = Path(__file__).resolve().parent
    yaml_path = SCRIPT_DIR / ".." / "third-party" / "awesome-regex-list" / "regexes.yml"

    with open(yaml_path) as stream:
        try:
            secretsPatterns = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logging.exception(exc)

    def lookForSecrets(flow, content=None):
        log.debug("EVALUATING SECRETS")
        if content:
            text = content
        else:
            text = flow.response.get_text(strict=False)
            ct = flow.response.headers.get("Content-Type", "")
            if not (("text/html" in ct or "application/json" in ct or "text/plain" in ct or "text/javascript") and len(text) > 0):
                return
            
        if not text:
            log.debug("Contents for secrets scanning are empty")
            return

        SecretsScanner.lookForSecretsWithRegexes(flow, text)
        
        try:
            task = asyncio.create_task(SecretsScanner.lookForSecretsWithGitLeaks(flow, text))
            from SessionAnalyzer import SessionAnalyzer
            SessionAnalyzer.activeTasks.add(task)
            task.add_done_callback(lambda t: SessionAnalyzer.activeTasks.discard(t))
        except RuntimeError as e:
            log.error(f"Failed to create GitLeaks task: {e}")
        
    def lookForSecretsWithRegexes(flow, text):
        log.debug("Starting regex secrets scan")
        matches = []

        for patternObj in SecretsScanner.secretsPatterns:
            # log.info(f"Checking for {patternObj.get('name', '')}")
            for regex in patternObj.get('regexes', []):
                finds = re.findall(regex, str(text))
                matches.extend(finds)
        
        if len(matches) > 0:
            for match in matches:
                if len(match) > 500:
                    log.info("Skipping match found by SecretsScanner; length too big")
                    continue
                Helpers.logVulnerability(flow, f"Found potentially sensitive string: {match}", flow.request.url)


    async def lookForSecretsWithGitLeaks(flow, text):
        process = None
        try:
            log.debug("Starting GitLeaks secrets scan")

            process = await asyncio.create_subprocess_exec(
                "./third-party/gitleaks.exe", "stdin", "-f", "json",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            from SessionAnalyzer import SessionAnalyzer
            SessionAnalyzer.activeGitLeaksProcesses.add(process)
            print("Active GitLeaks processes:", SessionAnalyzer.activeGitLeaksProcesses)

            # Add timeout to prevent hanging indefinitely
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
                if len(stdout) > 500:
                        log.info("Skipping match found by SecretsScanner; length too big")
                        return
                Helpers.logVulnerability(flow, f"(GitLeaks) Found potentially sensitive string: {json.loads(stdout)}")
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
                from SessionAnalyzer import SessionAnalyzer
                if process in SessionAnalyzer.activeGitLeaksProcesses:
                    SessionAnalyzer.activeGitLeaksProcesses.remove(process)