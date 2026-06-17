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
            
        if not content:
            log.debug("Contents empty")
            return

        SecretsScanner.lookForSecretsWithRegexes(text, flow)
        asyncio.create_task((SecretsScanner.lookForSecretsWithGitLeaks(text)))
        
        
        
    def lookForSecretsWithRegexes(text, flow):
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
                Helpers.logVulnerability(f"Found potentially sensitive string: {match}", flow.request.url)


    async def lookForSecretsWithGitLeaks(text):
        try:
            log.debug("Starting GitLeaks secrets scan")
            log.debug(f"Text to analyze: {text}")

            # with tempfile.NamedTemporaryFile(mode="w", encoding='utf-8', delete=False) as f:
            #     f.write(text)
            #     path = f.name

          
            process = await asyncio.create_subprocess_exec(
                "./third-party/gitleaks.exe", "stdin", "-f", "json",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            from SessionAnalyzer import SessionAnalyzer
            SessionAnalyzer.activeGitLeaksProcesses.add(process)
            print("ACTIVE", SessionAnalyzer.activeGitLeaksProcesses)

            stdout, stderr = await process.communicate(input=text.encode('utf-8'))

            if stdout.strip():
                if len(stdout) > 500:
                        log.info("Skipping match found by SecretsScanner; length too big")
                        return
                Helpers.vulnerabilityFound(f"(GitLeaks) Found potentially sensitive string: {json.loads(stdout)}")
        except asyncio.CancelledError:
            if process and process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
        except Exception as e:
            log.error(e)
        finally:
            if process in SessionAnalyzer.activeGitLeaksProcesses:
                SessionAnalyzer.activeGitLeaksProcesses.remove(process)