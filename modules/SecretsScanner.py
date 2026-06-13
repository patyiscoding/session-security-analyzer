# import whispers
import yaml
import logging
from helpers.log import log
import re
from helpers.helpers import Helpers
import tempfile
import subprocess
import json

class SecretsScanner():
    def __init__(self):
        self.secretsPatterns = []
        with open("../third-party/awesome-regex-list/regexes.yml") as stream:
            try:
                self.secretsPatterns = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                logging.exception(exc)

    def lookForSecrets(self, content):
        matches = []

        for patternObj in self.secretsPatterns:
            log.info(f"Checking for {patternObj.get('name', '')}")
            for regex in patternObj.get('regexes', []):
                finds = re.findall(regex, str(content))
                matches.extend(finds)
        
        if len(matches) > 0:
            for match in matches:
                Helpers.vulnerabilityFound(f"Found potentially sensitive string: {match}")



    def lookForSecretsWithGitLeaks(self, text):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(text)
            path = f.name

        result = subprocess.run(
            ["gitleaks", "detect", "-s", path, "-f", "json"],
            capture_output=True,
            text=True
        )

        if result.stdout.strip():
            log.info(json.loads(result.stdout))

        return []