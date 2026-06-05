from mitmproxy import http
import logging
import re
import json
import jwt


class SessionAnalyzer:
    def request(self, flow: http.HTTPFlow):
        if "localhost" not in flow.request.pretty_host and "127.0.0.1" not in flow.request.pretty_host:
            return

        CORS = flow.request.headers.get("Access-Control-Allow-Origin")
        if CORS is not None:
            logging.info(f"CORS headers {CORS}")

       

        logging.info("ALL HEADERS", flow.request.headers)

        AUTHORIZATION = flow.request.headers.get("Authorization ")
        if AUTHORIZATION and AUTHORIZATION.startswith("Bearer "):
            self.evaluateJWT(AUTHORIZATION.split(" ")[1], flow)

        if not AUTHORIZATION:
            matches = re.findall("token=((?:[a-zA-Z0-9_-]+\\.){2}[a-zA-Z0-9_-]+)", flow.request.headers.get("Cookie"))
            logging.info("MATCH")
            logging.info(matches)
            if matches[0] is not None:
                self.evaluateJWT(matches[0], flow)

        

    def response(self, flow):
        SETCOOKIES = flow.response.headers.get_all("Set-Cookie")
        if SETCOOKIES is not None:
            self.evaluateSETCOOKIES(SETCOOKIES)
        return


    def evaluateSETCOOKIES(self, setCookieHeaders) -> None:
        logging.info(f"Set-Cookie header(s) found. Evaluating...")

        for setCookieHeader in setCookieHeaders:
            # Covering the case insensitive nature of cookie attributes
            cookie = setCookieHeader.lower()

            cookieName = cookie.split("=")[0].strip()

            # Checking if the cookie is sensitive for context awareness
            isSensitive = any(sensitiveCookieName in cookie for sensitiveCookieName in ["sess", "auth", "token", "jwt", "id", "user"])

            # HttpOnly, Secure, SameSite
            if "httponly" not in cookie:
                logging.warning(f"Cookie {cookieName}: No HttpOnly attribute found. This cookie can be retrieved via JavaScript!") 

            if "secure" not in cookie:
                logLevel = logging.ERROR if isSensitive else logging.WARNING
                logging.log(logLevel, f"Cookie {cookieName}: No Secure attribute found. This cookie will be sent over unencrypted connections!")
            
            if "samesite=none" in cookie:
                if "secure" not in cookie:
                    logging.warning(f"Cookie {cookieName}: Attribute SameSite is set to None but no Secure attribute set.")
            
            # check cookie expiry


    def evaluateJWT(self, JWT, flow):
        logging.info(f"JWT extracted for path {flow.request.path}: {JWT}. Evaluating...")

        try:
            unverifiedHeader = jwt.get_unverified_header(JWT)
            unverifiedPayload = jwt.decode(JWT, options={"verify_signature": False})

            # --- TEST 1: The 'none' Algorithm Vulnerability ---
            # Attackers can change 'alg' to 'none', remove the signature, and forge data.
            alg = unverifiedHeader.get("alg", "").lower()
            if alg == "none":
                logging.warning(f"JWT 'none' algorithm is accepted/used by the client!")

            # TODO: carry it out

            # --- TEST 2: Weak/Insecure Signature Algorithms ---
            # Symmetric algorithms (like HS256) are prone to brute-forcing if secrets are weak.
            # Asymmetric (like RS256) is safer. If HS256 is used, flag it for manual review.
            if alg == "hs256":
                logging.warning(f"JWT uses symmetric HS256. Risk of secret brute-forcing.")

            # --- TEST 3: Sensitive Information Leakage in Payload ---
            # JWT payloads are NOT encrypted; they are only base64 encoded. anyone can read them.
            sensitiveKeywords = ["password", "secret", "ssn", "role", "admin"]
            payload_string = json.dumps(unverifiedPayload).lower()
            
            for keyword in sensitiveKeywords:
                if keyword in payload_string:
                    logging.warning(f"Potential sensitive data leakage; JWT Payload contains keyword '{keyword}': {unverifiedPayload}")

            # change role to admin
            #if hs256, then compute hashes using hashcat
            # if rs256, algorithm confusion

            # --- TEST 4: Missing Expiration (No 'exp' claim) ---
            # If a token never expires, a stolen token is valid forever.
            if "exp" not in unverifiedPayload:
                logging.warning(f"JWT is missing an expiration timestamp ('exp' claim)")

            #lack of signature verification

        except Exception as e:
            logging.error(e)
            pass

        return



    def evaluateCORS():
        # 
        return


addons = [SessionAnalyzer()]    