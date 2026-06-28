from helpers.log import log
import re
from dateutil import parser
from datetime import datetime, timedelta, timezone
import time

class CookiesAnalyzer:
    def __init__(self, Helpers, SessionAnalyzer):
        self.SessionAnalyzer = SessionAnalyzer
        self.Helpers = Helpers

    cookiesEvaluated = set()

    def evaluateSetCookies(self, flow):
        log.debug("EVALUATING SETCOOKIE")
        
        # start_time = time.time()
        SETCOOKIES = flow.response.headers.get_all("Set-Cookie")
        if len(SETCOOKIES) == 0:
            return

        log.info(f"Set-Cookie header(s) found: {SETCOOKIES}. Evaluating...")

        for cookieHeader in SETCOOKIES:
            if cookieHeader in CookiesAnalyzer.cookiesEvaluated:
                continue
            
            CookiesAnalyzer.cookiesEvaluated.add(cookieHeader)

            # Covering the case insensitive nature of cookie attributes
            cookie = cookieHeader.lower()

            cookieName = cookie.split("=")[0].strip()

            # Checking if the cookie is sensitive for context awareness
            isSensitive = any(sensitiveCookieName in cookie for sensitiveCookieName in ["sess", "auth", "token", "jwt", "id", "user"])

            # HttpOnly, Secure, SameSite
            if "httponly" not in cookie:
                self.Helpers.logWarning(flow, f"Cookie {cookieName}: No HttpOnly attribute found. This cookie can be retrieved via JavaScript!", flow.request.url)
               

            if "secure" not in cookie:
                if isSensitive:
                    self.Helpers.logVulnerability(flow, f"Cookie {cookieName}: No Secure attribute found. This cookie will be sent over unencrypted connections!", flow.request.url)
                else:
                    self.Helpers.logWarning(flow, f"Cookie {cookieName}: No Secure attribute found. This cookie will be sent over unencrypted connections!", flow.request.url)
            
            if "samesite=none" in cookie:
                if "secure" not in cookie:
                    self.Helpers.logWarning(flow, f"Cookie {cookieName}: Attribute SameSite is set to None but no Secure attribute set.", flow.request.url)
            
            
            if "expires=" in cookie or "max-age=" in cookie:
                if len(cookie.split("expires=")) != 2:
                    return
                
                expiresDate = cookie.split("expires=")[1].split(";")[0].strip()
                    
                now = datetime.now(timezone.utc)

                try:
                    dt = datetime.strptime(expiresDate, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                except ValueError:
                    dt = datetime.strptime(expiresDate, "%a, %d-%b-%Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                    
                if dt > now + timedelta(days=30) or dt <= now:
                    self.Helpers.logWarning(flow, f"Cookie {cookieName}'s expiry date is in the past or more than 30 days in the future ({dt - now})", flow.request.url)
                    
        
        # print("COOKIESANALYZER, SET COOKIE: --- %s seconds ---" % (time.time() - start_time))
        # self.SessionAnalyzer.timings["cookies"]["time"].append(time.time() - start_time)