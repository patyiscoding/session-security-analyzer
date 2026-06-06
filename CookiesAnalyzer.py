from log import log

class CookiesAnalyzer:
    cookiesEvaluated = set()

    def evaluateSETCOOKIES(setCookieHeaders) -> None:
        log.info(f"Set-Cookie header(s) found: {setCookieHeaders}. Evaluating...")

        for cookieHeader in setCookieHeaders:
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
                log.warning(f"Cookie {cookieName}: No HttpOnly attribute found. This cookie can be retrieved via JavaScript!") 

            if "secure" not in cookie:
                logLevel = log.ERROR if isSensitive else log.WARNING
                log.log(logLevel, f"Cookie {cookieName}: No Secure attribute found. This cookie will be sent over unencrypted connections!")
            
            if "samesite=none" in cookie:
                if "secure" not in cookie:
                    log.warning(f"Cookie {cookieName}: Attribute SameSite is set to None but no Secure attribute set.")
            
            # check cookie expiry