from helpers.log import log
import json
from mitmproxy import http
from bs4 import BeautifulSoup
import time

class WebStorageAnalyzer:
    def __init__(self, SessionAnalyzer):
            self.SessionAnalyzer = SessionAnalyzer

    webStorageEndpoint = "webStorageDump"
    lastWebStorageDump = None

    def isHTMLResponse(self, flow):
        if "text/html" in flow.response.headers.get("Content-Type", ""):
            return True

        bytes = flow.response.raw_content
        
        if bytes:
            strippedBytes = bytes.lstrip()[:50].lower()
            
            if (
                strippedBytes.startswith(b"<!--") or 
                strippedBytes.startswith(b"<!doctype html") or 
                strippedBytes.startswith(b"<html") or 
                strippedBytes.startswith(b"<head") or 
                strippedBytes.startswith(b"<body")
            ):
                return True
        return False

    def analyzeWebStorage(self, flow):
        # start_time = time.time()

        log.debug(f"EVALUATING WEB STORAGE {self.isHTMLResponse(flow)}")
        if flow.response and self.isHTMLResponse(flow):
            log.debug("INJECTING")
            HTML = flow.response.text
            
            if len(HTML) > 10_000_000:  # >10MB
                log.warning(f"Skipping Web Storage analysis: HTML too large ({len(HTML)/1024/1024:.1f}MB)")
                return
                
            JSPayload = f"""
                <script type="module">
                    let webStorageData = {{
                        'localStorage': {{}}, 
                        'sessionStorage': {{}}, 
                        'indexedDB': {{}}
                    }}

                    if(localStorage.length > 0){{
                        for (let i = 0; i < localStorage.length; i++) {{
                            let key = localStorage.key(i);
                            webStorageData['localStorage'][key] = localStorage.getItem(key);
                        }}}}


                    if(sessionStorage.length > 0){{
                        for (let i = 0; i < sessionStorage.length; i++) {{
                            let key = sessionStorage.key(i);
                            webStorageData['sessionStorage'][key] = sessionStorage.getItem(key);
                        }}
                    }}

                    const dbs = await indexedDB.databases();

                    for (const dbInfo of dbs) {{
                            console.log("DB:", dbInfo.name);

                            const request = indexedDB.open(dbInfo.name);

                            request.onsuccess = (event) => {{
                                const db = event.target.result;
                                const storeNames = Array.from(db.objectStoreNames);

                                webStorageData['indexedDB'][dbInfo.name] = {{}};
                                
                                for (const storeName of storeNames) {{
                                    const getAll = db.transaction(storeName, 'readonly').objectStore(storeName).getAll();
                                    getAll.onsuccess = () => {{
                                        webStorageData['indexedDB'][dbInfo.name][storeName] = getAll.result
                                    }}
                                }}   
                            }};

                            request.onerror = function(event){{
                                console.log("Database not created " + event.target.errorCode);
                            }}
                        }}

                    fetch("http://127.0.0.1:8080/webStorageDump", {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify(webStorageData)
                        }}).catch(err => console.error("Mitmproxy telemetry failure:", err));
                </script>"""
            
            if "<head>" in HTML:
                modified = HTML.replace("<head>", f"<head>\n{JSPayload}", 1)
                flow.response.set_text(modified)
                log.info(f"Injected web storage script at path {flow.request.url}")
            else:
                log.info(f"Failed to inject web storage script at path {flow.request.url}. No <head> tag.")
        
        # print("WEBSTORAGEANALYZER, ANALYZEWEBSTORAGE: --- %s seconds ---" % (time.time() - start_time))
        # self.SessionAnalyzer.timings["webstorage"]["time"].append(time.time() - start_time)