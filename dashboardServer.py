import asyncio
import uvicorn
import json
from queue import Empty
from helpers.log import log
from fastapi import FastAPI, Request
from multiprocessing import Queue
from urllib.parse import urlparse, urlunparse
from fastapi.responses import JSONResponse, Response
from sse_starlette.sse import EventSourceResponse
from fastapi.middleware.cors import CORSMiddleware
import uuid

CHUNK_SIZE = 500
lastSentState = {}
telemetryQueue = Queue()

# def normalize_url(url_string: str) -> str:
#     """Normalize URL by removing query parameters and fragments.
    
#     This treats https://example.com/path?a=1 and https://example.com/path?b=2 as the same.
#     """
#     try:
#         parsed = urlparse(url_string)
#         # Reconstruct URL without query string and fragment
#         normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
#         return normalized
#     except Exception:
#         return url_string

def deduplicateVulnerabilities(data: dict) -> dict:
    """Deduplicate vulnerabilities by normalizing URLs in keys.
    
    Merges vulnerabilities from URLs that differ only in query parameters.
    """
    deduplicated = {}
    for url, vuln_data in data.items():
        if url not in deduplicated:
            deduplicated[url] = vuln_data
        else:
            # Merge vulnerability data for duplicate URLs
            if isinstance(vuln_data, dict) and isinstance(deduplicated[url], dict):
                deduplicated[url].update(vuln_data)
            elif isinstance(vuln_data, list) and isinstance(deduplicated[url], list):
                deduplicated[url].extend(vuln_data)
    
    return deduplicated

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)

@app.options("/vulnerabilityStream")
async def OPTIONSVulnerabilityStream():
    return Response(status_code=200)

@app.get("/health")
async def health():
    """Health check endpoint"""
    return JSONResponse({"status": "ok"})

@app.get("/vulnerabilityStream")
async def vulnerabilityStream(request: Request):
    """SSE endpoint for streaming vulnerabilities"""
    global lastSentState
    
    async def eventGenerator():
        log.debug("Client connected via SSE")
        clientState = {}
        
        while True:
            if await request.is_disconnected():
                log.debug("Client disconnected via SSE")
                break
            
            try:
                data = await asyncio.to_thread(telemetryQueue.get, block=True, timeout=0.5)
                
                # Parse incoming data
                if isinstance(data, str):
                    parsedData = json.loads(data)
                    # Extract only the 'data' field if it has the wrapper structure
                    rawState = parsedData.get("data", parsedData) if isinstance(parsedData, dict) and "data" in parsedData else parsedData
                else:
                    rawState = data
                
                # Deduplicate URLs
                currentState = deduplicateVulnerabilities(rawState)
                
                # Calculate delta for this client
                allKeys = set(currentState.keys()) | set(clientState.keys())
                delta = {}
                
                for key in allKeys:
                    if key not in clientState or currentState.get(key) != clientState.get(key):
                        if key in currentState:
                            delta[key] = currentState[key]
                
                if not delta:
                    # No changes
                    await asyncio.sleep(0.1)
                    continue
                
                # Split delta into chunks and send
                deltaKeys = list(delta.keys())
                eventType = "full" if not clientState else "delta"
                
                for i in range(0, len(deltaKeys), CHUNK_SIZE):
                    chunk = {k: delta[k] for k in deltaKeys[i:i+CHUNK_SIZE]}
                    
                    message = {
                        "type": eventType,
                        "data": chunk,
                        "metadata": {"vulnerabilities": len(currentState), "warnings": 0}
                    }
                    
                    log.debug(f"Sending {eventType} event with {len(chunk)} entries")
                    yield {
                        "id": str(uuid.uuid4()),
                        "event": "vulnerability",
                        "retry": 1500,
                        "data": json.dumps(message)
                    }
                
                # Update client state
                clientState = currentState.copy()
                
            except Empty:
                # Queue is empty, continue waiting
                await asyncio.sleep(0.1)
            except Exception as e:
                log.error(f"Error in SSE loop: {type(e).__name__}: {str(e)}")
                await asyncio.sleep(0.1)
    
    return EventSourceResponse(eventGenerator())


def startDashboardServer(queueInstance):
    global telemetryQueue
    telemetryQueue = queueInstance
    uvicorn.run(app, host="0.0.0.0", port=9998, log_level="warning")