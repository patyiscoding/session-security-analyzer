import uuid
import asyncio
import uvicorn
import json
from queue import Empty
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from multiprocessing import Queue
from urllib.parse import urlparse, urlunparse
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware

telemetryQueue = Queue()
lastSentState = {}
CHUNKSIZE = 10
connectedClients = set() 

def normalize_url(url_string: str) -> str:
    """Normalize URL by removing query parameters and fragments.
    
    This treats https://example.com/path?a=1 and https://example.com/path?b=2 as the same.
    """
    try:
        parsed = urlparse(url_string)
        # Reconstruct URL without query string and fragment
        normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        return normalized
    except Exception:
        return url_string

def deduplicateVulnerabilities(data: dict) -> dict:
    """Deduplicate vulnerabilities by normalizing URLs in keys.
    
    Merges vulnerabilities from URLs that differ only in query parameters.
    """
    if not isinstance(data, dict):
        return data
    
    deduplicated = {}
    for url, vuln_data in data.items():
        normalized_url = normalize_url(url)
        
        if normalized_url not in deduplicated:
            deduplicated[normalized_url] = vuln_data
        else:
            # Merge vulnerability data for duplicate URLs
            if isinstance(vuln_data, dict) and isinstance(deduplicated[normalized_url], dict):
                deduplicated[normalized_url].update(vuln_data)
            elif isinstance(vuln_data, list) and isinstance(deduplicated[normalized_url], list):
                deduplicated[normalized_url].extend(vuln_data)
    
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

@app.websocket("/vulnerabilityStream")
async def websocket_vulnerabilityStream(websocket: WebSocket):
    global lastSentState
    
    await websocket.accept()
    connectedClients.add(websocket)
    print(f"Client connected via WebSocket. Total clients: {len(connectedClients)}")
    
    try:
        clientState = {}
        
        while True:
            try:
                # Non-blocking get with timeout
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
                
                for i in range(0, len(deltaKeys), CHUNKSIZE):
                    chunk = {k: delta[k] for k in deltaKeys[i:i+CHUNKSIZE]}
                    
                    message = {
                        "type": eventType,
                        "data": chunk,
                        "metadata": {"vulnerabilities": len(currentState), "warnings": 0}
                    }
                    
                    print(f"Sending {eventType} message with {len(chunk)} entries")
                    await websocket.send_json(message)
                
                # Update client state
                clientState = currentState.copy()
                
            except Empty:
                # Queue is empty, continue waiting
                await asyncio.sleep(0.1)
            except Exception as e:
                print(f"Error in WebSocket loop: {type(e).__name__}: {str(e)}")
                await asyncio.sleep(0.1)
    
    except WebSocketDisconnect:
        print("Client disconnected via WebSocket")
        connectedClients.discard(websocket)
    except Exception as e:
        print(f"WebSocket error: {type(e).__name__}: {str(e)}")
        connectedClients.discard(websocket)


def startDashboardServer(queueInstance):
    global telemetryQueue
    telemetryQueue = queueInstance
    uvicorn.run(app, host="0.0.0.0", port=9999, log_level="warning")