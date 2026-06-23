import asyncio
import uvicorn
import json
from queue import Empty
from helpers.log import log
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from multiprocessing import Queue
from urllib.parse import urlparse, urlunparse
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware

CHUNKSIZE = 10
lastSentState = {}
connectedClients = set()
telemetryQueue = Queue()

def normalize_url(url_string: str) -> str:
    """Normalize URL by removing query parameters and fragments.
connectedClients = set()
telemetryQueue = Queue()

# def normalize_url(url_string: str) -> str:
    
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

@app.websocket("/vulnerabilityStream")
async def vulnerabilityStream(websocket: WebSocket):
    global lastSentState
    
    await websocket.accept()
    connectedClients.add(websocket)
    log.debug(f"Client connected via WebSocket. Total clients: {len(connectedClients)}")
    
    try:
        clientState = {}
        
        while True:
            try:
                dataObject = await asyncio.to_thread(telemetryQueue.get, block=True, timeout=0.5)
             
                parsedDataObject = json.loads(dataObject)
                # Extract only the 'data' field if it has the wrapper structure
                metadata = parsedDataObject.get("metadata", parsedDataObject)
                data = parsedDataObject.get("data", parsedDataObject)
             
                # Deduplicate URLs
                currentState = deduplicateVulnerabilities(data)
                
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
                        "metadata": metadata
                    }
                    
                    log.debug(f"Sending {eventType} message with {len(chunk)} entries")
                    try:
                        await websocket.send_json(message)
                    except RuntimeError as e:
                        # Connection closed, exit the loop
                        if "close message has been sent" in str(e):
                            print("WebSocket connection closed, stopping transmission")
                            break
                        raise
                
                # Update client state
                clientState = currentState.copy()
                
            except Empty:
                # Queue is empty, continue waiting
                await asyncio.sleep(0.1)
            except RuntimeError as e:
                # Handle connection errors (including "close message has been sent")
                if "close message has been sent" in str(e) or "closed" in str(e).lower():
                    print("WebSocket connection closed, exiting loop")
                    break
                else:
                    print(f"RuntimeError in WebSocket loop: {str(e)}")
                    await asyncio.sleep(0.1)
            except Exception as e:
                log.error(f"Error in WebSocket loop: {type(e).__name__}: {str(e)}")
                await asyncio.sleep(0.1)
    
    except WebSocketDisconnect:
        log.debug("Client disconnected via WebSocket")
        connectedClients.discard(websocket)
    except Exception as e:
        log.error(f"WebSocket error: {type(e).__name__}: {str(e)}")
        connectedClients.discard(websocket)


def startDashboardServer(queueInstance):
    global telemetryQueue
    telemetryQueue = queueInstance
    uvicorn.run(app, host="0.0.0.0", port=9998, log_level="warning")