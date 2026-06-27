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
                
                # Calculate delta
                allKeys = set(data.keys()) | set(clientState.keys())
                delta = {}
                
                for key in allKeys:
                    if key not in clientState or data.get(key) != clientState.get(key):
                        if key in data:
                            delta[key] = data[key]
                
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
                clientState = data.copy()
                
            except Empty:
                # Queue is empty, continue waiting
                await asyncio.sleep(0.1)
            except RuntimeError as e:
                # Handle connection errors
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