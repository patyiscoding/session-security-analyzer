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

CHUNKSIZE = 100
lastSentState = {}
connectedClients = set()
vulnerabilityQueue = Queue()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)

@app.get("/health")
async def health():
    return JSONResponse({"status": "ok"})

@app.options("/vulnerabilityStream")
async def OPTIONSVulnerabilityStream():
    return Response(status_code=200)

@app.websocket("/vulnerabilityStream")
async def vulnerabilityStream(websocket: WebSocket):
    global lastSentState
    
    await websocket.accept()
    connectedClients.add(websocket)
    log.debug(f"VD SERVER: Client connected via WebSocket. Total clients: {len(connectedClients)}")
    
    try:
        clientState = {}
        
        while True:
            try:
                dataObject = await asyncio.to_thread(vulnerabilityQueue.get, block=True, timeout=0.5)
                parsedDataObject = json.loads(dataObject)

                metadata = parsedDataObject.get("metadata", parsedDataObject)
                data = parsedDataObject.get("data", parsedDataObject)
            
                allKeys = set(data.keys()) | set(clientState.keys())
                delta = {}
                
                for key in allKeys:
                    if key not in clientState or data.get(key) != clientState.get(key):
                        if key in data:
                            delta[key] = data[key]
                
                if not delta:
                    await asyncio.sleep(0.1)
                    continue
                
                deltaKeys = list(delta.keys())
                eventType = "full" if not clientState else "delta"
                
                for i in range(0, len(deltaKeys), CHUNKSIZE):
                    chunk = {k: delta[k] for k in deltaKeys[i:i+CHUNKSIZE]}
                    
                    message = {
                        "type": eventType,
                        "data": chunk,
                        "metadata": metadata
                    }
                    
                    log.debug(f"VD SERVER: Sending {eventType} message with {len(chunk)} entries")
                    try:
                        await websocket.send_json(message)
                    except RuntimeError as e:
                        if "close message has been sent" in str(e):
                            print("WebSocket connection closed, stopping transmission")
                            break
                        raise
                
                clientState = data.copy()
                
            except Empty:
                # queue is empty, continue waiting
                await asyncio.sleep(0.1)
            except RuntimeError as e:
                # handle connection errors
                if "close message has been sent" in str(e) or "closed" in str(e).lower():
                    print("WebSocket connection closed, exiting loop")
                    break
                else:
                    print(f"RuntimeError in WebSocket loop: {str(e)}")
                    await asyncio.sleep(0.1)
            except Exception as e:
                log.error(f"VD SERVER: Error in WebSocket loop: {type(e).__name__}: {str(e)}")
                await asyncio.sleep(0.1)
    
    except WebSocketDisconnect:
        log.debug("VD SERVER: Client disconnected via WebSocket")
        connectedClients.discard(websocket)
    except Exception as e:
        log.error(f"VD SERVER: WebSocket error: {type(e).__name__}: {str(e)}")
        connectedClients.discard(websocket)


def startDashboardServer(queueInstance):
    global vulnerabilityQueue
    vulnerabilityQueue = queueInstance
    uvicorn.run(app, host="0.0.0.0", port=9998, log_level="warning")