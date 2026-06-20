import uuid
import asyncio
import uvicorn
from multiprocessing import Process, Queue
from fastapi import FastAPI, Request
from collections.abc import AsyncIterable, Iterable
from sse_starlette.sse import EventSourceResponse
from fastapi.middleware.cors import CORSMiddleware

telemetryQueue = Queue()

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/vulnerabilityStream") # SSE endpoint
async def vulnerabilityStream(request: Request):
    async def eventGenerator():
        print("Client connected")  
        while True:
            if await request.is_disconnected():
                print("Client disconnected")  #
                break

            if not telemetryQueue.empty():
                try:
                    data = await asyncio.to_thread(telemetryQueue, True, 0.15)
                    
                    yield {
                        "id": str(uuid.uuid4()),
                        "event": "vulnerability",
                        "retry": 1500,
                        "data": data
                    }
                except Exception:
                    pass

    return EventSourceResponse(eventGenerator())


def startDashboardServer(queueInstance):
    global telemetryQueue
    telemetryQueue = queueInstance
    uvicorn.run(app, host="127.0.0.1", port=9999, log_level="warning")