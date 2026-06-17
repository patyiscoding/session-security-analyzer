from collections.abc import AsyncIterable, Iterable
import asyncio
import uvicorn
from multiprocessing import Process, Queue
from fastapi import FastAPI, Request
from fastapi.sse import EventSourceResponse
from fastapi.middleware.cors import CORSMiddleware
import json

telemetryQueue = Queue()

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/vulnerabilityStream") # SSE endpoint
async def vulnerabilityStream(request: Request):
    async def eventGenerator():
        while True:
            if await request.is_disconnected():
                break

            if not telemetryQueue.empty():
                data = telemetryQueue.get()
                yield {
                    "data": data
                }

            await asyncio.sleep(0.2)

    return EventSourceResponse(eventGenerator())


def startDashboardServer(queueInstance):
    global telemetryQueue
    telemetryQueue = queueInstance
    uvicorn.run(app, host="127.0.0.1", port=9999, log_level="warning")