from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import os
import redis.asyncio as redis
from tasks import run_pipeline

app = FastAPI(title="HAST Pipeline API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development. Limit this in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class JobRequest(BaseModel):
    repo_url: str

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.on_event("startup")
async def startup_event():
    url = os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0')
    app.state.redis = redis.from_url(url)
    app.state.pubsub = app.state.redis.pubsub()
    await app.state.pubsub.subscribe("pipeline_logs")
    asyncio.create_task(redis_listener())

async def redis_listener():
    async for message in app.state.pubsub.listen():
        if message["type"] == "message":
            await manager.broadcast(message["data"].decode("utf-8"))

@app.post("/api/jobs")
async def submit_job(job: JobRequest):
    # Delegate the heavy pipeline to Celery
    task = run_pipeline.delay(job.repo_url)
    return {"message": "Job submitted successfully", "task_id": task.id}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Client payload processing can be done here
    except WebSocketDisconnect:
        manager.disconnect(websocket)
