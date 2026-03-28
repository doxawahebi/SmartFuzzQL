import asyncio
import aiohttp
import json
import websockets

async def main():
    repo_url = "https://github.com/kermitt2/xpdf-3.04.git"
    api_url = "http://localhost:8000/api/jobs"
    ws_url = "ws://localhost:8000/ws"

    print(f"[*] Submitting Job for {repo_url}...")
    
    async with aiohttp.ClientSession() as session:
        async with session.post(api_url, json={"repo_url": repo_url}) as resp:
            data = await resp.json()
            print(f"[*] API Response: {data}")
            
    print(f"[*] Connecting to WebSocket: {ws_url}")
    try:
        async with websockets.connect(ws_url) as ws:
            print("[*] WebSocket connected. Listening for logs... (Press Ctrl+C to stop)")
            while True:
                msg = await ws.recv()
                try:
                    log_data = json.loads(msg)
                    stage = log_data.get('stage', 'LOG')
                    timestamp = log_data.get('timestamp', 'NOW')
                    message = log_data.get('message', msg)
                    print(f"[{timestamp}] [{stage}] {message}")
                except Exception as e:
                    print(f"[RAW WS]: {msg}")
    except Exception as e:
        print(f"[-] WebSocket Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
