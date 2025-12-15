import os
import json
import base64
import asyncio
from aiohttp import web, WSMsgType
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# --------------------------
# ENCRYPTION CONFIG
# --------------------------
SECRET_KEY = b"this_is_32bytes_key_for_family_chat"  # exactly 32 bytes
  # 32 bytes

def encrypt_message(message: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return json.dumps({"iv": iv, "ciphertext": ct})

def decrypt_message(json_data: str) -> str:
    try:
        data = json.loads(json_data)
        iv = base64.b64decode(data["iv"])
        ct = base64.b64decode(data["ciphertext"])
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except:
        return "[DECRYPTION ERROR]"

# --------------------------
# WEBSOCKET HANDLER
# --------------------------
connected_clients = set()

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    connected_clients.add(ws)
    print("Client connected")

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                decrypted = decrypt_message(msg.data)
                encrypted_broadcast = encrypt_message(decrypted)
                # Broadcast to all other clients
                for client in connected_clients:
                    if client != ws:
                        await client.send_str(encrypted_broadcast)
            elif msg.type == WSMsgType.ERROR:
                print(f'WebSocket connection closed with exception {ws.exception()}')
    finally:
        connected_clients.remove(ws)
        print("Client disconnected")
    return ws

# --------------------------
# HTTP HEALTH CHECK
# --------------------------
async def health_check(request):
    return web.Response(text="Encrypted Chat Server is running")

# --------------------------
# MAIN APP
# --------------------------
app = web.Application()
app.router.add_get("/", health_check)       # Health check
app.router.add_get("/ws", websocket_handler)  # WebSocket path

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"Server running on http://0.0.0.0:{port} and WebSocket /ws")
    web.run_app(app, host="0.0.0.0", port=port)

