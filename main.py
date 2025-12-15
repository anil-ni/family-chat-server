import asyncio
import websockets
import json
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
from aiohttp import web

# --------------------------
# ENCRYPTION CONFIG
# --------------------------
SECRET_KEY = b"this_is_32bytes_key_for_family_chat!!"  # 32 bytes key

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
# WEBSOCKET SERVER
# --------------------------
connected_clients = set()

async def ws_handler(websocket):
    connected_clients.add(websocket)
    print("Client connected:", websocket.remote_address)
    try:
        async for encrypted_msg in websocket:
            decrypted = decrypt_message(encrypted_msg)
            encrypted_broadcast = encrypt_message(decrypted)
            for client in connected_clients:
                if client != websocket:
                    await client.send(encrypted_broadcast)
    except:
        pass
    finally:
        connected_clients.remove(websocket)
        print("Client disconnected.")

# --------------------------
# HTTP HEALTH CHECK SERVER
# --------------------------
async def http_handler(request):
    return web.Response(text="Encrypted Chat Server is running")

# --------------------------
# MAIN FUNCTION
# --------------------------
async def main():
    port = int(os.environ.get("PORT", 10000))
    print(f"Server running on ws://0.0.0.0:{port} and HTTP /")

    # HTTP server for health checks
    app = web.Application()
    app.router.add_get("/", http_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()

    # WebSocket server (no path)
    ws_server = await websockets.serve(ws_handler, "0.0.0.0", port)

    # Keep running
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
