import asyncio
import websockets
import json
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64

SECRET_KEY = b"this_is_32bytes_key_for_family_chat!!"

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

connected_clients = set()

async def handler(websocket, path):
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

async def main():
    port = int(os.environ.get("PORT", 10000))
    print(f"Encrypted Chat Server Running on ws://0.0.0.0:{port}")
    async with websockets.serve(handler, "0.0.0.0", port):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
