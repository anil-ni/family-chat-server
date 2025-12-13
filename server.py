import socket
import threading

clients = []

def handle_client(client):
    while True:
        try:
            msg = client.recv(1024).decode()
            broadcast(msg, client)
        except:
            clients.remove(client)
            break

def broadcast(message, sender):
    for client in clients:
        if client != sender:
            client.send(message.encode())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 10000))  # PORT FOR RENDER
server.listen()

print("Server running...")

while True:
    client, addr = server.accept()
    clients.append(client)
    print(f"{addr} connected")
    threading.Thread(target=handle_client, args=(client,)).start()
