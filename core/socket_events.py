from flask_socketio import join_room
from core.extensions import socketio

@socketio.on('join_scan')
def handle_join_scan(data):
    scan_id = data.get('scan_id')
    if scan_id:
        room = f"scan_{scan_id}"
        join_room(room)
        print(f"Client joined room: {room}")

@socketio.on('connect')
def handle_connect():
    print("Client connected to Socket.IO")
