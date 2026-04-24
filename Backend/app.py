# Backend entry module for Secure IoT Device Authentication (SIOTDA)
# Initializes Flask server, WebSocket communication, and API routing

import os
import sys

from flask import Flask, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask import request

# Adds project root to Python path for module imports
sys.path.insert(0, os.path.dirname(__file__))

# Imports database utilities and API routes
from database import init_db, get_db
from routes   import bp as api_blueprint

# Configures Socket.IO for real-time bidirectional communication between devices and server
socketio = SocketIO(
    cors_allowed_origins="*",   # Allows connections from any origin
    async_mode="eventlet",      # Enables asynchronous event handling
    logger=False,               # Disables internal logging
    engineio_logger=False,      # Disables Engine.IO logs
    ping_timeout=20,            # Connection timeout threshold
    ping_interval=10,           # Interval for heartbeat checks
)

# Retrieves all registered IoT devices from the database
def _all_devices():
    conn = get_db()

    # Query device records sorted by registration time (latest first)
    rows = conn.execute(
        "SELECT device_id, registered_at FROM devices ORDER BY registered_at DESC"
    ).fetchall()

    conn.close()

    # Format database records into dictionary structure for frontend
    return [
        {
            "device_id":     r["device_id"],
            "device_name":   r["device_id"],
            "registered_at": r["registered_at"],
            "status":        "Online",
        }
        for r in rows
    ]


# Broadcasts updated device list to all connected clients via WebSocket
def _broadcast_devices():
    socketio.emit("devices_update", _all_devices(), to=None)


# Broadcasts log update event to trigger real-time dashboard refresh
def _broadcast_log_update():
    socketio.emit("log_update", {})


# Stores encrypted message between devices and returns stored message data
def _save_message(sender, receiver, ciphertext, iv):
    conn = get_db()

    # Insert encrypted message into database
    cursor = conn.execute(
        "INSERT INTO messages (sender, receiver, ciphertext, iv) VALUES (?,?,?,?)",
        (sender, receiver, ciphertext, iv)
    )

    msg_id = cursor.lastrowid

    # Retrieve stored message record
    row = conn.execute(
        "SELECT id, sender, receiver, ciphertext, iv, timestamp FROM messages WHERE id=?",
        (msg_id,)
    ).fetchone()

    conn.commit()
    conn.close()

    # Return message data for real-time delivery
    return {
        "id": row["id"],
        "sender": row["sender"],
        "receiver": row["receiver"],
        "ciphertext": row["ciphertext"],
        "iv": row["iv"],
        "timestamp": row["timestamp"]
    }


# Inserts security-related events (e.g., attacks, authentication logs) into database
def _add_log(event, device, description):
    conn = get_db()

    conn.execute(
        "INSERT INTO logs (event, device, description) VALUES (?,?,?)",
        (event, device, description)
    )

    conn.commit()
    conn.close()

# Creates and configures the Flask application instance
def create_app(frontend_dir=None):
    app = Flask(__name__)

    # Preserve JSON key order in API responses
    app.config["JSON_SORT_KEYS"] = False

    # Enable CORS for API endpoints to allow frontend communication
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Register API routes blueprint
    app.register_blueprint(api_blueprint)

    # Initialize Socket.IO with the Flask app for real-time communication
    socketio.init_app(app)

    # Attach broadcast helper functions to app for use in routes via current_app
    app.broadcast_devices    = _broadcast_devices
    app.broadcast_log_update = _broadcast_log_update

    # Configure serving of frontend files if directory is provided
    if frontend_dir and os.path.isdir(frontend_dir):
        frontend_dir = os.path.abspath(frontend_dir)

        print(f"[INFO] Serving frontend from: {frontend_dir}")

        # Serve main entry page
        @app.route("/")
        def serve_index():
            return send_from_directory(frontend_dir, "index.html")

        # Serve static assets and handle client-side routing fallback
        @app.route("/<path:path>")
        def serve_static(path):
            fp = os.path.join(frontend_dir, path)

            return send_from_directory(
                frontend_dir,
                path if os.path.exists(fp) else "index.html"
            )

    return app

# Handles client request to fetch current device list
@socketio.on("request_devices")
def handle_request_devices():
    emit("devices_update", _all_devices())


# Handles new WebSocket connection from client
@socketio.on("connect")
def handle_connect():
    print("[WS] Client connected")

    # Send device list immediately for UI initialization
    emit("devices_update", _all_devices())


# Handles client disconnection event
@socketio.on("disconnect")
def handle_disconnect():
    print("[WS] Client disconnected")


# Adds client socket to a device-specific room for targeted communication
@socketio.on("join")
def handle_join(data):
    device_id = (data or {}).get("device_id", "").strip()

    # Ignore if no device ID provided
    if not device_id:
        return

    # Join room associated with device
    join_room(device_id)

    print(f"[JOIN] Socket {request.sid} joined room: {device_id}")
    print(f"[WS] '{device_id}' joined room")

    # Acknowledge successful room join
    emit("joined", {"device_id": device_id, "status": "ok"})


# Handles sending of encrypted messages between IoT devices
@socketio.on("send_message")
def handle_send_message(data):
    sender     = (data or {}).get("sender", "").strip()
    receiver   = (data or {}).get("receiver", "").strip()
    ciphertext = (data or {}).get("ciphertext", "")
    iv         = (data or {}).get("iv", "")
    is_mitm    = bool((data or {}).get("mitm", False))

    # Validate required message fields
    if not sender or not receiver or not ciphertext:
        emit("message_error", {"error": "Missing fields"})
        return

    # Log incoming message metadata
    print("\n" + "="*60)
    print("[BACKEND RECEIVED]")
    print(f"  Sender   : {sender}")
    print(f"  Receiver : {receiver}")
    print(f"  MITM     : {is_mitm}")
    print(f"  IV       : {iv}")
    print(f"  Data     : {ciphertext[:50]}{'...' if len(ciphertext) > 50 else ''}")
    print("="*60)

    # Handle MITM attack simulation by blocking message delivery
    if is_mitm:
        _add_log("MITM", sender,
                 f"MITM intercept: {sender} → {receiver} blocked")

        emit("message_blocked", {
            "reason": "MITM",
            "message": "MITM ATTACK DETECTED: Message intercepted and blocked!"
        }, room=request.sid)

        # Notify dashboard for log update
        socketio.emit("log_update", {})
        return

    # Store encrypted message in database
    msg = _save_message(sender, receiver, ciphertext, iv)

    # Deliver message to both sender and receiver via their rooms
    socketio.emit("receive_message", msg, room=receiver)
    socketio.emit("receive_message", msg, room=sender)

    print(f"\n[DELIVERED] {sender} → {receiver}\n")

    # Trigger dashboard update after message event
    socketio.emit("log_update", {})

    # Send acknowledgment to sender
    emit("message_sent_ack", {
        "id": msg["id"],
        "timestamp": msg["timestamp"]
    })

# Application entry point for starting the SIOTDA backend server
if __name__ == "__main__":
    init_db()
    print("[DB]  SQLite initialised → iot_security.db")
    if len(sys.argv) > 1:
        frontend_path = sys.argv[1]
    else:
        candidates = [
            os.path.join(os.path.dirname(__file__), ".."),
            os.path.join(os.path.dirname(__file__), "frontend"),
            os.path.dirname(__file__),
        ]
        frontend_path = next(
            (p for p in candidates if os.path.isfile(os.path.join(p, "index.html"))),
            None
        )

    app = create_app(frontend_dir=frontend_path)
    print("=" * 60)
    print("  SIOTDA — Real-Time WebSocket Edition")
    print("  Server  →  http://localhost:5000")
    print("  Stop    →  Ctrl+C")
    print("=" * 60)

    try:
        socketio.run(
            app,
            host="0.0.0.0",
            port=5000,
            debug=True,
            use_reloader=False,
            log_output=False,
        )

    except KeyboardInterrupt:
        print("\n[Server shutdown complete]")