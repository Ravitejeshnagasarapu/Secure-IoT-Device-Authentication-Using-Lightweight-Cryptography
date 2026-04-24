import time
from flask import Blueprint, request, jsonify, current_app

from database import get_db
from utils    import (compute_hmac, verify_hmac, generate_nonce,
                      generate_session_token, current_ts,
                      aes_encrypt, aes_decrypt)

bp = Blueprint("api", __name__, url_prefix="/api")



#  Internal helper
def add_log(event: str, device: str, description: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO logs (event, device, description) VALUES (?,?,?)",
        (event, device, description)
    )
    conn.commit()
    conn.close()


def _broadcast_log():
    """Safely call broadcast_log_update if the app exposes it."""
    try:
        if hasattr(current_app, "broadcast_log_update"):
            current_app.broadcast_log_update()
    except Exception as e:
        print(f"[WARN] broadcast_log_update failed: {e}")



#  GET /api/stats
@bp.route("/stats")
def get_stats():
    conn = get_db()
    now  = time.time()
    total_devices     = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    active_sessions   = conn.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", (now,)).fetchone()[0]
    active_challenges = conn.execute("SELECT COUNT(*) FROM nonces WHERE used=0 AND (created_at + ttl) > ?", (now,)).fetchone()[0]
    auth_success      = conn.execute("SELECT COUNT(*) FROM logs WHERE event='AUTH'").fetchone()[0]
    attacks_blocked   = conn.execute("SELECT COUNT(*) FROM logs WHERE event IN ('REPLAY','SPOOF','MITM')").fetchone()[0]
    replay_blocked    = conn.execute("SELECT COUNT(*) FROM logs WHERE event='REPLAY'").fetchone()[0]
    spoof_blocked     = conn.execute("SELECT COUNT(*) FROM logs WHERE event='SPOOF'").fetchone()[0]
    conn.close()

    total          = (auth_success + attacks_blocked) or 1
    security_score = round((auth_success / total) * 100)

    return jsonify({
        "status":            "operational",
        "total_devices":     total_devices,
        "active_sessions":   active_sessions,
        "active_challenges": active_challenges,
        "auth_success":      auth_success,
        "attacks_blocked":   attacks_blocked,
        "replay_blocked":    replay_blocked,
        "spoof_blocked":     spoof_blocked,
        "security_score":    f"{security_score}%",
    })



#  POST /api/register
@bp.route("/register", methods=["POST"])
def register_device():
    data      = request.get_json(silent=True) or {}
    device_id = (data.get("deviceId")  or "").strip()
    psk       = (data.get("secretKey") or "").strip()

    if not device_id or len(device_id) < 3:
        return jsonify({"error": "Device ID must be at least 3 characters"}), 400
    if not psk or len(psk) < 8:
        return jsonify({"error": "Secret key must be at least 8 characters"}), 400

    conn     = get_db()
    existing = conn.execute("SELECT 1 FROM devices WHERE device_id=?", (device_id,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": f"Device '{device_id}' is already registered"}), 409

    conn.execute("INSERT INTO devices (device_id, psk) VALUES (?,?)", (device_id, psk))
    conn.commit()
    conn.close()

    add_log("REGISTER", device_id, f"New device provisioned: {device_id}")

    # Broadcast updated device list to all WebSocket clients immediately
    if hasattr(current_app, "broadcast_devices"):
        current_app.broadcast_devices()

    # Dashboard update
    _broadcast_log()

    return jsonify({"success": True, "device_id": device_id}), 201



#  GET /api/devices
@bp.route("/devices")
def list_devices():
    conn = get_db()
    rows = conn.execute(
        "SELECT device_id, registered_at FROM devices ORDER BY registered_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([
        {"device_id": r["device_id"], "device_name": r["device_id"],
         "registered_at": r["registered_at"], "status": "Online"}
        for r in rows
    ])



#  POST /api/hmac
@bp.route("/hmac", methods=["POST"])
def compute_hmac_endpoint():
    data      = request.get_json(silent=True) or {}
    device_id = data.get("device_id", "")
    psk       = data.get("psk", "")
    timestamp = str(data.get("timestamp", current_ts()))
    nonce     = data.get("nonce", "")
    payload   = data.get("payload", "iot_data")

    if not psk or not nonce:
        return jsonify({"error": "psk and nonce are required"}), 400

    return jsonify({"hmac": compute_hmac(psk, device_id, timestamp, nonce, payload)})



#  POST /api/auth/flow
@bp.route("/auth/flow", methods=["POST"])
def auth_flow():
    t_start   = time.time()
    data      = request.get_json(silent=True) or {}
    device_id = (data.get("device_id") or "").strip()
    mode      = data.get("mode", "normal")

    conn = get_db()
    row  = conn.execute("SELECT psk FROM devices WHERE device_id=?", (device_id,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": f"Device '{device_id}' not registered"}), 404

    real_psk = row["psk"]
    ts       = current_ts()

    step1    = {"device_id": device_id}
    sequence = [{"dir": "ltr", "msg": f"→ POST /api/challenge  {{device_id: \"{device_id}\"}}"}]

    # Step 2: nonce
    if mode == "replay":
        nonce = generate_nonce()
        _store_nonce(nonce, device_id, ts, used=True)
        sequence.append({"dir": "rtl", "msg": f"← nonce: {nonce[:16]}… (ALREADY CONSUMED)"})
    else:
        nonce = generate_nonce()
        _store_nonce(nonce, device_id, ts, used=False)
        sequence.append({"dir": "rtl", "msg": f"← nonce: {nonce[:16]}…  ts:{ts}  ttl:30s"})

    step2 = {"nonce": nonce, "ts": ts}

    # Step 3: device computes HMAC
    msg_preview = f"{nonce[:8]}:{device_id}:{ts}"
    used_psk    = "WRONG_KEY_ATTACKER" if mode == "wrong_psk" else real_psk
    device_mac  = compute_hmac(used_psk, device_id, ts, nonce)
    step3       = {"msg": msg_preview, "mac": device_mac[:32] + "…"}
    sequence.append({"dir": "ltr", "msg": f"→ POST /api/authenticate  mac:{device_mac[:16]}…"})

    # Step 4: server verifies
    expected_mac = compute_hmac(real_psk, device_id, ts, nonce)
    elapsed      = lambda: round((time.time() - t_start) * 1000, 2)

    if mode == "replay":
        step4 = {"expected": expected_mac[:32]+"…", "received": device_mac[:32]+"…",
                 "match": False, "reason": "REPLAY"}
        sequence.append({"dir": "rtl", "msg": "← 401 REPLAY: Nonce already consumed", "error": True})
        add_log("REPLAY", device_id, f"Replay attack blocked — nonce {nonce[:16]} already used")
        _broadcast_log()   # ← FIXED: dashboard refreshes live
        return jsonify({"status": "replay",
                        "steps": {"step1":step1,"step2":step2,"step3":step3,"step4":step4,"step5":{"token":""}},
                        "sequence": sequence, "timing": {"round_trip": f"~{elapsed()}ms"}})

    if mode == "wrong_psk":
        step4 = {"expected": expected_mac[:32]+"…", "received": device_mac[:32]+"…",
                 "match": False, "reason": "HMAC_MISMATCH"}
        sequence.append({"dir": "rtl", "msg": "← 401 UNAUTHORIZED: HMAC mismatch — wrong PSK", "error": True})
        add_log("AUTH_FAIL", device_id, "Auth failed — HMAC mismatch (wrong PSK)")
        _broadcast_log()   # ← FIXED
        return jsonify({"status": "wrong_psk",
                        "steps": {"step1":step1,"step2":step2,"step3":step3,"step4":step4,"step5":{"token":""}},
                        "sequence": sequence, "timing": {"round_trip": f"~{elapsed()}ms"}})

    # Normal flow
    _consume_nonce(nonce)
    token = generate_session_token()
    _store_session(token, device_id)
    step4 = {"expected": expected_mac[:32]+"…", "received": device_mac[:32]+"…",
             "match": True, "reason": None}
    step5 = {"token": token}
    sequence.append({"dir": "rtl", "msg": "← 200 OK — HMAC verified ✓ nonce consumed"})
    sequence.append({"dir": "rtl", "msg": f"← session_token: {token[:16]}…  ttl:3600s"})
    add_log("AUTH", device_id, f"Device authenticated. Session: {token[:16]}…")
    _broadcast_log()   # ← FIXED
    return jsonify({"status": "success",
                    "steps": {"step1":step1,"step2":step2,"step3":step3,"step4":step4,"step5":step5},
                    "sequence": sequence, "timing": {"round_trip": f"~{elapsed()}ms"}})



#  POST /api/attack
@bp.route("/attack", methods=["POST"])
def simulate_attack():
    data      = request.get_json(silent=True) or {}
    attack    = data.get("type", "").lower()
    device_id = (data.get("device") or "").strip()

    conn = get_db()
    row  = conn.execute("SELECT psk FROM devices WHERE device_id=?", (device_id,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": f"Device '{device_id}' not found — register it first"}), 404

    real_psk = row["psk"]
    ts       = current_ts()
    lines    = []

    if attack == "replay":
        nonce = generate_nonce()
        mac   = compute_hmac(real_psk, device_id, ts, nonce)
        _store_nonce(nonce, device_id, ts, used=True)
        add_log("REPLAY", device_id, f"Replay attack blocked — nonce {nonce[:16]} reused")
        lines = [
            f"[ATTACK:REPLAY] Target: {device_id}",
            f"[STEP 1] Attacker requests challenge → nonce: {nonce[:16]}…",
            f"[STEP 2] Attacker captures valid HMAC: {mac[:24]}…",
            f"[STEP 3] Server consumes nonce on first use → AUTH GRANTED",
            f"[STEP 4] Attacker replays identical request",
            f"[CHECK]  Server: nonce used=True → immediate reject",
            f"[BLOCKED] ⚠ REPLAY DETECTED: nonce '{nonce[:16]}…' already consumed",
            f"[RESULT] 401 Forbidden. Event logged.",
        ]

    elif attack == "spoof":
        nonce     = generate_nonce()
        wrong_key = "ATTACKER_UNKNOWN_KEY"
        bad_mac   = compute_hmac(wrong_key, device_id, ts, nonce)
        expected  = compute_hmac(real_psk,  device_id, ts, nonce)
        _store_nonce(nonce, device_id, ts, used=False)
        _consume_nonce(nonce)
        add_log("SPOOF", device_id, f"Device spoofing blocked — wrong PSK for {device_id}")
        lines = [
            f"[ATTACK:SPOOF] Target: {device_id}",
            f"[STEP 1] Attacker knows device_id='{device_id}' and nonce: {nonce[:16]}…",
            f"[STEP 2] Attacker does NOT know PSK — computing HMAC with wrong key",
            f"[STEP 3] Attacker HMAC:  {bad_mac[:24]}…",
            f"[STEP 4] Expected HMAC:  {expected[:24]}…",
            f"[CHECK]  hmac.compare_digest() → FALSE",
            f"[BLOCKED] ⚠ SPOOF DETECTED: HMAC mismatch. PSK never leaves device.",
            f"[RESULT] 401 Unauthorized. Event logged.",
        ]

    elif attack == "mitm":
        real_nonce   = generate_nonce()
        tampered     = generate_nonce()
        device_mac   = compute_hmac(real_psk, device_id, ts, real_nonce)
        server_check = compute_hmac(real_psk, device_id, ts, tampered)
        _store_nonce(real_nonce, device_id, ts, used=False)
        _consume_nonce(real_nonce)
        add_log("MITM", device_id, f"MITM attack blocked — nonce tampered for {device_id}")
        lines = [
            f"[ATTACK:MITM] Target: {device_id}",
            f"[STEP 1] Server sends nonce: {real_nonce[:16]}… to device",
            f"[STEP 2] Attacker intercepts → substitutes: {tampered[:16]}…",
            f"[STEP 3] Device HMAC over REAL nonce:     {device_mac[:24]}…",
            f"[STEP 4] Server checks HMAC over TAMPERED: {server_check[:24]}…",
            f"[CHECK]  Nonce is inside HMAC — modification causes mismatch",
            f"[BLOCKED] ⚠ MITM DETECTED: HMAC mismatch. Tampered nonce exposed.",
            f"[RESULT] 401 Unauthorized. Event logged.",
        ]

    else:
        return jsonify({"error": f"Unknown attack type: {attack}"}), 400

    # ← FIXED: broadcast log_update so dashboard refreshes live after every attack
    _broadcast_log()

    return jsonify({"message": "\n".join(lines)})



#  POST /api/message
@bp.route("/message", methods=["POST"])
def send_message():
    data = request.get_json(silent=True) or {}

    sender     = (data.get("sender") or "").strip()
    receiver   = (data.get("receiver") or "").strip()
    ciphertext = data.get("ciphertext")
    iv         = data.get("iv")
    is_mitm    = bool(data.get("mitm", False))

    if not sender or not receiver or not ciphertext or not iv:
        return jsonify({"error": "sender, receiver, ciphertext, and iv are required"}), 400

    # -- MITM simulation --
    if is_mitm:
        add_log("MITM", sender, f"MITM intercept: {sender} → {receiver} blocked")
        _broadcast_log()
        return jsonify({"blocked": True, "reason": "MITM simulation active"})

    # -- Store encrypted message --
    conn = get_db()
    conn.execute(
        "INSERT INTO messages (sender, receiver, ciphertext, iv) VALUES (?,?,?,?)",
        (sender, receiver, ciphertext, iv)
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True})



#  GET /api/messages
@bp.route("/messages")
def get_messages():
    me    = request.args.get("device_id", "").strip()
    other = request.args.get("other_id",  "").strip()
    if not me or not other:
        return jsonify({"error": "device_id and other_id are required"}), 400

    conn = get_db()
    rows = conn.execute(
        """SELECT id, sender, receiver, ciphertext, iv, timestamp
        FROM messages
        WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
        ORDER BY id ASC""",
        (me, other, other, me)
    ).fetchall()
    conn.close()

    return jsonify({
        "messages": [
            {
                "id": r["id"],
                "sender": r["sender"],
                "receiver": r["receiver"],
                "ciphertext": r["ciphertext"],
                "iv": r["iv"],
                "timestamp": r["timestamp"]
            }
            for r in rows
        ]
    })



#  GET /api/logs
@bp.route("/logs")
def get_logs():
    conn = get_db()
    rows = conn.execute(
        "SELECT timestamp, event, device, description FROM logs ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return jsonify([
        {"timestamp": r["timestamp"], "event": r["event"],
         "device": r["device"], "description": r["description"]}
        for r in rows
    ])



#  Internal helpers
def _store_nonce(nonce, device_id, ts, used=False):
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO nonces (nonce, device_id, created_at, used) VALUES (?,?,?,?)",
        (nonce, device_id, float(ts), 1 if used else 0)
    )
    conn.commit()
    conn.close()


def _consume_nonce(nonce):
    conn = get_db()
    conn.execute("UPDATE nonces SET used=1 WHERE nonce=?", (nonce,))
    conn.commit()
    conn.close()


def _is_nonce_valid(nonce):
    conn = get_db()
    row  = conn.execute("SELECT used, created_at, ttl FROM nonces WHERE nonce=?", (nonce,)).fetchone()
    conn.close()
    if not row or row["used"] or time.time() > row["created_at"] + row["ttl"]:
        return False
    return True


def _store_session(token, device_id, ttl=3600):
    now = time.time()
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token, device_id, created_at, expires_at) VALUES (?,?,?,?)",
        (token, device_id, now, now + ttl)
    )
    conn.commit()
    conn.close()