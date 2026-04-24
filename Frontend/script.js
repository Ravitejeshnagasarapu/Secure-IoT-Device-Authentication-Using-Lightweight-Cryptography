// Global WebSocket instance used for real-time communication with backend
window.globalSocket = null;

// Tracks backend connectivity status
let backendConnected = false;

// Currently selected device for operations (chat, attack, flow, etc.)
let selectedDevice = null;

// Cached list of registered IoT devices received from backend
let devicesCache = [];

// Flag indicating whether device list has been loaded at least once
let devicesLoadedOnce = false;

// Controls visibility of encrypted message content in UI
let showEncryption = true;

// Currently active chat device (peer device in communication)
let activeDeviceId = null;

// Tracks last displayed message ID to prevent duplicate rendering
let lastMessageId = 0;

// Retrieves pre-shared secret key used for encryption from local storage
function getSharedSecret() {
  return localStorage.getItem("deviceKey");
}

// Stores the current device identity acting as the authenticated node
window.masterDevice = null;
try {
  const stored = localStorage.getItem("masterDevice");
  if (stored) window.masterDevice = JSON.parse(stored);
} catch (_) {}

// Encoder and decoder for converting between text and binary data
const enc = new TextEncoder();
const dec = new TextDecoder();

// Derives AES-GCM encryption key from shared secret using SHA-256 hashing
async function deriveKey(secret) {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(secret));
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

// Encrypts plaintext message using AES-GCM with derived key and random IV
async function encryptMessage(text, secret) {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(text),
  );

  const buf = new Uint8Array(encrypted);

  // Returns Base64-encoded ciphertext and initialization vector
  return {
    ciphertext: btoa(String.fromCharCode(...buf)),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

// Decrypts AES-GCM encrypted message using shared secret key
async function decryptMessage(ciphertext, iv, secret) {
  const key = await deriveKey(secret);

  // Convert Base64 encoded ciphertext and IV back to byte arrays
  const ct = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0));
  const ivBytes = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));

  // Perform AES-GCM decryption
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    key,
    ct,
  );

  // Convert decrypted binary data back to plaintext string
  return dec.decode(decrypted);
}

// Handles communication with backend REST APIs for device management and authentication flows
const api = {
  // Sends GET request to retrieve data from backend
  get: async (endpoint) => {
    try {
      const res = await fetch(endpoint);
      if (!res.ok) throw new Error(await res.text());
      return await res.json();
    } catch (err) {
      console.error("[API GET]", endpoint, err.message);
      return null;
    }
  },

  // Sends POST request with JSON body for operations like register, auth, attack simulation
  post: async (endpoint, body) => {
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      return { ok: res.ok, data };
    } catch (err) {
      console.error("[API POST]", endpoint, err.message);
      return { ok: false, error: err.message };
    }
  },
};

// Displays notification messages for system events such as authentication status, errors, or attacks
function toast(message, type = "info") {
  let container = document.getElementById("toast-container");

  // Create container if it does not exist
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.style.cssText =
      "position:fixed;bottom:20px;right:20px;z-index:9999;" +
      "display:flex;flex-direction:column;gap:10px;pointer-events:none;";
    document.body.appendChild(container);
  }

  // Select background color based on message type
  const bg =
    {
      success: "var(--success)",
      danger: "var(--danger)",
      warning: "var(--warning)",
      info: "var(--accent)",
    }[type] || "var(--accent)";

  // Create toast element
  const el = document.createElement("div");
  el.style.cssText =
    `background:${bg};color:#fff;padding:12px 24px;border-radius:8px;` +
    "box-shadow:0 4px 12px rgba(0,0,0,.25);opacity:0;transform:translateY(20px);" +
    "transition:all .3s ease;font-weight:500;font-size:.875rem;max-width:320px;" +
    "pointer-events:none;";
  el.textContent = message;

  container.appendChild(el);

  // Animate toast appearance
  requestAnimationFrame(() => {
    el.style.opacity = "1";
    el.style.transform = "translateY(0)";
  });

  // Automatically remove toast after timeout
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transform = "translateY(20px)";
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

// Global reference for displaying alerts across the application
window.showAlert = toast;

// Wrapper function for triggering toast notifications
function showToast(msg, type = "warning") {
  toast(msg, type);
}

// Creates delay for simulating network timing or step-by-step animations
function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Formats timestamp into readable time for chat messages and logs
function formatTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d)
    ? iso
    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// Scrolls chat/message container to latest message
function scrollToBottom(id) {
  const el = document.getElementById(id);
  if (el) el.scrollTop = el.scrollHeight;
}

// IDs of dropdown elements used across different modules (attack, authentication flow, crypto, encryption)
const DEVICE_SELECT_IDS = [
  "attackDevice",
  "flowDevice",
  "cryptoDeviceId",
  "encryptionDeviceId",
];

// Populates all device selection dropdowns with available IoT devices from backend
function populateDeviceSelects(devices) {
  DEVICE_SELECT_IDS.forEach((id) => {
    const sel = document.getElementById(id);
    if (!sel) return;

    const prev = sel.value;

    // Reset dropdown options (flow page includes default placeholder)
    sel.innerHTML =
      id === "flowDevice" ? '<option value="">Select device</option>' : "";

    devices.forEach((d) => {
      const opt = document.createElement("option");
      opt.value = d.device_id;
      opt.textContent = d.device_id;

      // Automatically select master device or preserve previous selection
      if (window.masterDevice && d.device_id === window.masterDevice.id)
        opt.selected = true;
      else if (d.device_id === prev) opt.selected = true;

      sel.appendChild(opt);
    });

    // Update active device if selection exists
    if (sel.value) setActiveDevice(sel.value);
  });
}

// Sets the currently selected device for operations like authentication, attack simulation, and messaging
function setActiveDevice(deviceId) {
  // Default to master device if no device is explicitly selected
  if (!deviceId && window.masterDevice) deviceId = window.masterDevice.id;

  // Validate device selection and assign active device
  selectedDevice =
    !deviceId ||
    deviceId === "" ||
    deviceId === "Loading..." ||
    deviceId.includes("No devices")
      ? null
      : deviceId;

  // Update UI controls based on selection state
  updateButtonStates();
}

// Enables or disables UI controls based on backend connectivity and selected device
function updateButtonStates() {
  const disabled = !backendConnected || !selectedDevice;

  // Control attack simulation button
  const runAll = document.getElementById("runAll");
  if (runAll) runAll.disabled = disabled;

  // Disable individual attack buttons
  document
    .querySelectorAll("button[onclick^='runAttack']")
    .forEach((b) => (b.disabled = disabled));

  // Control authentication flow execution button
  const runFlow =
    document.getElementById("runFlowBtn") || document.getElementById("runFlow");
  if (runFlow) runFlow.disabled = disabled;

  // Control chat input and send button based on device selection
  const chatForm = document.getElementById("chatForm");
  if (chatForm) {
    const send = chatForm.querySelector('button[type="submit"]');
    const inp = document.getElementById("messageInput");

    if (send) send.disabled = disabled;
    if (inp && !activeDeviceId) inp.disabled = true;
  }
}

// Validates system readiness before performing actions like attack simulation or authentication flow
function validateBeforeAction() {
  // Ensure backend server is reachable
  if (!backendConnected) {
    toast("Backend Offline", "danger");
    return false;
  }

  // Ensure a master device (authenticated IoT node) is selected
  if (!window.masterDevice) {
    toast("Set a Master Device on the Register page first", "warning");
    return false;
  }

  // Default to master device if no specific device is selected
  if (!selectedDevice) selectedDevice = window.masterDevice.id;

  return true;
}

// Checks backend health status and updates UI connection indicator
async function checkBackendConnection() {
  const bar = document.getElementById("connectionStatus");
  const text = document.getElementById("statusText");

  // Set temporary "connecting" state
  if (bar && !bar.classList.contains("offline")) {
    bar.className = "connection-bar connecting";
    if (text) text.innerText = "Connecting…";
  }

  try {
    // Fetch backend status
    const res = await api.get("/api/stats");
    backendConnected = !!(res && res.status === "operational");
  } catch {
    backendConnected = false;
  }

  // Update UI controls based on connection state
  updateButtonStates();

  if (!bar) return;

  // Update connection status indicator
  if (backendConnected) {
    bar.className = "connection-bar connected";
    if (text) text.innerText = "Connected";
  } else {
    bar.className = "connection-bar offline";
    if (text) text.innerText = "Offline";
  }
}

// Updates connection status UI and internal state based on WebSocket events
function setConnectionBar(connected) {
  const bar = document.getElementById("connectionStatus");
  const text = document.getElementById("statusText");

  backendConnected = connected;

  // Update dependent UI controls
  updateButtonStates();

  if (!bar) return;

  // Reflect connection status visually
  bar.className = connected
    ? "connection-bar connected"
    : "connection-bar offline";

  if (text) text.innerText = connected ? "Connected" : "Offline";
}

// Initializes global WebSocket connection for real-time communication with backend
function initGlobalSocket() {
  const sock = window.globalSocket;

  // Exit if WebSocket is not available (fallback to REST mode)
  if (!sock) {
    console.warn(
      "[Socket] socket.io not available on this page - running in REST-only mode",
    );
    return;
  }

  // Handles successful connection to backend server
  sock.on("connect", () => {
    console.log("[Socket] connected:", sock.id);

    // Update connection status in UI
    setConnectionBar(true);

    // Join device-specific room for receiving targeted messages/events
    if (window.masterDevice?.id) {
      console.log("[JOIN] Joining room:", window.masterDevice.id);
      sock.emit("join", { device_id: window.masterDevice.id });
      console.log("[JOIN SENT]", window.masterDevice.id);
    }

    // Request latest device list from backend
    sock.emit("request_devices");

    // Reload chat history if a device is already selected
    if (typeof loadMessageHistory === "function" && activeDeviceId) {
      loadMessageHistory();
    }
  });

  // Handles disconnection from backend
  sock.on("disconnect", (reason) => {
    console.warn("[Socket] disconnected:", reason);
    setConnectionBar(false);
  });

  // Handles connection errors
  sock.on("connect_error", (err) => {
    console.error("[Socket] connection error:", err.message);
    setConnectionBar(false);
  });

  // Receives updated list of IoT devices and refreshes UI components
  sock.on("devices_update", (devices) => {
    console.log("[Socket] devices_update →", devices.length, "devices");

    devicesCache = Array.isArray(devices) ? devices : [];
    devicesLoadedOnce = true;

    // Update all device selection dropdowns
    populateDeviceSelects(devicesCache);

    // Refresh chat contact list if chat module is active
    if (typeof window.renderContacts === "function") {
      window.renderContacts();
    }
  });

  // Triggers dashboard refresh when new logs are generated
  sock.on("log_update", () => {
    if (document.getElementById("logTableBody")) loadDashboard();
  });

  // Receives real-time system statistics and updates dashboard metrics
  sock.on("stats_update", (stats) => applyStatsToDOM(stats, null));
}

// Initializes chat-specific WebSocket listeners for secure real-time messaging
function initChatSocket() {
  const sock = window.globalSocket;

  // Ensure socket and chat UI are available
  if (!sock || !document.getElementById("chatForm")) return;

  // Handles incoming encrypted messages from backend
  sock.on("receive_message", async (msg) => {
    const me = window.masterDevice?.id;
    const other = activeDeviceId;

    // Logs message flow for debugging communication between devices
    console.log("\n====== MESSAGE FLOW ======");
    console.log("\nME:", me);
    console.log("\nACTIVE:", activeDeviceId);
    console.log("\nMSG:", msg);
    console.log("\n==========================");

    // Validate message structure
    if (!msg.sender || !msg.receiver) {
      console.warn("⚠️ Invalid message format", msg);
      return;
    }

    // Ensure current device identity exists
    if (!me) return;

    // Process only messages involving this device
    if (msg.sender !== me && msg.receiver !== me) return;

    // Identify the communicating peer device
    const otherUser = msg.sender === me ? msg.receiver : msg.sender;

    // Auto-switch chat to the sender/receiver device if not already active
    if (!activeDeviceId || activeDeviceId !== otherUser) {
      activeDeviceId = otherUser;

      if (typeof switchContact === "function") {
        switchContact(otherUser);
      }
    }

    // Fallback assignment if active device is not set
    if (!activeDeviceId) {
      activeDeviceId = msg.sender === me ? msg.receiver : msg.sender;
    }

    // Retrieve shared secret key for decryption
    const SHARED_SECRET = getSharedSecret();

    if (!SHARED_SECRET) {
      toast("No encryption key set!", "danger");
      return;
    }

    try {
      // Decrypt received ciphertext using AES-GCM
      const decryptedText = await decryptMessage(
        msg.ciphertext,
        msg.iv,
        SHARED_SECRET,
      );
      msg.text = decryptedText;
    } catch (err) {
      // Handle decryption failure (possible tampering or wrong key)
      msg.text = "❌ Decryption failed";
    }

    // Display message in chat if it belongs to this device session
    if (msg.sender === me || msg.receiver === me) {
      window._appendMessage(msg);
    }
  });

  // Handles intercepted or blocked messages (e.g., MITM attack simulation)
  sock.on("message_blocked", (data) => {
    toast(
      `${data.message || "MITM: Message intercepted & blocked!"}`,
      "danger",
    );

    // Reset MITM toggle in UI after interception
    const cb = document.getElementById("mitmAttack");
    if (cb) cb.checked = false;
  });

  // Ensures device joins its communication room if socket is already connected
  if (sock.connected && window.masterDevice) {
    sock.emit("join", { device_id: window.masterDevice.id });
    sock.emit("request_devices");
  }
}

//  Theme
function initTheme() {
  if (localStorage.getItem("theme") !== "false")
    document.body.classList.add("dark");
  document.querySelectorAll("#darkToggle").forEach((btn) => {
    btn.onclick = () => {
      document.body.classList.toggle("dark");
      localStorage.setItem(
        "theme",
        document.body.classList.contains("dark").toString(),
      );
    };
  });
}

//  Navbar
function initNavbar() {
  const hamburger = document.getElementById("hamburger");
  const navLinks = document.getElementById("navLinks");
  if (hamburger && navLinks) {
    hamburger.onclick = () => navLinks.classList.toggle("active");
    document
      .querySelectorAll(".nav-links a")
      .forEach((a) => (a.onclick = () => navLinks.classList.remove("active")));
  }
}

//  Register page
function initRegister() {
  const form = document.getElementById("registerForm");
  if (!form) return;
  const deviceIdInput = document.getElementById("deviceId");
  const secretKeyInput = document.getElementById("secretKey");
  const deviceIdError = document.getElementById("deviceIdError");
  const secretKeyError = document.getElementById("secretKeyError");
  const toggleBtn = document.getElementById("toggleSecretKeyBtn");

  if (toggleBtn) {
    toggleBtn.onclick = () => {
      const pw = secretKeyInput.type === "password";
      secretKeyInput.type = pw ? "text" : "password";
      toggleBtn.textContent = pw ? "🙈" : "👁️";
    };
  }
  deviceIdInput.addEventListener("input", () => {
    deviceIdInput.classList.remove("error");
    deviceIdError.style.display = "none";
  });
  secretKeyInput.addEventListener("input", () => {
    secretKeyInput.classList.remove("error");
    secretKeyError.style.display = "none";
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!backendConnected) {
      toast("Backend Offline", "danger");
      return;
    }
    const deviceId = deviceIdInput.value.trim();
    const key = secretKeyInput.value.trim();
    let valid = true;

    if (
      !deviceId ||
      deviceId.length < 3 ||
      !/^[a-zA-Z0-9_\-]+$/.test(deviceId)
    ) {
      deviceIdInput.classList.add("error");
      deviceIdError.style.display = "block";
      deviceIdError.textContent = "Min 3 chars - alphanumeric, _ or - only.";
      valid = false;
    }
    if (!key || key.length < 8) {
      secretKeyInput.classList.add("error");
      secretKeyError.style.display = "block";
      secretKeyError.textContent = "Min 8 characters.";
      valid = false;
    }
    if (!valid) return;

    const { ok, data } = await api.post("/api/register", {
      deviceId,
      secretKey: key,
    });
    if (ok) {
      localStorage.setItem("deviceKey", key);
      showRegisterSuccess(deviceId);
      loadDevicesListForRegister();
    } else {
      toast(data?.error || "Registration failed", "danger");
    }
  });

  document
    .getElementById("registerAnotherBtn")
    ?.addEventListener("click", () => {
      document.getElementById("registerSuccess")?.classList.add("hidden");
      form.classList.remove("hidden");
      form.reset();
    });
  document
    .getElementById("refreshDevicesBtn")
    ?.addEventListener("click", loadDevicesListForRegister);
  loadDevicesListForRegister();
}

function showRegisterSuccess(deviceId) {
  document.getElementById("registerForm")?.classList.add("hidden");
  document.getElementById("registerSuccess")?.classList.remove("hidden");
  const txt = document.getElementById("successDeviceText");
  if (txt) txt.textContent = `ID: ${deviceId} • Key provisioned securely`;
}

async function loadDevicesListForRegister() {
  const container = document.getElementById("deviceListContainer");
  if (!container) return;
  container.innerHTML = `<div style="padding:1rem;">
        <div style="height:12px;background:var(--border);width:60%;border-radius:4px;margin-bottom:8px;"></div>
        <div style="height:12px;background:var(--border);width:40%;border-radius:4px;"></div></div>`;

  const res = await api.get("/api/devices");
  const devices = Array.isArray(res) ? res : res?.devices || [];
  container.innerHTML = "";

  if (!devices.length) {
    container.innerHTML =
      '<p style="color:var(--text-muted);text-align:center;padding:1rem;font-size:.875rem;">No devices registered yet.</p>';
    return;
  }

  devices.forEach((d) => {
    const deviceId = typeof d === "string" ? d : d.device_id || "Unknown";
    const isMaster = window.masterDevice?.id === deviceId;
    const div = document.createElement("div");
    div.className = `device-item${isMaster ? " selected" : ""}`;
    Object.assign(div.style, {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      padding: ".75rem 1rem",
      cursor: "pointer",
      borderRadius: "8px",
      transition: "all .2s ease",
      background: isMaster ? "rgba(74,144,226,.12)" : "rgba(255,255,255,.02)",
      border: isMaster ? "1px solid var(--accent)" : "1px solid var(--border)",
      marginBottom: "0.25rem",
    });
    div.innerHTML = `
            <div>
                <strong style="color:var(--text-main);font-weight:600;">${deviceId}</strong>
                <div style="font-size:.75rem;color:var(--text-muted);margin-top:2px;">${isMaster ? "Master Device (Active)" : "IoT Mesh Node"}</div>
            </div>
            ${isMaster ? '<span class="badge badge-success" style="font-size:.7rem;">ACTIVE</span>' : ""}`;
    div.onclick = () => {
      window.masterDevice = { id: deviceId };
      localStorage.setItem("masterDevice", JSON.stringify(window.masterDevice));
      toast(`Master Device → ${deviceId}`, "success");
      if (window.globalSocket)
        window.globalSocket.emit("join", { device_id: deviceId });
      setActiveDevice(deviceId);
      loadDevicesListForRegister();
    };
    container.appendChild(div);
  });
}

//  Chat page - DOM setup only
//  Socket listeners are wired in initChatSocket() called from window.load.
function initChat() {
  const chatMessages = document.getElementById("chatMessages");
  const chatForm = document.getElementById("chatForm");
  const toggleEncBtn = document.getElementById("toggleEncryption");
  const contactList = document.getElementById("contactList");
  const activeContactInfo = document.getElementById("activeContactInfo");
  const contactSearch = document.getElementById("contactSearch");
  const messageInput = document.getElementById("messageInput");
  const sendButton = chatForm?.querySelector('button[type="submit"]');

  if (!chatForm || !contactList) return;

  window.renderContacts = function renderContacts(filter = "") {
    contactList.innerHTML = "";
    const q = (filter || "").toLowerCase();
    const filtered = devicesCache.filter((c) => {
      if (window.masterDevice && c.device_id === window.masterDevice.id)
        return false;
      return c.device_id.toLowerCase().includes(q);
    });
    if (!filtered.length) {
      contactList.innerHTML =
        '<div style="padding:1.5rem;text-align:center;color:var(--text-muted);font-size:.875rem;">' +
        (devicesLoadedOnce
          ? "No other devices registered."
          : "Loading devices…") +
        "</div>";
      return;
    }
    filtered.forEach((contact) => {
      const div = document.createElement("div");
      div.className = `contact-item${contact.device_id === activeDeviceId ? " active" : ""}`;
      const col =
        contact.status === "Online" ? "var(--success)" : "var(--text-muted)";
      div.innerHTML = `
                <div class="contact-avatar" style="background:var(--border);">${contact.device_id.substring(0, 2).toUpperCase()}</div>
                <div class="contact-info">
                    <div class="contact-name">${contact.device_id}</div>
                    <div class="contact-status" style="color:${col};">${contact.status || "Registered Node"}</div>
                </div>`;
      div.onclick = () => switchContact(contact.device_id);
      contactList.appendChild(div);
    });
  };

  window._appendMessage = function appendMessage(msg) {
    if (!msg) return;
    if (msg.id && msg.id <= lastMessageId) return;
    document.getElementById("no-messages")?.remove();

    const isSent = msg.sender === window.masterDevice?.id;
    const wrap = document.createElement("div");
    wrap.className = `message-container ${isSent ? "sent" : "received"}`;
    const bubble = document.createElement("div");
    bubble.className = `message ${isSent ? "sent" : "received"}`;
    const safeText = msg.text || "⚠️ Empty message";
    bubble.innerHTML =
      `<div>${safeText}</div>` +
      (msg.ciphertext
        ? `<span class="encryption-text" style="display:${showEncryption ? "block" : "none"};` +
          `word-break:break-all;font-size:.75rem;margin-top:4px;opacity:.65;">${msg.ciphertext}</span>`
        : "");
    const ts = document.createElement("div");
    ts.className = "message-timestamp";
    ts.textContent = formatTime(msg.timestamp);
    wrap.appendChild(bubble);
    wrap.appendChild(ts);
    chatMessages.appendChild(wrap);
    lastMessageId = Math.max(lastMessageId, msg.id);
    scrollToBottom("chatMessages");
  };

  function updateHeader() {
    if (!activeContactInfo) return;
    const contact = devicesCache.find((c) => c.device_id === activeDeviceId);
    if (!contact) return;
    activeContactInfo.innerHTML = `
            <div class="contact-avatar" style="width:40px;height:40px;font-size:.8rem;">${contact.device_id.substring(0, 2).toUpperCase()}</div>
            <div>
                <div style="font-weight:700;font-size:.9375rem;color:var(--text-main);">${contact.device_id}</div>
                <div style="font-size:.75rem;color:var(--success);font-weight:500;">Secure Channel Active</div>
            </div>`;
  }

  function switchContact(id) {
    if (window.masterDevice && id === window.masterDevice.id) {
      toast("Cannot chat with yourself", "warning");
      return;
    }
    activeDeviceId = id;
    lastMessageId = 0;

    if (!id) {
      if (activeContactInfo)
        activeContactInfo.innerHTML =
          '<div style="font-weight:600;color:var(--text-muted);">Select a recipient to start</div>';
      if (chatMessages) chatMessages.innerHTML = "";
      window.renderContacts(contactSearch?.value || "");
      if (messageInput) messageInput.disabled = true;
      if (sendButton) sendButton.disabled = true;
      return;
    }
    if (messageInput) messageInput.disabled = false;
    if (sendButton) sendButton.disabled = false;
    updateHeader();
    window.renderContacts(contactSearch?.value || "");
    chatMessages.innerHTML = "";
    loadMessageHistory();
  }

  async function loadMessageHistory() {
    if (!activeDeviceId || !window.masterDevice) return;

    const me = window.masterDevice.id;

    const res = await api.get(
      `/api/messages?device_id=${encodeURIComponent(me)}&other_id=${encodeURIComponent(activeDeviceId)}`,
    );

    if (!res?.messages) return;

    chatMessages.innerHTML = "";

    if (!res.messages.length) {
      const el = document.createElement("div");
      el.id = "no-messages";
      el.textContent = `No messages yet between ${me} and ${activeDeviceId}.`;
      chatMessages.appendChild(el);
      return;
    }

    for (const msg of res.messages) {
      const SHARED_SECRET = getSharedSecret();

      if (msg.ciphertext && msg.iv && SHARED_SECRET) {
        try {
          msg.text = await decryptMessage(
            msg.ciphertext,
            msg.iv,
            SHARED_SECRET,
          );
        } catch {
          msg.text = "❌ Decryption failed";
        }
      }

      if (
        (msg.sender === activeDeviceId && msg.receiver === me) ||
        (msg.sender === me && msg.receiver === activeDeviceId)
      ) {
        window._appendMessage(msg);
      }
    }
  }

  if (contactSearch)
    contactSearch.oninput = (e) => window.renderContacts(e.target.value);

  if (toggleEncBtn) {
    toggleEncBtn.onclick = () => {
      showEncryption = !showEncryption;
      toggleEncBtn.textContent = showEncryption
        ? "Hide Encryption"
        : "Show Encryption";
      document
        .querySelectorAll(".encryption-text")
        .forEach(
          (el) => (el.style.display = showEncryption ? "block" : "none"),
        );
    };
  }

  chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!window.masterDevice) {
      toast("Set a Master Device first", "warning");
      return;
    }
    if (!window.globalSocket) {
      toast("Socket not connected - check backend", "danger");
      return;
    }
    const text = messageInput?.value.trim();
    if (!text || !activeDeviceId) return;

    const mitmCb = document.getElementById("mitmAttack");
    const isMitm = mitmCb?.checked ?? false;
    const SHARED_SECRET = getSharedSecret();
    if (!SHARED_SECRET) {
      toast("No encryption key set!", "danger");
      return;
    }
    const { ciphertext, iv } = await encryptMessage(text, SHARED_SECRET);

    window.globalSocket.emit("send_message", {
      sender: window.masterDevice.id,
      receiver: activeDeviceId,
      ciphertext,
      iv,
      mitm: isMitm,
    });
    console.log("[SENDING MESSAGE]", {
      sender: window.masterDevice.id,
      receiver: activeDeviceId,
      text,
    });
    if (messageInput) messageInput.value = "";
    if (mitmCb) mitmCb.checked = false;
  });

  messageInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      chatForm.requestSubmit();
    }
  });

  switchContact(null);
  if (devicesLoadedOnce && devicesCache.length > 0) {
    window.renderContacts();
  }
}

//  Dashboard page
async function loadDashboard() {
  if (!document.getElementById("logTableBody")) return;
  try {
    const [logs, stats] = await Promise.all([
      api.get("/api/logs"),
      api.get("/api/stats"),
    ]);
    if (!logs) return;
    applyStatsToDOM(stats || {}, logs);
    renderAuditLogs(logs);
    renderThreatBreakdown(logs);
    renderDeviceActivity(logs);
  } catch {}
}

function applyStatsToDOM(stats, logs) {
  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el && v !== undefined) el.innerText = v;
  };
  if (logs) {
    const devices = new Set(logs.map((l) => l.device));
    let auth = 0,
      attacks = 0,
      replay = 0,
      spoof = 0,
      mitm = 0;
    logs.forEach((l) => {
      if (l.event === "AUTH") auth++;
      if (["REPLAY", "SPOOF", "MITM"].includes(l.event)) attacks++;
      if (l.event === "REPLAY") replay++;
      if (l.event === "SPOOF") spoof++;
      if (l.event === "MITM") mitm++;
    });
    set("totalDevices", devices.size);
    set("authSuccess", auth);
    set("attacksBlocked", attacks);
    set("replayBlocked", replay);
    set("spoofBlocked", spoof);
    set("securityScore", Math.round((auth / (logs.length || 1)) * 100) + "%");
  }
  if (stats) {
    set("activeSessions", stats.active_sessions);
    set("activeChallenges", stats.active_challenges);
  }
}

function renderAuditLogs(logs) {
  const tbody = document.getElementById("logTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";
  logs.forEach((log) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${log.timestamp}</td><td>${log.event}</td>` +
      `<td>${log.device}</td><td>${log.description}</td>`;
    tbody.appendChild(tr);
  });
}

function renderDeviceActivity(logs) {
  const container = document.getElementById("deviceActivity");
  if (!container) return;
  container.innerHTML = "";
  const counts = {};
  logs.forEach((l) => (counts[l.device] = (counts[l.device] || 0) + 1));
  Object.entries(counts).forEach(([device, count]) => {
    const el = document.createElement("div");
    el.style.cssText =
      "padding:.5rem;background:rgba(255,255,255,.02);border:1px solid var(--border);" +
      "border-radius:6px;font-family:var(--font-mono);font-size:.875rem;display:flex;justify-content:space-between;";
    el.innerHTML = `<div>${device}</div><div>${count} events</div>`;
    container.appendChild(el);
  });
}

function renderThreatBreakdown(logs) {
  let replay = 0,
    spoof = 0,
    mitm = 0,
    auth = 0;
  logs.forEach((l) => {
    if (l.event === "REPLAY") replay++;
    if (l.event === "SPOOF") spoof++;
    if (l.event === "MITM") mitm++;
    if (l.event === "AUTH") auth++;
  });
  setBar("replayBar", replay);
  setBar("spoofBar", spoof);
  setBar("mitmBar", mitm);
  setBar("authBar", auth);
}

function setBar(id, value, max = 20) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = Math.min((value / max) * 100, 100) + "%";
  el.innerText = value;
}

async function loadDashboardFiltered(type) {
  const MAP = {
    "Auth OK": "AUTH",
    "Auth Fail": "AUTH_FAIL",
    Replay: "REPLAY",
    Spoof: "SPOOF",
    MITM: "MITM",
    Register: "REGISTER",
  };
  const logs = await api.get("/api/logs");
  if (!logs) return;
  renderAuditLogs(
    type === "ALL" ? logs : logs.filter((l) => l.event === (MAP[type] || type)),
  );
}

function initDashboard() {
  if (!document.getElementById("logTableBody")) return;
  const logFilter = document.getElementById("logFilter");
  if (logFilter)
    logFilter.onchange = (e) => loadDashboardFiltered(e.target.value);
  const refreshBtn = document.getElementById("refreshLogsBtn");
  if (refreshBtn)
    refreshBtn.onclick = () => {
      const val = logFilter?.value || "ALL";
      val === "ALL" ? loadDashboard() : loadDashboardFiltered(val);
    };
  loadDashboard();
  // Real-time updates via socket 'log_update' event
}

//  Flow page
function logAttack(msg) {
  const log = document.getElementById("attackLog");
  if (!log) return;
  log.textContent += `\n[${new Date().toLocaleTimeString()}] ${msg}`;
  log.scrollTop = log.scrollHeight;
}

async function runFlow(mode) {
  if (!backendConnected) {
    toast("Backend Offline", "danger");
    return;
  }
  if (!selectedDevice) {
    const err = document.getElementById("authError");
    if (err) {
      err.style.display = "block";
      setTimeout(() => (err.style.display = "none"), 3000);
    }
    toast("Select a device first", "warning");
    return;
  }
  logAttack(`[FLOW] Starting handshake (Mode: ${mode.toUpperCase()})`);
  resetFlowUI();
  const runBtn = document.getElementById("runFlowBtn");
  if (runBtn) runBtn.disabled = true;
  try {
    const { ok, data } = await api.post("/api/auth/flow", {
      device_id: selectedDevice,
      mode,
    });
    if (!ok) throw new Error(data?.error || "Backend error");
    await renderFlowAnimation(data);
  } catch (err) {
    logAttack(`[ERROR] ${err.message}`);
    toast(err.message, "danger");
  } finally {
    if (runBtn) runBtn.disabled = false;
  }
}

async function renderFlowAnimation(data) {
  for (const i of [1, 2, 3, 4, 5]) {
    setStep(i - 1, "active");
    await delay(600);
    if (i === 1) setText("v-deviceId", data.steps.step1.device_id);
    if (i === 2) {
      setText("v-nonce", data.steps.step2.nonce);
      setText("v-ts", data.steps.step2.ts);
    }
    if (i === 3) {
      setText("v-msg", data.steps.step3.msg);
      setText("v-mac", data.steps.step3.mac);
    }
    if (i === 4) {
      setText("v-expected", data.steps.step4.expected);
      setText("v-received", data.steps.step4.received);
      const matchEl = document.getElementById("v-match");
      if (matchEl) {
        matchEl.innerHTML = data.steps.step4.match
          ? `<span style="color:var(--success);font-weight:700;">TRUE ✓</span>`
          : `<span style="color:var(--danger);font-weight:700;">${data.steps.step4.reason === "REPLAY" ? "REPLAY ✗" : "FALSE ✗"}</span>`;
      }
      if (data.status !== "success") {
        setStep(i - 1, "fail");
        showFlowResult(false, data.status);
        break;
      }
    }
    if (i === 5) setText("v-token", data.steps.step5.token);
    setStep(i - 1, "success");
    if (i === 5) showFlowResult(true);
  }
  renderSequence(data.sequence);
  const ttEl = document.getElementById("v-totalTime");
  if (ttEl) ttEl.textContent = data.timing?.round_trip || "---";
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setStep(index, state) {
  const steps = document.querySelectorAll(".step");
  if (steps[index]) {
    steps[index].classList.remove("active", "success", "fail", "error");
    steps[index].classList.add(state);
    if (state === "fail") steps[index].classList.add("error");
  }
}

function showFlowResult(success, status) {
  const box = document.getElementById("flowResult");
  if (!box) return;
  if (success) {
    box.innerHTML = `<div class="success-box" style="display:flex;flex-direction:column;align-items:center;gap:.5rem;">
            <span style="font-size:2rem;">✅</span>
            <div style="font-size:1.125rem;">Authentication Successful</div>
            <div style="font-size:.8rem;opacity:.8;">Nonce consumed - replay prevention active.</div>
            <button class="btn btn-small" style="margin-top:.5rem;background:var(--success);color:#000;font-weight:700;">Session token issued ✓</button></div>`;
  } else {
    const isReplay = status === "replay";
    box.innerHTML = `<div class="fail-box" style="display:flex;flex-direction:column;align-items:center;gap:.5rem;">
            <span style="font-size:2rem;">🚫</span>
            <div style="font-size:1.125rem;">${isReplay ? "Replay Attack Blocked" : "Authentication Rejected"}</div>
            <div style="font-size:.8rem;opacity:.8;">${
              isReplay
                ? "Nonce already consumed - server rejects reuse instantly."
                : "HMAC mismatch - device cannot prove identity without the PSK."
            }</div></div>`;
  }
}

function resetFlowUI(hard = false) {
  document
    .querySelectorAll(".step")
    .forEach((s) => s.classList.remove("success", "fail", "error", "active"));
  const fr = document.getElementById("flowResult");
  if (fr) fr.innerHTML = "";
  if (hard) {
    [
      "v-deviceId",
      "v-nonce",
      "v-ts",
      "v-msg",
      "v-mac",
      "v-expected",
      "v-received",
      "v-token",
      "v-match",
    ].forEach((id) => setText(id, ""));
    const seq = document.getElementById("seqMessages");
    if (seq) seq.innerHTML = "";
    const tt = document.getElementById("v-totalTime");
    if (tt) tt.textContent = "---";
    logAttack("[SYSTEM] UI reset to idle.");
  }
}

function renderSequence(seq) {
  const container = document.getElementById("seqMessages");
  if (!container) return;
  container.innerHTML = "";
  seq.forEach((item, idx) => {
    setTimeout(() => {
      let color = item.dir === "rtl" ? "var(--success)" : "var(--accent)";
      if (item.error) color = "var(--danger)";
      if (item.alert) color = "var(--warning)";
      const div = document.createElement("div");
      div.className = `seq-msg ${item.dir}`;
      div.style.justifyContent = item.dir === "ltr" ? "flex-start" : "flex-end";
      div.innerHTML = `<span style="padding:6px 10px;border-radius:4px;background:rgba(0,0,0,.4);color:${color};border:1px solid ${color}44;font-size:.7rem;border-left:2px solid ${color};">${item.msg}</span>`;
      container.appendChild(div);
      container.scrollTop = container.scrollHeight;
    }, idx * 400);
  });
}

function initFlow() {
  const runBtn = document.getElementById("runFlowBtn");
  const resetBtn = document.getElementById("resetFlowBtn");
  const modeBtns = document.querySelectorAll("#flowModeSelectors button");
  let currentMode = "normal";

  if (runBtn) runBtn.onclick = () => runFlow(currentMode);
  if (resetBtn) resetBtn.onclick = () => resetFlowUI(true);

  modeBtns.forEach((btn) => {
    btn.onclick = () => {
      modeBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentMode = btn.dataset.mode;
    };
  });

  const select = document.getElementById("flowDevice");
  if (select) select.onchange = (e) => setActiveDevice(e.target.value);

  // Populate now if cache is warm, else REST fallback
  if (devicesLoadedOnce && devicesCache.length) {
    populateDeviceSelects(devicesCache);
  } else {
    api.get("/api/devices").then((d) => {
      if (Array.isArray(d)) populateDeviceSelects(d);
    });
  }

  // Pre-select from URL param if present
  const urlDevice = new URLSearchParams(window.location.search).get("deviceId");
  if (urlDevice && select) {
    // Wait briefly for options to populate
    setTimeout(() => {
      const opt = Array.from(select.options).find((o) => o.value === urlDevice);
      if (opt) {
        select.value = urlDevice;
        setActiveDevice(urlDevice);
      }
    }, 300);
  }
}

//  Attack simulation page
async function runAttack(type) {
  const select = document.getElementById("attackDevice");
  if (select) setActiveDevice(select.value);
  if (!validateBeforeAction()) return;
  logAttack(
    `[SYS] Initiating ${type.toUpperCase()} attack against ${selectedDevice}…`,
  );
  const { ok, data } = await api.post("/api/attack", {
    type,
    device: selectedDevice,
  });
  if (ok && data) {
    logAttack(data.message || JSON.stringify(data));
  } else {
    logAttack("[ERROR] Server rejected simulation.");
  }
}

function initAttackPage() {
  if (!document.getElementById("attackDevice")) return;
  const select = document.getElementById("attackDevice");
  if (select) select.onchange = (e) => setActiveDevice(e.target.value);

  if (devicesLoadedOnce && devicesCache.length) {
    populateDeviceSelects(devicesCache);
  } else {
    api.get("/api/devices").then((d) => {
      if (Array.isArray(d)) populateDeviceSelects(d);
    });
  }

  const runAllBtn = document.getElementById("runAll");
  if (runAllBtn) {
    runAllBtn.onclick = () => {
      if (select) setActiveDevice(select.value);
      if (!validateBeforeAction()) return;
      logAttack("--- RUNNING ALL ATTACKS ---");
      ["replay", "spoof", "mitm"].forEach((t, i) =>
        setTimeout(() => runAttack(t), i * 800),
      );
    };
  }
  const clearHandler = () => {
    const log = document.getElementById("attackLog");
    if (log)
      log.textContent =
        "root@iot-auth-lab:~$ Ready. Select a device and run an attack.";
  };
  document
    .getElementById("clearAttack")
    ?.addEventListener("click", clearHandler);
  document
    .getElementById("clearAttackLogBtn")
    ?.addEventListener("click", clearHandler);
}

//  Quick Auth
function initQuickAuth() {
  const btn = document.getElementById("quickAuthBtn");
  const input = document.getElementById("quickAuthId");
  const error = document.getElementById("quickAuthError");
  if (!btn || !input) return;
  if (error) error.style.display = "none";
  input.oninput = () => {
    input.classList.remove("error");
    if (error) error.style.display = "none";
  };
  btn.onclick = () => {
    const id = input.value.trim();
    if (!id) {
      input.classList.add("error");
      if (error) error.style.display = "block";
      return;
    }
    window.location.href = `flow.html?deviceId=${encodeURIComponent(id)}`;
  };
}

// Initializes AES-256-GCM encryption module for secure IoT message processing
function initEncryption() {
  // Exit if encryption page elements are not present
  if (!document.getElementById("encryptBtn")) return;

  // UI elements for encryption, decryption, and visualization
  const encryptBtn = document.getElementById("encryptBtn");
  const input = document.getElementById("encryptionInput");
  const keyInput = document.getElementById("encryptionKey");
  const ivInput = document.getElementById("encryptionIv");
  const genKeyBtn = document.getElementById("genEncKeyBtn");
  const deviceSelect = document.getElementById("encryptionDeviceId");
  const toggleKeyBtn = document.getElementById("toggleKeyVisibility");
  const avalancheTestBtn = document.getElementById("testEncAvalancheBtn");
  const simulateAttackBtn = document.getElementById("simulateAttackBtn");
  const resultCard = document.getElementById("encryptionResult");
  const plainOutput = document.getElementById("plainTextOutput");
  const encOutputSpan = document
    .getElementById("encryptedTextOutput")
    ?.querySelector("span");
  const authTagOutput = document.getElementById("authTagOutput");
  const ivOutput = document.getElementById("ivOutput");
  const formatLabel = document.querySelector(".format-label");
  const formatBtn = document.getElementById("toggleHexB64");
  const toggle = document.getElementById("showEncryptedToggle");
  const encWrapper = document.getElementById("encryptedTextWrapper");
  const placeholder = document.getElementById("hiddenPlaceholder");
  const copyBtn = document.getElementById("copyEncryptedBtn");
  const avalancheCnt = document.getElementById("avalanche-container");
  const avalancheStat = document.getElementById("encryptionAvalancheStat");
  const debugArea = document.getElementById("rawMessageDebug");
  const debugOutput = document.getElementById("rawMessageOutput");
  const decryptBtn = document.getElementById("decryptBtn");
  const decInput = document.getElementById("decryptCipherInput");
  const decTagInput = document.getElementById("decryptTagInput");
  const decIvInput = document.getElementById("decryptIvInput");
  const decResult = document.getElementById("decryptionResult");
  const decOutput = document.getElementById("decryptedOutput");

  // Tracks current output format (hex or base64)
  let currentMode = "hex";

  // Stores latest encryption result for UI updates
  let currentData = null;

  // Stores last AES parameters for reuse (e.g., attack simulation, decryption)
  window.lastAESParams = { ct: null, tag: null, iv: null, key: null };

  // Converts binary data to hexadecimal representation
  const toHex = (buf) =>
    Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  // Converts binary data to Base64 representation
  const toBase64 = (buf) => {
    let s = "";
    new Uint8Array(buf).forEach((b) => (s += String.fromCharCode(b)));
    return btoa(s);
  };

  // Converts hexadecimal string back to byte array
  const fromHex = (hex) =>
    new Uint8Array(hex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));

  // Converts Base64 string back to byte array
  const fromB64 = (b64) => {
    const s = atob(b64);
    const u = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  };

  // Derives a 256-bit AES key from user-provided key using SHA-256 hashing
  async function deriveKey(userKey) {
    const enc = new TextEncoder();

    // If no key is provided, generate a random 256-bit key
    if (!userKey?.trim()) return crypto.getRandomValues(new Uint8Array(32));

    // Hash user key to produce fixed-length AES key
    return new Uint8Array(
      await crypto.subtle.digest("SHA-256", enc.encode(userKey)),
    );
  }

  // Constructs message format combining device identity, timestamp, nonce, and payload
  function buildMessage(deviceId, text) {
    const ts = Date.now().toString();

    // Generate random nonce to ensure uniqueness and prevent replay
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(8)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Final message structure used for encryption
    return { message: deviceId + ts + nonce + text };
  }

  // Encrypts message using AES-GCM, producing ciphertext and authentication tag
  async function encryptAES(message, keyBytes, iv) {
    const ck = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );

    const enc = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      ck,
      new TextEncoder().encode(message),
    );

    const buf = new Uint8Array(enc);

    // Split encrypted output into ciphertext and authentication tag
    return {
      ct: buf.slice(0, buf.length - 16),
      tag: buf.slice(buf.length - 16),
      iv,
    };
  }

  // Decrypts AES-GCM encrypted data and verifies integrity using authentication tag
  async function decryptAES(ct, keyBytes, iv, tag) {
    const ck = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    // Combine ciphertext and tag for decryption
    const com = new Uint8Array(ct.length + tag.length);
    com.set(ct);
    com.set(tag, ct.length);

    return new TextDecoder().decode(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, ck, com),
    );
  }

  // Updates encryption output display in selected format (Hex/Base64)
  function updateResultsUI() {
    if (!currentData) return;

    const { ct, tag, iv } = currentData;

    // Select format based on current mode
    const fmt = currentMode === "hex" ? toHex : toBase64;

    // Update UI elements with encrypted output values
    if (encOutputSpan) encOutputSpan.textContent = fmt(ct);
    if (authTagOutput) authTagOutput.textContent = fmt(tag);
    if (ivOutput) ivOutput.textContent = fmt(iv);

    // Update format label in UI
    if (formatLabel)
      formatLabel.textContent = currentMode === "hex" ? "(Hex)" : "(Base64)";
  }

  // Handles encryption of user input using AES-GCM for secure IoT message transmission
  async function handleEncryption() {
    const text = input.value.trim();
    const keyStr = keyInput.value.trim() || "DefaultSecretKey123";
    const ivHex = ivInput.value.trim();
    const devId = deviceSelect?.value || "UNKNOWN";

    // Validate input message
    if (!text) {
      toast("Enter a message first", "warning");
      return;
    }

    try {
      // Construct structured message with device ID, timestamp, and nonce
      const { message } = buildMessage(devId, text);

      // Derive encryption key from user input
      const keyBytes = await deriveKey(keyStr);

      // Use provided IV or generate a random IV
      const iv = ivHex
        ? fromHex(ivHex)
        : crypto.getRandomValues(new Uint8Array(12));

      // Display raw constructed message for debugging/analysis
      if (debugArea) debugArea.style.display = "block";
      if (debugOutput) debugOutput.textContent = message;

      // Perform AES-GCM encryption
      currentData = await encryptAES(message, keyBytes, iv);

      // Set output format to hexadecimal by default
      currentMode = "hex";

      // Store encryption parameters for later use (decryption or attack simulation)
      window.lastAESParams = {
        ct: currentData.ct,
        tag: currentData.tag,
        iv: currentData.iv,
        key: keyBytes,
      };

      // Display original plaintext in UI
      if (plainOutput) plainOutput.textContent = text;

      // Update UI with encrypted values
      updateResultsUI();

      // Show encryption result section
      if (resultCard) resultCard.style.display = "block";

      // Hide encrypted text initially (controlled via toggle)
      if (placeholder) placeholder.style.display = "block";
      if (encWrapper) encWrapper.style.display = "none";
      if (toggle) toggle.checked = false;

      // Populate decryption fields with generated values for testing
      if (decInput) decInput.value = toHex(currentData.ct);
      if (decTagInput) decTagInput.value = toHex(currentData.tag);
      if (decIvInput) decIvInput.value = toHex(currentData.iv);
    } catch (e) {
      console.error(e);
      toast("Encryption failed", "danger");
    }
  }

  // Handles decryption and integrity verification of AES-GCM encrypted data
  async function handleDecryption() {
    const keyStr = keyInput.value.trim() || "DefaultSecretKey123";
    const ctStr = decInput?.value.trim();
    const tagStr = decTagInput?.value.trim();
    const ivStr = decIvInput?.value.trim();

    // Validate required decryption inputs
    if (!ctStr || !tagStr || !ivStr) {
      toast("Missing decryption params", "warning");
      return;
    }

    try {
      // Derive decryption key
      const keyBytes = await deriveKey(keyStr);

      // Detect input format (hex or base64)
      const isHex = /^[0-9a-fA-F]+$/.test(ctStr);
      const parse = isHex ? fromHex : fromB64;

      // Perform AES-GCM decryption and authentication check
      const dec = await decryptAES(
        parse(ctStr),
        keyBytes,
        parse(ivStr),
        parse(tagStr),
      );

      // Display decrypted result
      if (decResult) decResult.style.display = "block";
      if (decOutput) {
        decOutput.style.color = "var(--success)";
        decOutput.textContent = dec;
      }

      // Notify successful integrity verification
      toast("Integrity verified ✓", "success");
    } catch {
      // Handle authentication failure (tampering or incorrect key)
      if (decResult) decResult.style.display = "block";
      if (decOutput) {
        decOutput.style.color = "var(--danger)";
        decOutput.textContent = "❌ AUTH FAILURE: Data tampered or wrong key.";
      }

      toast("Decryption failed - tamper detected", "danger");
    }
  }

  // Demonstrates avalanche effect by comparing ciphertext differences for small input changes
  async function handleAvalanche() {
    const text = input.value.trim();

    // Ensure input message exists
    if (!text) {
      toast("Enter a message first", "warning");
      return;
    }

    // Modify last character to create minimal input change
    const mod = text.slice(0, -1) + (text.slice(-1) === "!" ? "?" : "!");

    // Derive encryption key
    const key = await deriveKey(keyInput.value.trim() || "DefaultSecretKey123");

    // Generate random IV for both encryptions
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const devId = deviceSelect?.value || "SENSOR_001";

    // Encrypt original and modified messages
    const r1 = await encryptAES(buildMessage(devId, text).message, key, iv);
    const r2 = await encryptAES(buildMessage(devId, mod).message, key, iv);

    // Calculate byte-level differences between ciphertexts
    let diff = 0;
    const minL = Math.min(r1.ct.length, r2.ct.length);
    for (let i = 0; i < minL; i++) if (r1.ct[i] !== r2.ct[i]) diff++;

    const pct = Math.round((diff / minL) * 100);

    // Display avalanche effect statistics
    if (avalancheStat)
      avalancheStat.textContent = `${diff} bytes changed (~${pct}% diffusion).`;

    if (avalancheCnt) avalancheCnt.style.display = "block";

    toast(`Avalanche: ${pct}% diffusion`, "info");
  }

  // Simulates tampering attack by modifying ciphertext and testing integrity verification
  async function handleSimulateAttack() {
    const p = window.lastAESParams;

    // Ensure encryption has been performed before simulation
    if (!p.ct || !p.key) {
      toast("Encrypt a message first", "warning");
      return;
    }

    try {
      toast("Simulating bit-flip tamper…", "info");

      // Create tampered ciphertext by flipping bits
      const tampered = new Uint8Array(p.ct);
      tampered[0] ^= 0xff;

      try {
        // Attempt decryption with modified ciphertext
        await decryptAES(tampered, p.key, p.iv, p.tag);

        // Indicates unexpected integrity bypass
        toast("⚠️ Unexpected: integrity bypass!", "warning");
      } catch {
        // Expected behavior: authentication fails due to tampering
        toast("✅ Tamper detected by GCM Auth Tag", "success");

        if (decResult) decResult.style.display = "block";

        if (decOutput) {
          decOutput.style.color = "var(--danger)";
          decOutput.textContent =
            "CRITICAL: [TAMPER_DETECTED] Auth tag mismatch - decryption halted.";
        }

        // Scroll to result section for visibility
        decResult?.scrollIntoView({ behavior: "smooth" });
      }
    } catch {
      toast("Simulation error", "danger");
    }
  }

  // Bind encryption button to encryption handler
  encryptBtn.onclick = handleEncryption;

  // Bind decryption button to decryption handler
  decryptBtn?.addEventListener("click", handleDecryption);

  // Bind avalanche test button
  avalancheTestBtn?.addEventListener("click", handleAvalanche);

  // Bind attack simulation button
  simulateAttackBtn?.addEventListener("click", handleSimulateAttack);

  // Generates a random 256-bit key and displays it in hex format
  genKeyBtn?.addEventListener("click", () => {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    keyInput.value = toHex(b);
    toast("256-bit key generated", "success");
  });

  // Toggles visibility of encryption key input field
  toggleKeyBtn?.addEventListener("click", () => {
    keyInput.type = keyInput.type === "password" ? "text" : "password";
    toggleKeyBtn.textContent = keyInput.type === "password" ? "👁️" : "🙈";
  });

  // Switches output format between hexadecimal and Base64
  formatBtn?.addEventListener("click", () => {
    currentMode = currentMode === "hex" ? "base64" : "hex";
    updateResultsUI();
  });

  // Toggles visibility of encrypted output in UI
  toggle?.addEventListener("change", () => {
    if (encWrapper)
      encWrapper.style.display = toggle.checked ? "block" : "none";
    if (placeholder)
      placeholder.style.display = toggle.checked ? "none" : "block";
  });

  // Copies encrypted output to clipboard
  copyBtn?.addEventListener("click", () =>
    navigator.clipboard
      .writeText(encOutputSpan?.textContent || "")
      .then(() => toast("Copied!", "success")),
  );

  // Populate device dropdown from cache if available
  if (devicesLoadedOnce && devicesCache.length)
    populateDeviceSelects(devicesCache);
  else
    // Fetch device list from backend if cache is empty
    api.get("/api/devices").then((d) => {
      if (Array.isArray(d)) populateDeviceSelects(d);
    });
}

// Initializes HMAC-SHA256 based authentication explorer for IoT device security analysis
async function initCrypto() {
  const pskInput = document.getElementById("cryptoPsk");
  const nonceInput = document.getElementById("cryptoNonce");
  const devIdInput = document.getElementById("cryptoDeviceId");
  const tsInput = document.getElementById("cryptoTimestamp");
  const hmacBox = document.getElementById("hmacResultBox");
  const bitGrid = document.getElementById("bitGrid");
  const avalancheStat = document.getElementById("avalanche-stat");
  const genNonceBtn = document.getElementById("genNonceBtn");
  const copyHmacBtn = document.getElementById("copyHmacBtn");

  // Exit if required elements are not present (page not active)
  if (!pskInput) return;

  // Initialize timestamp (used in authentication message)
  tsInput.value = Math.floor(Date.now() / 1000).toString();

  // Generates random nonce to ensure uniqueness and prevent replay attacks
  function generateNonce() {
    const b = new Uint8Array(8);
    crypto.getRandomValues(b);
    return Array.from(b)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  }

  // Set initial nonce value
  nonceInput.value = generateNonce();

  // Populate device selection dropdown
  if (devicesLoadedOnce && devicesCache.length)
    populateDeviceSelects(devicesCache);
  else
    api.get("/api/devices").then((d) => {
      if (Array.isArray(d)) populateDeviceSelects(d);
    });

  // Regenerate nonce and timestamp, then recompute HMAC
  genNonceBtn.onclick = () => {
    nonceInput.value = generateNonce();
    tsInput.value = Math.floor(Date.now() / 1000).toString();
    updateHMAC();
  };

  // Copy generated HMAC value to clipboard
  copyHmacBtn.onclick = () =>
    navigator.clipboard
      .writeText(hmacBox.textContent.trim())
      .then(() => toast("HMAC copied!", "success"));

  // Computes HMAC-SHA256 using pre-shared key for device authentication
  async function computeHMACjs(
    key,
    device_id,
    timestamp,
    nonce,
    payload = "iot_data",
  ) {
    const enc = new TextEncoder();

    // Import key for HMAC signing
    const ck = await crypto.subtle.importKey(
      "raw",
      enc.encode(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );

    // Generate HMAC signature for message
    const sig = await crypto.subtle.sign(
      "HMAC",
      ck,
      enc.encode(device_id + timestamp + nonce + payload),
    );

    // Convert signature to hexadecimal format
    return Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // Retrieves HMAC either from backend API or computes locally as fallback
  async function getHMAC(
    key,
    device_id,
    timestamp,
    nonce,
    payload = "iot_data",
  ) {
    // Prefer backend computation if available (centralized authentication logic)
    if (backendConnected) {
      const res = await api.post("/api/hmac", {
        psk: key,
        device_id,
        timestamp,
        nonce,
        payload,
      });
      if (res.ok) return res.data.hmac;
    }

    // Fallback to client-side HMAC computation
    return computeHMACjs(key, device_id, timestamp, nonce, payload);
  }

  // Stores original HMAC value for avalanche effect comparison
  let originalHmacHex = "";

  // Updates HMAC output and visual pipeline based on current inputs
  async function updateHMAC() {
    const key = pskInput.value || "MySecretKey12345!";
    const nonce = nonceInput.value;
    const devId = devIdInput.value || "SENSOR_001";
    const ts = tsInput.value;

    // Display truncated key in pipeline visualization
    document.getElementById("v-psk").textContent =
      key.length > 10 ? key.substring(0, 10) + "…" : key;

    // Display message structure (nonce:device_id:timestamp)
    document.getElementById("v-msg").textContent =
      `${nonce}:${devId}:${ts}`.substring(0, 12) + "…";

    // Reset and update active pipeline stages
    document
      .querySelectorAll(".pipeline-box")
      .forEach((b) => b.classList.remove("active"));

    if (key) document.getElementById("p-key").classList.add("active");
    document.getElementById("p-msg").classList.add("active");
    document.getElementById("p-func").classList.add("active");

    // Generate HMAC using selected method
    const hmac = await getHMAC(key, devId, ts, nonce);
    if (!hmac) return;

    // Display HMAC output
    hmacBox.textContent = hmac;

    // Show truncated output in pipeline
    document.getElementById("v-out").textContent = hmac.substring(0, 8) + "…";
    document.getElementById("p-out").classList.add("active");

    // Store original HMAC for later comparison
    originalHmacHex = hmac;

    // Render bit-level visualization
    renderBitGrid(hmac);
  }

  // Converts hexadecimal string to binary representation
  function hexToBin(hex) {
    return hex
      .split("")
      .map((c) => parseInt(c, 16).toString(2).padStart(4, "0"))
      .join("");
  }

  // Displays first 128 bits of HMAC output for visualization and interaction
  function renderBitGrid(hex) {
    const bin = hexToBin(hex).substring(0, 128);

    bitGrid.innerHTML = "";

    // Create interactive bit elements
    bin.split("").forEach((bit, i) => {
      const el = document.createElement("div");
      el.className = `bit ${bit === "1" ? "on" : ""}`;
      el.textContent = bit;

      // Allows user to flip bits to observe avalanche effect
      el.onclick = () => flipBit(i);

      bitGrid.appendChild(el);
    });
  }

  // Flips input at a specific index to demonstrate avalanche effect in HMAC output
  async function flipBit(index) {
    const chars = nonceInput.value.split("");

    // Select position in nonce to modify
    const idx = index % chars.length;

    // Toggle character to introduce minimal input change
    chars[idx] = chars[idx] === "a" ? "b" : "a";

    const mod = chars.join("");

    const key = pskInput.value || "MySecretKey12345!";
    const devId = devIdInput.value || "SENSOR_001";
    const ts = tsInput.value;

    // Recompute HMAC with modified input
    const newHex = await getHMAC(key, devId, ts, mod);
    if (!newHex) return;

    // Convert original and modified HMAC to binary for comparison
    const origBin = hexToBin(originalHmacHex).substring(0, 128);
    const newBin = hexToBin(newHex).substring(0, 128);

    let diff = 0;
    bitGrid.innerHTML = "";

    // Compare bit-by-bit differences to measure diffusion
    for (let i = 0; i < 128; i++) {
      const flipped = origBin[i] !== newBin[i];
      if (flipped) diff++;

      const el = document.createElement("div");
      el.className = `bit ${newBin[i] === "1" ? "on" : ""} ${flipped ? "flipped" : ""}`;
      el.textContent = newBin[i];

      // Allow repeated interaction for further bit changes
      el.onclick = () => flipBit(i);

      bitGrid.appendChild(el);
    }

    // Calculate percentage of bits changed (diffusion measure)
    const pct = Math.round((diff / 128) * 100);

    // Display avalanche effect result
    avalancheStat.innerHTML = `1-char change → <span style="color:var(--danger);font-weight:800;">${diff}/128 bits</span> flipped = ${pct}% (ideal ~50% ✓)`;
  }

  // Attach input listeners to dynamically recompute HMAC on value change
  [pskInput, nonceInput, devIdInput, tsInput].forEach(
    (inp) => (inp.oninput = updateHMAC),
  );

  // Initial HMAC computation on page load
  updateHMAC();
}

//  Scroll animations
function initScrollAnimations() {
  const obs = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("visible");
          obs.unobserve(e.target);
        }
      });
    },
    { threshold: 0.1, rootMargin: "0px 0px -50px 0px" },
  );
  document
    .querySelectorAll(
      ".card,.nav-card,.stat-card,.table-wrapper,.flow-visualizer",
    )
    .forEach((el) => {
      el.classList.add("animate-on-scroll");
      obs.observe(el);
    });
}

//  DOMContentLoaded
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initNavbar();
  initScrollAnimations();
  if (window.masterDevice) {
    selectedDevice = window.masterDevice.id;
    updateButtonStates();
  }
  initRegister();
  initChat();
  initDashboard();
  initFlow();
  initEncryption();
  initCrypto();
  initQuickAuth();
  initAttackPage();
  checkBackendConnection();
});

window.addEventListener("load", () => {
  if (typeof io !== "undefined") {
    window.globalSocket = io("http://localhost:5000", {
      transports: ["websocket"],
      upgrade: false,
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: Infinity,
    });
  }
  initGlobalSocket();
  initChatSocket();
  setInterval(checkBackendConnection, 30_000);
});