import hmac
import hashlib
import os
import secrets
import time


# -- Core HMAC ----------------------------------------------------------------
def compute_hmac(psk: str, device_id: str, timestamp: str,
                 nonce: str, payload: str = "iot_data") -> str:
    """
    Compute HMAC-SHA256 identical to the JS Web Crypto API implementation.
    All parts are concatenated WITHOUT separators to match JS byte layout.
    """
    message = device_id + timestamp + nonce + payload
    mac = hmac.new(
        psk.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    )
    return mac.hexdigest()


def verify_hmac(psk: str, device_id: str, timestamp: str,
                nonce: str, received_mac: str, payload: str = "iot_data") -> bool:
    """Constant-time HMAC verification (immune to timing attacks)."""
    expected = compute_hmac(psk, device_id, timestamp, nonce, payload)
    return hmac.compare_digest(expected, received_mac)

# -- Token / Nonce generators --------------------------------------------------
def generate_nonce() -> str:
    """16-byte (32 hex char) cryptographically-secure nonce."""
    return secrets.token_hex(16)


def generate_session_token() -> str:
    """128-bit URL-safe session token."""
    return secrets.token_urlsafe(16)


def current_ts() -> str:
    """Return current Unix timestamp as string (matches JS Math.floor(Date.now()/1000))."""
    return str(int(time.time()))


# Implements AES-256-GCM encryption for secure IoT message storage
try:
    # Import AES-GCM implementation for authenticated encryption
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    # Fallback if cryptography library is not available
    _HAS_CRYPTOGRAPHY = False


# Derives 256-bit AES key from device pre-shared key using SHA-256
def _derive_aes_key(psk: str) -> bytes:
    return hashlib.sha256(psk.encode("utf-8")).digest()


# Encrypts plaintext using AES-256-GCM and returns IV, ciphertext, and tag as hex string
def aes_encrypt(psk: str, plaintext: str) -> str:
    # Fallback mode if encryption library is missing
    if not _HAS_CRYPTOGRAPHY:
        encoded = plaintext.encode("utf-8").hex()
        return f"NO_CRYPTO_LIB:{encoded}:000000000000000000000000000000000000000000000000000000000000000000"

    # Derive AES key from PSK
    key = _derive_aes_key(psk)
    # Generate random 96-bit IV (nonce)
    iv = os.urandom(12)
    # Initialize AES-GCM cipher
    aesgcm = AESGCM(key)
    # Encrypt plaintext (returns ciphertext + authentication tag)
    ct_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    # Split ciphertext and authentication tag
    ciphertext = ct_tag[:-16]
    tag        = ct_tag[-16:]

    # Return combined encrypted output as colon-separated hex string
    return f"{iv.hex()}:{ciphertext.hex()}:{tag.hex()}"


# Decrypts AES-256-GCM encrypted data and verifies integrity using authentication tag
def aes_decrypt(psk: str, stored: str) -> str:
    # Handle fallback case when cryptography library is unavailable
    if not _HAS_CRYPTOGRAPHY or stored.startswith("NO_CRYPTO_LIB:"):
        parts = stored.split(":")
        return bytes.fromhex(parts[1]).decode("utf-8") if len(parts) >= 2 else stored

    # Extract IV, ciphertext, and authentication tag from stored format
    iv_hex, ct_hex, tag_hex = stored.split(":")
    # Derive AES key from PSK
    key = _derive_aes_key(psk)
    # Convert hex values back to byte arrays
    iv  = bytes.fromhex(iv_hex)
    ct  = bytes.fromhex(ct_hex)
    tag = bytes.fromhex(tag_hex)
    # Initialize AES-GCM cipher
    aesgcm = AESGCM(key)

    # Decrypt and verify data integrity (raises error if tampered or key is incorrect)
    return aesgcm.decrypt(iv, ct + tag, None).decode("utf-8")