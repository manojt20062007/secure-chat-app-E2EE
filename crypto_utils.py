# crypto_utils.py
import base64
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key_pair():
    """
    Returns (private_bytes, public_bytes) where both are raw 32-byte values.
    """
    priv = x25519.X25519PrivateKey.generate()
    priv_b = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_b = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv_b, pub_b

def derive_shared_key(private_key_bytes, peer_public_key_bytes):
    """
    Returns 32-byte shared key (slice of shared secret) for AES-256.
    """
    priv = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared = priv.exchange(peer)
    return shared[:32]

def encrypt_message(shared_key, plaintext):
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_message(shared_key, b64_data):
    raw = base64.b64decode(b64_data)
    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(shared_key)
    return aesgcm.decrypt(nonce, ct, None).decode()
