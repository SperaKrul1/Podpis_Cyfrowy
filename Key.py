import os
import json
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Random import get_random_bytes

# ---- Parametry ----
RSA_KEY_SIZE   = 2048         # bezpieczne minimum
AES_KEY_SIZE   = 32           # 256-bitowy klucz AES
AES_NONCE_SIZE = 12           # 96-bitowy nonce dla GCM
AES_TAG_SIZE   = 16           # 128-bitowy tag dla GCM
CHUNK_SIZE     = 4096         # do hashowania dużych plików

# ---- Generowanie/parowanie kluczy RSA ----
def generate_rsa_keypair():
    key = RSA.generate(RSA_KEY_SIZE)
    return key, key.publickey()

# ---- Hash pliku (SHA3-256) ----
def hash_file(path):
    h = hashlib.sha3_256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.digest()

# ---- Podpis cyfrowy (RSA-PSS na SHA-256) ----
def sign_digest(priv_key, digest):
    h = SHA256.new(digest)
    return pss.new(priv_key).sign(h)

def verify_signature(pub_key, digest, signature):
    h = SHA256.new(digest)
    try:
        pss.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ---- Hybrydowe szyfrowanie pliku ----
def encrypt_file(input_path, pub_key):
    # 1) Oblicz hash i podpisz go
    digest   = hash_file(input_path)
    signature = sign_digest(priv_key, digest)

    # 2) AES-GCM do treści
    aes_key = get_random_bytes(AES_KEY_SIZE)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=get_random_bytes(AES_NONCE_SIZE))
    with open(input_path, "rb") as f:
        ciphertext, tag = cipher_aes.encrypt_and_digest(f.read())

    # 3) Zaszyfruj klucz AES RSA-OAEP
    cipher_rsa    = PKCS1_OAEP.new(pub_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    # 4) Zapakuj wszystko w JSON z Base64
    envelope = {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "nonce":         base64.b64encode(cipher_aes.nonce).decode(),
        "tag":           base64.b64encode(tag).decode(),
        "ciphertext":    base64.b64encode(ciphertext).decode(),
        "digest":        base64.b64encode(digest).decode(),
        "signature":     base64.b64encode(signature).decode(),
    }
    return envelope

# ---- Odszyfrowanie i weryfikacja ----
def decrypt_file(output_path, priv_key, envelope):
    # 1) Odszyfruj klucz AES
    encrypted_key = base64.b64decode(envelope["encrypted_key"])
    aes_key = PKCS1_OAEP.new(priv_key).decrypt(encrypted_key)

    # 2) Odszyfruj plik AES-GCM
    nonce      = base64.b64decode(envelope["nonce"])
    tag        = base64.b64decode(envelope["tag"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext  = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # 3) Zweryfikuj podpis hasha
    digest    = base64.b64decode(envelope["digest"])
    signature = base64.b64decode(envelope["signature"])
    if not verify_signature(pub_key, digest, signature):
        raise ValueError("Nieudana weryfikacja podpisu – plik zmodyfikowany")

    # 4) Zapisz odszyfrowany plik
    with open(output_path, "wb") as f:
        f.write(plaintext)
    return True

# ---- Przykład użycia ----
if __name__ == "__main__":
    # 1. Generujemy klucze
    priv_key, pub_key = generate_rsa_keypair()

    # 2. Szyfrujemy plik tekst1.txt
    envelope = encrypt_file("tekst1.txt", pub_key)
    # Zapisz envelope do JSON-a:
    with open("tekst1.enc.json", "w") as f:
        json.dump(envelope, f, indent=2)

    # 3. Odszyfruj i weryfikuj
    with open("tekst1.enc.json") as f:
        loaded_env = json.load(f)
    try:
        decrypt_file("tekst1_decrypted.txt", priv_key, loaded_env)
        print("✅ Odszyfrowano i podpis jest prawidłowy")
    except Exception as e:
        print("❌ Błąd:", e)
