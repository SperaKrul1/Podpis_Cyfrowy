#!/usr/bin/env python3
import os
import argparse
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash      import SHA256, SHA3_256

# Plik RNG wykorzystywany do seedowania DRBG
RNG_FILE = "output.bin"

class DRBG:
    """Prosty deterministyczny generator z seedem SHA3-256."""
    def __init__(self, seed_bytes):
        self.seed = seed_bytes
        self.counter = 0

    def __call__(self, n):
        out = bytearray()
        while len(out) < n:
            ctr = self.counter.to_bytes(16, 'big')
            # nowy blok = SHA3-256(counter || seed)
            block = SHA3_256.new(ctr + self.seed).digest()
            out.extend(block)
            self.counter += 1
        return bytes(out[:n])

def generate_keys():
    if not os.path.exists(RNG_FILE):
        print(f"❌ Brak pliku RNG: {RNG_FILE}")
        exit(1)

    # 1) Odczytaj output.bin i oblicz seed
    data = open(RNG_FILE, 'rb').read()
    seed = SHA3_256.new(data).digest()
    drbg = DRBG(seed)

    print("🔄 Generuję parę kluczy RSA 2048-bit na podstawie DRBG...")
    key = RSA.generate(2048, randfunc=drbg)

    # 2) Zapisz klucze
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem",  "wb") as f:
        f.write(key.publickey().export_key())
    print("✔️ Klucze zapisane: private.pem, public.pem")
    return key

def sign_file(input_path, sig_path):
    # 1) przygotuj klucze
    key = generate_keys()
    priv = key

    # 2) wczytaj i oblicz hash
    if not os.path.exists(input_path):
        print(f"❌ Plik do podpisania nie istnieje: {input_path}")
        exit(1)
    data = open(input_path, "rb").read()
    print(f"🔄 Podpisuję plik: {input_path}")
    h = SHA256.new(data)

    # 3) podpiś
    signature = pss.new(priv).sign(h)

    # 4) zapis podpisu
    with open(sig_path, "wb") as f:
        f.write(signature)
    print(f"✍️  Podpis zapisany → {sig_path} ({len(signature)} bajtów)")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Signer: deterministyczne klucze z output.bin + podpis SHA256-PSS")
    p.add_argument("input", help="plik do podpisania (np. test.txt)")
    p.add_argument("-o","--output", default=None,
                   help="plik z podpisem (domyślnie <input>.sig)")
    args = p.parse_args()

    sig_file = args.output or args.input + ".sig"
    sign_file(args.input, sig_file)
