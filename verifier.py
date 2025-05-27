#!/usr/bin/env python3
import os
import argparse
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash      import SHA256

def verify_and_save(input_path, sig_path):
    # Wczytaj klucz publiczny
    pub = RSA.import_key(open("public.pem", "rb").read())

    # Wczytaj dane i sygnaturę
    data = open(input_path, "rb").read()
    sig  = open(sig_path,   "rb").read()

    # Oblicz hash SHA-256
    h = SHA256.new(data)

    # Weryfikuj podpis
    try:
        pss.new(pub).verify(h, sig)
    except (ValueError, TypeError):
        print("❌ Nieprawidłowy podpis lub plik zmodyfikowany!")
        return False

    # Jeśli podpis prawidłowy, zapisz plik z dopiskiem ".unlock"
    base, ext = os.path.splitext(input_path)
    out_path = f"{base}.unlock{ext}"
    with open(out_path, "wb") as f:
        f.write(data)

    print(f"🔓 Podpis prawidłowy. Zapisano plik → {out_path}")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verifier: weryfikuje podpis i zapisuje plik z dopiskiem .unlock")
    parser.add_argument("input", help="plik do weryfikacji (np. artur.png)")
    parser.add_argument("sig",   help="plik z podpisem (np. artur.png.sig)")
    args = parser.parse_args()

    verify_and_save(args.input, args.sig)
