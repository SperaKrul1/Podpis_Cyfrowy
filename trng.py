import sys
import numpy as np
import os
import matplotlib.pyplot as plt
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes


TARGET_SIZE = 10000  # 13.6 MB

def entropy(labels, base=2):
    vals, counts = np.unique(labels, return_counts=True)
    probs = counts / counts.sum()
    return -(probs * np.log(probs) / np.log(base)).sum()

def collect_data_from_multiple_files(target_size=TARGET_SIZE):
    data = bytearray()
    while len(data) < target_size:
        remaining = target_size - len(data)#ile jeszcze bajtów potrzebuję
        print(f"Potrzebuję jeszcze {remaining} bajtów. Podaj ścieżkę do pliku:")
        path = input("> ").strip()

        if not os.path.isfile(path):
            print(f"Plik '{path}' nie istnieje.")
            continue

        with open(path, 'rb') as f:
            chunk = f.read(remaining)#wczytaj z pliku f maxymalnie remaining bajtów
            data.extend(chunk)#dodaj bajty do data
            print(f"Dodano {len(chunk)} bajtów z '{path}'.")

    return bytes(data[:target_size])  #rzutowanie na bajty i przycięcie do target_size

def copy_binary_file_fixed_size(output_file, block_size=32):
    try:
        data = collect_data_from_multiple_files()
        raw_bytes = []
        hash_bytes = []
        file_hasher = hashlib.sha256()
        
        #Etap 1 Surowe dane przed SHA-256
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            if len(chunk) < block_size:
                chunk += b'\x00' * (block_size - len(chunk))
            raw_bytes.extend(chunk)

        raw_entropy = entropy(raw_bytes)
        print(f"Entropia surowych bajtów: {raw_entropy:.6f} bitów na bajt")

        byte_values = np.array(raw_bytes)
        plt.figure(figsize=(10, 5))
        plt.hist(byte_values, bins=256, range=(0, 255), color='steelblue', edgecolor='black')
        plt.title("Histogram rozkładu wartości bajtów (0–255)")
        plt.xlabel("Wartość bajtu")
        plt.ylabel("Liczba wystąpień")
        plt.grid(True)
        plt.tight_layout()
        plt.show()

        #Etap 2 SHA-256
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            if len(chunk) < block_size:
                chunk += b'\x00' * (block_size - len(chunk))
            digest = hashlib.sha256(chunk).digest()
            hash_bytes.extend(digest)
            file_hasher.update(chunk)

        hash_entropy = entropy(hash_bytes)
        print(f"Entropia bajtów po SHA-256: {hash_entropy:.6f} bitów na bajt")
        #print(f"Zapisano dane do: {output_file}")
        print(f"Hash SHA-256: {file_hasher.hexdigest()}")
        
        # Histogram danych po SHA-256
        plt.figure(figsize=(10, 4))
        plt.hist(hash_bytes, bins=256, range=(0, 255), color='steelblue', edgecolor='black')
        plt.title("Histogram bajtów po SHA-256")
        plt.xlabel("Wartość bajtu")
        plt.ylabel("Liczba wystąpień")
        plt.grid(True)
        plt.tight_layout()
        plt.show()

        #Etap 3 AES
        key = get_random_bytes(32)  # Klucz AES
        cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(128))
        encrypted_data = bytearray()
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            if len(chunk) < block_size:
                chunk += b'\x00' * (block_size - len(chunk))
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_data.extend(encrypted_chunk)
        encrypted_entropy = entropy(encrypted_data)
        print(f"Entropia bajtów po AES: {encrypted_entropy:.6f} bitów na bajt")

        # Histogram danych po AES
        plt.figure(figsize=(10, 4))
        plt.hist(encrypted_data, bins=256, range=(0, 255), color='steelblue', edgecolor='black')
        plt.title("Histogram bajtów po AES")
        plt.xlabel("Wartość bajtu")
        plt.ylabel("Liczba wystąpień")
        plt.grid(True)
        plt.tight_layout()
        plt.show()
        # Zapisanie zaszyfrowanych danych do pliku
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
        print(f"Zapisano zaszyfrowane dane do: {output_file}")
        print(f"Klucz AES: {key.hex()}")  # Wyświetlenie klucza w formacie szesnastkowym

    except Exception as e:
        print(f"Wystąpił błąd: {e}")

if __name__ == "__main__":
    copy_binary_file_fixed_size("output.bin")