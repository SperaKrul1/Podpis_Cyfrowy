## Opis działania programu

### 1. Generowanie kluczy RSA
- `generate_rsa_keypair()` tworzy parę kluczy (prywatny i publiczny) o długości 2048 bitów.

### 2. Obliczenie skrótu pliku (SHA3-256)
- `hash_file(path)` czyta plik w kawałkach (chunkach) i oblicza jego hash SHA3-256, zwracając bajty skrótu.

### 3. Podpis cyfrowy (RSA-PSS + SHA-256)
- `sign_digest(priv_key, digest)` podpisuje wcześniej obliczony hash przy użyciu algorytmu RSA-PSS na bazie SHA-256.
- `verify_signature(pub_key, digest, signature)` weryfikuje, czy podpis jest poprawny i spójny ze skrótem.

### 4. Hybrydowe szyfrowanie pliku
`encrypt_file(input_path, pub_key)`:
1. Oblicza hash pliku i generuje dla niego podpis.  
2. Tworzy losowy 256-bitowy klucz AES i szyfruje nim zawartość pliku w trybie GCM (uzyskując szyfrogram i tag uwierzytelniający).  
3. Zaszyfrowuje klucz AES kluczem publicznym RSA-OAEP.  
4. Pakuje w „kopertę” (JSON z Base64) wszystkie dane: zaszyfrowany klucz AES, nonce, tag, szyfrogram, hash i podpis.

### 5. Odszyfrowanie i weryfikacja integralności
`decrypt_file(output_path, priv_key, envelope)`:
1. RSA-OAEP odszyfrowuje klucz AES.  
2. AES-GCM odszyfrowuje szyfrogram i sprawdza tag (integralność danych).  
3. RSA-PSS weryfikuje podpis oryginalnego hasha, aby upewnić się, że plik nie był modyfikowany.  
4. Zapisuje odszyfrowaną treść do pliku.

---

Dzięki takiej konstrukcji program zapewnia:
- **Poufność** – symetryczne szyfrowanie AES-GCM + ochrona klucza AES RSA-OAEP.  
- **Integralność** – tag uwierzytelniający AES-GCM oraz weryfikacja podpisu.  
- **Uwierzytelnienie nadawcy** – podpis RSA-PSS na skrócie pliku.  
