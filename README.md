# filecrypt

Minimal AES-256-GCM file encryptor/decryptor with EC (P-256) signing. Everything runs on standard C++23 and OpenSSL.

## What it does

`filecrypt` is a command-line tool that allows you to:

- **Encrypt files:** Using AES-256-GCM, a modern and secure encryption cipher.
- **Decrypt files:** That have been encrypted with this tool.
- **Sign files:** Create a digital signature for a file using an elliptic curve private key (P-256).
- **Verify signatures:** Check the integrity and authenticity of a file using the corresponding public key.

This provides a secure way to protect your files from unauthorized access and to ensure they have not been tampered with.

### Prereqs

- **Build tools:** A C++23 compiler and CMake.
  - Recommended: GCC 14+ or Clang 18+.
- **Linux/Gentoo:** `sudo emerge --quiet dev-libs/openssl`
- **Ubuntu/Debian:** `sudo apt install libssl-dev`
- **macOS (Homebrew):** `brew install openssl@3`

---

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j8
```

Binary: `build/filecrypt`

## Test

```bash
cd build
ctest --output-on-failure
```

---

## Usage

1. Generate keys (example with P-256):
   ```bash
   openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem
   openssl ec -in ec_private.pem -pubout -out ec_public.pem
   ```
2. Create a 32-byte AES key:
   ```bash
   KEY_HEX=$(openssl rand -hex 32)
   ```
3. Encrypt (prints IV/Tag/Signature; default output is `<input>.enc` if `--out` omitted):
   ```bash
   SIGNATURE_HEX=$(
     build/filecrypt encrypt \
       --in plain.txt \
       --enc-key "$KEY_HEX" \
       --sign-key ec_private.pem \
       | awk '/Signature \(hex\): / {print $3}'
   )
   ```
4. Decrypt (default output strips trailing `.enc`, otherwise adds `.dec`):
   ```bash
   build/filecrypt decrypt \
     --in plain.txt.enc \
     --enc-key "$KEY_HEX" \
     --verify-key ec_public.pem \
     --signature "$SIGNATURE_HEX"
   ```

---

## Docker - gentoo build

Build image (compiles, runs `ctest`, performs smoke encrypt/decrypt):
```bash
docker build --progress=plain -t filecrypt-gentoo .
```

Run inside container (mount current dir, entrypoint already points to the binary in `/usr/local/bin/filecrypt`):
```bash
# Encrypt a host file
docker run --rm -v "$PWD":/workspace filecrypt-gentoo \
  encrypt --in /workspace/plain.txt --out /workspace/plain.txt.enc \
  --sign-key /workspace/ec_private.pem --enc-key 441be8b4193b8938fdb8d807bb13b07505e870f1845e8aca178836f9657f52e8

# Decrypt using the printed signature
docker run --rm -v "$PWD":/workspace filecrypt-gentoo \
  decrypt --in /workspace/plain.txt.enc --out /workspace/restored.txt \
  --enc-key 441be8b4193b8938fdb8d807bb13b07505e870f1845e8aca178836f9657f52e8 --verify-key /workspace/ec_public.pem \
  --signature "$SIGNATURE_HEX"
```
