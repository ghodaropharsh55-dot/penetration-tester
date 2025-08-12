import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import secrets

# ===============================
# AES-256 File Encryption & Decryption Tool
# ===============================

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte AES key from the password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32 bytes key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    """Encrypts a file using AES-256."""
    # Generate random salt and IV
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    key = derive_key(password, salt)

    # Read file data
    with open(file_path, "rb") as f:
        data = f.read()

    # Pad data to match block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save encrypted file with salt & IV
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(salt + iv + encrypted_data)

    print(f"[SUCCESS] File encrypted: {encrypted_file_path}")

def decrypt_file(file_path: str, password: str):
    """Decrypts a file encrypted with AES-256."""
    with open(file_path, "rb") as f:
        content = f.read()

    # Extract salt, IV, and encrypted data
    salt = content[:16]
    iv = content[16:32]
    encrypted_data = content[32:]

    key = derive_key(password, salt)

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Save decrypted file
    decrypted_file_path = file_path.replace(".enc", "_decrypted")
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"[SUCCESS] File decrypted: {decrypted_file_path}")

# ===============================
# MAIN MENU
# ===============================
if __name__ == "__main__":
    print("""
    ==========================
       Advanced Encryption Tool
    ==========================
    1. Encrypt a file
    2. Decrypt a file
    """)
    choice = input("Select option (1-2): ").strip()
    file_path = input("Enter file path: ").strip()
    password = input("Enter password: ").strip()

    if choice == "1":
        encrypt_file(file_path, password)
    elif choice == "2":
        decrypt_file(file_path, password)
    else:
        print("Invalid choice.")
