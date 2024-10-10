import os
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass
from tqdm import tqdm  # Import the tqdm library for progress bars

CHUNK_SIZE = 64 * 1024  # 64KB chunk size

# Function to derive a key from a password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file in chunks using AES-GCM with a progress bar
def encrypt_file(file_path, key):
    file_size = os.path.getsize(file_path)
    
    # Create a random nonce (12 bytes)
    nonce = os.urandom(12)
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    output_file = file_path + ".enc"
    
    with open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        # Write nonce to output file
        f_out.write(base64.b64encode(nonce))

        # Initialize progress bar
        with tqdm(total=file_size, unit='B', unit_scale=True, desc="Encrypting", ncols=100) as pbar:
            while chunk := f_in.read(CHUNK_SIZE):
                encrypted_chunk = encryptor.update(chunk)
                f_out.write(base64.b64encode(encrypted_chunk))
                pbar.update(len(chunk))  # Update the progress bar

        # Finalize encryption
        encrypted_final = encryptor.finalize()
        f_out.write(base64.b64encode(encrypted_final))

        # Write authentication tag
        f_out.write(base64.b64encode(encryptor.tag))

    os.remove(file_path)

# Decrypt a file in chunks using AES-GCM with a progress bar
def decrypt_file(file_path, key):
    file_size = os.path.getsize(file_path)
    
    with open(file_path, 'rb') as f_in:
        # Read nonce
        nonce = base64.b64decode(f_in.read(16))  # Nonce is base64-encoded (12 bytes -> 16 bytes)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        decryptor = cipher.decryptor()

        output_file = file_path.replace(".enc", "")
        
        with open(output_file, 'wb') as f_out:
            # Initialize progress bar
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Decrypting", ncols=100) as pbar:
                while True:
                    encrypted_chunk = f_in.read(88)  # Encrypted chunk size (64KB -> base64 -> ~88KB)
                    if len(encrypted_chunk) == 0:
                        break

                    decrypted_chunk = decryptor.update(base64.b64decode(encrypted_chunk))
                    f_out.write(decrypted_chunk)
                    pbar.update(len(encrypted_chunk))  # Update the progress bar

            # Finalize decryption
            decrypted_final = decryptor.finalize()
            f_out.write(decrypted_final)

            # Verify tag
            tag = base64.b64decode(f_in.read(24))  # Authentication tag is 16 bytes (base64 -> 24 bytes)
            if decryptor.tag != tag:
                raise ValueError("Authentication tag does not match!")

    os.remove(file_path)

# Encrypt all files in a folder
def encrypt_folder(folder_path, password):
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)

    # Save salt for decryption
    with open(os.path.join(folder_path, 'salt'), 'wb') as f:
        f.write(salt)

# Decrypt all files in a folder
def decrypt_folder(folder_path, password):
    # Retrieve salt
    with open(os.path.join(folder_path, 'salt'), 'rb') as f:
        salt = f.read()

    key = derive_key(password, salt)

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, key)

    # Remove salt file
    os.remove(os.path.join(folder_path, 'salt'))

# Main function to encrypt or decrypt a folder
def main():
    folder_path = input("Enter the folder path: ")
    action = input("Do you want to (E)ncrypt or (D)ecrypt the folder? ").lower()

    if action == 'e':
        password = getpass("Enter a password to encrypt: ")
        encrypt_folder(folder_path, password)
        print("Folder encrypted successfully.")
    elif action == 'd':
        password = getpass("Enter the password to decrypt: ")
        decrypt_folder(folder_path, password)
        print("Folder decrypted successfully.")
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
