# Folder Encryptor - Secure Folder Encryption and Decryption

## Overview
Folder Encryptor is a Python script that allows users to securely encrypt and decrypt folders using AES-GCM encryption. It supports encryption of individual files within a folder, ensuring that sensitive data is protected. The script provides a progress bar to visualize the encryption and decryption process in real time.

## Features
- Encrypts and decrypts folders containing multiple files.
- Uses AES-GCM encryption for strong data security.
- Generates a random salt for key derivation.
- Displays a real-time progress bar during encryption and decryption.
- Removes original files after encryption to prevent unauthorized access.

## Requirements
- Python 3.6 or higher
- Required Python libraries:
  - `cryptography`
  - `tqdm`

## Installation
1. Clone this repository or download the script file.
2. Install the required libraries using pip:
  if windows:

   ```
   pip install -r requirements.txt
   ```


  if linux:

   ```
    pip3 install -r requirements.txt
   ```
  
3. Run the script using the following command:

  if windows:

   ```
   python main.py
   ```

  if linux:
  
   ```
    python3 main.py
   ```

## Usage
1. Run the script and select the desired operation (encrypt or decrypt).
2. Enter the path of the folder to be encrypted or decrypted.
3. Enter the password for encryption or decryption.
4. The script will display a progress bar to visualize the process.
5. Once the process is complete, the encrypted or decrypted folder will be created in the same directory as the original folder.
6. The original files will be removed after encryption to ensure data security.
7. The encrypted folder can be decrypted using the same password.
8. The decrypted folder will contain the original files.
9. The script will display a success message upon completion of the process.
10. The encrypted folder can be safely shared or stored for secure data protection.
