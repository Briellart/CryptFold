# CryptFold

CryptFold is a Python script designed to encrypt and decrypt files and folders using the Fernet symmetric encryption method. It ensures data integrity by calculating and verifying SHA-256 hashes of the files before and after encryption/decryption.

## Features

- **Load Encryption Key**: Loads the encryption key from a file.
- **Calculate File Hash**: Computes the SHA-256 hash of a file.
- **Encrypt File**: Encrypts a single file and stores its hash.
- **Encrypt Folder**: Recursively encrypts all files in a folder.
- **Decrypt File**: Decrypts a single file and verifies its integrity.
- **Verify File**: Verifies the integrity of a file by comparing its current hash with the stored hash.

## Requirements

To run this script, you need the following Python packages:

- `cryptography`
- `hashlib`
- `os`

You can install the required packages using pip:

```sh
pip install cryptography
```

## Usage

- **Encrypt a File**: Call the encrypt_file method with the path to the file you want to encrypt.
- **Load the Encryption Key**: Ensure you have a file named key.key containing your encryption key in the same directory as the script.
- **Decrypt a File**: Call the decrypt_file method with the path to the file you want to decrypt.


## Acknowledgments
- cryptography library for providing the encryption tools.
- Python community for the support and resources.

## Note
I am a beginner, and any suggestions or help are very welcome as I do not have much experience in this field.


Contact
For any issues or inquiries, please open an issue on this repository or contact the maintainer.
