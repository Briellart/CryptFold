from cryptography.fernet import Fernet 
import os
import subprocess
import hashlib

class Encryptor:
    def __init__(self, key):
        self.key = key
        self.hashes = {}

    def generate_key(self):
        key = Fernet.generate_key()
        with open(r"key.key", "wb") as key_file:
            key_file.write(key)
        os.chmod(r"key.key", 0o600)  # Permisos seguros

    def load_key(self):
        try:
            with open(r"key.key", "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            raise Exception("Key file not found")
        except Exception as e:
            raise Exception(f"Error loading key: {e}")

    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def encrypt_file(self, file_path):
        try:
            f = Fernet(self.key)
            with open(file_path, "rb") as file:
                file_data = file.read()
            file_hash = self.calculate_hash(file_path)
            encrypted_data = f.encrypt(file_data)
            with open(file_path, "wb") as file:
                file.write(encrypted_data)
            self.hashes[file_path] = file_hash
        except Exception as e:
            raise Exception(f"Error encrypting file {file_path}: {e}")

    def encrypt_folder(self, folder):
        for root, dirs, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                self.encrypt_file(file_path)

    def decrypt_file(self, file_path):
        try:
            f = Fernet(self.key)
            with open(file_path, "rb") as file:
                encrypted_data = file.read()
            decrypted_data = f.decrypt(encrypted_data)
            with open(file_path, "wb") as file:
                file.write(decrypted_data)
            self.verify_file(file_path)
        except Exception as e:
            raise Exception(f"Error decrypting file {file_path}: {e}")
        
    def verify_file(self, file_path):
        current_hash = self.calculate_hash(file_path)
        stored_hash = self.hashes.get(file_path)
        if stored_hash is None:
            raise Exception(f"No hash stored for file {file_path}")
        if current_hash != stored_hash:
            raise Exception(f"File verification failed for {file_path}: hash mismatch")

    def decrypt_folder(self, folder):
        for root, dirs, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                self.decrypt_file(file_path)

    def list_encrypted_files(self, folder):
        encrypted_files = []
        for root, dirs, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                encrypted_files.append(file_path)
        return encrypted_files
    

def print_banner():
    print("""
   █████████                                  █████    ███████████          ████      █████
  ███░░░░░███                                ░░███    ░░███░░░░░░█         ░░███     ░░███ 
 ███     ░░░  ████████  █████ ████ ████████  ███████   ░███   █ ░   ██████  ░███   ███████ 
░███         ░░███░░███░░███ ░███ ░░███░░███░░░███░    ░███████    ███░░███ ░███  ███░░███ 
░███          ░███ ░░░  ░███ ░███  ░███ ░███  ░███     ░███░░░█   ░███ ░███ ░███ ░███ ░███ 
░░███     ███ ░███      ░███ ░███  ░███ ░███  ░███ ███ ░███  ░    ░███ ░███ ░███ ░███ ░███ 
 ░░█████████  █████     ░░███████  ░███████   ░░█████  █████      ░░██████  █████░░████████
  ░░░░░░░░░  ░░░░░       ░░░░░███  ░███░░░     ░░░░░  ░░░░░        ░░░░░░  ░░░░░  ░░░░░░░░ 
                         ███ ░███  ░███                                                    
                        ░░██████   █████                                                   
                         ░░░░░░   ░░░░░     


    by Briellart.                                                                                                                              
    """)


def run_icacls_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode(), result.stderr.decode()
    except subprocess.CalledProcessError as e:
        print(f"Command '{command}' failed with error: {e.stderr.decode()}")
        return None, e.stderr.decode()

if __name__ == "__main__":
    print_banner()
    
    encryptor = Encryptor(None)

    while True:
        print("\n")
        print("1.- Encrypt Folder")
        print("2.- Decrypt Folder")
        print("3.- List Encrypted Files")
        print("0.- Exit")
        print("\n")
        opcion=input("Choose an option: ")


        if opcion == "1":
            folder_path = input("Enter the folder path to encrypt: ") #C:\Users\34600\Desktop\carpeto
            if not os.path.isdir(folder_path):
                print("Invalid folder path.")
                continue

            encryptor.generate_key()
            key = encryptor.load_key()
            encryptor.key = key

            encryptor.encrypt_folder(folder_path)

            stdout, stderr = run_icacls_command(f'icacls "{folder_path}" /deny Todos:(OI)(CI)F')
            if stderr:
                print(stderr)

  
        elif opcion == "2":
            try:
                key = encryptor.load_key()
                if key:
                    encryptor.key = key
                    folder_path = input("Enter the folder path to decrypt: ")
                    if not os.path.isdir(folder_path):
                        print("Invalid folder path.")
                        continue

                    

                    stdout, stderr = run_icacls_command(f'icacls "{folder_path}" /grant Todos:(OI)(CI)F')
                    encryptor.decrypt_folder(folder_path)
                    if stderr:
                        print(stderr)

            except FileNotFoundError:
                print("Error: key not found.")

            except Exception as e:
                print(f"An error occurred: {e}")

        elif opcion == "3":
            folder_path = input("Enter the folder path to list encrypted files: ")
            if not os.path.isdir(folder_path):
                print("Invalid folder path.")
                continue

            stdout, stderr = run_icacls_command(f'icacls "{folder_path}" /grant Todos:(OI)(CI)F')
            if stderr:
                print(stderr)

            encrypted_files = encryptor.list_encrypted_files(folder_path)

            stdout, stderr = run_icacls_command(f'icacls "{folder_path}" /deny Todos:(OI)(CI)F')
            if stderr:
                print(stderr)

            for file in encrypted_files:
                print(file)

        elif opcion == "0":
            print("Exiting...")
            break
        
        else:
            print("Invalid option. Please choose again.")