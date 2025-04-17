import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidKey
from eth_account import Account
from eth_utils import to_checksum_address
import sys
import platform

# Cross-platform imports for secure password input
if platform.system() == "Windows":
    import msvcrt
else:
    import tty
    import termios

def get_secure_password(prompt="Enter password: "):
    """Custom password input that shows asterisks (*) for each character entered, cross-platform."""
    print(prompt, end='', flush=True)
    password = []

    if platform.system() == "Windows":
        while True:
            char = msvcrt.getch()
            try:
                char = char.decode('utf-8')
            except UnicodeDecodeError:
                char = char.decode('cp1252')
            if char == '\r':
                print()
                break
            elif char == '\b':
                if password:
                    password.pop()
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            else:
                password.append(char)
                sys.stdout.write('*')
                sys.stdout.flush()
    else:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                char = sys.stdin.read(1)
                if char == '\r' or char == '\n':
                    print()
                    break
                elif char == '\x7f':
                    if password:
                        password.pop()
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                else:
                    password.append(char)
                    sys.stdout.write('*')
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return ''.join(password)

def load_passwords(file_path: str) -> list:
    """Load passwords from a file, one per line, with UTF-8 encoding."""
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
        if not passwords:
            raise Exception("Password file is empty.")
        
        for pwd in passwords:
            if any(ord(char) > 127 for char in pwd):
                print(f"Warning: Password '{pwd[:2]}...' contains special characters (e.g., diacritics). Ensure correct encoding.")
        
        return passwords
    except UnicodeDecodeError:
        raise Exception(f"Failed to decode {file_path}. Ensure the file is saved in UTF-8 encoding.")
    except FileNotFoundError:
        raise Exception(f"Password file {file_path} not found.")

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a key from the password using PBKDF2."""
    try:
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        ).derive(password.encode('utf-8'))
    except UnicodeEncodeError as e:
        raise Exception(f"Failed to encode password due to unsupported characters: {str(e)}") from e

def decrypt_vault(vault_data: dict, password: str) -> list:
    """Decrypt the MetaMask vault."""
    try:
        required_keys = ["data", "iv", "salt", "keyMetadata"]
        for key in required_keys:
            if key not in vault_data:
                raise Exception(f"Invalid vault format: Missing '{key}' field.")
        
        if "params" not in vault_data["keyMetadata"] or "iterations" not in vault_data["keyMetadata"]["params"]:
            raise Exception("Invalid vault format: Missing 'keyMetadata.params.iterations' field.")

        ciphertext = base64.b64decode(vault_data["data"])
        iv = base64.b64decode(vault_data["iv"])
        salt = base64.b64decode(vault_data["salt"])
        iterations = vault_data["keyMetadata"]["params"]["iterations"]

        key = derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(iv, ciphertext, None)
        return json.loads(decrypted_data.decode())
    except (InvalidKey, ValueError) as e:
        raise Exception(f"Incorrect password or invalid vault data: {str(e)}") from e
    except Exception as e:
        raise Exception(f"Decryption error: {str(e)}") from e

def get_ethereum_address(private_key: str) -> str:
    """Derive Ethereum address from a private key."""
    try:
        if not private_key.startswith("0x"):
            private_key = f"0x{private_key}"
        account = Account.from_key(private_key)
        return account.address
    except Exception as e:
        print(f"Warning: Could not derive address for key {private_key[:6]}...: {str(e)}")
        return "Invalid address"

def get_seed_phrase_address(mnemonic: str) -> str:
    """Derive the first Ethereum address from a seed phrase."""
    try:
        Account.enable_unaudited_hdwallet_features()
        account = Account.from_mnemonic(
            mnemonic,
            account_path="m/44'/60'/0'/0/0"
        )
        return to_checksum_address(account.address)
    except Exception as e:
        print(f"Warning: Could not derive address from seed phrase: {str(e)}")
        return "Invalid address"

def extract_imported_private_keys(keyrings: list) -> list:
    """Extract private keys for imported accounts (Simple Key Pair)."""
    private_keys = []
    
    if not isinstance(keyrings, list):
        print("Error: Keyrings is not a list.")
        return private_keys

    for keyring in keyrings:
        if not isinstance(keyring, dict):
            print("Warning: Unexpected keyring format:", keyring)
            continue
        
        if keyring.get("type") == "Simple Key Pair":
            data = keyring.get("data")
            if isinstance(data, list):
                for key in data:
                    if isinstance(key, str):
                        if not key.startswith("0x"):
                            private_keys.append(f"0x{key}")
                        else:
                            private_keys.append(key)
                    else:
                        print("Warning: Unexpected key format:", key)
            else:
                print("Warning: 'data' field is not a list:", data)
    
    return private_keys

def extract_seed_phrase(decrypted_data) -> str:
    """Extract the seed phrase from the decrypted vault data."""
    try:
        if isinstance(decrypted_data, list):
            keyrings = decrypted_data
        elif isinstance(decrypted_data, dict):
            keyrings = decrypted_data.get("keyrings", [])
        else:
            print("Warning: Unexpected decrypted data format.")
            return "No seed phrase found."

        for keyring in keyrings:
            if not isinstance(keyring, dict):
                continue
            if keyring.get("type") == "HD Key Tree":
                mnemonic = keyring.get("data", {}).get("mnemonic")
                if mnemonic:
                    if isinstance(mnemonic, list):
                        try:
                            mnemonic = ''.join(chr(i) for i in mnemonic)
                            return mnemonic
                        except:
                            pass
                    elif isinstance(mnemonic, str):
                        try:
                            mnemonic_bytes = base64.b64decode(mnemonic)
                            return mnemonic_bytes.decode('utf-8')
                        except:
                            return mnemonic
                    elif isinstance(mnemonic, bytes):
                        return mnemonic.decode('utf-8')
                return "No seed phrase found."
        return "No seed phrase found."
    except Exception as e:
        print(f"Warning: Could not extract seed phrase: {str(e)}")
        return "No seed phrase found."

def load_vault_from_file(file_path: str) -> dict:
    """Load vault from a file with UTF-8 encoding."""
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            vault_data = f.read()
        return json.loads(vault_data)
    except FileNotFoundError:
        raise Exception(f"File {file_path} not found.")
    except json.JSONDecodeError:
        raise Exception("Invalid vault format in file. Expected JSON.")
    except UnicodeDecodeError:
        raise Exception(f"Failed to decode {file_path}. Ensure the file is saved in UTF-8 encoding.")

def mask_seed_phrase(seed_phrase: str) -> str:
    """Mask the seed phrase for console output, showing only the first 4 words."""
    if seed_phrase == "No seed phrase found.":
        return seed_phrase
    words = seed_phrase.split()
    if len(words) < 4:
        return f"{seed_phrase[:4]}... (hidden for security)"
    return f"{' '.join(words[:4])}... (hidden for security)"

def mask_private_key(private_key: str) -> str:
    """Mask the private key for console output, showing only the first 4 characters after '0x'."""
    if not private_key.startswith("0x"):
        return f"0x{private_key[:4]}... (hidden for security)"
    return f"{private_key[:6]}... (hidden for security)"

def main():
    print("")
    print("+---------------------------------------------------+")
    print("|                                                   |")
    print("|              MetaMask Vault Extractor             |")
    print("|          Created by MetaMask Guide Luigi          |")
    print("|                                                   |")
    print("+---------------------------------------------------+")

    vault_file = "vault_data.txt"
    password_file = "password_list.txt"

    try:
        print(f"\nLoading vault from file: {vault_file}")
        vault = load_vault_from_file(vault_file)

        decrypted = None
        used_password = None
        try:
            print(f"\nLoading passwords from file: {password_file}")
            passwords = load_passwords(password_file)
            print(f"Found {len(passwords)} passwords to try:")
            for idx, pwd in enumerate(passwords, 1):
                print(f"  {idx}. {pwd[:2]}... (hidden for security)")

            for idx, password in enumerate(passwords, 1):
                print(f"\nTrying password {idx}/{len(passwords)}: {password[:2]}... (hidden for security)")
                try:
                    decrypted = decrypt_vault(vault, password)
                    used_password = password
                    print("Password successful! Decryption complete.")
                    break
                except Exception as e:
                    print(f"Decryption unsuccessful with this password.")

        except Exception as e:
            print(f"Error loading passwords: {str(e)}")

        if decrypted is None:
            print("\nNone of the passwords from the file were correct.")
            print("Falling back to manual password input.")
            password = get_secure_password("Enter password manually: ")
            try:
                decrypted = decrypt_vault(vault, password)
                used_password = password
                print("Manual password successful! Decryption complete.")
            except Exception as e:
                raise Exception(f"Manual password also failed: {str(e)}")

        print(f"\nSuccessfully decrypted using password: {used_password[:2]}... (hidden for security)")

        # Extract and display seed phrase first
        seed_phrase = extract_seed_phrase(decrypted)
        print("\nSeed Phrase:")
        print("------------")
        print(mask_seed_phrase(seed_phrase))
        
        with open("decrypt_data.txt", "w", encoding='utf-8') as f:
            f.write(f"Seed Phrase: {seed_phrase}\n")
            if seed_phrase != "No seed phrase found.":
                seed_address = get_seed_phrase_address(seed_phrase)
                print(f"Account 1: {seed_address}")
                f.write(f"Account 1: {seed_address}\n")

        # Extract and display imported private keys
        private_keys = extract_imported_private_keys(decrypted)

        if not private_keys:
            print("\nNo private keys found for imported accounts (Simple Key Pair).")
        else:
            print("\nImported Accounts (Private Keys & Addresses):")
            print("--------------------------------------------")
            key_info = []
            for idx, key in enumerate(private_keys, 1):
                address = get_ethereum_address(key)
                print(f"Account {idx}:")
                print(f"  Private Key: {mask_private_key(key)}")
                print(f"  Address:     {address}")
                key_info.append({"private_key": key, "address": address})

            with open("decrypt_data.txt", "a", encoding='utf-8') as f:
                for info in key_info:
                    f.write(f"\nPrivate Key: {info['private_key']}\n")
                    f.write(f"Ethereum Address: {info['address']}\n")

        print("\nAll data has been saved to file: decrypt_data.txt")

    except Exception as e:
        print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()