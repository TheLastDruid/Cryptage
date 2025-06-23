"""
AES (Advanced Encryption Standard) Implementation
Symmetric encryption algorithm using the cryptography library.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64


class AES:
    """
    AES encryption/decryption implementation.
    """
    
    def __init__(self, key_size=256):
        """
        Initialize AES with specified key size.
        
        Args:
            key_size (int): Key size in bits (128, 192, or 256)
        """
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits")
        
        self.key_size = key_size
        self.key_bytes = key_size // 8
        self.block_size = 16  # AES block size is always 128 bits (16 bytes)
    
    def generate_key(self):
        """
        Generate a random AES key.
        
        Returns:
            bytes: Random key
        """
        return os.urandom(self.key_bytes)
    
    def derive_key_from_password(self, password, salt=None):
        """
        Derive AES key from password using PBKDF2.
        
        Args:
            password (str): Password to derive key from
            salt (bytes): Salt for key derivation (generated if None)
            
        Returns:
            tuple: (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_bytes,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    def encrypt_cbc(self, plaintext, key, iv=None):
        """
        Encrypt plaintext using AES-CBC mode.
        
        Args:
            plaintext (bytes): Data to encrypt
            key (bytes): Encryption key
            iv (bytes): Initialization vector (generated if None)
            
        Returns:
            tuple: (ciphertext, iv)
        """
        if iv is None:
            iv = os.urandom(self.block_size)
        
        # Pad the plaintext to block size
        padder = padding.PKCS7(self.block_size * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Create cipher and encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return ciphertext, iv
    
    def decrypt_cbc(self, ciphertext, key, iv):
        """
        Decrypt ciphertext using AES-CBC mode.
        
        Args:
            ciphertext (bytes): Data to decrypt
            key (bytes): Decryption key
            iv (bytes): Initialization vector
            
        Returns:
            bytes: Decrypted plaintext
        """
        # Create cipher and decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(self.block_size * 8).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def encrypt_gcm(self, plaintext, key, nonce=None, associated_data=None):
        """
        Encrypt plaintext using AES-GCM mode (authenticated encryption).
        
        Args:
            plaintext (bytes): Data to encrypt
            key (bytes): Encryption key
            nonce (bytes): Nonce (generated if None)
            associated_data (bytes): Additional authenticated data
            
        Returns:
            tuple: (ciphertext, nonce, tag)
        """
        if nonce is None:
            nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Create cipher and encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        return ciphertext, nonce, tag
    
    def decrypt_gcm(self, ciphertext, key, nonce, tag, associated_data=None):
        """
        Decrypt ciphertext using AES-GCM mode.
        
        Args:
            ciphertext (bytes): Data to decrypt
            key (bytes): Decryption key
            nonce (bytes): Nonce
            tag (bytes): Authentication tag
            associated_data (bytes): Additional authenticated data
            
        Returns:
            bytes: Decrypted plaintext
        """
        # Create cipher and decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def encrypt_string(self, plaintext, password):
        """
        Encrypt a string using password-based encryption.
        
        Args:
            plaintext (str): String to encrypt
            password (str): Password for encryption
            
        Returns:
            str: Base64-encoded encrypted data with salt and IV
        """
        # Derive key from password
        key, salt = self.derive_key_from_password(password)
        
        # Encrypt using CBC mode
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext, iv = self.encrypt_cbc(plaintext_bytes, key)
        
        # Combine salt, IV, and ciphertext
        encrypted_data = salt + iv + ciphertext
        
        # Return base64-encoded result
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_string(self, encrypted_data, password):
        """
        Decrypt a string using password-based decryption.
        
        Args:
            encrypted_data (str): Base64-encoded encrypted data
            password (str): Password for decryption
            
        Returns:
            str: Decrypted string
        """
        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Extract salt, IV, and ciphertext
        salt = encrypted_bytes[:16]
        iv = encrypted_bytes[16:32]
        ciphertext = encrypted_bytes[32:]
        
        # Derive key from password and salt
        key, _ = self.derive_key_from_password(password, salt)
        
        # Decrypt
        plaintext_bytes = self.decrypt_cbc(ciphertext, key, iv)
        
        return plaintext_bytes.decode('utf-8')


def main():
    """
    Demonstrate AES encryption/decryption.
    """
    print("AES (Advanced Encryption Standard) Demonstration")
    print("=" * 50)
    
    # Create AES instance
    aes = AES(key_size=256)
    
    # Test 1: Basic encryption with random key
    print("Test 1: Basic AES-CBC Encryption")
    print("-" * 30)
    
    plaintext = b"Hello, AES encryption!"
    key = aes.generate_key()
    
    print(f"Plaintext: {plaintext}")
    print(f"Key (hex): {key.hex()}")
    
    # Encrypt
    ciphertext, iv = aes.encrypt_cbc(plaintext, key)
    print(f"IV (hex): {iv.hex()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    # Decrypt
    decrypted = aes.decrypt_cbc(ciphertext, key, iv)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {plaintext == decrypted}")
    print()
    
    # Test 2: AES-GCM (authenticated encryption)
    print("Test 2: AES-GCM Authenticated Encryption")
    print("-" * 40)
    
    plaintext = b"Confidential message"
    associated_data = b"Public metadata"
    
    ciphertext, nonce, tag = aes.encrypt_gcm(plaintext, key, associated_data=associated_data)
    print(f"Plaintext: {plaintext}")
    print(f"Associated data: {associated_data}")
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Tag (hex): {tag.hex()}")
    
    # Decrypt
    decrypted = aes.decrypt_gcm(ciphertext, key, nonce, tag, associated_data)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {plaintext == decrypted}")
    print()
    
    # Test 3: Password-based encryption
    print("Test 3: Password-based Encryption")
    print("-" * 35)
    
    message = "This is a secret message!"
    password = "my_secure_password_123"
    
    print(f"Original message: {message}")
    print(f"Password: {password}")
    
    # Encrypt
    encrypted = aes.encrypt_string(message, password)
    print(f"Encrypted (base64): {encrypted}")
    
    # Decrypt
    decrypted = aes.decrypt_string(encrypted, password)
    print(f"Decrypted message: {decrypted}")
    print(f"Match: {message == decrypted}")
    print()
    
    # Test 4: Key derivation
    print("Test 4: Key Derivation from Password")
    print("-" * 35)
    
    password = "test_password"
    key1, salt1 = aes.derive_key_from_password(password)
    key2, salt2 = aes.derive_key_from_password(password, salt1)  # Same salt
    key3, salt3 = aes.derive_key_from_password(password)  # Different salt
    
    print(f"Password: {password}")
    print(f"Key 1 (hex): {key1.hex()}")
    print(f"Key 2 (hex): {key2.hex()}")
    print(f"Key 3 (hex): {key3.hex()}")
    print(f"Key 1 == Key 2 (same salt): {key1 == key2}")
    print(f"Key 1 == Key 3 (different salt): {key1 == key3}")


if __name__ == "__main__":
    try:
        main()
    except ImportError:
        print("Error: cryptography library not installed.")
        print("Install with: pip install cryptography")
        print("\nFalling back to simplified demonstration...")
        
        # Simplified demonstration without cryptography library
        print("\nSimplified AES concepts:")
        print("- AES is a symmetric encryption algorithm")
        print("- Key sizes: 128, 192, or 256 bits")
        print("- Block size: 128 bits (16 bytes)")
        print("- Common modes: CBC, GCM, ECB (not recommended)")
        print("- CBC requires IV (Initialization Vector)")
        print("- GCM provides authenticated encryption")
