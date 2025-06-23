"""
Hash Functions Implementation
Common cryptographic hash functions: MD5, SHA-1, SHA-256
"""

import hashlib
import struct


class HashFunctions:
    """
    Implementation of various hash functions for educational purposes.
    """
    
    @staticmethod
    def md5_hash(message):
        """
        Compute MD5 hash of a message.
        
        Args:
            message (str or bytes): Message to hash
            
        Returns:
            str: Hexadecimal MD5 hash
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return hashlib.md5(message).hexdigest()
    
    @staticmethod
    def sha1_hash(message):
        """
        Compute SHA-1 hash of a message.
        
        Args:
            message (str or bytes): Message to hash
            
        Returns:
            str: Hexadecimal SHA-1 hash
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return hashlib.sha1(message).hexdigest()
    
    @staticmethod
    def sha256_hash(message):
        """
        Compute SHA-256 hash of a message.
        
        Args:
            message (str or bytes): Message to hash
            
        Returns:
            str: Hexadecimal SHA-256 hash
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return hashlib.sha256(message).hexdigest()
    
    @staticmethod
    def sha512_hash(message):
        """
        Compute SHA-512 hash of a message.
        
        Args:
            message (str or bytes): Message to hash
            
        Returns:
            str: Hexadecimal SHA-512 hash        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return hashlib.sha512(message).hexdigest()
    
    @staticmethod
    def compare_hashes(message, hash1, hash2):
        """
        Compare two hashes for equality (constant-time comparison).
        
        Args:
            message (str): Original message
            hash1 (str): First hash
            hash2 (str): Second hash
            
        Returns:
            bool: True if hashes match
        """
        try:
            return hashlib.compare_digest(hash1, hash2)
        except AttributeError:
            # Fallback for older Python versions
            return hash1 == hash2
    
    @staticmethod
    def hash_with_salt(message, salt):
        """
        Hash message with salt for password storage.
        
        Args:
            message (str): Message to hash
            salt (str or bytes): Salt value
            
        Returns:
            str: Hexadecimal hash of salted message
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
        
        return hashlib.sha256(salt + message).hexdigest()
    
    @staticmethod
    def hmac_hash(message, key, hash_function='sha256'):
        """
        Compute HMAC (Hash-based Message Authentication Code).
        
        Args:
            message (str or bytes): Message to authenticate
            key (str or bytes): Secret key
            hash_function (str): Hash function to use
            
        Returns:
            str: Hexadecimal HMAC
        """
        import hmac
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        if hash_function == 'md5':
            return hmac.new(key, message, hashlib.md5).hexdigest()
        elif hash_function == 'sha1':
            return hmac.new(key, message, hashlib.sha1).hexdigest()
        elif hash_function == 'sha256':
            return hmac.new(key, message, hashlib.sha256).hexdigest()
        elif hash_function == 'sha512':
            return hmac.new(key, message, hashlib.sha512).hexdigest()
        else:
            raise ValueError("Unsupported hash function")


class SimpleHashFunction:
    """
    Simple hash function implementation for educational purposes.
    """
    
    @staticmethod
    def simple_hash(message, table_size=1000):
        """
        Simple hash function using polynomial rolling hash.
        
        Args:
            message (str): Message to hash
            table_size (int): Size of hash table
            
        Returns:
            int: Hash value
        """
        hash_value = 0
        prime = 31
        
        for char in message:
            hash_value = (hash_value * prime + ord(char)) % table_size
        
        return hash_value
    
    @staticmethod
    def djb2_hash(message):
        """
        DJB2 hash function by Dan Bernstein.
        
        Args:
            message (str): Message to hash
            
        Returns:
            int: Hash value
        """
        hash_value = 5381
        
        for char in message:
            hash_value = ((hash_value << 5) + hash_value) + ord(char)
            hash_value &= 0xFFFFFFFF  # Ensure 32-bit
        
        return hash_value
    
    @staticmethod
    def fnv1a_hash(message):
        """
        FNV-1a hash function.
        
        Args:
            message (str): Message to hash
            
        Returns:
            int: Hash value
        """
        fnv_prime = 0x01000193
        fnv_offset_basis = 0x811c9dc5
        
        hash_value = fnv_offset_basis
        
        for char in message:
            hash_value ^= ord(char)
            hash_value = (hash_value * fnv_prime) & 0xFFFFFFFF
        
        return hash_value


def demonstrate_hash_collision():
    """
    Demonstrate hash collision vulnerability (educational purpose).
    """
    print("Hash Collision Demonstration")
    print("=" * 30)
    
    # Simple hash function is prone to collisions
    simple_hash = SimpleHashFunction()
    
    messages = ["hello", "world", "test", "hash", "collision"]
    hash_table_size = 10
    
    print(f"Using simple hash with table size {hash_table_size}:")
    hash_values = {}
    
    for message in messages:
        hash_val = simple_hash.simple_hash(message, hash_table_size)
        print(f"'{message}' -> {hash_val}")
        
        if hash_val in hash_values:
            print(f"  COLLISION! '{message}' and '{hash_values[hash_val]}' have the same hash")
        else:
            hash_values[hash_val] = message
    
    print()


def main():
    """
    Demonstrate various hash functions.
    """
    print("Hash Functions Demonstration")
    print("=" * 30)
    
    message = "Hello, Cryptography!"
    print(f"Original message: {message}")
    print()
    
    # Standard hash functions
    hash_funcs = HashFunctions()
    
    print("Standard Hash Functions:")
    print(f"MD5:    {hash_funcs.md5_hash(message)}")
    print(f"SHA-1:  {hash_funcs.sha1_hash(message)}")
    print(f"SHA-256: {hash_funcs.sha256_hash(message)}")
    print(f"SHA-512: {hash_funcs.sha512_hash(message)}")
    print()
    
    # Hash with salt
    salt = "random_salt_123"
    print(f"Hash with salt '{salt}':")
    print(f"Salted hash: {hash_funcs.hash_with_salt(message, salt)}")
    print()
    
    # HMAC
    key = "secret_key"
    print(f"HMAC with key '{key}':")
    print(f"HMAC-SHA256: {hash_funcs.hmac_hash(message, key)}")
    print()
    
    # Simple hash functions
    simple_hash = SimpleHashFunction()
    print("Simple Hash Functions:")
    print(f"Simple hash: {simple_hash.simple_hash(message)}")
    print(f"DJB2 hash:  {simple_hash.djb2_hash(message)}")
    print(f"FNV-1a hash: {simple_hash.fnv1a_hash(message)}")
    print()
    
    # Demonstrate avalanche effect
    print("Avalanche Effect Demonstration:")
    message1 = "Hello World"
    message2 = "Hello World!"  # Just one character difference
    
    hash1 = hash_funcs.sha256_hash(message1)
    hash2 = hash_funcs.sha256_hash(message2)
    
    print(f"Message 1: '{message1}'")
    print(f"SHA-256:   {hash1}")
    print(f"Message 2: '{message2}'")
    print(f"SHA-256:   {hash2}")
    
    # Count different bits
    diff_bits = bin(int(hash1, 16) ^ int(hash2, 16)).count('1')
    total_bits = len(hash1) * 4  # Each hex digit = 4 bits
    print(f"Different bits: {diff_bits}/{total_bits} ({diff_bits/total_bits*100:.1f}%)")
    print()
    
    # Collision demonstration
    demonstrate_hash_collision()


if __name__ == "__main__":
    main()
