import hashlib
import struct

class HashFunctions:
    @staticmethod
    def md5_hash(message):
        if isinstance(message, str): message = message.encode('utf-8')
        return hashlib.md5(message).hexdigest()
    
    @staticmethod
    def sha1_hash(message):
        if isinstance(message, str): message = message.encode('utf-8')
        return hashlib.sha1(message).hexdigest()
    
    @staticmethod
    def sha256_hash(message):
        if isinstance(message, str): message = message.encode('utf-8')
        return hashlib.sha256(message).hexdigest()
    
    @staticmethod
    def sha512_hash(message):
        if isinstance(message, str): message = message.encode('utf-8')
        return hashlib.sha512(message).hexdigest()
    
    @staticmethod
    def compare_hashes(message, hash1, hash2):
        try:
            return hashlib.compare_digest(hash1, hash2)
        except AttributeError:
            return hash1 == hash2
    
    @staticmethod
    def hash_with_salt(message, salt):
        if isinstance(message, str): message = message.encode('utf-8')
        if isinstance(salt, str): salt = salt.encode('utf-8')
        return hashlib.sha256(salt + message).hexdigest()
    
    @staticmethod
    def hmac_hash(message, key, hash_function='sha256'):
        import hmac
        if isinstance(message, str): message = message.encode('utf-8')
        if isinstance(key, str): key = key.encode('utf-8')
        if hash_function == 'md5': return hmac.new(key, message, hashlib.md5).hexdigest()
        elif hash_function == 'sha1': return hmac.new(key, message, hashlib.sha1).hexdigest()
        elif hash_function == 'sha256': return hmac.new(key, message, hashlib.sha256).hexdigest()
        elif hash_function == 'sha512': return hmac.new(key, message, hashlib.sha512).hexdigest()
        else: raise ValueError("Unsupported hash function")

class SimpleHashFunction:
    @staticmethod
    def simple_hash(message, table_size=1000):
        hash_value, prime = 0, 31
        for char in message:
            hash_value = (hash_value * prime + ord(char)) % table_size
        return hash_value
    
    @staticmethod
    def djb2_hash(message):
        hash_value = 5381
        for char in message:
            hash_value = ((hash_value << 5) + hash_value) + ord(char)
            hash_value &= 0xFFFFFFFF
        return hash_value
    
    @staticmethod
    def fnv1a_hash(message):
        fnv_prime, fnv_offset_basis = 0x01000193, 0x811c9dc5
        hash_value = fnv_offset_basis
        for char in message:
            hash_value ^= ord(char)
            hash_value = (hash_value * fnv_prime) & 0xFFFFFFFF
        return hash_value


def demonstrate_hash_collision():
    print("Hash Collision Demonstration")
    print("=" * 30)
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
    print("Hash Functions Demonstration")
    print("=" * 30)
    message = "Hello, Cryptography!"
    print(f"Original message: {message}")
    print()
    hash_funcs = HashFunctions()
    print("Standard Hash Functions:")
    print(f"MD5:    {hash_funcs.md5_hash(message)}")
    print(f"SHA-1:  {hash_funcs.sha1_hash(message)}")
    print(f"SHA-256: {hash_funcs.sha256_hash(message)}")
    print(f"SHA-512: {hash_funcs.sha512_hash(message)}")
    print()
    salt = "random_salt_123"
    print(f"Hash with salt '{salt}':")
    print(f"Salted hash: {hash_funcs.hash_with_salt(message, salt)}")
    print()
    key = "secret_key"
    print(f"HMAC with key '{key}':")
    print(f"HMAC-SHA256: {hash_funcs.hmac_hash(message, key)}")
    print()
    simple_hash = SimpleHashFunction()
    print("Simple Hash Functions:")
    print(f"Simple hash: {simple_hash.simple_hash(message)}")
    print(f"DJB2 hash:  {simple_hash.djb2_hash(message)}")
    print(f"FNV-1a hash: {simple_hash.fnv1a_hash(message)}")
    print()
    print("Avalanche Effect Demonstration:")
    message1 = "Hello World"
    message2 = "Hello World!"
    hash1 = hash_funcs.sha256_hash(message1)
    hash2 = hash_funcs.sha256_hash(message2)
    print(f"Message 1: '{message1}'")
    print(f"SHA-256:   {hash1}")
    print(f"Message 2: '{message2}'")
    print(f"SHA-256:   {hash2}")
    diff_bits = bin(int(hash1, 16) ^ int(hash2, 16)).count('1')
    total_bits = len(hash1) * 4
    print(f"Different bits: {diff_bits}/{total_bits} ({diff_bits/total_bits*100:.1f}%)")
    print()
    demonstrate_hash_collision()

if __name__ == "__main__":
    main()
