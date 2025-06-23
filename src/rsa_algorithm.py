import random
import math

class RSA:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
        
    def _is_prime(self, n, k=5):
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0: return False
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1: continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else: return False
        return True
    
    def _generate_prime(self, bits):
        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1
            if self._is_prime(n): return n
    
    def _extended_gcd(self, a, b):
        if a == 0: return b, 0, 1
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    def _mod_inverse(self, a, m):
        gcd, x, _ = self._extended_gcd(a, m)
        if gcd != 1: raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m
    
    def generate_keypair(self):
        p = self._generate_prime(self.key_size // 2)
        q = self._generate_prime(self.key_size // 2)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while math.gcd(e, phi) != 1: e += 2
        d = self._mod_inverse(e, phi)
        self.public_key = (e, self.n)
        self.private_key = (d, self.n)
        return self.public_key, self.private_key
    
    def encrypt(self, message, public_key=None):
        if public_key is None: public_key = self.public_key
        if public_key is None: raise ValueError("No public key available")
        e, n = public_key
        if message >= n: raise ValueError("Message too large for key size")
        return pow(message, e, n)
    
    def decrypt(self, ciphertext, private_key=None):
        if private_key is None: private_key = self.private_key
        if private_key is None: raise ValueError("No private key available")
        d, n = private_key
        return pow(ciphertext, d, n)
    
    def encrypt_string(self, message):
        if self.public_key is None: raise ValueError("No public key available")
        message_bytes = message.encode('utf-8')
        encrypted = []
        for byte in message_bytes:
            encrypted.append(self.encrypt(byte))
        return encrypted
    
    def decrypt_string(self, encrypted_message):
        if self.private_key is None: raise ValueError("No private key available")
        decrypted_bytes = []
        for encrypted_byte in encrypted_message:
            decrypted_bytes.append(self.decrypt(encrypted_byte))
        return bytes(decrypted_bytes).decode('utf-8')


def main():
    print("RSA Algorithm Demonstration")
    print("=" * 30)
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keypair()
    print(f"Public Key (e, n): {public_key}")
    print(f"Private Key (d, n): {private_key}")
    print()
    message = 42
    print(f"Original message: {message}")
    encrypted = rsa.encrypt(message)
    print(f"Encrypted message: {encrypted}")
    decrypted = rsa.decrypt(encrypted)
    print(f"Decrypted message: {decrypted}")
    print()
    string_message = "Hello RSA!"
    print(f"Original string: {string_message}")
    encrypted_string = rsa.encrypt_string(string_message)
    print(f"Encrypted string: {encrypted_string}")
    decrypted_string = rsa.decrypt_string(encrypted_string)
    print(f"Decrypted string: {decrypted_string}")

if __name__ == "__main__":
    main()
