"""
RSA Algorithm Implementation
Public-key cryptosystem for secure communication.
"""

import random
import math


class RSA:
    def __init__(self, key_size=1024):
        """
        Initialize RSA with specified key size.
        
        Args:
            key_size (int): Size of the RSA key in bits
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
        
    def _is_prime(self, n, k=5):
        """
        Miller-Rabin primality test.
        
        Args:
            n (int): Number to test
            k (int): Number of iterations
            
        Returns:
            bool: True if probably prime, False if composite
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as d * 2^r
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Perform k iterations
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _generate_prime(self, bits):
        """
        Generate a prime number with specified bit length.
        
        Args:
            bits (int): Number of bits
            
        Returns:
            int: Prime number
        """
        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
            if self._is_prime(n):
                return n
    
    def _extended_gcd(self, a, b):
        """
        Extended Euclidean Algorithm.
        
        Args:
            a, b (int): Input numbers
            
        Returns:
            tuple: (gcd, x, y) where gcd = a*x + b*y
        """
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def _mod_inverse(self, a, m):
        """
        Calculate modular multiplicative inverse.
        
        Args:
            a (int): Number to find inverse of
            m (int): Modulus
            
        Returns:
            int: Modular inverse of a mod m
        """
        gcd, x, _ = self._extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m
    
    def generate_keypair(self):
        """
        Generate RSA public and private key pair.
        """
        # Generate two prime numbers
        p = self._generate_prime(self.key_size // 2)
        q = self._generate_prime(self.key_size // 2)
        
        # Calculate n = p * q
        self.n = p * q
        
        # Calculate Euler's totient function
        phi = (p - 1) * (q - 1)
        
        # Choose e (commonly 65537)
        e = 65537
        while math.gcd(e, phi) != 1:
            e += 2
        
        # Calculate d (private exponent)
        d = self._mod_inverse(e, phi)
        
        self.public_key = (e, self.n)
        self.private_key = (d, self.n)
        
        return self.public_key, self.private_key
    
    def encrypt(self, message, public_key=None):
        """
        Encrypt a message using RSA public key.
        
        Args:
            message (int): Message to encrypt (must be < n)
            public_key (tuple): Public key (e, n). Uses instance key if None.
            
        Returns:
            int: Encrypted message
        """
        if public_key is None:
            public_key = self.public_key
        
        if public_key is None:
            raise ValueError("No public key available")
        
        e, n = public_key
        if message >= n:
            raise ValueError("Message too large for key size")
        
        return pow(message, e, n)
    
    def decrypt(self, ciphertext, private_key=None):
        """
        Decrypt a message using RSA private key.
        
        Args:
            ciphertext (int): Message to decrypt
            private_key (tuple): Private key (d, n). Uses instance key if None.
            
        Returns:
            int: Decrypted message
        """
        if private_key is None:
            private_key = self.private_key
        
        if private_key is None:
            raise ValueError("No private key available")
        
        d, n = private_key
        return pow(ciphertext, d, n)
    
    def encrypt_string(self, message):
        """
        Encrypt a string message (converts to bytes first).
        
        Args:
            message (str): String message to encrypt
            
        Returns:
            list: List of encrypted integers
        """
        if self.public_key is None:
            raise ValueError("No public key available")
        
        message_bytes = message.encode('utf-8')
        encrypted = []
        
        for byte in message_bytes:
            encrypted.append(self.encrypt(byte))
        
        return encrypted
    
    def decrypt_string(self, encrypted_message):
        """
        Decrypt a string message from list of encrypted integers.
        
        Args:
            encrypted_message (list): List of encrypted integers
            
        Returns:
            str: Decrypted string message
        """
        if self.private_key is None:
            raise ValueError("No private key available")
        
        decrypted_bytes = []
        
        for encrypted_byte in encrypted_message:
            decrypted_bytes.append(self.decrypt(encrypted_byte))
        
        return bytes(decrypted_bytes).decode('utf-8')


def main():
    # Example usage
    print("RSA Algorithm Demonstration")
    print("=" * 30)
    
    # Create RSA instance and generate keys
    rsa = RSA(key_size=512)  # Small key size for demo
    public_key, private_key = rsa.generate_keypair()
    
    print(f"Public Key (e, n): {public_key}")
    print(f"Private Key (d, n): {private_key}")
    print()
    
    # Test with integer message
    message = 42
    print(f"Original message: {message}")
    
    encrypted = rsa.encrypt(message)
    print(f"Encrypted message: {encrypted}")
    
    decrypted = rsa.decrypt(encrypted)
    print(f"Decrypted message: {decrypted}")
    print()
    
    # Test with string message
    string_message = "Hello RSA!"
    print(f"Original string: {string_message}")
    
    encrypted_string = rsa.encrypt_string(string_message)
    print(f"Encrypted string: {encrypted_string}")
    
    decrypted_string = rsa.decrypt_string(encrypted_string)
    print(f"Decrypted string: {decrypted_string}")


if __name__ == "__main__":
    main()
