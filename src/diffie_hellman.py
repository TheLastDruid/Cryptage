"""
Diffie-Hellman Key Exchange Implementation
Secure method for exchanging cryptographic keys over a public channel.
"""

import random
import hashlib


class DiffieHellman:
    def __init__(self, key_size=1024):
        """
        Initialize Diffie-Hellman with specified key size.
        
        Args:
            key_size (int): Size of the prime in bits
        """
        self.key_size = key_size
        self.p = None  # Large prime
        self.g = None  # Generator
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
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
        Generate a safe prime p where p = 2q + 1 and q is also prime.
        
        Args:
            bits (int): Number of bits
            
        Returns:
            int: Safe prime number
        """
        while True:
            q = random.getrandbits(bits - 1)
            q |= (1 << bits - 2) | 1  # Set MSB and LSB to 1
            
            if self._is_prime(q):
                p = 2 * q + 1
                if self._is_prime(p):
                    return p
    
    def _find_generator(self, p):
        """
        Find a generator for the multiplicative group modulo p.
        
        Args:
            p (int): Prime number
            
        Returns:
            int: Generator
        """
        # For safe prime p = 2q + 1, we can use small generators
        candidates = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        
        for g in candidates:
            if g >= p:
                continue
            
            # Check if g is a generator
            # For safe prime p = 2q + 1, g is a generator if:
            # g^2 ≢ 1 (mod p) and g^q ≢ 1 (mod p)
            q = (p - 1) // 2
            
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                return g
        
        # If no small generator found, generate randomly
        while True:
            g = random.randrange(2, p)
            q = (p - 1) // 2
            
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                return g
    
    def generate_parameters(self):
        """
        Generate public parameters (p, g).
        
        Returns:
            tuple: (p, g) - prime and generator
        """
        print("Generating prime number... (this may take a moment)")
        self.p = self._generate_prime(self.key_size)
        
        print("Finding generator...")
        self.g = self._find_generator(self.p)
        
        return self.p, self.g
    
    def generate_private_key(self):
        """
        Generate private key (random number).
        
        Returns:
            int: Private key
        """
        if self.p is None:
            raise ValueError("Parameters not generated. Call generate_parameters() first.")
        
        self.private_key = random.randrange(1, self.p - 1)
        return self.private_key
    
    def generate_public_key(self):
        """
        Generate public key from private key.
        
        Returns:
            int: Public key
        """
        if self.private_key is None:
            raise ValueError("Private key not generated. Call generate_private_key() first.")
        
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key):
        """
        Compute shared secret using other party's public key.
        
        Args:
            other_public_key (int): Other party's public key
            
        Returns:
            int: Shared secret
        """
        if self.private_key is None:
            raise ValueError("Private key not available.")
        
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        return self.shared_secret
    
    def derive_key(self, key_length=32):
        """
        Derive encryption key from shared secret using SHA-256.
        
        Args:
            key_length (int): Length of derived key in bytes
            
        Returns:
            bytes: Derived encryption key
        """
        if self.shared_secret is None:
            raise ValueError("Shared secret not computed.")
        
        # Convert shared secret to bytes
        secret_bytes = self.shared_secret.to_bytes((self.shared_secret.bit_length() + 7) // 8, 'big')
        
        # Use SHA-256 to derive key
        hash_obj = hashlib.sha256(secret_bytes)
        
        # If we need more bytes, use HKDF-like approach
        derived_key = b''
        counter = 1
        
        while len(derived_key) < key_length:
            hash_input = secret_bytes + counter.to_bytes(4, 'big')
            derived_key += hashlib.sha256(hash_input).digest()
            counter += 1
        
        return derived_key[:key_length]


def main():
    """
    Demonstrate Diffie-Hellman key exchange between Alice and Bob.
    """
    print("Diffie-Hellman Key Exchange Demonstration")
    print("=" * 45)
    
    # Alice's side
    print("Alice generates parameters...")
    alice = DiffieHellman(key_size=512)  # Small key size for demo
    p, g = alice.generate_parameters()
    
    print(f"Public parameters:")
    print(f"p (prime): {p}")
    print(f"g (generator): {g}")
    print()
    
    # Alice generates her keys
    alice_private = alice.generate_private_key()
    alice_public = alice.generate_public_key()
    
    print(f"Alice's private key: {alice_private}")
    print(f"Alice's public key: {alice_public}")
    print()
    
    # Bob's side (uses same parameters)
    print("Bob generates his keys using the same parameters...")
    bob = DiffieHellman(key_size=512)
    bob.p = p
    bob.g = g
    
    bob_private = bob.generate_private_key()
    bob_public = bob.generate_public_key()
    
    print(f"Bob's private key: {bob_private}")
    print(f"Bob's public key: {bob_public}")
    print()
    
    # Both parties compute the shared secret
    print("Computing shared secrets...")
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    
    print(f"Alice's computed shared secret: {alice_shared}")
    print(f"Bob's computed shared secret: {bob_shared}")
    print(f"Secrets match: {alice_shared == bob_shared}")
    print()
    
    # Derive encryption keys
    alice_key = alice.derive_key(32)
    bob_key = bob.derive_key(32)
    
    print(f"Alice's derived key: {alice_key.hex()}")
    print(f"Bob's derived key: {bob_key.hex()}")
    print(f"Keys match: {alice_key == bob_key}")


if __name__ == "__main__":
    main()
