import random
import hashlib

class DiffieHellman:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.p = None
        self.g = None
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
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
            q = random.getrandbits(bits - 1)
            q |= (1 << bits - 2) | 1
            if self._is_prime(q):
                p = 2 * q + 1
                if self._is_prime(p): return p
    
    def _find_generator(self, p):
        candidates = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        for g in candidates:
            if g >= p: continue
            q = (p - 1) // 2
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1: return g
        while True:
            g = random.randrange(2, p)
            q = (p - 1) // 2
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1: return g
    
    def generate_parameters(self):
        print("Generating prime number... (this may take a moment)")
        self.p = self._generate_prime(self.key_size)
        print("Finding generator...")
        self.g = self._find_generator(self.p)
        return self.p, self.g
    
    def generate_private_key(self):
        if self.p is None: raise ValueError("Parameters not generated. Call generate_parameters() first.")
        self.private_key = random.randrange(1, self.p - 1)
        return self.private_key
    
    def generate_public_key(self):
        if self.private_key is None: raise ValueError("Private key not generated. Call generate_private_key() first.")
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key):
        if self.private_key is None: raise ValueError("Private key not available.")
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        return self.shared_secret
    
    def derive_key(self, key_length=32):
        if self.shared_secret is None: raise ValueError("Shared secret not computed.")
        secret_bytes = self.shared_secret.to_bytes((self.shared_secret.bit_length() + 7) // 8, 'big')
        derived_key = b''
        counter = 1
        while len(derived_key) < key_length:
            hash_input = secret_bytes + counter.to_bytes(4, 'big')
            derived_key += hashlib.sha256(hash_input).digest()
            counter += 1
        return derived_key[:key_length]

def main():
    print("Diffie-Hellman Key Exchange Demonstration")
    print("=" * 45)
    print("Alice generates parameters...")
    alice = DiffieHellman(key_size=512)
    p, g = alice.generate_parameters()
    print("Public parameters:")
    print(f"p (prime): {p}")
    print(f"g (generator): {g}")
    print()
    alice_private = alice.generate_private_key()
    alice_public = alice.generate_public_key()
    print(f"Alice's private key: {alice_private}")
    print(f"Alice's public key: {alice_public}")
    print()
    print("Bob generates his keys using the same parameters...")
    bob = DiffieHellman(key_size=512)
    bob.p = p
    bob.g = g
    bob_private = bob.generate_private_key()
    bob_public = bob.generate_public_key()
    print(f"Bob's private key: {bob_private}")
    print(f"Bob's public key: {bob_public}")
    print()
    print("Computing shared secrets...")
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    print(f"Alice's computed shared secret: {alice_shared}")
    print(f"Bob's computed shared secret: {bob_shared}")
    print(f"Secrets match: {alice_shared == bob_shared}")
    print()
    alice_key = alice.derive_key(32)
    bob_key = bob.derive_key(32)
    print(f"Alice's derived key: {alice_key.hex()}")
    print(f"Bob's derived key: {bob_key.hex()}")
    print(f"Keys match: {alice_key == bob_key}")

if __name__ == "__main__":
    main()
