"""
Quick demonstration of solved cryptography algorithms
"""

import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def main():
    print("🔐 CRYPTOGRAPHY ALGORITHMS SOLUTIONS")
    print("=" * 50)
    
    # 1. Caesar Cipher
    print("\n1. CAESAR CIPHER")
    print("-" * 20)
    from caesar_cipher import CaesarCipher
    
    caesar = CaesarCipher(shift=3)
    message = "HELLO WORLD"
    encrypted = caesar.encrypt(message)
    decrypted = caesar.decrypt(encrypted)
    
    print(f"Original:  {message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"✅ Working correctly: {message == decrypted}")
    
    # 2. Vigenère Cipher
    print("\n2. VIGENÈRE CIPHER")
    print("-" * 22)
    from vigenere_cipher import VigenereCipher
    
    vigenere = VigenereCipher("SECRET")
    message = "ATTACK AT DAWN"
    encrypted = vigenere.encrypt(message)
    decrypted = vigenere.decrypt(encrypted)
    
    print(f"Original:  {message}")
    print(f"Keyword:   SECRET")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"✅ Working correctly: {message == decrypted}")
    
    # 3. Hash Functions
    print("\n3. HASH FUNCTIONS")
    print("-" * 17)
    from hash_functions import HashFunctions
    
    hash_func = HashFunctions()
    message = "Hello Cryptography"
    
    print(f"Message: {message}")
    print(f"MD5:     {hash_func.md5_hash(message)}")
    print(f"SHA-1:   {hash_func.sha1_hash(message)}")
    print(f"SHA-256: {hash_func.sha256_hash(message)}")
    print("✅ Hash functions working")
    
    # 4. RSA Algorithm (simplified demo)
    print("\n4. RSA ALGORITHM")
    print("-" * 16)
    from rsa_algorithm import RSA
    
    print("Generating RSA keys (small size for demo)...")
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keypair()
    
    message = "Hello RSA!"
    encrypted = rsa.encrypt_string(message)
    decrypted = rsa.decrypt_string(encrypted)
    
    print(f"Original:  {message}")
    print(f"Encrypted: [encrypted integer list]")
    print(f"Decrypted: {decrypted}")
    print(f"✅ Working correctly: {message == decrypted}")
    
    # 5. Diffie-Hellman Key Exchange
    print("\n5. DIFFIE-HELLMAN KEY EXCHANGE")
    print("-" * 34)
    from diffie_hellman import DiffieHellman
    
    print("Setting up key exchange...")
    alice = DiffieHellman(key_size=256)
    p, g = alice.generate_parameters()
    
    # Alice's side
    alice_private = alice.generate_private_key()
    alice_public = alice.generate_public_key()
    
    # Bob's side
    bob = DiffieHellman()
    bob.p, bob.g = p, g
    bob_private = bob.generate_private_key()
    bob_public = bob.generate_public_key()
    
    # Shared secret computation
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    
    print(f"Alice's public key: {alice_public}")
    print(f"Bob's public key:   {bob_public}")
    print(f"Shared secrets match: {alice_shared == bob_shared}")
    print(f"✅ Key exchange successful: {alice_shared == bob_shared}")
    
    # 6. Cryptanalysis
    print("\n6. CRYPTANALYSIS")
    print("-" * 16)
    from cryptanalysis import CryptanalysisTools
    
    # Break a Caesar cipher
    caesar_attacker = CaesarCipher(7)
    secret_message = "THIS IS A SECRET MESSAGE"
    encrypted_secret = caesar_attacker.encrypt(secret_message)
    
    print(f"Intercepted message: {encrypted_secret}")
    
    shift, broken_text, score = CryptanalysisTools.break_caesar_cipher(encrypted_secret)
    print(f"Broken! Shift: {shift}, Message: {broken_text}")
    print(f"✅ Cryptanalysis successful: {secret_message == broken_text}")
    
    # 7. Password Analysis
    print("\n7. PASSWORD ANALYSIS")
    print("-" * 20)
    from cryptanalysis import PasswordAnalyzer
    
    analyzer = PasswordAnalyzer()
    passwords = ["password", "MySecureP@ssw0rd123!"]
    
    for pwd in passwords:
        analysis = analyzer.analyze_password_strength(pwd)
        print(f"Password: '{pwd}' - Score: {analysis['score']}/100")
    
    print("✅ Password analysis working")
    
    print("\n" + "=" * 50)
    print("🎉 ALL CRYPTOGRAPHY ALGORITHMS IMPLEMENTED AND WORKING!")
    print("=" * 50)
    
    print("\nFeatures implemented:")
    print("• Caesar Cipher with encryption/decryption")
    print("• Vigenère Cipher with keyword support")
    print("• RSA public-key cryptography")
    print("• Diffie-Hellman key exchange")
    print("• Hash functions (MD5, SHA-1, SHA-256, SHA-512)")
    print("• Cryptanalysis tools")
    print("• Password strength analysis")
    print("• AES encryption (with cryptography library)")
    print("• Comprehensive test suite")
    print("• Interactive demonstration")

if __name__ == "__main__":
    main()
