"""
Interactive demonstration of all cryptography algorithms
"""

import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from caesar_cipher import CaesarCipher
from vigenere_cipher import VigenereCipher
from rsa_algorithm import RSA
from diffie_hellman import DiffieHellman
from hash_functions import HashFunctions
from cryptanalysis import CryptanalysisTools, PasswordAnalyzer


def demonstrate_caesar_cipher():
    """Demonstrate Caesar cipher"""
    print("\n" + "="*50)
    print("CAESAR CIPHER DEMONSTRATION")
    print("="*50)
    
    shift = 3
    cipher = CaesarCipher(shift)
    
    plaintext = "Hello, World! This is a secret message."
    print(f"Original message: {plaintext}")
    print(f"Shift value: {shift}")
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Brute force attack
    print(f"\nBrute force attack on '{encrypted[:10]}...':")
    attacks = cipher.brute_force_attack(encrypted)
    for shift_val, result in list(attacks.items())[:5]:  # Show first 5
        print(f"  Shift {shift_val:2d}: {result[:30]}...")


def demonstrate_vigenere_cipher():
    """Demonstrate Vigenère cipher"""
    print("\n" + "="*50)
    print("VIGENÈRE CIPHER DEMONSTRATION")
    print("="*50)
    
    keyword = "SECRET"
    cipher = VigenereCipher(keyword)
    
    plaintext = "ATTACK AT DAWN"
    print(f"Original message: {plaintext}")
    print(f"Keyword: {keyword}")
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Frequency analysis
    print(f"\nFrequency analysis of encrypted text:")
    freq = cipher.analyze_frequency(encrypted)
    for char, percentage in sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]:
        if percentage > 0:
            print(f"  {char}: {percentage:.1f}%")


def demonstrate_rsa():
    """Demonstrate RSA algorithm"""
    print("\n" + "="*50)
    print("RSA ALGORITHM DEMONSTRATION")
    print("="*50)
    
    print("Generating RSA keys (this may take a moment)...")
    rsa = RSA(key_size=512)  # Small key for demo
    public_key, private_key = rsa.generate_keypair()
    
    print(f"Public key (e, n): ({public_key[0]}, {public_key[1]})")
    print(f"Key size: {rsa.key_size} bits")
    
    # String encryption
    message = "Hello RSA!"
    print(f"\nOriginal message: {message}")
    
    encrypted = rsa.encrypt_string(message)
    print(f"Encrypted (first 5 values): {encrypted[:5]}...")
    
    decrypted = rsa.decrypt_string(encrypted)
    print(f"Decrypted: {decrypted}")


def demonstrate_diffie_hellman():
    """Demonstrate Diffie-Hellman key exchange"""
    print("\n" + "="*50)
    print("DIFFIE-HELLMAN KEY EXCHANGE DEMONSTRATION")
    print("="*50)
    
    print("Alice generates parameters...")
    alice = DiffieHellman(key_size=256)  # Small for demo
    p, g = alice.generate_parameters()
    
    print(f"Public parameters - p: {p}, g: {g}")
    
    # Alice's keys
    alice_private = alice.generate_private_key()
    alice_public = alice.generate_public_key()
    
    # Bob's keys
    bob = DiffieHellman()
    bob.p, bob.g = p, g
    bob_private = bob.generate_private_key()
    bob_public = bob.generate_public_key()
    
    print(f"\nAlice's public key: {alice_public}")
    print(f"Bob's public key: {bob_public}")
    
    # Compute shared secrets
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    
    print(f"\nShared secrets match: {alice_shared == bob_shared}")
    
    # Derive encryption keys
    alice_key = alice.derive_key(16)
    bob_key = bob.derive_key(16)
    
    print(f"Derived keys match: {alice_key == bob_key}")
    print(f"Derived key (hex): {alice_key.hex()}")


def demonstrate_hash_functions():
    """Demonstrate hash functions"""
    print("\n" + "="*50)
    print("HASH FUNCTIONS DEMONSTRATION")
    print("="*50)
    
    message = "Hello, Cryptography!"
    hash_funcs = HashFunctions()
    
    print(f"Original message: {message}")
    print(f"MD5:     {hash_funcs.md5_hash(message)}")
    print(f"SHA-1:   {hash_funcs.sha1_hash(message)}")
    print(f"SHA-256: {hash_funcs.sha256_hash(message)}")
    
    # Demonstrate avalanche effect
    message2 = "Hello, Cryptography?"  # One character difference
    print(f"\nAvalanche effect demonstration:")
    print(f"Message 1: {message}")
    print(f"Message 2: {message2}")
    
    hash1 = hash_funcs.sha256_hash(message)
    hash2 = hash_funcs.sha256_hash(message2)
    
    print(f"SHA-256 hash 1: {hash1}")
    print(f"SHA-256 hash 2: {hash2}")
    
    # Count different characters
    diff_chars = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
    print(f"Different characters: {diff_chars}/{len(hash1)} ({diff_chars/len(hash1)*100:.1f}%)")


def demonstrate_cryptanalysis():
    """Demonstrate cryptanalysis techniques"""
    print("\n" + "="*50)
    print("CRYPTANALYSIS DEMONSTRATION")
    print("="*50)
    
    # Caesar cipher cryptanalysis
    caesar = CaesarCipher(13)
    plaintext = "THIS IS A SECRET MESSAGE THAT NEEDS TO BE BROKEN"
    ciphertext = caesar.encrypt(plaintext)
    
    print(f"Breaking Caesar cipher...")
    print(f"Ciphertext: {ciphertext}")
    
    shift, broken_text, score = CryptanalysisTools.break_caesar_cipher(ciphertext)
    print(f"Broken! Shift: {shift}, Text: {broken_text}")
    print(f"Chi-squared score: {score:.2f}")
    
    # Frequency analysis
    print(f"\nFrequency analysis of ciphertext:")
    freq = CryptanalysisTools.frequency_analysis(ciphertext)
    most_frequent = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]
    for letter, percentage in most_frequent:
        if percentage > 0:
            print(f"  {letter}: {percentage:.1f}%")
    
    # Index of Coincidence
    ic = CryptanalysisTools.index_of_coincidence(ciphertext)
    print(f"\nIndex of Coincidence: {ic:.4f}")
    if ic > 0.06:
        print("  Likely monoalphabetic cipher")
    else:
        print("  Likely polyalphabetic cipher")


def demonstrate_password_analysis():
    """Demonstrate password analysis"""
    print("\n" + "="*50)
    print("PASSWORD ANALYSIS DEMONSTRATION")
    print("="*50)
    
    passwords = [
        "password",
        "Password123",
        "MySecureP@ssw0rd!",
        "ThisIsAVeryLongAndSecurePasswordWith123AndSymbols!"
    ]
    
    analyzer = PasswordAnalyzer()
    
    for pwd in passwords:
        print(f"\nAnalyzing: '{pwd}'")
        analysis = analyzer.analyze_password_strength(pwd)
        
        print(f"  Length: {analysis['length']} characters")
        print(f"  Score: {analysis['score']}/100")
        print(f"  Entropy: {analysis['entropy']:.1f} bits")
        
        if analysis['recommendations']:
            print(f"  Recommendations: {', '.join(analysis['recommendations'])}")
        
        # Crack time estimation
        crack_times = analyzer.estimate_crack_time(pwd)
        print(f"  Offline crack time (GPU): {crack_times.get('offline_fast', 'N/A')}")


def main_menu():
    """Interactive main menu"""
    while True:
        print("\n" + "="*60)
        print("CRYPTOGRAPHY ALGORITHMS - INTERACTIVE DEMONSTRATION")
        print("="*60)
        print("1. Caesar Cipher")
        print("2. Vigenère Cipher")
        print("3. RSA Algorithm")
        print("4. Diffie-Hellman Key Exchange")
        print("5. Hash Functions")
        print("6. Cryptanalysis")
        print("7. Password Analysis")
        print("8. Run All Demonstrations")
        print("9. Exit")
        
        choice = input("\nEnter your choice (1-9): ").strip()
        
        if choice == '1':
            demonstrate_caesar_cipher()
        elif choice == '2':
            demonstrate_vigenere_cipher()
        elif choice == '3':
            demonstrate_rsa()
        elif choice == '4':
            demonstrate_diffie_hellman()
        elif choice == '5':
            demonstrate_hash_functions()
        elif choice == '6':
            demonstrate_cryptanalysis()
        elif choice == '7':
            demonstrate_password_analysis()
        elif choice == '8':
            run_all_demonstrations()
        elif choice == '9':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")


def run_all_demonstrations():
    """Run all demonstrations in sequence"""
    print("\nRunning all demonstrations...")
    
    demonstrate_caesar_cipher()
    demonstrate_vigenere_cipher()
    demonstrate_rsa()
    demonstrate_diffie_hellman()
    demonstrate_hash_functions()
    demonstrate_cryptanalysis()
    demonstrate_password_analysis()
    
    print("\n" + "="*50)
    print("ALL DEMONSTRATIONS COMPLETED")
    print("="*50)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Please check that all required modules are available.")
