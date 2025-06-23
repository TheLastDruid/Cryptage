"""
Cryptography Algorithms Package

This package contains educational implementations of various cryptographic algorithms
including classical ciphers, modern encryption, hash functions, and cryptanalysis tools.

Modules:
    caesar_cipher: Caesar cipher implementation with cryptanalysis
    vigenere_cipher: Vigenère cipher with keyword encryption
    rsa_algorithm: RSA public-key cryptography
    diffie_hellman: Diffie-Hellman key exchange protocol
    aes_algorithm: AES symmetric encryption
    hash_functions: Various hash functions and HMAC
    cryptanalysis: Cryptanalysis and security analysis tools
"""

__version__ = "1.0.0"
__author__ = "TP Cryptography Project"

# Import main classes for easy access
from .caesar_cipher import CaesarCipher
from .vigenere_cipher import VigenereCipher
from .hash_functions import HashFunctions
from .cryptanalysis import CryptanalysisTools, PasswordAnalyzer

try:
    from .rsa_algorithm import RSA
    from .diffie_hellman import DiffieHellman
    from .aes_algorithm import AES
except ImportError as e:
    # Handle missing dependencies gracefully
    print(f"Warning: Some advanced algorithms may not be available: {e}")

__all__ = [
    'CaesarCipher',
    'VigenereCipher', 
    'HashFunctions',
    'CryptanalysisTools',
    'PasswordAnalyzer',
    'RSA',
    'DiffieHellman',
    'AES'
]
