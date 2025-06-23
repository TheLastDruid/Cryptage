"""
Test suite for cryptography algorithms
"""

import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import unittest
from caesar_cipher import CaesarCipher
from vigenere_cipher import VigenereCipher
from hash_functions import HashFunctions, SimpleHashFunction


class TestCaesarCipher(unittest.TestCase):
    """Test cases for Caesar Cipher"""
    
    def setUp(self):
        self.cipher = CaesarCipher(3)
    
    def test_encryption(self):
        plaintext = "HELLO"
        expected = "KHOOR"
        result = self.cipher.encrypt(plaintext)
        self.assertEqual(result, expected)
    
    def test_decryption(self):
        ciphertext = "KHOOR"
        expected = "HELLO"
        result = self.cipher.decrypt(ciphertext)
        self.assertEqual(result, expected)
    
    def test_round_trip(self):
        plaintext = "Hello, World!"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(plaintext, decrypted)
    
    def test_non_alpha_characters(self):
        plaintext = "Hello, 123!"
        encrypted = self.cipher.encrypt(plaintext)
        self.assertIn(",", encrypted)
        self.assertIn("1", encrypted)
        self.assertIn("2", encrypted)
        self.assertIn("3", encrypted)
        self.assertIn("!", encrypted)
    
    def test_different_shifts(self):
        for shift in [1, 5, 13, 25]:
            cipher = CaesarCipher(shift)
            plaintext = "TEST"
            encrypted = cipher.encrypt(plaintext)
            decrypted = cipher.decrypt(encrypted)
            self.assertEqual(plaintext, decrypted)


class TestVigenereCipher(unittest.TestCase):
    """Test cases for Vigenère Cipher"""
    
    def setUp(self):
        self.cipher = VigenereCipher("SECRET")
    
    def test_encryption(self):
        plaintext = "HELLO"
        # Expected: H+S=Z, E+E=I, L+C=N, L+R=C, O+E=S
        expected = "ZINCS"
        result = self.cipher.encrypt(plaintext)
        self.assertEqual(result, expected)
    
    def test_decryption(self):
        ciphertext = "ZINCS"
        expected = "HELLO"
        result = self.cipher.decrypt(ciphertext)
        self.assertEqual(result, expected)
    
    def test_round_trip(self):
        plaintext = "Hello, World!"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(plaintext, decrypted)
    
    def test_keyword_extension(self):
        cipher = VigenereCipher("KEY")
        # Should extend to KEYKEYK... for longer texts
        plaintext = "ATTACKATDAWN"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(plaintext, decrypted)
    
    def test_invalid_keyword(self):
        with self.assertRaises(ValueError):
            VigenereCipher("KEY123")  # Contains numbers
        
        with self.assertRaises(ValueError):
            VigenereCipher("")  # Empty keyword


class TestHashFunctions(unittest.TestCase):
    """Test cases for Hash Functions"""
    
    def setUp(self):
        self.hash_funcs = HashFunctions()
        self.simple_hash = SimpleHashFunction()
    
    def test_md5_consistency(self):
        message = "test message"
        hash1 = self.hash_funcs.md5_hash(message)
        hash2 = self.hash_funcs.md5_hash(message)
        self.assertEqual(hash1, hash2)
    
    def test_sha256_consistency(self):
        message = "test message"
        hash1 = self.hash_funcs.sha256_hash(message)
        hash2 = self.hash_funcs.sha256_hash(message)
        self.assertEqual(hash1, hash2)
    
    def test_different_messages_different_hashes(self):
        hash1 = self.hash_funcs.sha256_hash("message1")
        hash2 = self.hash_funcs.sha256_hash("message2")
        self.assertNotEqual(hash1, hash2)
    
    def test_hash_with_salt(self):
        message = "password"
        salt1 = "salt1"
        salt2 = "salt2"
        
        hash1 = self.hash_funcs.hash_with_salt(message, salt1)
        hash2 = self.hash_funcs.hash_with_salt(message, salt2)
        
        self.assertNotEqual(hash1, hash2)
    
    def test_hmac_consistency(self):
        message = "test message"
        key = "secret key"
        
        hmac1 = self.hash_funcs.hmac_hash(message, key)
        hmac2 = self.hash_funcs.hmac_hash(message, key)
        
        self.assertEqual(hmac1, hmac2)
    
    def test_simple_hash_functions(self):
        message = "test"
        
        # Test that simple hash functions return integers
        simple_hash_result = self.simple_hash.simple_hash(message)
        djb2_result = self.simple_hash.djb2_hash(message)
        fnv1a_result = self.simple_hash.fnv1a_hash(message)
        
        self.assertIsInstance(simple_hash_result, int)
        self.assertIsInstance(djb2_result, int)
        self.assertIsInstance(fnv1a_result, int)
    
    def test_hash_compare(self):
        message = "test"
        hash1 = self.hash_funcs.sha256_hash(message)
        hash2 = self.hash_funcs.sha256_hash(message)
        hash3 = self.hash_funcs.sha256_hash("different")
        
        self.assertTrue(self.hash_funcs.compare_hashes(message, hash1, hash2))
        self.assertFalse(self.hash_funcs.compare_hashes(message, hash1, hash3))


def run_performance_tests():
    """Run performance tests for different algorithms"""
    print("Performance Tests")
    print("=" * 20)
    
    import time
      # Test Caesar Cipher performance
    caesar = CaesarCipher(3)
    message = "A" * 10000  # 10KB message
    
    start_time = time.time()
    encrypted = caesar.encrypt(message)
    encrypt_time = time.time() - start_time
    
    start_time = time.time()
    caesar.decrypt(encrypted)  # Just test performance, don't store result
    decrypt_time = time.time() - start_time
    
    print("Caesar Cipher (10KB):")
    print(f"  Encryption: {encrypt_time:.4f}s")
    print(f"  Decryption: {decrypt_time:.4f}s")
    
    # Test hash function performance
    hash_funcs = HashFunctions()
    message = "A" * 1000000  # 1MB message
    
    algorithms = ['md5_hash', 'sha1_hash', 'sha256_hash', 'sha512_hash']
    
    print("\nHash Functions (1MB):")
    for algo in algorithms:
        start_time = time.time()
        getattr(hash_funcs, algo)(message)
        hash_time = time.time() - start_time
        print(f"  {algo.replace('_hash', '').upper()}: {hash_time:.4f}s")


def main():
    """Run all tests"""
    print("Cryptography Algorithms Test Suite")
    print("=" * 35)
    
    # Run unit tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestCaesarCipher))
    suite.addTests(loader.loadTestsFromTestCase(TestVigenereCipher))
    suite.addTests(loader.loadTestsFromTestCase(TestHashFunctions))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n")
    
    # Run performance tests
    run_performance_tests()
      # Summary
    print("\nTest Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
    
    return len(result.failures) + len(result.errors) == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
