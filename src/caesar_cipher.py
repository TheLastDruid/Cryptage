"""
Caesar Cipher Implementation
A simple substitution cipher where each letter is shifted by a fixed number of positions.
"""

class CaesarCipher:
    def __init__(self, shift=3):
        """
        Initialize Caesar cipher with a shift value.
        
        Args:
            shift (int): Number of positions to shift each letter (default: 3)
        """
        self.shift = shift % 26
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using Caesar cipher.
        
        Args:
            plaintext (str): Text to encrypt
            
        Returns:
            str: Encrypted text
        """
        result = ""
        for char in plaintext:
            if char.isalpha():
                # Handle uppercase letters
                if char.isupper():
                    result += chr((ord(char) - ord('A') + self.shift) % 26 + ord('A'))
                # Handle lowercase letters
                else:
                    result += chr((ord(char) - ord('a') + self.shift) % 26 + ord('a'))
            else:
                # Keep non-alphabetic characters unchanged
                result += char
        return result
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using Caesar cipher.
        
        Args:
            ciphertext (str): Text to decrypt
            
        Returns:
            str: Decrypted text
        """
        result = ""
        for char in ciphertext:
            if char.isalpha():
                # Handle uppercase letters
                if char.isupper():
                    result += chr((ord(char) - ord('A') - self.shift) % 26 + ord('A'))
                # Handle lowercase letters
                else:
                    result += chr((ord(char) - ord('a') - self.shift) % 26 + ord('a'))
            else:
                # Keep non-alphabetic characters unchanged
                result += char
        return result
    
    def brute_force_attack(self, ciphertext):
        """
        Attempt to break Caesar cipher by trying all possible shifts.
        
        Args:
            ciphertext (str): Text to decrypt
            
        Returns:
            dict: Dictionary with shift values as keys and decrypted text as values
        """
        results = {}
        for shift in range(26):
            temp_cipher = CaesarCipher(shift)
            results[shift] = temp_cipher.decrypt(ciphertext)
        return results


def main():
    # Example usage
    cipher = CaesarCipher(3)
    
    plaintext = "Hello, World!"
    print(f"Original text: {plaintext}")
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted text: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted text: {decrypted}")
    
    # Brute force attack demonstration
    print("\nBrute force attack on 'KHOOR':")
    attacks = cipher.brute_force_attack("KHOOR")
    for shift, result in attacks.items():
        print(f"Shift {shift}: {result}")


if __name__ == "__main__":
    main()
