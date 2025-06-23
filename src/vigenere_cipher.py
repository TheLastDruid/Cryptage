"""
Vigenère Cipher Implementation
A polyalphabetic substitution cipher using a keyword.
"""

class VigenereCipher:
    def __init__(self, keyword):
        """
        Initialize Vigenère cipher with a keyword.
        
        Args:
            keyword (str): Keyword for encryption/decryption
        """
        self.keyword = keyword.upper().replace(' ', '')
        if not self.keyword.isalpha():
            raise ValueError("Keyword must contain only alphabetic characters")
    
    def _extend_keyword(self, text_length):
        """
        Extend keyword to match the length of the text.
        
        Args:
            text_length (int): Length of text to match
            
        Returns:
            str: Extended keyword
        """
        if len(self.keyword) == 0:
            raise ValueError("Keyword cannot be empty")
        
        extended = ""
        keyword_index = 0
        
        for i in range(text_length):
            extended += self.keyword[keyword_index % len(self.keyword)]
            keyword_index += 1
            
        return extended
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using Vigenère cipher.
        
        Args:
            plaintext (str): Text to encrypt
            
        Returns:
            str: Encrypted text
        """
        # Remove non-alphabetic characters for key extension calculation
        alpha_only = ''.join(char for char in plaintext if char.isalpha())
        extended_key = self._extend_keyword(len(alpha_only))
        
        result = ""
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                # Get the shift value from the extended keyword
                shift = ord(extended_key[key_index]) - ord('A')
                key_index += 1
                
                if char.isupper():
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                result += char
                
        return result
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using Vigenère cipher.
        
        Args:
            ciphertext (str): Text to decrypt
            
        Returns:
            str: Decrypted text
        """
        # Remove non-alphabetic characters for key extension calculation
        alpha_only = ''.join(char for char in ciphertext if char.isalpha())
        extended_key = self._extend_keyword(len(alpha_only))
        
        result = ""
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                # Get the shift value from the extended keyword
                shift = ord(extended_key[key_index]) - ord('A')
                key_index += 1
                
                if char.isupper():
                    result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                result += char
                
        return result
    
    def analyze_frequency(self, text):
        """
        Analyze character frequency in text (useful for cryptanalysis).
        
        Args:
            text (str): Text to analyze
            
        Returns:
            dict: Character frequency dictionary
        """
        frequency = {}
        total_chars = 0
        
        for char in text.upper():
            if char.isalpha():
                frequency[char] = frequency.get(char, 0) + 1
                total_chars += 1
        
        # Convert to percentages
        for char in frequency:
            frequency[char] = (frequency[char] / total_chars) * 100
            
        return frequency


def main():
    # Example usage
    keyword = "SECRET"
    cipher = VigenereCipher(keyword)
    
    plaintext = "HELLO WORLD"
    print(f"Keyword: {keyword}")
    print(f"Original text: {plaintext}")
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted text: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted text: {decrypted}")
    
    # Frequency analysis
    print(f"\nFrequency analysis of encrypted text:")
    freq = cipher.analyze_frequency(encrypted)
    for char, percentage in sorted(freq.items()):
        print(f"{char}: {percentage:.2f}%")


if __name__ == "__main__":
    main()
