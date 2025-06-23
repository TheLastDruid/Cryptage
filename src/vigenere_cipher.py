class VigenereCipher:
    def __init__(self, keyword):
        self.keyword = keyword.upper().replace(' ', '')
        if not self.keyword.isalpha():
            raise ValueError("Keyword must contain only alphabetic characters")
    
    def _extend_keyword(self, text_length):
        if len(self.keyword) == 0:
            raise ValueError("Keyword cannot be empty")
        return ''.join(self.keyword[i % len(self.keyword)] for i in range(text_length))
    
    def encrypt(self, plaintext):
        alpha_only = ''.join(char for char in plaintext if char.isalpha())
        extended_key = self._extend_keyword(len(alpha_only))
        result, key_index = "", 0
        for char in plaintext:
            if char.isalpha():
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
        alpha_only = ''.join(char for char in ciphertext if char.isalpha())
        extended_key = self._extend_keyword(len(alpha_only))
        result, key_index = "", 0
        for char in ciphertext:
            if char.isalpha():
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
        frequency, total_chars = {}, 0
        for char in text.upper():
            if char.isalpha():
                frequency[char] = frequency.get(char, 0) + 1
                total_chars += 1
        for char in frequency:
            frequency[char] = (frequency[char] / total_chars) * 100
        return frequency


def main():
    keyword = "SECRET"
    cipher = VigenereCipher(keyword)
    plaintext = "HELLO WORLD"
    print(f"Keyword: {keyword}")
    print(f"Original text: {plaintext}")
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted text: {encrypted}")
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted text: {decrypted}")
    print("\nFrequency analysis of encrypted text:")
    freq = cipher.analyze_frequency(encrypted)
    for char, percentage in sorted(freq.items()):
        print(f"{char}: {percentage:.2f}%")

if __name__ == "__main__":
    main()
