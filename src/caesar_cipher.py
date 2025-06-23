class CaesarCipher:
    def __init__(self, shift=3):
        self.shift = shift % 26
    
    def encrypt(self, plaintext):
        result = ""
        for char in plaintext:
            if char.isalpha():
                if char.isupper():
                    result += chr((ord(char) - ord('A') + self.shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + self.shift) % 26 + ord('a'))
            else:
                result += char
        return result
    
    def decrypt(self, ciphertext):
        result = ""
        for char in ciphertext:
            if char.isalpha():
                if char.isupper():
                    result += chr((ord(char) - ord('A') - self.shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') - self.shift) % 26 + ord('a'))
            else:
                result += char
        return result
    
    def brute_force_attack(self, ciphertext):
        results = {}
        for shift in range(26):
            temp_cipher = CaesarCipher(shift)
            results[shift] = temp_cipher.decrypt(ciphertext)
        return results

def main():
    cipher = CaesarCipher(3)
    plaintext = "Hello, World!"
    print(f"Original text: {plaintext}")
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted text: {encrypted}")
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted text: {decrypted}")
    print("\nBrute force attack on 'KHOOR':")
    attacks = cipher.brute_force_attack("KHOOR")
    for shift, result in attacks.items():
        print(f"Shift {shift}: {result}")

if __name__ == "__main__":
    main()
