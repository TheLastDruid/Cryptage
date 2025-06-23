import string
from collections import Counter
import re

class CryptanalysisTools:
    ENGLISH_FREQ = {
        'A': 8.12, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.02,
        'F': 2.23, 'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15,
        'K': 0.77, 'L': 4.03, 'M': 2.41, 'N': 6.75, 'O': 7.51,
        'P': 1.93, 'Q': 0.10, 'R': 5.99, 'S': 6.33, 'T': 9.06,
        'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15, 'Y': 1.97,
        'Z': 0.07
    }
    
    @staticmethod
    def frequency_analysis(text):
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        if not clean_text: return {}
        letter_counts = Counter(clean_text)
        total_letters = len(clean_text)
        frequencies = {}
        for letter in string.ascii_uppercase:
            count = letter_counts.get(letter, 0)
            frequencies[letter] = (count / total_letters) * 100
        return frequencies
    
    @staticmethod
    def chi_squared_test(observed_freq, expected_freq=None):
        if expected_freq is None: expected_freq = CryptanalysisTools.ENGLISH_FREQ
        chi_squared = 0
        for letter in string.ascii_uppercase:
            observed = observed_freq.get(letter, 0)
            expected = expected_freq.get(letter, 0)
            if expected > 0: chi_squared += ((observed - expected) ** 2) / expected
        return chi_squared
    
    @staticmethod
    def index_of_coincidence(text):
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        if len(clean_text) < 2: return 0
        letter_counts = Counter(clean_text)
        n = len(clean_text)
        ic = 0
        for count in letter_counts.values():
            ic += count * (count - 1)
        ic = ic / (n * (n - 1))
        return ic
    
    @staticmethod
    def break_caesar_cipher(ciphertext):
        from caesar_cipher import CaesarCipher
        best_shift, best_score, best_plaintext = 0, float('inf'), ""
        for shift in range(26):
            cipher = CaesarCipher(shift)
            plaintext = cipher.decrypt(ciphertext)
            freq = CryptanalysisTools.frequency_analysis(plaintext)
            score = CryptanalysisTools.chi_squared_test(freq)
            if score < best_score:
                best_score = score
                best_shift = shift
                best_plaintext = plaintext
        return best_shift, best_plaintext, best_score
    
    @staticmethod
    def estimate_vigenere_key_length(ciphertext, max_length=20):
        clean_text = re.sub(r'[^A-Za-z]', '', ciphertext.upper())
        if len(clean_text) < 50: return {}
        ic_scores = {}
        for key_length in range(2, min(max_length + 1, len(clean_text) // 10)):
            subsequences = [''] * key_length
            for i, char in enumerate(clean_text):
                subsequences[i % key_length] += char
            total_ic = 0
            valid_subsequences = 0
            for subseq in subsequences:
                if len(subseq) > 1:
                    ic = CryptanalysisTools.index_of_coincidence(subseq)
                    total_ic += ic
                    valid_subsequences += 1
            if valid_subsequences > 0:
                avg_ic = total_ic / valid_subsequences
                ic_scores[key_length] = avg_ic
        return ic_scores
    
    @staticmethod
    def find_repeated_sequences(text, min_length=3):
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        repeated_sequences = {}
        for length in range(min_length, min(10, len(clean_text) // 3)):
            for i in range(len(clean_text) - length + 1):
                sequence = clean_text[i:i + length]
                positions = []
                for j in range(len(clean_text) - length + 1):
                    if clean_text[j:j + length] == sequence:
                        positions.append(j)
                if len(positions) > 1:
                    if sequence not in repeated_sequences:
                        repeated_sequences[sequence] = positions
        return repeated_sequences
    
    @staticmethod
    def break_substitution_cipher_partial(ciphertext, known_mappings=None):
        if known_mappings is None: known_mappings = {}
        cipher_freq = CryptanalysisTools.frequency_analysis(ciphertext)
        cipher_sorted = sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)
        english_sorted = sorted(CryptanalysisTools.ENGLISH_FREQ.items(), key=lambda x: x[1], reverse=True)
        suggested_mappings = known_mappings.copy()
        cipher_index = 0
        english_index = 0
        while cipher_index < len(cipher_sorted) and english_index < len(english_sorted):
            cipher_char = cipher_sorted[cipher_index][0]
            english_char = english_sorted[english_index][0]
            if cipher_char in suggested_mappings:
                cipher_index += 1
                continue
            if english_char in suggested_mappings.values():
                english_index += 1
                continue
            suggested_mappings[cipher_char] = english_char
            cipher_index += 1
            english_index += 1
        return suggested_mappings


class PasswordAnalyzer:
    @staticmethod
    def analyze_password_strength(password):
        analysis = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'entropy': 0,
            'score': 0,
            'recommendations': []
        }
        charset_size = 0
        if analysis['has_lowercase']: charset_size += 26
        if analysis['has_uppercase']: charset_size += 26
        if analysis['has_digits']: charset_size += 10
        if analysis['has_special']: charset_size += 32
        if charset_size > 0:
            import math
            analysis['entropy'] = len(password) * math.log2(charset_size)
        score = 0
        if analysis['length'] >= 8: score += 25
        if analysis['length'] >= 12: score += 25
        if analysis['has_lowercase']: score += 10
        if analysis['has_uppercase']: score += 10
        if analysis['has_digits']: score += 10
        if analysis['has_special']: score += 20
        analysis['score'] = min(score, 100)
        if analysis['length'] < 8: analysis['recommendations'].append("Use at least 8 characters")
        if not analysis['has_lowercase']: analysis['recommendations'].append("Include lowercase letters")
        if not analysis['has_uppercase']: analysis['recommendations'].append("Include uppercase letters")
        if not analysis['has_digits']: analysis['recommendations'].append("Include numbers")
        if not analysis['has_special']: analysis['recommendations'].append("Include special characters")
        return analysis
    
    @staticmethod
    def estimate_crack_time(password):
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'\d', password): charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): charset_size += 32
        if charset_size == 0: return {"error": "Invalid password"}
        combinations = charset_size ** len(password)
        attack_speeds = {
            'online_slow': 1000,
            'online_fast': 1000000,
            'offline_slow': 1000000000,
            'offline_fast': 100000000000
        }
        results = {}
        for attack_type, speed in attack_speeds.items():
            seconds = (combinations / 2) / speed
            if seconds < 60: time_str = f"{seconds:.1f} seconds"
            elif seconds < 3600: time_str = f"{seconds/60:.1f} minutes"
            elif seconds < 86400: time_str = f"{seconds/3600:.1f} hours"
            elif seconds < 31536000: time_str = f"{seconds/86400:.1f} days"
            else: time_str = f"{seconds/31536000:.1f} years"
            results[attack_type] = time_str
        return results


def main():
    print("Cryptanalysis Tools Demonstration")
    print("=" * 35)
    sample_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    print(f"Sample text: {sample_text}")
    freq = CryptanalysisTools.frequency_analysis(sample_text)
    print("\nFrequency Analysis:")
    for letter, percentage in sorted(freq.items(), key=lambda x: x[1], reverse=True):
        if percentage > 0:
            print(f"{letter}: {percentage:.2f}%")
    ic = CryptanalysisTools.index_of_coincidence(sample_text)
    print(f"\nIndex of Coincidence: {ic:.4f}")
    print("(English text typically has IC ≈ 0.067)")
    from caesar_cipher import CaesarCipher
    caesar = CaesarCipher(7)
    encrypted_text = caesar.encrypt("HELLO WORLD THIS IS A TEST MESSAGE")
    print(f"\nEncrypted with Caesar cipher (shift 7): {encrypted_text}")
    shift, plaintext, score = CryptanalysisTools.break_caesar_cipher(encrypted_text)
    print(f"Broken! Shift: {shift}, Plaintext: {plaintext}")
    print(f"Chi-squared score: {score:.2f}")
    passwords = ["password", "Password123", "P@ssw0rd123!", "MyVeryLongAndSecurePassword2024!"]
    print("\nPassword Strength Analysis:")
    print("-" * 30)
    analyzer = PasswordAnalyzer()
    for pwd in passwords:
        analysis = analyzer.analyze_password_strength(pwd)
        crack_times = analyzer.estimate_crack_time(pwd)
        print(f"\nPassword: '{pwd}'")
        print(f"Score: {analysis['score']}/100")
        print(f"Entropy: {analysis['entropy']:.1f} bits")
        print(f"Offline crack time (GPU): {crack_times.get('offline_fast', 'N/A')}")
        if analysis['recommendations']:
            print(f"Recommendations: {', '.join(analysis['recommendations'])}")

if __name__ == "__main__":
    main()
