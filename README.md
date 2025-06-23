# 🔐 Cryptography Algorithms - TP Implementation

A comprehensive implementation of fundamental cryptography algorithms for academic purposes. This project provides educational implementations of classical and modern cryptographic techniques with interactive demonstrations and analysis tools.

## 🎯 Features

### **Classical Cryptography**
- ✅ **Caesar Cipher** - Substitution cipher with configurable shift
- ✅ **Vigenère Cipher** - Polyalphabetic cipher with keyword encryption
- ✅ **Cryptanalysis Tools** - Frequency analysis and cipher breaking

### **Modern Cryptography**
- ✅ **RSA Algorithm** - Public-key cryptosystem with key generation
- ✅ **AES Encryption** - Advanced Encryption Standard (CBC/GCM modes)
- ✅ **Diffie-Hellman** - Secure key exchange protocol
- ✅ **Hash Functions** - MD5, SHA-1, SHA-256, SHA-512, HMAC

### **Security Analysis**
- ✅ **Password Analysis** - Strength evaluation and crack time estimation
- ✅ **Cryptanalysis** - Breaking techniques and vulnerability assessment
- ✅ **Interactive GUI** - User-friendly testing interface

## 🚀 Quick Start

### **1. GUI Interface (Recommended)**
```bash
python gui.py
```
Interactive graphical interface with tabs for each algorithm.

### **2. Command Line Demo**
```bash
python demo.py
```
Automated demonstration of all algorithms.

### **3. Interactive Console**
```bash
python main.py
```
Menu-driven console interface.

### **4. Run Tests**
```bash
python tests/test_algorithms.py
```
Comprehensive test suite validation.

## 📁 Project Structure

```
TP algo/
├── src/                    # Core algorithm implementations
│   ├── caesar_cipher.py    # Caesar cipher with cryptanalysis
│   ├── vigenere_cipher.py  # Vigenère cipher implementation
│   ├── rsa_algorithm.py    # RSA public-key cryptography
│   ├── diffie_hellman.py   # Diffie-Hellman key exchange
│   ├── aes_algorithm.py    # AES symmetric encryption
│   ├── hash_functions.py   # Hash algorithms and HMAC
│   └── cryptanalysis.py    # Cryptanalysis and security tools
├── tests/                  # Test suite
│   └── test_algorithms.py  # Comprehensive unit tests
├── gui.py                  # Interactive GUI interface
├── demo.py                 # Quick demonstration script
├── main.py                 # Console interface
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## 🔧 Requirements

- **Python 3.8+**
- **cryptography** library (for AES implementation)

### Installation
```bash
pip install -r requirements.txt
```

## 📖 Usage Examples

### Caesar Cipher
```python
from src.caesar_cipher import CaesarCipher

cipher = CaesarCipher(shift=3)
encrypted = cipher.encrypt("Hello World")
decrypted = cipher.decrypt(encrypted)
```

### RSA Encryption
```python
from src.rsa_algorithm import RSA

rsa = RSA(key_size=1024)
public_key, private_key = rsa.generate_keypair()
encrypted = rsa.encrypt_string("Secret message")
decrypted = rsa.decrypt_string(encrypted)
```

### Password Analysis
```python
from src.cryptanalysis import PasswordAnalyzer

analyzer = PasswordAnalyzer()
analysis = analyzer.analyze_password_strength("MyPassword123!")
print(f"Score: {analysis['score']}/100")
```

## 🧪 Testing

The project includes comprehensive unit tests covering:
- Algorithm correctness
- Edge cases and error handling
- Performance benchmarks
- Security validation

Run the test suite:
```bash
python tests/test_algorithms.py
```

## 📊 Performance

| Algorithm | Operation | Time (10KB) |
|-----------|-----------|-------------|
| Caesar Cipher | Encrypt/Decrypt | ~0.007s |
| Vigenère Cipher | Encrypt/Decrypt | ~0.010s |
| Hash SHA-256 | 1MB data | ~0.005s |
| RSA 1024-bit | Key Generation | ~0.500s |

## 🎓 Educational Value

This implementation demonstrates:
- **Classical vs Modern** cryptography evolution
- **Symmetric vs Asymmetric** encryption principles
- **Cryptanalysis techniques** and vulnerability assessment
- **Security best practices** in implementation
- **Real-world applications** of cryptographic algorithms

## ⚠️ Security Notice

This implementation is for **educational purposes only**. Some algorithms (like MD5) are included for historical learning but should not be used in production environments due to known vulnerabilities.

## 🤝 Contributing

This is an academic project. Contributions should focus on:
- Educational clarity
- Algorithm correctness
- Documentation improvements
- Test coverage enhancement

## 📝 License

Educational use only. See individual algorithm implementations for specific notes and references.

---
*Cryptography TP Implementation - Academic Project*
