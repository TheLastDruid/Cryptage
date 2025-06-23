# 🔐 Cryptage - Cryptography Algorithms Implementation

A comprehensive educational implementation of fundamental cryptographic algorithms and security analysis tools.

[![Tests](https://img.shields.io/badge/tests-17%20passing-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](requirements.txt)
[![License](https://img.shields.io/badge/license-Educational-yellow)](#)

## 🎯 Features

### **Classical Cryptography**
- ✅ **Caesar Cipher** - Substitution cipher with configurable shift + cryptanalysis
- ✅ **Vigenère Cipher** - Polyalphabetic cipher with keyword encryption
- ✅ **Cryptanalysis Tools** - Frequency analysis and cipher breaking techniques

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

### **1. Clone the Repository**
```bash
git clone https://github.com/TheLastDruid/Cryptage.git
cd Cryptage
```

### **2. Install Dependencies**
```bash
pip install -r requirements.txt
```

### **3. Choose Your Interface**

#### 🖼️ **GUI Interface (Recommended)**
```bash
python run.py
```

#### 🎮 **Quick Demo**
```bash
python run.py --demo
```

#### 💻 **Interactive Console**
```bash
python run.py --console
```

#### 🧪 **Run Tests**
```bash
python run.py --test
```

## 📖 Usage Examples

### Caesar Cipher
```python
from src.caesar_cipher import CaesarCipher

cipher = CaesarCipher(shift=3)
encrypted = cipher.encrypt("Hello World")  # "Khoor Zruog"
decrypted = cipher.decrypt(encrypted)      # "Hello World"
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

## 📁 Project Structure

```
Cryptage/
├── 📋 README.md               # This file
├── 🚀 QUICKSTART.md           # Quick start guide
├── ⚙️  run.py                 # Main entry point
├── 🖼️  gui.py                 # Interactive GUI interface
├── 🎮 demo.py                 # Quick demonstration
├── 💻 main.py                 # Console interface
├── 📦 requirements.txt        # Dependencies
│
├── 📁 src/                    # Core implementations
│   ├── 🔤 caesar_cipher.py   # Caesar cipher + cryptanalysis
│   ├── 🔑 vigenere_cipher.py # Vigenère cipher
│   ├── 🔐 rsa_algorithm.py   # RSA public-key cryptography
│   ├── 🤝 diffie_hellman.py  # Key exchange protocol
│   ├── 🛡️  aes_algorithm.py   # AES symmetric encryption
│   ├── #️⃣  hash_functions.py  # Hash algorithms + HMAC
│   └── 🔍 cryptanalysis.py   # Security analysis tools
│
└── 📁 tests/                  # Test suite
    └── 🧪 test_algorithms.py # Comprehensive unit tests
```

## 🧪 Testing

Run the comprehensive test suite:
```bash
python run.py --test
```

**Test Coverage:**
- 17 unit tests covering all algorithms
- Performance benchmarks
- Security validation
- Edge cases and error handling

## 📊 Performance Benchmarks

| Algorithm | Operation | Time (10KB) |
|-----------|-----------|-------------|
| Caesar Cipher | Encrypt/Decrypt | ~0.010s |
| Vigenère Cipher | Encrypt/Decrypt | ~0.015s |
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

Contributions welcome! Please focus on:
- Educational clarity
- Algorithm correctness
- Documentation improvements
- Test coverage enhancement

## 📝 License

Educational use only. This project is designed for learning cryptographic concepts and should not be used for actual security implementations.

---

**🔐 Learn Cryptography • 🧪 Test Algorithms • 🛡️ Understand Security**
