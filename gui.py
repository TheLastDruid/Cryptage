"""
Simple GUI Interface for Testing Cryptography Algorithms
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from caesar_cipher import CaesarCipher
from vigenere_cipher import VigenereCipher
from hash_functions import HashFunctions
from cryptanalysis import CryptanalysisTools, PasswordAnalyzer


class CryptographyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Algorithms Tester")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_caesar_tab()
        self.create_vigenere_tab()
        self.create_hash_tab()
        self.create_cryptanalysis_tab()
        self.create_password_tab()
        self.create_rsa_tab()
    
    def create_caesar_tab(self):
        """Create Caesar Cipher tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Caesar Cipher")
        
        # Title
        title = tk.Label(frame, text="Caesar Cipher", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Shift value
        shift_frame = tk.Frame(frame)
        shift_frame.pack(pady=5)
        tk.Label(shift_frame, text="Shift Value:").pack(side=tk.LEFT)
        self.caesar_shift = tk.IntVar(value=3)
        shift_spin = tk.Spinbox(shift_frame, from_=1, to=25, textvariable=self.caesar_shift, width=5)
        shift_spin.pack(side=tk.LEFT, padx=5)
        
        # Input text
        tk.Label(frame, text="Input Text:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.caesar_input = scrolledtext.ScrolledText(frame, height=4, width=70)
        self.caesar_input.pack(padx=20, pady=5)
        self.caesar_input.insert(tk.END, "Hello, World! This is a test message.")
        
        # Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=10)
        
        encrypt_btn = tk.Button(button_frame, text="Encrypt", 
                               command=self.caesar_encrypt, bg='#4CAF50', fg='white')
        encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        decrypt_btn = tk.Button(button_frame, text="Decrypt", 
                               command=self.caesar_decrypt, bg='#2196F3', fg='white')
        decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        break_btn = tk.Button(button_frame, text="Break Cipher", 
                             command=self.caesar_break, bg='#FF9800', fg='white')
        break_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", 
                             command=self.caesar_clear, bg='#f44336', fg='white')
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Output text
        tk.Label(frame, text="Output:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.caesar_output = scrolledtext.ScrolledText(frame, height=4, width=70)
        self.caesar_output.pack(padx=20, pady=5)
    
    def create_vigenere_tab(self):
        """Create Vigenère Cipher tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Vigenère Cipher")
        
        # Title
        title = tk.Label(frame, text="Vigenère Cipher", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Keyword
        keyword_frame = tk.Frame(frame)
        keyword_frame.pack(pady=5)
        tk.Label(keyword_frame, text="Keyword:").pack(side=tk.LEFT)
        self.vigenere_keyword = tk.StringVar(value="SECRET")
        keyword_entry = tk.Entry(keyword_frame, textvariable=self.vigenere_keyword, width=20)
        keyword_entry.pack(side=tk.LEFT, padx=5)
        
        # Input text
        tk.Label(frame, text="Input Text:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.vigenere_input = scrolledtext.ScrolledText(frame, height=4, width=70)
        self.vigenere_input.pack(padx=20, pady=5)
        self.vigenere_input.insert(tk.END, "ATTACK AT DAWN")
        
        # Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=10)
        
        encrypt_btn = tk.Button(button_frame, text="Encrypt", 
                               command=self.vigenere_encrypt, bg='#4CAF50', fg='white')
        encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        decrypt_btn = tk.Button(button_frame, text="Decrypt", 
                               command=self.vigenere_decrypt, bg='#2196F3', fg='white')
        decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        analyze_btn = tk.Button(button_frame, text="Frequency Analysis", 
                               command=self.vigenere_analyze, bg='#9C27B0', fg='white')
        analyze_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", 
                             command=self.vigenere_clear, bg='#f44336', fg='white')
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Output text
        tk.Label(frame, text="Output:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.vigenere_output = scrolledtext.ScrolledText(frame, height=4, width=70)
        self.vigenere_output.pack(padx=20, pady=5)
    
    def create_hash_tab(self):
        """Create Hash Functions tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Hash Functions")
        
        # Title
        title = tk.Label(frame, text="Hash Functions", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Input text
        tk.Label(frame, text="Input Text:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.hash_input = scrolledtext.ScrolledText(frame, height=3, width=70)
        self.hash_input.pack(padx=20, pady=5)
        self.hash_input.insert(tk.END, "Hello, Cryptography!")
        
        # Hash type selection
        hash_frame = tk.Frame(frame)
        hash_frame.pack(pady=10)
        tk.Label(hash_frame, text="Hash Type:").pack(side=tk.LEFT)
        
        self.hash_type = tk.StringVar(value="SHA-256")
        hash_combo = ttk.Combobox(hash_frame, textvariable=self.hash_type, 
                                 values=["MD5", "SHA-1", "SHA-256", "SHA-512"], 
                                 state="readonly", width=15)
        hash_combo.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=10)
        
        hash_btn = tk.Button(button_frame, text="Generate Hash", 
                            command=self.generate_hash, bg='#4CAF50', fg='white')
        hash_btn.pack(side=tk.LEFT, padx=5)
        
        compare_btn = tk.Button(button_frame, text="Compare Hashes", 
                               command=self.compare_hashes, bg='#2196F3', fg='white')
        compare_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", 
                             command=self.hash_clear, bg='#f44336', fg='white')
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Output text
        tk.Label(frame, text="Hash Output:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.hash_output = scrolledtext.ScrolledText(frame, height=6, width=70)
        self.hash_output.pack(padx=20, pady=5)
    
    def create_cryptanalysis_tab(self):
        """Create Cryptanalysis tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Cryptanalysis")
        
        # Title
        title = tk.Label(frame, text="Cryptanalysis Tools", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Input text
        tk.Label(frame, text="Ciphertext to Analyze:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.crypto_input = scrolledtext.ScrolledText(frame, height=4, width=70)
        self.crypto_input.pack(padx=20, pady=5)
        self.crypto_input.insert(tk.END, "KHOOR ZRUOG")
        
        # Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=10)
        
        freq_btn = tk.Button(button_frame, text="Frequency Analysis", 
                            command=self.frequency_analysis, bg='#4CAF50', fg='white')
        freq_btn.pack(side=tk.LEFT, padx=5)
        
        break_caesar_btn = tk.Button(button_frame, text="Break Caesar", 
                                    command=self.break_caesar, bg='#FF9800', fg='white')
        break_caesar_btn.pack(side=tk.LEFT, padx=5)
        
        ic_btn = tk.Button(button_frame, text="Index of Coincidence", 
                          command=self.calculate_ic, bg='#9C27B0', fg='white')
        ic_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", 
                             command=self.crypto_clear, bg='#f44336', fg='white')
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Output text
        tk.Label(frame, text="Analysis Results:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.crypto_output = scrolledtext.ScrolledText(frame, height=8, width=70)
        self.crypto_output.pack(padx=20, pady=5)
    
    def create_password_tab(self):
        """Create Password Analysis tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Password Analysis")
        
        # Title
        title = tk.Label(frame, text="Password Strength Analysis", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Password input
        tk.Label(frame, text="Password to Analyze:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.password_input = tk.Entry(frame, width=50, show="*")
        self.password_input.pack(padx=20, pady=5)
        self.password_input.insert(0, "MyPassword123!")
        
        # Show/Hide password
        show_frame = tk.Frame(frame)
        show_frame.pack(pady=5)
        self.show_password = tk.BooleanVar()
        show_check = tk.Checkbutton(show_frame, text="Show Password", 
                                   variable=self.show_password, 
                                   command=self.toggle_password_visibility)
        show_check.pack()
        
        # Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=10)
        
        analyze_btn = tk.Button(button_frame, text="Analyze Password", 
                               command=self.analyze_password, bg='#4CAF50', fg='white')
        analyze_btn.pack(side=tk.LEFT, padx=5)
        
        crack_time_btn = tk.Button(button_frame, text="Estimate Crack Time", 
                                  command=self.estimate_crack_time, bg='#FF9800', fg='white')
        crack_time_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", 
                             command=self.password_clear, bg='#f44336', fg='white')
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Output text
        tk.Label(frame, text="Analysis Results:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.password_output = scrolledtext.ScrolledText(frame, height=10, width=70)
        self.password_output.pack(padx=20, pady=5)
    
    def create_rsa_tab(self):
        """Create RSA demo tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="RSA Demo")
        
        # Title
        title = tk.Label(frame, text="RSA Algorithm Demo", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Key size selection
        key_frame = tk.Frame(frame)
        key_frame.pack(pady=5)
        tk.Label(key_frame, text="Key Size:").pack(side=tk.LEFT)
        self.rsa_key_size = tk.IntVar(value=512)
        key_combo = ttk.Combobox(key_frame, textvariable=self.rsa_key_size, 
                                values=[512, 1024, 2048], state="readonly", width=10)
        key_combo.pack(side=tk.LEFT, padx=5)
        
        # Generate keys button
        gen_keys_btn = tk.Button(frame, text="Generate RSA Keys", 
                                command=self.generate_rsa_keys, bg='#4CAF50', fg='white')
        gen_keys_btn.pack(pady=5)
        
        # Input text
        tk.Label(frame, text="Message to Encrypt:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.rsa_input = tk.Entry(frame, width=50)
        self.rsa_input.pack(padx=20, pady=5)
        self.rsa_input.insert(0, "Hello RSA!")
        
        # Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=10)
        
        encrypt_btn = tk.Button(button_frame, text="Encrypt", 
                               command=self.rsa_encrypt, bg='#2196F3', fg='white')
        encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        decrypt_btn = tk.Button(button_frame, text="Decrypt", 
                               command=self.rsa_decrypt, bg='#9C27B0', fg='white')
        decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", 
                             command=self.rsa_clear, bg='#f44336', fg='white')
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Output text
        tk.Label(frame, text="RSA Output:").pack(anchor=tk.W, padx=20, pady=(10,0))
        self.rsa_output = scrolledtext.ScrolledText(frame, height=8, width=70)
        self.rsa_output.pack(padx=20, pady=5)
        
        # Store RSA instance
        self.rsa_instance = None
        self.encrypted_data = None
    
    # Caesar Cipher methods
    def caesar_encrypt(self):
        try:
            text = self.caesar_input.get(1.0, tk.END).strip()
            shift = self.caesar_shift.get()
            cipher = CaesarCipher(shift)
            result = cipher.encrypt(text)
            self.caesar_output.delete(1.0, tk.END)
            self.caesar_output.insert(tk.END, f"Encrypted (shift {shift}): {result}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def caesar_decrypt(self):
        try:
            text = self.caesar_input.get(1.0, tk.END).strip()
            shift = self.caesar_shift.get()
            cipher = CaesarCipher(shift)
            result = cipher.decrypt(text)
            self.caesar_output.delete(1.0, tk.END)
            self.caesar_output.insert(tk.END, f"Decrypted (shift {shift}): {result}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def caesar_break(self):
        try:
            text = self.caesar_input.get(1.0, tk.END).strip()
            shift, plaintext, score = CryptanalysisTools.break_caesar_cipher(text)
            self.caesar_output.delete(1.0, tk.END)
            self.caesar_output.insert(tk.END, 
                f"Broken! Detected shift: {shift}\n"
                f"Decrypted text: {plaintext}\n"
                f"Chi-squared score: {score:.2f}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def caesar_clear(self):
        self.caesar_input.delete(1.0, tk.END)
        self.caesar_output.delete(1.0, tk.END)
    
    # Vigenère Cipher methods
    def vigenere_encrypt(self):
        try:
            text = self.vigenere_input.get(1.0, tk.END).strip()
            keyword = self.vigenere_keyword.get().strip()
            if not keyword:
                messagebox.showerror("Error", "Please enter a keyword")
                return
            cipher = VigenereCipher(keyword)
            result = cipher.encrypt(text)
            self.vigenere_output.delete(1.0, tk.END)
            self.vigenere_output.insert(tk.END, f"Encrypted (keyword: {keyword}): {result}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def vigenere_decrypt(self):
        try:
            text = self.vigenere_input.get(1.0, tk.END).strip()
            keyword = self.vigenere_keyword.get().strip()
            if not keyword:
                messagebox.showerror("Error", "Please enter a keyword")
                return
            cipher = VigenereCipher(keyword)
            result = cipher.decrypt(text)
            self.vigenere_output.delete(1.0, tk.END)
            self.vigenere_output.insert(tk.END, f"Decrypted (keyword: {keyword}): {result}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def vigenere_analyze(self):
        try:
            text = self.vigenere_input.get(1.0, tk.END).strip()
            keyword = self.vigenere_keyword.get().strip()
            if not keyword:
                messagebox.showerror("Error", "Please enter a keyword")
                return
            cipher = VigenereCipher(keyword)
            freq = cipher.analyze_frequency(text)
            
            self.vigenere_output.delete(1.0, tk.END)
            self.vigenere_output.insert(tk.END, "Frequency Analysis:\n")
            
            # Sort by frequency
            sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
            for letter, percentage in sorted_freq[:10]:  # Top 10
                if percentage > 0:
                    self.vigenere_output.insert(tk.END, f"{letter}: {percentage:.2f}%\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def vigenere_clear(self):
        self.vigenere_input.delete(1.0, tk.END)
        self.vigenere_output.delete(1.0, tk.END)
    
    # Hash Functions methods
    def generate_hash(self):
        try:
            text = self.hash_input.get(1.0, tk.END).strip()
            hash_type = self.hash_type.get()
            hash_func = HashFunctions()
            
            if hash_type == "MD5":
                result = hash_func.md5_hash(text)
            elif hash_type == "SHA-1":
                result = hash_func.sha1_hash(text)
            elif hash_type == "SHA-256":
                result = hash_func.sha256_hash(text)
            elif hash_type == "SHA-512":
                result = hash_func.sha512_hash(text)
            
            self.hash_output.delete(1.0, tk.END)
            self.hash_output.insert(tk.END, f"Input: {text}\n")
            self.hash_output.insert(tk.END, f"{hash_type}: {result}\n")
            self.hash_output.insert(tk.END, f"Length: {len(result)} characters\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def compare_hashes(self):
        try:
            text = self.hash_input.get(1.0, tk.END).strip()
            hash_func = HashFunctions()
            
            md5 = hash_func.md5_hash(text)
            sha1 = hash_func.sha1_hash(text)
            sha256 = hash_func.sha256_hash(text)
            sha512 = hash_func.sha512_hash(text)
            
            self.hash_output.delete(1.0, tk.END)
            self.hash_output.insert(tk.END, f"Input: {text}\n\n")
            self.hash_output.insert(tk.END, f"MD5:     {md5}\n")
            self.hash_output.insert(tk.END, f"SHA-1:   {sha1}\n")
            self.hash_output.insert(tk.END, f"SHA-256: {sha256}\n")
            self.hash_output.insert(tk.END, f"SHA-512: {sha512}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def hash_clear(self):
        self.hash_input.delete(1.0, tk.END)
        self.hash_output.delete(1.0, tk.END)
    
    # Cryptanalysis methods
    def frequency_analysis(self):
        try:
            text = self.crypto_input.get(1.0, tk.END).strip()
            freq = CryptanalysisTools.frequency_analysis(text)
            
            self.crypto_output.delete(1.0, tk.END)
            self.crypto_output.insert(tk.END, "Frequency Analysis:\n")
            self.crypto_output.insert(tk.END, "-" * 30 + "\n")
            
            # Sort by frequency
            sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
            for letter, percentage in sorted_freq:
                if percentage > 0:
                    self.crypto_output.insert(tk.END, f"{letter}: {percentage:6.2f}%\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def break_caesar(self):
        try:
            text = self.crypto_input.get(1.0, tk.END).strip()
            shift, plaintext, score = CryptanalysisTools.break_caesar_cipher(text)
            
            self.crypto_output.delete(1.0, tk.END)
            self.crypto_output.insert(tk.END, "Caesar Cipher Cryptanalysis:\n")
            self.crypto_output.insert(tk.END, "-" * 30 + "\n")
            self.crypto_output.insert(tk.END, f"Ciphertext: {text}\n")
            self.crypto_output.insert(tk.END, f"Detected shift: {shift}\n")
            self.crypto_output.insert(tk.END, f"Decrypted text: {plaintext}\n")
            self.crypto_output.insert(tk.END, f"Chi-squared score: {score:.2f}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def calculate_ic(self):
        try:
            text = self.crypto_input.get(1.0, tk.END).strip()
            ic = CryptanalysisTools.index_of_coincidence(text)
            
            self.crypto_output.delete(1.0, tk.END)
            self.crypto_output.insert(tk.END, "Index of Coincidence Analysis:\n")
            self.crypto_output.insert(tk.END, "-" * 30 + "\n")
            self.crypto_output.insert(tk.END, f"Text: {text}\n")
            self.crypto_output.insert(tk.END, f"Index of Coincidence: {ic:.4f}\n\n")
            
            if ic > 0.06:
                self.crypto_output.insert(tk.END, "Analysis: Likely monoalphabetic cipher\n")
                self.crypto_output.insert(tk.END, "(IC ≈ 0.067 for English text)\n")
            else:
                self.crypto_output.insert(tk.END, "Analysis: Likely polyalphabetic cipher\n")
                self.crypto_output.insert(tk.END, "(IC ≈ 0.038 for random text)\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def crypto_clear(self):
        self.crypto_input.delete(1.0, tk.END)
        self.crypto_output.delete(1.0, tk.END)
    
    # Password Analysis methods
    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_input.config(show="")
        else:
            self.password_input.config(show="*")
    
    def analyze_password(self):
        try:
            password = self.password_input.get()
            analyzer = PasswordAnalyzer()
            analysis = analyzer.analyze_password_strength(password)
            
            self.password_output.delete(1.0, tk.END)
            self.password_output.insert(tk.END, "Password Strength Analysis:\n")
            self.password_output.insert(tk.END, "-" * 30 + "\n")
            self.password_output.insert(tk.END, f"Password: {'*' * len(password)}\n")
            self.password_output.insert(tk.END, f"Length: {analysis['length']} characters\n")
            self.password_output.insert(tk.END, f"Score: {analysis['score']}/100\n")
            self.password_output.insert(tk.END, f"Entropy: {analysis['entropy']:.1f} bits\n\n")
            
            self.password_output.insert(tk.END, "Character Types:\n")
            self.password_output.insert(tk.END, f"  Lowercase: {'✓' if analysis['has_lowercase'] else '✗'}\n")
            self.password_output.insert(tk.END, f"  Uppercase: {'✓' if analysis['has_uppercase'] else '✗'}\n")
            self.password_output.insert(tk.END, f"  Digits: {'✓' if analysis['has_digits'] else '✗'}\n")
            self.password_output.insert(tk.END, f"  Special: {'✓' if analysis['has_special'] else '✗'}\n")
            
            if analysis['recommendations']:
                self.password_output.insert(tk.END, "\nRecommendations:\n")
                for rec in analysis['recommendations']:
                    self.password_output.insert(tk.END, f"  • {rec}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def estimate_crack_time(self):
        try:
            password = self.password_input.get()
            analyzer = PasswordAnalyzer()
            crack_times = analyzer.estimate_crack_time(password)
            
            self.password_output.delete(1.0, tk.END)
            self.password_output.insert(tk.END, "Password Crack Time Estimation:\n")
            self.password_output.insert(tk.END, "-" * 30 + "\n")
            self.password_output.insert(tk.END, f"Password: {'*' * len(password)}\n\n")
            
            self.password_output.insert(tk.END, "Estimated crack times:\n")
            self.password_output.insert(tk.END, f"  Online (slow):     {crack_times.get('online_slow', 'N/A')}\n")
            self.password_output.insert(tk.END, f"  Online (fast):     {crack_times.get('online_fast', 'N/A')}\n")
            self.password_output.insert(tk.END, f"  Offline (CPU):     {crack_times.get('offline_slow', 'N/A')}\n")
            self.password_output.insert(tk.END, f"  Offline (GPU):     {crack_times.get('offline_fast', 'N/A')}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def password_clear(self):
        self.password_input.delete(0, tk.END)
        self.password_output.delete(1.0, tk.END)
    
    # RSA methods
    def generate_rsa_keys(self):
        try:
            from rsa_algorithm import RSA
            key_size = self.rsa_key_size.get()
            
            self.rsa_output.delete(1.0, tk.END)
            self.rsa_output.insert(tk.END, f"Generating {key_size}-bit RSA keys...\n")
            self.rsa_output.update()
            
            self.rsa_instance = RSA(key_size)
            public_key, private_key = self.rsa_instance.generate_keypair()
            
            self.rsa_output.insert(tk.END, f"✓ Keys generated successfully!\n\n")
            self.rsa_output.insert(tk.END, f"Public Key (e, n):\n")
            self.rsa_output.insert(tk.END, f"  e = {public_key[0]}\n")
            self.rsa_output.insert(tk.END, f"  n = {str(public_key[1])[:50]}...\n\n")
            self.rsa_output.insert(tk.END, f"Key size: {key_size} bits\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def rsa_encrypt(self):
        try:
            if not self.rsa_instance:
                messagebox.showerror("Error", "Please generate RSA keys first")
                return
            
            message = self.rsa_input.get()
            self.encrypted_data = self.rsa_instance.encrypt_string(message)
            
            self.rsa_output.delete(1.0, tk.END)
            self.rsa_output.insert(tk.END, f"Original message: {message}\n")
            self.rsa_output.insert(tk.END, f"Encrypted data: {self.encrypted_data[:5]}...\n")
            self.rsa_output.insert(tk.END, f"(Showing first 5 encrypted integers)\n")
            self.rsa_output.insert(tk.END, f"Total encrypted values: {len(self.encrypted_data)}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def rsa_decrypt(self):
        try:
            if not self.rsa_instance or not self.encrypted_data:
                messagebox.showerror("Error", "Please encrypt a message first")
                return
            
            decrypted = self.rsa_instance.decrypt_string(self.encrypted_data)
            
            self.rsa_output.insert(tk.END, f"\nDecrypted message: {decrypted}\n")
            self.rsa_output.insert(tk.END, f"✓ Encryption/Decryption successful!\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def rsa_clear(self):
        self.rsa_input.delete(0, tk.END)
        self.rsa_output.delete(1.0, tk.END)
        self.rsa_instance = None
        self.encrypted_data = None


def main():
    root = tk.Tk()
    app = CryptographyGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
