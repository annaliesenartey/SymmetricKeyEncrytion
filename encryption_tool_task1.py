#!/usr/bin/env python3
# Symmetric Key Encryption Tool - Task 1
# Supports AES and DES with multiple modes: ECB, CBC, CTR

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import sys


class EncryptionTool:
    # Main encryption tool class supporting AES and DES with multiple modes
    
    def __init__(self, algorithm='AES', mode='CBC', key=None, iv=None):
        # Initialize encryption tool
        # algorithm: 'AES' or 'DES'
        # mode: 'ECB', 'CBC', or 'CTR'
        # key: Encryption key (bytes). If None, generates a random key
        # iv: Initialization Vector (bytes). If None, generates a random IV
        self.algorithm = algorithm.upper()
        self.mode = mode.upper()
        
        # Set key sizes
        if self.algorithm == 'AES':
            self.key_size = 16  # 128 bits
        elif self.algorithm == 'DES':
            self.key_size = 8   # 64 bits
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Generate or use provided key
        if key is None:
            self.key = get_random_bytes(self.key_size)
        else:
            if len(key) != self.key_size:
                raise ValueError(f"Key must be {self.key_size} bytes for {self.algorithm}")
            self.key = key
        
        # Generate or use provided IV (not needed for ECB)
        if self.mode == 'ECB':
            self.iv = None
        else:
            if iv is None:
                if self.algorithm == 'AES':
                    self.iv = get_random_bytes(16)
                else:  # DES
                    self.iv = get_random_bytes(8)
            else:
                self.iv = iv
    
    def encrypt(self, plaintext):
        # Encrypt plaintext
        # plaintext: bytes to encrypt
        # Returns: ciphertext: bytes
        if self.algorithm == 'AES':
            if self.mode == 'ECB':
                cipher = AES.new(self.key, AES.MODE_ECB)
                padded_plaintext = pad(plaintext, AES.block_size)
            elif self.mode == 'CBC':
                cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
                padded_plaintext = pad(plaintext, AES.block_size)
            elif self.mode == 'CTR':
                cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.iv[:8])
                padded_plaintext = plaintext  # CTR doesn't need padding
            else:
                raise ValueError(f"Unsupported mode: {self.mode}")
                
        elif self.algorithm == 'DES':
            if self.mode == 'ECB':
                cipher = DES.new(self.key, DES.MODE_ECB)
                padded_plaintext = pad(plaintext, DES.block_size)
            elif self.mode == 'CBC':
                cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
                padded_plaintext = pad(plaintext, DES.block_size)
            elif self.mode == 'CTR':
                # DES CTR mode requires nonce
                cipher = DES.new(self.key, DES.MODE_CTR, nonce=self.iv[:4])
                padded_plaintext = plaintext
            else:
                raise ValueError(f"Unsupported mode: {self.mode}")
        
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext
    
    def decrypt(self, ciphertext):
        # Decrypt ciphertext
        # ciphertext: bytes to decrypt
        # Returns: plaintext: bytes
        if self.algorithm == 'AES':
            if self.mode == 'ECB':
                cipher = AES.new(self.key, AES.MODE_ECB)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, AES.block_size)
            elif self.mode == 'CBC':
                cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, AES.block_size)
            elif self.mode == 'CTR':
                cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.iv[:8])
                plaintext = cipher.decrypt(ciphertext)
            else:
                raise ValueError(f"Unsupported mode: {self.mode}")
                
        elif self.algorithm == 'DES':
            if self.mode == 'ECB':
                cipher = DES.new(self.key, DES.MODE_ECB)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, DES.block_size)
            elif self.mode == 'CBC':
                cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, DES.block_size)
            elif self.mode == 'CTR':
                cipher = DES.new(self.key, DES.MODE_CTR, nonce=self.iv[:4])
                plaintext = cipher.decrypt(ciphertext)
            else:
                raise ValueError(f"Unsupported mode: {self.mode}")
        
        return plaintext
    
    def encrypt_file(self, input_file, output_file):
        # Encrypt a file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = self.encrypt(plaintext)
        
        with open(output_file, 'wb') as f:
            if self.iv is not None:
                f.write(self.iv)
            f.write(ciphertext)
        
        return ciphertext
    
    def decrypt_file(self, input_file, output_file):
        # Decrypt a file
        with open(input_file, 'rb') as f:
            data = f.read()
        
        if self.iv is not None:
            iv_size = len(self.iv)
            self.iv = data[:iv_size]
            ciphertext = data[iv_size:]
        else:
            ciphertext = data
        
        plaintext = self.decrypt(ciphertext)
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        return plaintext
    
    def get_key(self):
        # Get the encryption key
        return self.key
    
    def get_iv(self):
        # Get the IV
        return self.iv


def main():
    # Command-line interface for the encryption tool
    if len(sys.argv) < 5:
        print("Usage: python encryption_tool_task1.py <encrypt|decrypt> <algorithm> <mode> <input_file> <output_file> [key_file] [iv_file]")
        print("Example: python encryption_tool_task1.py encrypt AES CBC plaintext.txt encrypted.bin")
        sys.exit(1)
    
    operation = sys.argv[1].lower()
    algorithm = sys.argv[2].upper()
    mode = sys.argv[3].upper()
    input_file = sys.argv[4]
    output_file = sys.argv[5]
    
    # Load key and IV if provided
    key = None
    iv = None
    
    if len(sys.argv) > 6:
        with open(sys.argv[6], 'rb') as f:
            key = f.read()
    
    if len(sys.argv) > 7:
        with open(sys.argv[7], 'rb') as f:
            iv = f.read()
    
    # Create encryption tool
    tool = EncryptionTool(algorithm=algorithm, mode=mode, key=key, iv=iv)
    
    if operation == 'encrypt':
        tool.encrypt_file(input_file, output_file)
        print(f"Encrypted {input_file} -> {output_file}")
        print(f"Algorithm: {algorithm}, Mode: {mode}")
        print(f"Key (hex): {tool.get_key().hex()}")
        if tool.get_iv():
            print(f"IV (hex): {tool.get_iv().hex()}")
    elif operation == 'decrypt':
        tool.decrypt_file(input_file, output_file)
        print(f"Decrypted {input_file} -> {output_file}")
    else:
        print(f"Unknown operation: {operation}")
        sys.exit(1)


if __name__ == "__main__":
    main()

