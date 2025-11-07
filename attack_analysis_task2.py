#!/usr/bin/env python3
# Attack and Analysis Tools - Task 2
# Demonstrates ECB pattern leakage and key reuse vulnerabilities

from encryption_tool_task1 import EncryptionTool
from Crypto.Random import get_random_bytes
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
import csv


# Analyze patterns in ECB ciphertext using histograms
def analyze_ecb_patterns(ciphertext1, ciphertext2=None):
    # Convert to numpy array
    arr1 = np.frombuffer(ciphertext1, dtype=np.uint8)
    
    # Create histogram
    hist1, bins = np.histogram(arr1, bins=256, range=(0, 256))
    
    plt.figure(figsize=(12, 5))
    
    plt.subplot(1, 2, 1)
    plt.bar(bins[:-1], hist1, width=1)
    plt.title('Ciphertext 1 Byte Distribution')
    plt.xlabel('Byte Value')
    plt.ylabel('Frequency')
    
    if ciphertext2 is not None:
        arr2 = np.frombuffer(ciphertext2, dtype=np.uint8)
        hist2, _ = np.histogram(arr2, bins=256, range=(0, 256))
        
        plt.subplot(1, 2, 2)
        plt.bar(bins[:-1], hist2, width=1)
        plt.title('Ciphertext 2 Byte Distribution')
        plt.xlabel('Byte Value')
        plt.ylabel('Frequency')
    
    plt.tight_layout()
    plt.savefig('ecb_pattern_analysis.png', dpi=150, bbox_inches='tight')
    print("Pattern analysis saved: ecb_pattern_analysis.png")
    plt.show()
    
    return hist1


# Calculate XOR-based similarity between two byte sequences
def xor_similarity(data1, data2):
    if len(data1) != len(data2):
        min_len = min(len(data1), len(data2))
        data1 = data1[:min_len]
        data2 = data2[:min_len]
    
    xor_result = bytes(a ^ b for a, b in zip(data1, data2))
    different_bytes = sum(1 for b in xor_result if b != 0)
    total_bytes = len(xor_result)
    
    similarity = (1 - (different_bytes / total_bytes)) * 100
    return similarity


# Demonstrate key reuse vulnerability
def key_reuse_attack():
    print("Key Reuse Vulnerability Demonstration")
    
    # Same key for both encryptions
    key = get_random_bytes(16)
    print(f"Using same key: {key.hex()}")
    
    # Different IVs
    iv1 = get_random_bytes(16)
    iv2 = get_random_bytes(16)
    
    # Two different plaintexts
    plaintext1 = b"This is a secret message number one for testing encryption."
    plaintext2 = b"This is a secret message number two for testing encryption."
    
    print(f"\nPlaintext 1: {plaintext1.decode()}")
    print(f"Plaintext 2: {plaintext2.decode()}")
    
    # Encrypt with CBC mode (different IVs)
    tool1 = EncryptionTool(algorithm='AES', mode='CBC', key=key, iv=iv1)
    tool2 = EncryptionTool(algorithm='AES', mode='CBC', key=key, iv=iv2)
    
    ciphertext1 = tool1.encrypt(plaintext1)
    ciphertext2 = tool2.encrypt(plaintext2)
    
    print(f"\nCiphertext 1 (hex): {ciphertext1.hex()[:64]}...")
    print(f"Ciphertext 2 (hex): {ciphertext2.hex()[:64]}...")
    
    # Compare ciphertexts
    similarity = xor_similarity(ciphertext1, ciphertext2)
    print(f"\nXOR Similarity: {similarity:.2f}%")
    
    # Now demonstrate with ECB mode (same key, no IV)
    print("\nECB Mode with Same Key")
    
    tool_ecb1 = EncryptionTool(algorithm='AES', mode='ECB', key=key, iv=None)
    tool_ecb2 = EncryptionTool(algorithm='AES', mode='ECB', key=key, iv=None)
    
    ciphertext_ecb1 = tool_ecb1.encrypt(plaintext1)
    ciphertext_ecb2 = tool_ecb2.encrypt(plaintext2)
    
    # Check for identical blocks (ECB weakness)
    block_size = 16
    identical_blocks = 0
    total_blocks = min(len(ciphertext_ecb1), len(ciphertext_ecb2)) // block_size
    
    for i in range(total_blocks):
        start = i * block_size
        end = start + block_size
        block1 = ciphertext_ecb1[start:end]
        block2 = ciphertext_ecb2[start:end]
        if block1 == block2:
            identical_blocks += 1
    
    print(f"Identical blocks found: {identical_blocks}/{total_blocks}")
    
    similarity_ecb = xor_similarity(ciphertext_ecb1, ciphertext_ecb2)
    print(f"XOR Similarity (ECB): {similarity_ecb:.2f}%")
    
    # Analyze patterns
    analyze_ecb_patterns(ciphertext_ecb1, ciphertext_ecb2)
    
    return {
        'cbc_similarity': similarity,
        'ecb_similarity': similarity_ecb,
        'identical_blocks': identical_blocks,
        'total_blocks': total_blocks
    }


# Attack ECB mode by recovering visible structure from ciphertext images
def image_pattern_attack(image_path):
    print("ECB Mode Image Pattern Attack")
    
    # Read image
    img = Image.open(image_path)
    img_bytes = np.array(img).tobytes()
    size = img.size
    mode = img.mode
    
    print(f"Image: {image_path}")
    print(f"Size: {size}, Mode: {mode}")
    print(f"Image bytes: {len(img_bytes)}")
    
    # Encrypt with ECB mode
    key = get_random_bytes(16)
    tool_ecb = EncryptionTool(algorithm='AES', mode='ECB', key=key, iv=None)
    ciphertext_ecb = tool_ecb.encrypt(img_bytes)
    
    # Encrypt with CBC mode for comparison
    iv = get_random_bytes(16)
    tool_cbc = EncryptionTool(algorithm='AES', mode='CBC', key=key, iv=iv)
    ciphertext_cbc = tool_cbc.encrypt(img_bytes)
    
    # Visualize encrypted images
    total_bytes_needed = size[0] * size[1] * (3 if mode == 'RGB' else 4 if mode == 'RGBA' else 1)
    
    # ECB visualization
    ecb_bytes = ciphertext_ecb[:total_bytes_needed]
    if len(ecb_bytes) < total_bytes_needed:
        ecb_bytes = ecb_bytes + b'\x00' * (total_bytes_needed - len(ecb_bytes))
    
    ecb_array = np.frombuffer(ecb_bytes, dtype=np.uint8)
    if mode == 'RGB':
        ecb_array = ecb_array[:size[0]*size[1]*3].reshape((size[1], size[0], 3))
    elif mode == 'RGBA':
        ecb_array = ecb_array[:size[0]*size[1]*4].reshape((size[1], size[0], 4))
    else:
        ecb_array = ecb_array[:size[0]*size[1]].reshape((size[1], size[0]))
    
    ecb_img = Image.fromarray(ecb_array, mode=mode)
    ecb_img.save('ecb_encrypted_image.png')
    
    # CBC visualization (excluding IV)
    cbc_bytes = ciphertext_cbc[16:16+total_bytes_needed]
    if len(cbc_bytes) < total_bytes_needed:
        cbc_bytes = cbc_bytes + b'\x00' * (total_bytes_needed - len(cbc_bytes))
    
    cbc_array = np.frombuffer(cbc_bytes, dtype=np.uint8)
    if mode == 'RGB':
        cbc_array = cbc_array[:size[0]*size[1]*3].reshape((size[1], size[0], 3))
    elif mode == 'RGBA':
        cbc_array = cbc_array[:size[0]*size[1]*4].reshape((size[1], size[0], 4))
    else:
        cbc_array = cbc_array[:size[0]*size[1]].reshape((size[1], size[0]))
    
    cbc_img = Image.fromarray(cbc_array, mode=mode)
    cbc_img.save('cbc_encrypted_image.png')
    
    # Create comparison
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    axes[0].imshow(img)
    axes[0].set_title('Original Image')
    axes[0].axis('off')
    
    axes[1].imshow(ecb_img)
    axes[1].set_title('ECB Mode (Pattern Leakage!)')
    axes[1].axis('off')
    
    axes[2].imshow(cbc_img)
    axes[2].set_title('CBC Mode (Secure)')
    axes[2].axis('off')
    
    plt.tight_layout()
    plt.savefig('ecb_vs_cbc_comparison.png', dpi=150, bbox_inches='tight')
    print("\nComparison saved: ecb_vs_cbc_comparison.png")
    plt.show()
    
    # Analyze patterns
    analyze_ecb_patterns(ciphertext_ecb, ciphertext_cbc)
    
    print("\nObservation: ECB mode preserves visual patterns from the original image!")
    print("CBC mode completely obscures the image structure.")


# Analyze encryption of structured data (CSV)
def analyze_structured_data(csv_file):
    print("Structured Data Encryption Analysis")
    
    # Read CSV
    with open(csv_file, 'r') as f:
        content = f.read()
    
    print(f"CSV Content:\n{content[:200]}...")
    
    # Encrypt with different modes
    key = get_random_bytes(16)
    
    modes = ['ECB', 'CBC', 'CTR']
    results = {}
    
    for mode in modes:
        if mode == 'ECB':
            tool = EncryptionTool(algorithm='AES', mode=mode, key=key, iv=None)
        else:
            iv = get_random_bytes(16)
            tool = EncryptionTool(algorithm='AES', mode=mode, key=key, iv=iv)
        
        ciphertext = tool.encrypt(content.encode())
        results[mode] = ciphertext
        
        print(f"\n{mode} Mode:")
        print(f"  Ciphertext (hex): {ciphertext.hex()[:64]}...")
        print(f"  Length: {len(ciphertext)} bytes")
    
    # Compare patterns
    analyze_ecb_patterns(results['ECB'], results['CBC'])


# Main function
def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python attack_analysis_task2.py <command> [arguments]")
        print("Commands:")
        print("  key_reuse          - Demonstrate key reuse vulnerability")
        print("  image_attack <img> - Attack ECB mode on image")
        print("  analyze_csv <csv>  - Analyze structured data encryption")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == 'key_reuse':
        key_reuse_attack()
    elif command == 'image_attack':
        if len(sys.argv) < 3:
            print("Error: Please provide image path")
            sys.exit(1)
        image_pattern_attack(sys.argv[2])
    elif command == 'analyze_csv':
        if len(sys.argv) < 3:
            print("Error: Please provide CSV file path")
            sys.exit(1)
        analyze_structured_data(sys.argv[2])
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

