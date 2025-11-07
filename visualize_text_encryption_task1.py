#!/usr/bin/env python3
# Visualization tool for text encryption patterns - Task 1
# Shows hex dumps, histograms, and comparisons between different modes

from encryption_tool_task1 import EncryptionTool
from Crypto.Random import get_random_bytes
import numpy as np
import matplotlib.pyplot as plt


# Analyze patterns in ECB ciphertext using histograms (self-contained for Task 1)
def analyze_patterns(ciphertext1, ciphertext2=None):
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
    plt.savefig('text_pattern_analysis.png', dpi=150, bbox_inches='tight')
    print("Pattern analysis saved: text_pattern_analysis.png")
    plt.close()
    
    return hist1


# Visualize encrypted text with hex dump and statistics
def visualize_text_encryption(text_file, algorithm='AES', mode='ECB', output_prefix='encrypted_text'):
    # Read text file
    with open(text_file, 'r', encoding='utf-8') as f:
        plaintext = f.read()
    
    print(f"Original text file: {text_file}")
    print(f"Text length: {len(plaintext)} characters")
    print(f"Text preview: {plaintext[:100]}...")
    
    # Generate key and IV
    if algorithm == 'AES':
        key = get_random_bytes(16)
        if mode != 'ECB':
            iv = get_random_bytes(16)
        else:
            iv = None
    else:  # DES
        key = get_random_bytes(8)
        if mode != 'ECB':
            iv = get_random_bytes(8)
        else:
            iv = None
    
    # Encrypt
    tool = EncryptionTool(algorithm=algorithm, mode=mode, key=key, iv=iv)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = tool.encrypt(plaintext_bytes)
    
    # Save encrypted file
    output_file = f"{output_prefix}_{algorithm}_{mode}.bin"
    with open(output_file, 'wb') as f:
        if iv:
            f.write(iv)
        f.write(ciphertext)
    
    print(f"\nEncrypted file saved: {output_file}")
    print(f"Key (hex): {key.hex()}")
    if iv:
        print(f"IV (hex): {iv.hex()}")
    
    # Display hex dump
    print(f"\nCiphertext hex dump (first 256 bytes):")
    hex_dump(ciphertext[:256])
    
    # Create histogram
    create_text_histogram(ciphertext, f"{output_prefix}_{algorithm}_{mode}_histogram.png", f"{algorithm} {mode} Mode")
    
    # Analyze patterns
    analyze_patterns(ciphertext)
    
    return output_file, ciphertext, key, iv


# Create hex dump of bytes
def hex_dump(data, bytes_per_line=16):
    for i in range(0, len(data), bytes_per_line):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+bytes_per_line])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+bytes_per_line])
        print(f"{i:08x}  {hex_part:<48}  {ascii_part}")


# Create histogram visualization for encrypted text
def create_text_histogram(ciphertext, output_file, title):
    arr = np.frombuffer(ciphertext, dtype=np.uint8)
    hist, bins = np.histogram(arr, bins=256, range=(0, 256))
    
    plt.figure(figsize=(12, 6))
    plt.bar(bins[:-1], hist, width=1)
    plt.title(f'Byte Distribution: ')
    plt.xlabel('Byte Value')
    plt.ylabel('Frequency')
    plt.xlim(0, 256)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"Histogram saved: {output_file}")
    plt.close()


# Compare text encryption across different modes
def compare_text_modes(text_file, algorithm='AES'):
    # Read text file
    with open(text_file, 'r', encoding='utf-8') as f:
        plaintext = f.read()
    
    plaintext_bytes = plaintext.encode('utf-8')
    modes = ['ECB', 'CBC', 'CTR']
    results = {}
    
    # Use same key for comparison
    if algorithm == 'AES':
        key = get_random_bytes(16)
    else:
        key = get_random_bytes(8)
    
    print(f"Comparing encryption modes for: {text_file}")
    print(f"Using same key: {key.hex()[:32]}...")
    print(f"\nOriginal text preview: {plaintext[:100]}...")
    
    # Encrypt with each mode
    for mode in modes:
        print(f"\n{mode} Mode:")
        if mode == 'ECB':
            iv = None
        else:
            if algorithm == 'AES':
                iv = get_random_bytes(16)
            else:
                iv = get_random_bytes(8)
        
        tool = EncryptionTool(algorithm=algorithm, mode=mode, key=key, iv=iv)
        ciphertext = tool.encrypt(plaintext_bytes)
        results[mode] = ciphertext
        
        print(f"  Ciphertext length: {len(ciphertext)} bytes")
        print(f"  Ciphertext (hex, first 64 chars): {ciphertext.hex()[:64]}...")
        if iv:
            print(f"  IV (hex): {iv.hex()}")
        
        # Create histogram for each mode
        create_text_histogram(ciphertext, f'text_histogram_{algorithm}_{mode}.png', f'{algorithm} {mode}')
    
    # Compare patterns
    print(f"\nComparing ECB vs CBC patterns...")
    analyze_patterns(results['ECB'], results['CBC'])
    
    # Check for identical blocks in ECB (demonstrating weakness)
    block_size = 16
    ecb_blocks = [results['ECB'][i:i+block_size] for i in range(0, len(results['ECB']), block_size)]
    unique_blocks = len(set(ecb_blocks))
    total_blocks = len(ecb_blocks)
    print(f"\nECB Mode Block Analysis:")
    print(f"  Total blocks: {total_blocks}")
    print(f"  Unique blocks: {unique_blocks}")
    print(f"  Repeated blocks: {total_blocks - unique_blocks}")
    if total_blocks > unique_blocks:
        print(f"  Warning: ECB mode has repeating blocks (pattern leakage!)")
    
    return results


# Show side-by-side comparison of encrypted text
def show_text_comparison(text_file, algorithm='AES'):
    results = compare_text_modes(text_file, algorithm)
    
    # Create comparison figure with hex dumps
    fig, axes = plt.subplots(3, 1, figsize=(14, 10))
    
    modes = ['ECB', 'CBC', 'CTR']
    for idx, mode in enumerate(modes):
        ciphertext = results[mode]
        arr = np.frombuffer(ciphertext[:256], dtype=np.uint8)  # First 256 bytes
        
        axes[idx].bar(range(len(arr)), arr, width=0.8)
        axes[idx].set_title(f'{algorithm} {mode} Mode - First 256 Bytes', fontsize=9, pad=15)
        axes[idx].set_xlabel('Byte Position', fontsize=5)
        axes[idx].set_ylabel('Byte Value', fontsize=5,loc='top')
        axes[idx].grid(True, alpha=0.3)
    
    plt.tight_layout(pad=2.0)
    plt.savefig('text_encryption_comparison.png', dpi=150, bbox_inches='tight')
    print(f"\nComparison chart saved: text_encryption_comparison.png")
    plt.show()


# Main function
def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python visualize_text_encryption_task1.py <text_file> [algorithm] [mode]")
        print("Example: python visualize_text_encryption_task1.py plaintext.txt AES ECB")
        print("Or: python visualize_text_encryption_task1.py plaintext.txt AES all  (to compare all modes)")
        sys.exit(1)
    
    text_file = sys.argv[1]
    algorithm = sys.argv[2].upper() if len(sys.argv) > 2 else 'AES'
    
    if len(sys.argv) > 3 and sys.argv[3].lower() == 'all':
        show_text_comparison(text_file, algorithm)
    else:
        mode = sys.argv[3].upper() if len(sys.argv) > 3 else 'ECB'
        visualize_text_encryption(text_file, algorithm=algorithm, mode=mode)


if __name__ == "__main__":
    main()

