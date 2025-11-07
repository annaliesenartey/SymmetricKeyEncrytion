#!/usr/bin/env python3
# Visualization tool for encryption patterns - Task 1
# Demonstrates ECB mode pattern leakage vs CBC/CTR modes

from encryption_tool_task1 import EncryptionTool
from Crypto.Random import get_random_bytes
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
import os


# Convert image to byte array
def image_to_bytes(image_path):
    img = Image.open(image_path)
    return np.array(img).tobytes(), img.size, img.mode


# Convert byte array back to image
def bytes_to_image(data, size, mode, output_path):
    img_array = np.frombuffer(data, dtype=np.uint8)
    
    # Reshape based on image mode
    if mode == 'RGB':
        total_pixels = size[0] * size[1]
        expected_size = total_pixels * 3
        img_array = img_array[:expected_size]
        img_array = img_array.reshape((size[1], size[0], 3))
    elif mode == 'RGBA':
        total_pixels = size[0] * size[1]
        expected_size = total_pixels * 4
        img_array = img_array[:expected_size]
        img_array = img_array.reshape((size[1], size[0], 4))
    else:  # Grayscale
        total_pixels = size[0] * size[1]
        img_array = img_array[:total_pixels]
        img_array = img_array.reshape((size[1], size[0]))
    
    img = Image.fromarray(img_array, mode=mode)
    img.save(output_path)
    return img


# Encrypt an image and save the encrypted version
def encrypt_image(input_image, algorithm='AES', mode='ECB', output_prefix='encrypted'):
    # input_image: Path to input image
    # algorithm: 'AES' or 'DES'
    # mode: 'ECB', 'CBC', or 'CTR'
    # output_prefix: Prefix for output files
    # Read image
    img_bytes, size, mode_info = image_to_bytes(input_image)
    print(f"Image size: {size}, Mode: {mode_info}, Bytes: {len(img_bytes)}")
    
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
    ciphertext = tool.encrypt(img_bytes)
    
    # Save encrypted image
    output_file = f"{output_prefix}_{algorithm}_{mode}.bin"
    with open(output_file, 'wb') as f:
        if iv:
            f.write(iv)
        f.write(ciphertext)
    
    # Try to visualize encrypted bytes as image
    # For visualization, we'll pad or truncate to match original image size
    total_bytes_needed = size[0] * size[1] * (3 if mode_info == 'RGB' else 4 if mode_info == 'RGBA' else 1)
    
    # Take first total_bytes_needed bytes from ciphertext (excluding IV if present)
    iv_size = len(iv) if iv else 0
    encrypted_bytes = ciphertext[iv_size:iv_size+total_bytes_needed]
    
    # Pad if necessary
    if len(encrypted_bytes) < total_bytes_needed:
        encrypted_bytes = encrypted_bytes + b'\x00' * (total_bytes_needed - len(encrypted_bytes))
    
    # Create visualization image
    vis_file = f"{output_prefix}_{algorithm}_{mode}_visualization.png"
    bytes_to_image(encrypted_bytes, size, mode_info, vis_file)
    
    print(f"Encrypted image saved: {output_file}")
    print(f"Visualization saved: {vis_file}")
    print(f"Key (hex): {key.hex()}")
    if iv:
        print(f"IV (hex): {iv.hex()}")
    
    return output_file, vis_file, key, iv


# Compare encryption results across different modes for the same image
def compare_modes(image_path, algorithm='AES'):
    modes = ['ECB', 'CBC', 'CTR']
    fig, axes = plt.subplots(2, 2, figsize=(12, 12))
    
    # Original image
    img = Image.open(image_path)
    axes[0, 0].imshow(img)
    axes[0, 0].set_title('Original Image')
    axes[0, 0].axis('off')
    
    # Encrypt with each mode
    for i, mode in enumerate(modes):
        row = (i + 1) // 2
        col = (i + 1) % 2
        
        output_file, vis_file, key, iv = encrypt_image(
            image_path, algorithm=algorithm, mode=mode,
            output_prefix=f'temp_{mode.lower()}'
        )
        
        # Load and display encrypted visualization
        try:
            encrypted_img = Image.open(vis_file)
            axes[row, col].imshow(encrypted_img)
            axes[row, col].set_title(f'{algorithm} {mode} Mode')
            axes[row, col].axis('off')
        except Exception as e:
            print(f"Error displaying {mode} mode: {e}")
    
    plt.tight_layout()
    plt.savefig('encryption_mode_comparison.png', dpi=150, bbox_inches='tight')
    print("Comparison saved: encryption_mode_comparison.png")
    plt.show()


# Main function
def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python visualize_encryption_task1.py <image_path> [algorithm] [mode]")
        print("Example: python visualize_encryption_task1.py dog.jpeg AES ECB")
        print("Or: python visualize_encryption_task1.py dog.jpeg AES all  (to compare all modes)")
        sys.exit(1)
    
    image_path = sys.argv[1]
    algorithm = sys.argv[2].upper() if len(sys.argv) > 2 else 'AES'
    
    if len(sys.argv) > 3 and sys.argv[3].lower() == 'all':
        compare_modes(image_path, algorithm)
    else:
        mode = sys.argv[3].upper() if len(sys.argv) > 3 else 'ECB'
        encrypt_image(image_path, algorithm=algorithm, mode=mode)


if __name__ == "__main__":
    main()

