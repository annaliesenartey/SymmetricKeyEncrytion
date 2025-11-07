# 
# Code Organization by Task

## Overview

The code has been organized and labeled according to tasks. All essential Task 1 code uses `_task1` suffix, and Task 2 code uses `_task2` suffix.

## Task 1: Design & Implementation

### Files (Essential for Task 1):

1. **encryption_tool_task1.py**

   - Core encryption/decryption functionality
   - Supports AES and DES
   - Supports ECB, CBC, CTR modes
   - File encryption/decryption

2. **visualize_encryption_task1.py**

   - Image encryption visualization
   - Compares encryption modes
   - Uses `dog.jpeg` as test image
   - Generates visualization images

3. **visualize_text_encryption_task1.py**
   - Text encryption visualization
   - Hex dumps
   - Histograms
   - Mode comparisons

### Usage Examples:

```bash
# Encrypt a file
python encryption_tool_task1.py encrypt AES CBC plaintext.txt encrypted.bin

# Visualize image encryption
python visualize_encryption_task1.py dog.jpeg AES all

# Visualize text encryption
python visualize_text_encryption_task1.py plaintext.txt AES all
```

## Task 2: Analysis & Attack

### Files (Essential for Task 2):

1. **attack_analysis_task2.py**
   - Key reuse vulnerability demonstration
   - ECB pattern attack
   - Structured data analysis
   - Pattern analysis tools

### Usage Examples:

```bash
# Key reuse attack
python attack_analysis_task2.py key_reuse

# Image pattern attack
python attack_analysis_task2.py image_attack dog.jpeg

# Analyze CSV
python attack_analysis_task2.py analyze_csv studentdata.csv
```

## Image File

- **tux.png** - Test image used provided in the assignmentfor encryption visualization
- **dog.jpeg** - Random Test image used for encryption visualization (replaces tux.png)

## File Dependencies

- Task 1 files are independent and can run standalone
- Task 2 depends on `encryption_tool_task1.py` (imports EncryptionTool class)

## Quick Reference

| Task   | File                               | Purpose             |
| ------ | ---------------------------------- | ------------------- |
| Task 1 | encryption_tool_task1.py           | Core encryption     |
| Task 1 | visualize_encryption_task1.py      | Image visualization |
| Task 1 | visualize_text_encryption_task1.py | Text visualization  |
| Task 2 | attack_analysis_task2.py           | Attack analysis     |
