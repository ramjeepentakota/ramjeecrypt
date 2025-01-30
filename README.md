**RAMJEECRYPT User Guide**

## Introduction
RAMJEECRYPT is a tool designed to detect encryption algorithms and salted combinations in data. It uses statistical analysis, machine learning, and heuristic rules to identify encryption and salting patterns.

## How to Use

### Step 1: Install Dependencies
Make sure you have Python 3.8 or higher installed. Then, install the required dependencies:
```bash
pip install -r requirements.txt

python ramjeecrypt.py

**1. Detect Encryption**

Copy
Options:
1. Detect Encryption
2. Encrypt Data
3. Decrypt Data
4. Exit
Select an option (1/2/3/4): 1

Enter data to analyze: $2b$12$3e7U9z8Zq1Q2w3e4r5t6y7u8i9o0p1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p

Detected encryption/hash algorithm: bcrypt

**2 Encrypt Data**
Copy
Options:
1. Detect Encryption
2. Encrypt Data
3. Decrypt Data
4. Exit
Select an option (1/2/3/4): 2

Enter data to encrypt: Hello, World!
Encrypted data: !dlroW ,olleH

**3. Decrypt Data**
Copy
Options:
1. Detect Encryption
2. Encrypt Data
3. Decrypt Data
4. Exit
Select an option (1/2/3/4): 3

Enter data to decrypt: !dlroW ,olleH
Decrypted data: Hello, World!

**4. Exit**
Copy
Options:
1. Detect Encryption
2. Encrypt Data
3. Decrypt Data
4. Exit
Select an option (1/2/3/4): 4

Exiting RAMJEECRYPT. Goodbye!


