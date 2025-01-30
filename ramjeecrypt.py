import re
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Simulated dataset for training (in real-world, use a larger dataset)
# Format: [feature1, feature2, ..., label]
# Features: entropy, block_size, byte_frequency_std, is_base64, is_hex, has_salt
# Labels: 0 = Unencrypted, 1 = AES, 2 = DES, 3 = RSA, 4 = bcrypt, 5 = PBKDF2, 6 = SHA-256, 7 = Argon2
dataset = [
    [7.5, 16, 0.1, 0, 0, 0, 1],  # AES
    [6.8, 8, 0.2, 0, 0, 0, 2],   # DES
    [7.9, 256, 0.3, 1, 0, 0, 3], # RSA (Base64 encoded)
    [7.2, 64, 0.15, 0, 1, 0, 4], # ChaCha20 (hex encoded)
    [5.5, 0, 0.4, 0, 0, 1, 5],   # bcrypt (salted hash)
    [5.8, 0, 0.35, 0, 0, 1, 6],  # PBKDF2 (salted hash)
    [6.5, 0, 0.3, 0, 0, 0, 7],   # SHA-256
    [6.7, 0, 0.25, 0, 0, 1, 8],  # Argon2 (salted hash)
    [2.0, 0, 0.5, 0, 0, 0, 0],   # Unencrypted
]

# Split dataset into features and labels
X = [row[:-1] for row in dataset]
y = [row[-1] for row in dataset]

# Train a Random Forest classifier
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

# Function to calculate entropy of data
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    counter = {}
    for byte in data:
        counter[byte] = counter.get(byte, 0) + 1
    for count in counter.values():
        p = count / len(data)
        entropy -= p * np.log2(p)
    return entropy

# Function to detect salting
def detect_salt(data):
    """
    Detects potential salting by checking for random-looking data prepended or appended.
    """
    if len(data) < 16:  # Salt is typically at least 8-16 bytes
        return False
    # Check for high entropy in the first 16 bytes (potential salt)
    salt_candidate = data[:16]
    entropy = calculate_entropy(salt_candidate)
    return entropy > 6.0  # High entropy suggests randomness (salt)

# Function to extract features from data
def extract_features(data):
    features = []
    
    # Feature 1: Entropy
    entropy = calculate_entropy(data)
    features.append(entropy)
    
    # Feature 2: Block size (assume data is padded)
    block_size = len(data) % 16 if len(data) >= 16 else 0
    features.append(block_size)
    
    # Feature 3: Byte frequency standard deviation
    byte_freq = np.bincount(np.frombuffer(data, dtype=np.uint8))
    byte_freq_std = np.std(byte_freq)
    features.append(byte_freq_std)
    
    # Feature 4: Is Base64 encoded
    is_base64 = bool(re.match(r"^[A-Za-z0-9+/]+={0,2}$", data.decode("utf-8", errors="ignore")))
    features.append(int(is_base64))
    
    # Feature 5: Is hex encoded
    is_hex = bool(re.match(r"^[0-9A-Fa-f]+$", data.decode("utf-8", errors="ignore")))
    features.append(int(is_hex))
    
    # Feature 6: Has salt
    has_salt = detect_salt(data)
    features.append(int(has_salt))
    
    return features

# Function to detect encryption algorithm and salting
def detect_encryption_algorithm(data):
    features = extract_features(data)
    prediction = clf.predict([features])
    algorithms = ["Unencrypted", "AES", "DES", "RSA", "ChaCha20", "bcrypt", "PBKDF2", "SHA-256", "Argon2"]
    return algorithms[prediction[0]]

# Function to display the banner
def display_banner():
    banner = """
=============================================
   ____  __  __  ____  _____  _____  _____ 
  |  _ \|  \/  |/ __ \|  __ \|  __ \|  __ \\
  | |_) | \  / | |  | | |__) | |__) | |__) |
  |  _ <| |\/| | |  | |  ___/|  _  /|  _  / 
  | |_) | |  | | |__| | |    | | \ \| | \ \\
  |____/|_|  |_|\____/|_|    |_|  \_\_|  \_\\
=============================================
              RAMJEECRYPT v1.0
=============================================
    """
    print(banner)

# Function to encrypt data (placeholder)
def encrypt_data():
    print("\nEncrypting data... (This is a placeholder)")
    data = input("Enter data to encrypt: ")
    print(f"Encrypted data: {data[::-1]}")  # Placeholder encryption (reverse string)

# Function to decrypt data (placeholder)
def decrypt_data():
    print("\nDecrypting data... (This is a placeholder)")
    data = input("Enter data to decrypt: ")
    print(f"Decrypted data: {data[::-1]}")  # Placeholder decryption (reverse string)

# Main function
def main():
    display_banner()
    while True:
        print("\nOptions:")
        print("1. Detect Encryption")
        print("2. Encrypt Data")
        print("3. Decrypt Data")
        print("4. Exit")
        choice = input("Select an option (1/2/3/4): ")

        if choice == "1":
            data = input("\nEnter data to analyze: ").encode()
            result = detect_encryption_algorithm(data)
            print(f"\nDetected encryption/hash algorithm: {result}")
        elif choice == "2":
            encrypt_data()
        elif choice == "3":
            decrypt_data()
        elif choice == "4":
            print("\nExiting RAMJEECRYPT. Goodbye!")
            break
        else:
            print("\nInvalid choice. Please try again.")

if __name__ == "__main__":
    main()
