# Project: Secure Communication with RSA and AES

This project implements a secure communication system using RSA and AES encryption algorithms. The modularized code includes key generation, encryption, decryption, and signature verification functionalities.

---

## Features
- **AES Encryption/Decryption**: Implements AES for fast and secure encryption of messages.
- **RSA Encryption/Decryption**: RSA ensures secure exchange of AES keys and signatures.
- **Key Management**: Random key generation for AES and RSA.
- **OAEP Padding**: Optimal Asymmetric Encryption Padding (OAEP) for RSA.

## Prerequisites
- Python 3.6 or later
- Required modules (install via `pip install`):
  - hashlib
  - random
  - base64

## Repository Link
GitHub: [Secure Communication Project](https://github.com/ViniciusGN/Cryptography-Cybersec)

## Getting Started

### Running the Python Code
1. Clone the repository: <br>
  ```
   git clone https://github.com/ViniciusGN/Cryptography-Cybersec
   cd Cryptography-Cybersec
   ```
2. Execute the `main.py` file: <br>
```python main.py``` <br>
This will automatically import all required modules (rsa, aes, etc.)
 
3. Follow the menu prompts to: <br>
Perform encryption and decryption using AES, generate RSA keys and encrypt/decrypt messages securely.

### Running the Python Code
1. Navigate to the dist directory: <br>
`cd dist/main`

2. Run the executable: <br>
`./main.exe`

## Modular Structure
The codebase is organized as follows:

- `aes_encrypt.py`: Handles AES encryption logic.
- `aes_decrypt.py`: Implements AES decryption functions.
- `key_generator.py`: Provides key generation functionalities.
- `rsa.py`: Contains RSA encryption, decryption, and signature logic.
- `operations.py`: Utility functions for XOR operations, padding, and transformations.
- `oaep_teste.py`: Implements OAEP encoding and decoding for RSA.

---

## Contact

For questions or issues, contact:

- Vinicius Nascimento: 170115437@aluno.unb.br
- Adriano Wiedmann: 202014824@aluno.unb.br