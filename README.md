# StegoTool AES – Steganography with AES Encryption (GUI)

StegoTool AES is a Python-based desktop application that lets you **securely encrypt text with AES** and **hide it in PNG images using steganography**. The hidden message can later be **extracted and decrypted**, all via a simple graphical interface built with Tkinter.

---

## Features

- Select and preview PNG images
- Enter a text message and encrypt it using AES (CBC mode)
- Hide encrypted text inside an image using LSB (Least Significant Bit) steganography
- Extract and decrypt the hidden message from the image
- Toggle password visibility
- Clean, tabbed user interface

---

## Technologies Used

- **Python 3**
- **Tkinter** – GUI
- **Pillow** – Image processing
- **cryptography** – AES encryption/decryption (CBC with PKCS7 padding)
- **base64** – Binary encoding

---

### Prerequisites

Install required packages using pip:

```bash
pip install pillow cryptography
