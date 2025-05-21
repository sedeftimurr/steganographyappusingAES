import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

class StegoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganografi ve AES Şifreleme Programı")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f0f0")
        self.root.resizable(True, True)
        
        self.tab_control = ttk.Notebook(root)
        self.encode_tab = ttk.Frame(self.tab_control)
        self.decode_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.encode_tab, text="Metin Şifrele ve Gizle")
        self.tab_control.add(self.decode_tab, text="Metni Çıkar ve Şifreyi Çöz")
        self.tab_control.pack(expand=1, fill="both")
        
        self.setup_encode_tab()
        self.setup_decode_tab()
        
        self.image_path = None
        self.stego_image_path = None
        
    def generate_key(self, password):
        return password.ljust(32)[:32].encode()
    
    def generate_iv(self):
        return secrets.token_bytes(16)
    
    def encrypt_aes(self, plaintext, password):
        key = self.generate_key(password)
        iv = self.generate_iv()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()
    
    def decrypt_aes(self, encrypted_text, password):
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            key = self.generate_key(password)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext.decode()
        except Exception as e:
            raise Exception(f"Şifre çözme hatası: {str(e)}")
    
    def setup_encode_tab(self):
        main_frame = ttk.Frame(self.encode_tab, padding=10)
        main_frame.pack(fill="both", expand=True)
        left_frame = ttk.LabelFrame(main_frame, text="Resim Seçimi", padding=10)
        left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self.encode_preview = ttk.Label(left_frame, text="Resim burada görüntülenecek")
        self.encode_preview.pack(fill="both", expand=True, padx=5, pady=5)
        self.select_image_btn = ttk.Button(left_frame, text="Resim Seç", command=self.select_image)
        self.select_image_btn.pack(fill="x", padx=5, pady=5)
        right_frame = ttk.LabelFrame(main_frame, text="Gizlenecek Metin ve Şifreleme", padding=10)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        ttk.Label(right_frame, text="Gizlenecek Metni Girin:").pack(anchor="w", padx=5, pady=2)
        self.secret_text = tk.Text(right_frame, height=10, width=40)
        self.secret_text.pack(fill="both", expand=True, padx=5, pady=5)
        password_frame = ttk.Frame(right_frame)
        password_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(password_frame, text="AES Şifre:").pack(side="left", padx=5)
        self.encode_password = ttk.Entry(password_frame, show="*")
        self.encode_password.pack(side="left", fill="x", expand=True, padx=5)
        self.show_encode_password_var = tk.BooleanVar()
        self.show_encode_password_var.trace("w", self.toggle_encode_password_visibility)
        ttk.Checkbutton(password_frame, text="Göster", variable=self.show_encode_password_var).pack(side="right", padx=5)
        self.encode_btn = ttk.Button(right_frame, text="Şifrele ve Gizle", command=self.encode_message)
        self.encode_btn.pack(fill="x", padx=5, pady=5)
        self.encode_status = ttk.Label(right_frame, text="")
        self.encode_status.pack(fill="x", padx=5, pady=5)
    
    def setup_decode_tab(self):
        main_frame = ttk.Frame(self.decode_tab, padding=10)
        main_frame.pack(fill="both", expand=True)
        left_frame = ttk.LabelFrame(main_frame, text="Şifreli Resim Seçimi", padding=10)
        left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self.decode_preview = ttk.Label(left_frame, text="Şifreli resim burada görüntülenecek")
        self.decode_preview.pack(fill="both", expand=True, padx=5, pady=5)
        self.select_stego_btn = ttk.Button(left_frame, text="Şifreli Resim Seç", command=self.select_stego_image)
        self.select_stego_btn.pack(fill="x", padx=5, pady=5)
        right_frame = ttk.LabelFrame(main_frame, text="Gizli Mesaj ve Şifre Çözme", padding=10)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        password_frame = ttk.Frame(right_frame)
        password_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(password_frame, text="AES Şifre:").pack(side="left", padx=5)
        self.decode_password = ttk.Entry(password_frame, show="*")
        self.decode_password.pack(side="left", fill="x", expand=True, padx=5)
        self.show_decode_password_var = tk.BooleanVar()
        self.show_decode_password_var.trace("w", self.toggle_decode_password_visibility)
        ttk.Checkbutton(password_frame, text="Göster", variable=self.show_decode_password_var).pack(side="right", padx=5)
        self.decode_btn = ttk.Button(right_frame, text="Mesajı Çıkar ve Şifreyi Çöz", command=self.decode_message)
        self.decode_btn.pack(fill="x", padx=5, pady=5)
        ttk.Label(right_frame, text="Çıkarılan ve Şifresi Çözülen Mesaj:").pack(anchor="w", padx=5, pady=2)
        self.decoded_text = tk.Text(right_frame, height=10, width=40)
        self.decoded_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.decode_status = ttk.Label(right_frame, text="")
        self.decode_status.pack(fill="x", padx=5, pady=5)
    
    def toggle_encode_password_visibility(self, *args):
        self.encode_password.config(show="" if self.show_encode_password_var.get() else "*")
    
    def toggle_decode_password_visibility(self, *args):
        self.decode_password.config(show="" if self.show_decode_password_var.get() else "*")
    
    def select_image(self):
        file_path = filedialog.askopenfilename(title="Resim Seç", filetypes=[("PNG Dosyaları", "*.png")])
        if file_path:
            self.image_path = file_path
            self.display_image(self.encode_preview, file_path)
            self.root.title(f"{os.path.basename(file_path)}")
    
    def select_stego_image(self):
        file_path = filedialog.askopenfilename(title="Şifreli Resim Seç", filetypes=[("PNG Dosyaları", "*.png")])
        if file_path:
            self.stego_image_path = file_path
            self.display_image(self.decode_preview, file_path)
    
    def display_image(self, label_widget, path):
        img = Image.open(path)
        img.thumbnail((300, 300))
        photo = ImageTk.PhotoImage(img)
        label_widget.config(image=photo)
        label_widget.image = photo
    
    def encode_message(self):
        if not self.image_path:
            messagebox.showwarning("Uyarı", "Lütfen bir resim seçin.")
            return
        text = self.secret_text.get("1.0", tk.END).strip()
        password = self.encode_password.get().strip()
        if not text or not password:
            messagebox.showwarning("Uyarı", "Lütfen metni ve şifreyi girin.")
            return
        encrypted = self.encrypt_aes(text, password)
        img = Image.open(self.image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        binary_data = ''.join(format(ord(c), '08b') for c in encrypted + chr(0))
        pixels = list(img.getdata())
        new_pixels = []
        data_index = 0
        for pixel in pixels:
            r, g, b = pixel
            if data_index < len(binary_data):
                r = (r & ~1) | int(binary_data[data_index])
                data_index += 1
            if data_index < len(binary_data):
                g = (g & ~1) | int(binary_data[data_index])
                data_index += 1
            if data_index < len(binary_data):
                b = (b & ~1) | int(binary_data[data_index])
                data_index += 1
            new_pixels.append((r, g, b))
        img.putdata(new_pixels)
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if save_path:
            img.save(save_path)
            self.encode_status.config(text="Mesaj başarıyla gizlendi.")
        else:
            self.encode_status.config(text="Kaydetme iptal edildi.")
    
    def decode_message(self):
        if not self.stego_image_path:
            messagebox.showwarning("Uyarı", "Lütfen şifreli bir resim seçin.")
            return
        password = self.decode_password.get().strip()
        if not password:
            messagebox.showwarning("Uyarı", "Lütfen şifreyi girin.")
            return
        img = Image.open(self.stego_image_path)
        binary_data = ""
        for pixel in img.getdata():
            for channel in pixel[:3]:
                binary_data += str(channel & 1)
        chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        message = ""
        for ch in chars:
            char = chr(int(ch, 2))
            if char == '\x00':
                break
            message += char
        try:
            decrypted = self.decrypt_aes(message, password)
            self.decoded_text.delete("1.0", tk.END)
            self.decoded_text.insert(tk.END, decrypted)
            self.decode_status.config(text="Mesaj başarıyla çözüldü.")
        except Exception as e:
            self.decode_status.config(text=str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = StegoTool(root)
    root.mainloop()
