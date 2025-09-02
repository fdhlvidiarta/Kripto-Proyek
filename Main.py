import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# =======================
# Caesar Cipher
# =======================
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# =======================
# Vigenere Cipher
# =======================
def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base - shift) % 26 + shift_base)
            key_index += 1
        else:
            result += char
    return result

# =======================
# Binary File Cipher (XOR)
# =======================
def xor_cipher(data, key):
    return bytes([b ^ key for b in data])

def file_encrypt(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    result = xor_cipher(data, key)
    new_path = filepath + ".enc"
    with open(new_path, 'wb') as f:
        f.write(result)
    return new_path

def file_decrypt(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    result = xor_cipher(data, key)
    new_path = filepath.replace(".enc", ".dec")
    with open(new_path, 'wb') as f:
        f.write(result)
    return new_path

# =======================
# GUI Aplikasi
# =======================
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aplikasi Kriptografi")
        self.root.geometry("500x500")
        self.root.configure(bg="#2E2E2E")  # background gelap

        style = {"bg": "#2E2E2E", "fg": "white"}

        tk.Label(root, text="Masukkan Teks:", font=("Arial", 11, "bold"), **style).pack(pady=5)
        self.text_input = tk.Text(root, height=5, width=55, bg="#3C3C3C", fg="white", insertbackground="white")
        self.text_input.pack(pady=5)

        tk.Label(root, text="Masukkan Kunci / Shift:", font=("Arial", 11, "bold"), **style).pack(pady=5)
        self.key_entry = tk.Entry(root, width=30, bg="#3C3C3C", fg="white", insertbackground="white")
        self.key_entry.pack(pady=5)

        tk.Label(root, text="Pilih Metode:", font=("Arial", 11, "bold"), **style).pack(pady=5)
        self.method_combo = ttk.Combobox(root, values=["Vigenere (Classic)", "Caesar (Modern)", "Binary File XOR (Modern)"])
        self.method_combo.current(0)
        self.method_combo.pack(pady=5)

        # Tombol utama
        frame = tk.Frame(root, bg="#2E2E2E")
        frame.pack(pady=10)

        self.btn_encrypt = tk.Button(frame, text="Enkripsi Teks", bg="#4CAF50", fg="white", width=15, command=self.encrypt_action)
        self.btn_encrypt.grid(row=0, column=0, padx=5)

        self.btn_decrypt = tk.Button(frame, text="Dekripsi Teks", bg="#2196F3", fg="white", width=15, command=self.decrypt_action)
        self.btn_decrypt.grid(row=0, column=1, padx=5)

        frame2 = tk.Frame(root, bg="#2E2E2E")
        frame2.pack(pady=10)

        self.btn_file_encrypt = tk.Button(frame2, text="Enkripsi File", bg="#FF9800", fg="white", width=15, command=self.file_encrypt_action)
        self.btn_file_encrypt.grid(row=0, column=0, padx=5)

        self.btn_file_decrypt = tk.Button(frame2, text="Dekripsi File", bg="#9C27B0", fg="white", width=15, command=self.file_decrypt_action)
        self.btn_file_decrypt.grid(row=0, column=1, padx=5)

        tk.Label(root, text="Hasil:", font=("Arial", 11, "bold"), **style).pack(pady=5)
        self.result_text = tk.Text(root, height=6, width=55, bg="#3C3C3C", fg="white", insertbackground="white")
        self.result_text.pack(pady=5)

    def encrypt_action(self):
        text = self.text_input.get("1.0", tk.END).strip()
        key = self.key_entry.get()
        method = self.method_combo.get()
        if method.startswith("Caesar"):
            try:
                result = caesar_encrypt(text, int(key))
            except:
                messagebox.showerror("Error", "Shift harus berupa angka!")
                return
        elif method.startswith("Vigenere"):
            if not key:
                messagebox.showerror("Error", "Masukkan kunci!")
                return
            result = vigenere_encrypt(text, key)
        else:
            messagebox.showwarning("Warning", "Gunakan tombol File untuk metode ini!")
            return
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)

    def decrypt_action(self):
        text = self.text_input.get("1.0", tk.END).strip()
        key = self.key_entry.get()
        method = self.method_combo.get()
        if method.startswith("Caesar"):
            try:
                result = caesar_decrypt(text, int(key))
            except:
                messagebox.showerror("Error", "Shift harus berupa angka!")
                return
        elif method.startswith("Vigenere"):
            if not key:
                messagebox.showerror("Error", "Masukkan kunci!")
                return
            result = vigenere_decrypt(text, key)
        else:
            messagebox.showwarning("Warning", "Gunakan tombol File untuk metode ini!")
            return
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)

    def file_encrypt_action(self):
        method = self.method_combo.get()
        if not method.startswith("Binary"):
            messagebox.showwarning("Warning", "Metode ini hanya untuk Binary File XOR!")
            return
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        try:
            key = int(self.key_entry.get()) % 256
            new_path = file_encrypt(filepath, key)
            messagebox.showinfo("Sukses", f"File terenkripsi: {new_path}")
        except:
            messagebox.showerror("Error", "Masukkan kunci angka 0-255!")

    def file_decrypt_action(self):
        method = self.method_combo.get()
        if not method.startswith("Binary"):
            messagebox.showwarning("Warning", "Metode ini hanya untuk Binary File XOR!")
            return
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if not filepath:
            return
        try:
            key = int(self.key_entry.get()) % 256
            new_path = file_decrypt(filepath, key)
            messagebox.showinfo("Sukses", f"File terdekripsi: {new_path}")
        except:
            messagebox.showerror("Error", "Masukkan kunci angka 0-255!")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
