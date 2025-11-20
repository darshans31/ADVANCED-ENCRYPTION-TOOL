import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tkinter import Tk, Button, Entry, Label, filedialog, messagebox

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,  # 256-bit key
        n=2**14,
        r=8,
        p=1
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_file(key: bytes, in_filename: str, out_filename: str):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Recommended size 12 bytes for GCM
    with open(in_filename, 'rb') as f:
        data = f.read()
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    with open(out_filename, 'wb') as f:
        f.write(nonce + encrypted_data)

def decrypt_file(key: bytes, in_filename: str, out_filename: str):
    aesgcm = AESGCM(key)
    with open(in_filename, 'rb') as f:
        nonce = f.read(12)
        encrypted_data = f.read()
    try:
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    except Exception:
        raise ValueError("Decryption failed. Possibly wrong password or corrupted file.")
    with open(out_filename, 'wb') as f:
        f.write(decrypted_data)

def browse_file(entry):
    filename = filedialog.askopenfilename()
    if filename:
        entry.delete(0, 'end')
        entry.insert(0, filename)

def encrypt_action(input_entry, output_entry, password_entry):
    in_file = input_entry.get()
    out_file = output_entry.get()
    password = password_entry.get()
    if not (in_file and out_file and password):
        messagebox.showerror("Error", "Please provide input file, output file, and password.")
        return
    salt = b'secure_salt_12345'  # For demo, use a fixed salt; for production, randomly generate and store per file
    key = derive_key(password, salt)
    try:
        encrypt_file(key, in_file, out_file)
        messagebox.showinfo("Success", "File encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_action(input_entry, output_entry, password_entry):
    in_file = input_entry.get()
    out_file = output_entry.get()
    password = password_entry.get()
    if not (in_file and out_file and password):
        messagebox.showerror("Error", "Please provide input file, output file, and password.")
        return
    salt = b'secure_salt_12345'
    key = derive_key(password, salt)
    try:
        decrypt_file(key, in_file, out_file)
        messagebox.showinfo("Success", "File decrypted successfully.")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def main_gui():
    root = Tk()
    root.title("Advanced AES-256 Encryption Tool")
    root.geometry('500x250')

    Label(root, text="Input File:").grid(row=0, column=0, padx=10, pady=10)
    input_entry = Entry(root, width=50)
    input_entry.grid(row=0, column=1)
    Button(root, text="Browse", command=lambda: browse_file(input_entry)).grid(row=0, column=2)

    Label(root, text="Output File:").grid(row=1, column=0, padx=10, pady=10)
    output_entry = Entry(root, width=50)
    output_entry.grid(row=1, column=1)
    Button(root, text="Browse", command=lambda: browse_file(output_entry)).grid(row=1, column=2)

    Label(root, text="Password:").grid(row=2, column=0, padx=10, pady=10)
    password_entry = Entry(root, show='*', width=50)
    password_entry.grid(row=2, column=1, columnspan=2)

    Button(root, text="Encrypt", command=lambda: encrypt_action(input_entry, output_entry, password_entry)).grid(row=3, column=1, pady=20)
    Button(root, text="Decrypt", command=lambda: decrypt_action(input_entry, output_entry, password_entry)).grid(row=3, column=2)

    root.mainloop()

# Run the tool by calling main_gui()
if __name__ == "__main__":
    main_gui()