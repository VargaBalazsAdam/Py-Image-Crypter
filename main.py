from PIL import Image
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import tkinter as tk
from tkinter import ttk, filedialog
import os

def generate_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b"salt_123",  # You may want to change the salt
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_text(text, key):
    text_bytes = bytes(text)

    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text_bytes)

    return encrypted_text

def encrypt_image(image_path, password):
    try:
        img = Image.open(image_path)
    except Exception as e:
        return f"Error: {e}. Please select a valid image file."

    img_width, img_height = img.size

    pixels = list(img.getdata())
    ascii_chars = "".join([f"{value[0]:03}{value[1]:03}{value[2]:03}" for value in pixels])

    key = generate_key(password)
    cipher_text = encrypt_text(ascii_chars.encode(), key)

    filename, _ = os.path.splitext(os.path.basename(image_path))
    save_path = f"{filename}.en"
    with open(save_path, "wb") as file:
        file.write(img_width.to_bytes(4, byteorder='big'))
        file.write(img_height.to_bytes(4, byteorder='big'))
        file.write(cipher_text)

    return save_path

def decrypt_text(encrypted_text, key):
    cipher = Fernet(key)
    decrypted_text_bytes = cipher.decrypt(encrypted_text)
    
    return decrypted_text_bytes

def decrypt_image(encrypted_file, password):
    try:
        with open(encrypted_file, "rb") as file:
            img_width = int.from_bytes(file.read(4), byteorder='big')
            img_height = int.from_bytes(file.read(4), byteorder='big')
            cipher_text = file.read()
    except Exception as e:
        return f"Error: {e}. Please select a valid encrypted file."

    key = generate_key(password)
    try:
        decrypted_text_bytes = decrypt_text(cipher_text, key)
    except Exception as e:
        return f"Error: Incorrect password. {e}"

    decrypted_text = decrypted_text_bytes.decode()

    padding = 9 - len(decrypted_text) % 9
    decrypted_text = decrypted_text + '0' * padding

    pixels = [(int(decrypted_text[i:i+3]), int(decrypted_text[i+3:i+6]), int(decrypted_text[i+6:i+9])) for i in range(0, len(decrypted_text), 9)]

    img = Image.new("RGB", (img_width, img_height))

    num_pixels = img_width * img_height
    pixels = pixels[:num_pixels]

    img.putdata(pixels)

    filename, _ = os.path.splitext(os.path.basename(encrypted_file))
    save_path = f"{filename}.png"
    img.save(save_path)

    return save_path

def execute_encrypt():
    password = entry_password.get()

    if password:
        file_path = filedialog.askopenfilename()
        if file_path:
            result = encrypt_image(file_path, password)
            if result.startswith("Error"):
                lbl_result.config(text=result, fg="red")
            else:
                lbl_result.config(text=f"Encryption successful. File saved at: {result}", fg="green")
        else:
            lbl_result.config(text="Please select a file.", fg="red")
    else:
        lbl_result.config(text="Please enter the password.", fg="red")

def execute_decrypt():
    password = entry_password.get()

    if password:
        file_path = filedialog.askopenfilename()
        if file_path:
            result = decrypt_image(file_path, password)
            if result.startswith("Error"):
                lbl_result.config(text=result, fg="red")
            else:
                lbl_result.config(text=f"Decryption successful. Image saved at: {result}", fg="green")
        else:
            lbl_result.config(text="Please select a file.", fg="red")
    else:
        lbl_result.config(text="Please enter the password.", fg="red")

app = tk.Tk()
app.title("Image Encryption/Decryption")

style = ttk.Style()
style.configure('TButton', padding=(10, 5), font='Helvetica 10')

lbl_password = tk.Label(app, text="Password:")
entry_password = tk.Entry(app, show="*")

btn_encrypt = ttk.Button(app, text="Encrypt", command=execute_encrypt)
btn_decrypt = ttk.Button(app, text="Decrypt", command=execute_decrypt)

lbl_result = tk.Label(app, text="")

lbl_password.grid(row=0, column=0, padx=10, pady=5, sticky="e")
entry_password.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="we")

btn_encrypt.grid(row=1, column=1, pady=10)
btn_decrypt.grid(row=1, column=2, pady=10)

lbl_result.grid(row=2, column=0, columnspan=3, pady=10)

app.mainloop()
