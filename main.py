from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()
iterations = 100_000


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))


def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )


def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def save_encrypt_btn():
    title = title_entry.get()
    secret = secret_text.get("1.0", END)
    master = master_entry.get()

    if title.isspace() or secret.isspace() or master.isspace():
        messagebox.showerror(title="Error", message="Please Enter All Information!")
    else:
        enc_msg = password_encrypt(secret.encode(), master)

        with open("mysecret.txt", "a") as f:
            f.write(f"{title}\n{enc_msg}\n")

        title_entry.delete(0, END)
        secret_text.delete("1.0", END)
        master_entry.delete(0, END)

        messagebox.showinfo(title="Successful!", message="Your secret message encrypted.")


def decoder_btn():
    enc_msg = secret_text.get("1.0", END)
    master = master_entry.get()

    if enc_msg.isspace() or master.isspace():
        messagebox.showerror(title="Error", message="Please Enter All Information!")
    else:
        dec_msg = password_decrypt(enc_msg, master).decode()

        secret_text.delete("1.0", END)
        master_entry.delete(0, END)
        secret_text.insert("1.0", dec_msg)

        messagebox.showinfo(title="Successful!", message="Your secret message decrypted.")


window = Tk()
window.title("Secret Notes")
window.minsize(width=300, height=600)
window.config(pady=50)

# IMAGE OPEN
image = Image.open("topsecret.png")

# IMAGE RESIZE
resized_image = image.resize((100, 75), Image.LANCZOS)

# NEW RESIZED IMAGE
new_image = ImageTk.PhotoImage(resized_image)

# IMAGE LAYER
image_label = Label(image=new_image)
image_label.pack()

# TITLE LABEL
title_label = Label(text="Enter your title")
title_label.pack()

# TITLE ENTRY
title_entry = Entry()
title_entry.pack()

# SECRET LABEL
secret_label = Label(text="Enter your secret")
secret_label.pack()

# SECRET TEXT
secret_text = Text(width=30, height=20)
secret_text.pack()

# MASTER KEY LABEL
master_label = Label(text="Enter your master key")
master_label.pack()

# MASTER KEY ENTRY
master_entry = Entry()
master_entry.pack()

# SAVE & ENCRYPT BUTTON
sv_encrypt = Button(text="Save & Encrypt", command=save_encrypt_btn)
sv_encrypt.pack()

# DECRYPT BUTTON
decrypt_btn = Button(text="Decrypt", command=decoder_btn)
decrypt_btn.pack()

window.update()
window.update_idletasks()
mainloop()
