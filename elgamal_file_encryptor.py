import tkinter as tk
from tkinter import messagebox, filedialog
from sympy import mod_inverse, nextprime
import random
import json
import os
import time
import hashlib


def collect_mouse_entropy(parent, duration=3):
    """Zbiera dane ruchów myszy przez określony czas."""
    mouse_data = []

    def mouse_movement(event):
        x, y = event.x, event.y
        timestamp = int(time.time() * 1000)
        mouse_data.append((x, y, timestamp))

    top = tk.Toplevel(parent)
    top.geometry("400x300")
    top.title("Ruchy myszy - Zbieranie entropii")

    label = tk.Label(top, text="Porusz myszą przez kilka sekund...", font=("Arial", 14))
    label.pack(pady=50)

    top.bind("<Motion>", mouse_movement)
    parent.after(duration * 1000, top.destroy)
    parent.wait_window(top)

    data_string = ';'.join(f"{x},{y},{timestamp}" for x, y, timestamp in mouse_data)
    data_bytes = data_string.encode('utf-8')
    sha256_hash = hashlib.sha256(data_bytes).hexdigest()
    return int(sha256_hash[:32], 16)


def generate_large_prime(parent, bits=128):
    """Generuje dużą liczbę pierwszą z dodatkiem entropii myszy."""
    entropy = collect_mouse_entropy(parent)
    num = random.getrandbits(bits) ^ entropy
    return nextprime(num)


def split_file_to_chunks(file_path, chunk_size):
    """Dzieli plik na kawałki."""
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            yield chunk


def merge_chunks_to_file(chunks, output_path):
    """Łączy kawałki w jeden plik."""
    with open(output_path, "wb") as f:
        for chunk in chunks:
            f.write(chunk)


def encrypt_chunk(public_key, chunk):
    """Szyfruje kawałek danych."""
    p, g, h = public_key
    chunk_number = int.from_bytes(chunk, 'big')
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (pow(h, k, p) * chunk_number) % p
    return c1, c2


def decrypt_chunk(private_key, c1, c2):
    """Deszyfruje kawałek danych."""
    p, x = private_key
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    chunk_number = (c2 * s_inv) % p
    return chunk_number.to_bytes((chunk_number.bit_length() + 7) // 8, 'big')


class ElGamalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Szyfrowanie ElGamal")
        self.profiles = self.load_profiles()
        self.public_key = None
        self.private_key = None
        self.show_menu()

    def load_profiles(self):
        if os.path.exists("profiles.json"):
            with open("profiles.json", "r") as f:
                return json.load(f)
        return {}

    def save_profiles(self):
        with open("profiles.json", "w") as f:
            json.dump(self.profiles, f)

    def show_menu(self):
        self.clear_window()

        tk.Label(self.root, text="Wybierz opcję:").pack(pady=10)
        tk.Button(self.root, text="Wygeneruj nowe klucze", command=self.generate_new_keys).pack(pady=5)

        if self.profiles:
            tk.Label(self.root, text="Zapisane profile kluczy:").pack(pady=10)
            for profile_name in self.profiles.keys():
                frame = tk.Frame(self.root)
                frame.pack(pady=2)
                tk.Button(
                    frame, text=profile_name,
                    command=lambda name=profile_name: self.show_profile_interface(name)
                ).pack(side=tk.LEFT)
                tk.Button(
                    frame, text="Usuń", fg="red",
                    command=lambda name=profile_name: self.delete_profile(name)
                ).pack(side=tk.LEFT)

    def delete_profile(self, profile_name):
        del self.profiles[profile_name]
        self.save_profiles()
        self.show_menu()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def generate_new_keys(self):
        p = generate_large_prime(self.root)
        g = random.randint(2, p - 2)
        x = random.randint(1, p - 2)
        h = pow(g, x, p)
        self.public_key = (p, g, h)
        self.private_key = (p, x)
        self.save_new_profile()

    def save_new_profile(self):
        self.clear_window()

        tk.Label(self.root, text="Podaj nazwę profilu dla kluczy:").pack(pady=10)
        entry_name = tk.Entry(self.root)
        entry_name.pack(pady=5)

        def save_profile():
            profile_name = entry_name.get()
            if profile_name:
                self.profiles[profile_name] = {
                    "public_key": self.public_key,
                    "private_key": self.private_key
                }
                self.save_profiles()
                self.show_menu()

        tk.Button(self.root, text="Zapisz", command=save_profile).pack(pady=5)
        tk.Button(self.root, text="Powrót", command=self.show_menu).pack(pady=5)


    def show_profile_interface(self, profile_name):
        self.clear_window()

        profile = self.profiles[profile_name]
        self.public_key = tuple(profile["public_key"])
        self.private_key = tuple(profile["private_key"])

        tk.Label(self.root, text=f"Profil: {profile_name}").pack(pady=10)

        tk.Label(self.root, text="Klucz publiczny:").pack(pady=5)
        entry_public = tk.Text(self.root, height=3, width=50)
        entry_public.insert(tk.END, str(self.public_key))
        entry_public.config(state="normal")
        entry_public.pack(pady=5)

        tk.Label(self.root, text="Klucz prywatny:").pack(pady=5)
        entry_private = tk.Text(self.root, height=2, width=50)
        entry_private.insert(tk.END, str(self.private_key))
        entry_private.config(state="normal")
        entry_private.pack(pady=5)

        tk.Button(self.root, text="Szyfruj plik", command=self.encrypt_file).pack(pady=5)
        tk.Button(self.root, text="Deszyfruj plik", command=self.decrypt_file).pack(pady=5)
        tk.Button(self.root, text="Powrót", command=self.show_menu).pack(pady=5)

    def show_file_interface(self):
        self.clear_window()

        tk.Label(self.root, text="Wybierz plik do zaszyfrowania:").pack(pady=10)
        tk.Button(self.root, text="Szyfruj plik", command=self.encrypt_file).pack(pady=5)

        tk.Label(self.root, text="Wybierz plik do odszyfrowania:").pack(pady=10)
        tk.Button(self.root, text="Deszyfruj plik", command=self.decrypt_file).pack(pady=5)
        tk.Button(self.root, text="Powrót", command=self.show_menu).pack(pady=5)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if not output_path:
            return

        chunk_size = (self.public_key[0].bit_length() - 1) // 8
        encrypted_chunks = []

        for chunk in split_file_to_chunks(file_path, chunk_size):
            encrypted_chunks.append(encrypt_chunk(self.public_key, chunk))

        with open(output_path, "w") as f:
            json.dump(encrypted_chunks, f)

        messagebox.showinfo("Sukces", "Plik został zaszyfrowany.")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        output_path = filedialog.asksaveasfilename()
        if not output_path:
            return

        with open(file_path, "r") as f:
            encrypted_chunks = json.load(f)

        decrypted_chunks = []
        for c1, c2 in encrypted_chunks:
            decrypted_chunks.append(decrypt_chunk(self.private_key, c1, c2))

        merge_chunks_to_file(decrypted_chunks, output_path)
        messagebox.showinfo("Sukces", "Plik został odszyfrowany.")


if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalApp(root)
    root.mainloop()
