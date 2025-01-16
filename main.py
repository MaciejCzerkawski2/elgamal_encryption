import tkinter as tk
from tkinter import messagebox, filedialog
from sympy import mod_inverse, nextprime
import random
import json
import os
import time
import hashlib
import base64
import struct


def collect_mouse_entropy(parent, duration=3):
    """Collects mouse movement data for entropy."""
    mouse_data = []

    def mouse_movement(event):
        x, y = event.x, event.y
        timestamp = int(time.time() * 1000)
        mouse_data.append((x, y, timestamp))

    top = tk.Toplevel(parent)
    top.geometry("400x300")
    top.title("Mouse Movement - Collecting Entropy")

    label = tk.Label(top, text="Move the mouse for a few seconds...", font=("Arial", 14))
    label.pack(pady=50)

    top.bind("<Motion>", mouse_movement)
    parent.after(duration * 1000, top.destroy)
    parent.wait_window(top)

    data_string = ';'.join(f"{x},{y},{timestamp}" for x, y, timestamp in mouse_data)
    data_bytes = data_string.encode('utf-8')
    sha256_hash = hashlib.sha256(data_bytes).hexdigest()
    return int(sha256_hash[:32], 16)


def generate_large_prime(parent, bits=128):
    """Generates a large prime number with mouse entropy."""
    entropy = collect_mouse_entropy(parent)
    num = random.getrandbits(bits) ^ entropy
    return nextprime(num)


def split_file_to_chunks(file_path, chunk_size):
    """Splits a file into chunks with length information."""
    chunks = []
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size - 8):  # Reserve 8 bytes for length
            # Store the original length at the start of the chunk
            length_bytes = struct.pack(">Q", len(chunk))
            padded_chunk = length_bytes + chunk
            # Pad to full chunk size if needed
            if len(padded_chunk) < chunk_size:
                padded_chunk += b'\x00' * (chunk_size - len(padded_chunk))
            chunks.append(padded_chunk)
    return chunks


def merge_chunks_to_file(chunks, output_path):
    """Merges chunks into a single file, removing padding."""
    with open(output_path, "wb") as f:
        for chunk in chunks:
            # Extract the original length from the first 8 bytes
            original_length = struct.unpack(">Q", chunk[:8])[0]
            # Write only the actual data (no padding)
            f.write(chunk[8:8 + original_length])


def encrypt_chunk(public_key, chunk):
    """Encrypts a chunk of data."""
    p, g, h = public_key
    chunk_number = int.from_bytes(chunk, 'big')
    if chunk_number >= p:
        raise ValueError("Chunk too large for the selected public key!")
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (pow(h, k, p) * chunk_number) % p

    # Use a consistent byte length based on prime size
    bytes_length = (p.bit_length() + 7) // 8
    return base64.b64encode(c1.to_bytes(bytes_length, 'big')).decode(), \
        base64.b64encode(c2.to_bytes(bytes_length, 'big')).decode()


def decrypt_chunk(private_key, c1_encoded, c2_encoded, chunk_size):
    """Decrypts a chunk of data."""
    p, x = private_key
    c1 = int.from_bytes(base64.b64decode(c1_encoded), 'big')
    c2 = int.from_bytes(base64.b64decode(c2_encoded), 'big')
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    chunk_number = (c2 * s_inv) % p
    return chunk_number.to_bytes(chunk_size, 'big')


class ElGamalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ElGamal Encryption")
        self.setup_profiles_directory()
        self.profiles = self.load_profiles()
        self.public_key = None
        self.private_key = None
        self.show_menu()

    def setup_profiles_directory(self):
        """Creates a profiles directory if it doesn't exist."""
        self.profiles_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
        os.makedirs(self.profiles_dir, exist_ok=True)
        self.profiles_file = os.path.join(self.profiles_dir, "profiles.json")

    def load_profiles(self):
        """Loads profiles from the JSON file."""
        try:
            if os.path.exists(self.profiles_file):
                with open(self.profiles_file, "r") as f:
                    # Convert tuples stored as lists back to tuples
                    profiles = json.load(f)
                    for profile in profiles.values():
                        profile["public_key"] = tuple(profile["public_key"])
                        profile["private_key"] = tuple(profile["private_key"])
                    return profiles
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profiles: {str(e)}")
        return {}

    def save_profiles(self):
        """Saves profiles to the JSON file."""
        try:
            with open(self.profiles_file, "w") as f:
                # Convert tuples to lists for JSON serialization
                profiles_copy = {}
                for name, profile in self.profiles.items():
                    profiles_copy[name] = {
                        "public_key": list(profile["public_key"]),
                        "private_key": list(profile["private_key"])
                    }
                json.dump(profiles_copy, f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profiles: {str(e)}")

    def show_menu(self):
        self.clear_window()

        tk.Label(self.root, text="Select an option:").pack(pady=10)
        tk.Button(self.root, text="Generate New Keys", command=self.generate_new_keys).pack(pady=5)

        if self.profiles:
            tk.Label(self.root, text="Saved Key Profiles:").pack(pady=10)
            for profile_name in self.profiles.keys():
                frame = tk.Frame(self.root)
                frame.pack(pady=2)
                tk.Button(
                    frame, text=profile_name,
                    command=lambda name=profile_name: self.show_profile_interface(name)
                ).pack(side=tk.LEFT)
                tk.Button(
                    frame, text="Delete", fg="red",
                    command=lambda name=profile_name: self.delete_profile(name)
                ).pack(side=tk.LEFT)

    def delete_profile(self, profile_name):
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the profile '{profile_name}'?"):
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

        tk.Label(self.root, text="Enter a profile name for the keys:").pack(pady=10)
        entry_name = tk.Entry(self.root)
        entry_name.pack(pady=5)

        def save_profile():
            profile_name = entry_name.get().strip()
            if not profile_name:
                messagebox.showerror("Error", "Please enter a profile name")
                return
            if profile_name in self.profiles:
                messagebox.showerror("Error", "Profile name already exists")
                return

            self.profiles[profile_name] = {
                "public_key": self.public_key,
                "private_key": self.private_key
            }
            self.save_profiles()
            messagebox.showinfo("Success", "Profile saved successfully")
            self.show_menu()

        tk.Button(self.root, text="Save", command=save_profile).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.show_menu).pack(pady=5)

    def show_profile_interface(self, profile_name):
        self.clear_window()

        profile = self.profiles[profile_name]
        self.public_key = profile["public_key"]
        self.private_key = profile["private_key"]

        tk.Label(self.root, text=f"Profile: {profile_name}").pack(pady=10)

        tk.Label(self.root, text="Public Key:").pack(pady=5)
        entry_public = tk.Text(self.root, height=3, width=50)
        entry_public.insert(tk.END, str(self.public_key))
        entry_public.config(state="disabled")
        entry_public.pack(pady=5)

        tk.Label(self.root, text="Private Key:").pack(pady=5)
        entry_private = tk.Text(self.root, height=2, width=50)
        entry_private.insert(tk.END, str(self.private_key))
        entry_private.config(state="disabled")
        entry_private.pack(pady=5)

        tk.Button(self.root, text="Encrypt File", command=self.encrypt_file).pack(pady=5)
        tk.Button(self.root, text="Decrypt File", command=self.decrypt_file).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.show_menu).pack(pady=5)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if not output_path:
            return

        try:
            # Calculate chunk size based on prime size, reserving space for length
            chunk_size = (self.public_key[0].bit_length() - 1) // 8
            chunks = split_file_to_chunks(file_path, chunk_size)

            encrypted_chunks = []
            total_chunks = len(chunks)

            # Create progress window
            progress_window = tk.Toplevel(self.root)
            progress_window.title("Encryption Progress")
            progress_label = tk.Label(progress_window, text="Encrypting...")
            progress_label.pack(pady=10)

            for i, chunk in enumerate(chunks, 1):
                encrypted_chunks.append(encrypt_chunk(self.public_key, chunk))
                progress_label.config(text=f"Encrypting: {i}/{total_chunks} chunks")
                progress_window.update()

            with open(output_path, "w") as f:
                json.dump(encrypted_chunks, f)

            progress_window.destroy()
            messagebox.showinfo("Success", "File encrypted successfully.")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        output_path = filedialog.asksaveasfilename()
        if not output_path:
            return

        try:
            with open(file_path, "r") as f:
                encrypted_chunks = json.load(f)

            chunk_size = (self.private_key[0].bit_length() - 1) // 8
            decrypted_chunks = []
            total_chunks = len(encrypted_chunks)

            # Create progress window
            progress_window = tk.Toplevel(self.root)
            progress_window.title("Decryption Progress")
            progress_label = tk.Label(progress_window, text="Decrypting...")
            progress_label.pack(pady=10)

            for i, (c1, c2) in enumerate(encrypted_chunks, 1):
                decrypted_chunks.append(decrypt_chunk(self.private_key, c1, c2, chunk_size))
                progress_label.config(text=f"Decrypting: {i}/{total_chunks} chunks")
                progress_window.update()

            merge_chunks_to_file(decrypted_chunks, output_path)

            progress_window.destroy()
            messagebox.showinfo("Success", "File decrypted successfully.")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalApp(root)
    root.mainloop()