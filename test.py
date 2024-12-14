import tkinter as tk
from tkinter import messagebox
from sympy import isprime, mod_inverse
import random
import json
import os


def generate_large_prime(bits=128):
    """Generuje dużą liczbę pierwszą o zadanej liczbie bitów."""
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num


def generate_keys(bits=128):
    """Generuje klucze publiczne i prywatne."""
    p = generate_large_prime(bits)  # Duża liczba pierwsza
    g = random.randint(2, p - 2)  # Generator grupy
    x = random.randint(1, p - 2)  # Klucz prywatny
    h = pow(g, x, p)  # h = g^x mod p (część klucza publicznego)
    public_key = (p, g, h)
    private_key = (p, x)
    return public_key, private_key


def text_to_number(text):
    """Konwertuje tekst na liczbę."""
    return int.from_bytes(text.encode('utf-8'), 'big')


def number_to_text(number):
    """Konwertuje liczbę na tekst."""
    return number.to_bytes((number.bit_length() + 7) // 8, 'big').decode('utf-8')


def encrypt_message(public_key, message):
    """Szyfruje wiadomość za pomocą klucza publicznego."""
    p, g, h = public_key
    message_number = text_to_number(message)
    k = random.randint(1, p - 2)  # Losowy klucz sesyjny
    c1 = pow(g, k, p)
    c2 = (pow(h, k, p) * message_number) % p
    return c1, c2


def decrypt_message(private_key, ciphertext):
    """Deszyfruje wiadomość za pomocą klucza prywatnego."""
    p, x = private_key
    c1, c2 = ciphertext
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    message_number = (c2 * s_inv) % p
    return number_to_text(message_number)


class ElGamalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Szyfrowanie ElGamal")
        self.root.geometry("600x800")

        self.profiles = self.load_profiles()
        self.recipients = self.load_recipients()
        self.public_key = None
        self.private_key = None
        self.show_menu()

    def load_profiles(self):
        """Ładuje profile z pliku JSON."""
        if os.path.exists("profiles.json"):
            with open("profiles.json", "r") as f:
                return json.load(f)
        return {}

    def save_profiles(self):
        """Zapisuje profile do pliku JSON."""
        with open("profiles.json", "w") as f:
            json.dump(self.profiles, f)

    def load_recipients(self):
        """Ładuje odbiorców z pliku JSON."""
        if os.path.exists("recipients.json"):
            with open("recipients.json", "r") as f:
                return json.load(f)
        return {}

    def save_recipients(self):
        """Zapisuje odbiorców do pliku JSON."""
        with open("recipients.json", "w") as f:
            json.dump(self.recipients, f)

    def show_menu(self):
        """Wyświetla menu główne."""
        self.clear_window()

        tk.Label(self.root, text="Wybierz opcję:").pack(pady=10)
        tk.Button(self.root, text="Wygeneruj nowe klucze", command=self.generate_new_keys).pack(pady=5)
        tk.Button(self.root, text="Wprowadź istniejące klucze", command=self.use_existing_keys).pack(pady=5)

        if self.profiles:
            tk.Label(self.root, text="Zapisane profile kluczy:").pack(pady=10)
            for profile_name in list(self.profiles.keys()):
                frame = tk.Frame(self.root)
                frame.pack(pady=2)
                tk.Button(
                    frame,
                    text=profile_name,
                    command=lambda name=profile_name: self.load_profile(name)
                ).pack(side=tk.LEFT)
                tk.Button(
                    frame,
                    text="X",
                    fg="red",
                    command=lambda name=profile_name: self.delete_profile(name)
                ).pack(side=tk.LEFT)

        if self.recipients:
            tk.Label(self.root, text="Lista odbiorców:").pack(pady=10)
            for recipient_name in list(self.recipients.keys()):
                frame = tk.Frame(self.root)
                frame.pack(pady=2)
                tk.Button(
                    frame,
                    text=recipient_name,
                    command=lambda name=recipient_name: self.show_recipient_interface(name)
                ).pack(side=tk.LEFT)
                tk.Button(
                    frame,
                    text="X",
                    fg="red",
                    command=lambda name=recipient_name: self.delete_recipient(name)
                ).pack(side=tk.LEFT)

        tk.Button(self.root, text="Dodaj odbiorcę", command=self.add_recipient).pack(pady=10)

    def delete_profile(self, profile_name):
        """Usuwa profil klucza."""
        del self.profiles[profile_name]
        self.save_profiles()
        self.show_menu()

    def delete_recipient(self, recipient_name):
        """Usuwa odbiorcę."""
        del self.recipients[recipient_name]
        self.save_recipients()
        self.show_menu()

    def use_existing_keys(self):
        """Przechodzi do interfejsu wprowadzania istniejących kluczy."""
        self.clear_window()
        self.add_back_button()

        tk.Label(self.root, text="Wprowadź klucz publiczny (p, g, h):").pack(pady=5)
        self.entry_public_key = tk.Text(self.root, height=3, width=50)
        self.entry_public_key.pack(pady=5)

        tk.Label(self.root, text="Wprowadź klucz prywatny (p, x):").pack(pady=5)
        self.entry_private_key = tk.Text(self.root, height=2, width=50)
        self.entry_private_key.pack(pady=5)

        tk.Button(self.root, text="Zatwierdź", command=self.set_existing_keys).pack(pady=10)

    def set_existing_keys(self):
        """Ustawia istniejące klucze na podstawie wprowadzonych danych."""
        try:
            self.public_key = self.parse_key(self.entry_public_key.get("1.0", tk.END).strip())
            self.private_key = self.parse_key(self.entry_private_key.get("1.0", tk.END).strip())
            if len(self.public_key) != 3 or len(self.private_key) != 2:
                raise ValueError("Nieprawidłowy format kluczy.")
            self.show_main_interface()
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się wprowadzić kluczy: {e}")

    def load_profile(self, profile_name):
        """Ładuje klucze z wybranego profilu."""
        profile = self.profiles[profile_name]
        self.public_key, self.private_key = profile["public_key"], profile["private_key"]
        self.show_main_interface()

    def generate_new_keys(self):
        """Generuje nowe klucze."""
        self.public_key, self.private_key = generate_keys(bits=128)
        self.show_save_key_interface()

    def show_save_key_interface(self):
        """Interfejs zapisywania nowo wygenerowanych kluczy."""
        self.clear_window()
        self.add_back_button()

        tk.Label(self.root, text="Wygenerowano nowe klucze:").pack(pady=5)

        tk.Label(self.root, text="Klucz publiczny:").pack(pady=5)
        self.entry_public_key = tk.Text(self.root, height=3, width=50)
        self.entry_public_key.insert(tk.END, str(self.public_key))
        self.entry_public_key.config(state="disabled")
        self.entry_public_key.pack(pady=5)

        tk.Label(self.root, text="Klucz prywatny:").pack(pady=5)
        self.entry_private_key = tk.Text(self.root, height=2, width=50)
        self.entry_private_key.insert(tk.END, str(self.private_key))
        self.entry_private_key.config(state="disabled")
        self.entry_private_key.pack(pady=5)

        tk.Label(self.root, text="Podaj nazwę użytkownika dla kluczy:").pack(pady=5)
        self.entry_profile_name = tk.Entry(self.root, width=40)
        self.entry_profile_name.pack(pady=5)

        tk.Button(self.root, text="Zapisz klucze", command=self.save_new_keys).pack(pady=5)
        tk.Button(self.root, text="Pomiń i przejdź dalej", command=self.show_main_interface).pack(pady=5)

    def save_new_keys(self):
        """Zapisuje wygenerowane klucze z podaną nazwą."""
        profile_name = self.entry_profile_name.get()
        if profile_name:
            self.profiles[profile_name] = {
                "public_key": self.public_key,
                "private_key": self.private_key
            }
            self.save_profiles()
            messagebox.showinfo("Sukces", "Klucze zostały zapisane!")
            self.show_menu()
        else:
            messagebox.showerror("Błąd", "Nazwa użytkownika nie może być pusta.")

    def add_recipient(self):
        """Dodaje nowego odbiorcę."""
        self.clear_window()
        self.add_back_button()

        tk.Label(self.root, text="Dodaj nowego odbiorcę:").pack(pady=5)

        tk.Label(self.root, text="Nazwa odbiorcy:").pack(pady=5)
        self.entry_recipient_name = tk.Entry(self.root, width=40)
        self.entry_recipient_name.pack(pady=5)

        tk.Label(self.root, text="Klucz publiczny odbiorcy (p, g, h):").pack(pady=5)
        self.entry_recipient_key = tk.Text(self.root, height=3, width=50)
        self.entry_recipient_key.pack(pady=5)

        tk.Button(self.root, text="Zapisz odbiorcę", command=self.save_recipient).pack(pady=10)

    def save_recipient(self):
        """Zapisuje odbiorcę do listy."""
        name = self.entry_recipient_name.get()
        try:
            key = self.parse_key(self.entry_recipient_key.get("1.0", tk.END).strip())
            if len(key) != 3:
                raise ValueError("Klucz publiczny musi mieć format (p, g, h).")
            self.recipients[name] = key
            self.save_recipients()
            messagebox.showinfo("Sukces", "Odbiorca został zapisany!")
            self.show_menu()
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się zapisać odbiorcy: {e}")

    def show_recipient_interface(self, name):
        """Wyświetla interfejs dla zaszyfrowania wiadomości dla wybranego odbiorcy."""
        self.clear_window()
        self.add_back_button()

        public_key = self.recipients[name]

        tk.Label(self.root, text=f"Szyfrowanie wiadomości dla: {name}").pack(pady=5)
        tk.Label(self.root, text=f"Klucz publiczny: {public_key}").pack(pady=5)

        tk.Label(self.root, text="Wiadomość do zaszyfrowania (tekst):").pack(pady=5)
        self.entry_message_encrypt = tk.Entry(self.root, width=50)
        self.entry_message_encrypt.pack(pady=5)

        tk.Button(
            self.root,
            text="Szyfruj wiadomość",
            command=lambda: self.encrypt_for_recipient(name)
        ).pack(pady=10)

        tk.Label(self.root, text="Zaszyfrowana wiadomość:").pack(pady=5)
        self.text_encrypted = tk.Text(self.root, height=3, width=60)
        self.text_encrypted.pack(pady=5)

    def encrypt_for_recipient(self, name):
        """Szyfruje wiadomość dla wybranego odbiorcy."""
        try:
            message = self.entry_message_encrypt.get()
            public_key = self.recipients[name]
            c1, c2 = encrypt_message(public_key, message)
            self.text_encrypted.delete("1.0", tk.END)
            self.text_encrypted.insert(tk.END, f"({c1}, {c2})")
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się zaszyfrować wiadomości: {e}")

    def parse_key(self, key_string):
        """Parsuje klucz wprowadzony jako string i konwertuje go na tuple."""
        key_string = key_string.strip().strip("()")
        key_parts = tuple(map(int, key_string.split(",")))
        return key_parts

    def clear_window(self):
        """Czyści zawartość okna."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def add_back_button(self):
        """Dodaje przycisk powrotu do menu głównego."""
        tk.Button(self.root, text="Powrót", command=self.show_menu).pack(anchor="nw")

    def show_main_interface(self):
        """Wyświetla główny interfejs aplikacji z aktywnymi kluczami."""
        self.clear_window()
        self.add_back_button()

        tk.Label(self.root, text="Aktywne klucze:").pack(pady=5)

        tk.Label(self.root, text="Klucz publiczny:").pack(pady=5)
        self.entry_public_key = tk.Text(self.root, height=3, width=50)
        self.entry_public_key.insert(tk.END, str(self.public_key))
        self.entry_public_key.config(state="disabled")
        self.entry_public_key.pack(pady=5)

        tk.Label(self.root, text="Klucz prywatny:").pack(pady=5)
        self.entry_private_key = tk.Text(self.root, height=2, width=50)
        self.entry_private_key.insert(tk.END, str(self.private_key))
        self.entry_private_key.config(state="disabled")
        self.entry_private_key.pack(pady=5)

        tk.Label(self.root, text="Wiadomość do zaszyfrowania (tekst):").pack(pady=5)
        self.entry_message_encrypt = tk.Entry(self.root, width=50)
        self.entry_message_encrypt.pack(pady=5)

        tk.Button(self.root, text="Szyfruj", command=self.encrypt_message).pack(pady=5)

        tk.Label(self.root, text="Zaszyfrowana wiadomość:").pack(pady=5)
        self.text_encrypted = tk.Text(self.root, height=3, width=60)
        self.text_encrypted.pack(pady=5)

        tk.Label(self.root, text="Zaszyfrowana wiadomość (c1, c2):").pack(pady=5)
        self.entry_message_decrypt = tk.Text(self.root, height=3, width=50)
        self.entry_message_decrypt.pack(pady=5)

        tk.Button(self.root, text="Deszyfruj", command=self.decrypt_message).pack(pady=5)

        tk.Label(self.root, text="Odszyfrowana wiadomość:").pack(pady=5)
        self.text_decrypted = tk.Text(self.root, height=3, width=60)
        self.text_decrypted.pack(pady=5)

    def encrypt_message(self):
        """Obsługuje szyfrowanie wiadomości."""
        try:
            message = self.entry_message_encrypt.get()
            c1, c2 = encrypt_message(self.public_key, message)
            self.text_encrypted.delete("1.0", tk.END)
            self.text_encrypted.insert(tk.END, f"({c1}, {c2})")
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się zaszyfrować wiadomości: {e}")

    def decrypt_message(self):

        """Obsługuje deszyfrowanie wiadomości."""
        try:
            ciphertext = self.parse_key(self.entry_message_decrypt.get("1.0", tk.END).strip())
            if len(ciphertext) != 2:
                raise ValueError("Nieprawidłowy format szyfrogramu.")
            message = decrypt_message(self.private_key, ciphertext)
            self.text_decrypted.delete("1.0", tk.END)
            self.text_decrypted.insert(tk.END, message)
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się odszyfrować wiadomości: {e}")


# Uruchomienie aplikacji
if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalApp(root)
    root.mainloop()
