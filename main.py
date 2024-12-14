import tkinter as tk
from tkinter import messagebox
from sympy import isprime, mod_inverse
import random


# Funkcje związane z algorytmem ElGamal
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


def encrypt(public_key, plaintext):
    """Szyfruje wiadomość przy użyciu klucza publicznego."""
    p, g, h = public_key
    m = int.from_bytes(plaintext.encode(), 'big')  # Konwersja tekstu na liczbę
    if m >= p:
        raise ValueError("Wiadomość musi być mniejsza niż p.")
    k = random.randint(1, p - 2)  # Losowe k
    c1 = pow(g, k, p)  # c1 = g^k mod p
    s = pow(h, k, p)  # s = h^k mod p
    c2 = (m * s) % p  # c2 = m * s mod p
    return (c1, c2)


def decrypt(private_key, ciphertext):
    """Deszyfruje wiadomość przy użyciu klucza prywatnego."""
    p, x = private_key
    c1, c2 = ciphertext
    s = pow(c1, x, p)  # s = c1^x mod p
    s_inv = mod_inverse(s, p)  # s_inv = s^(-1) mod p
    m = (c2 * s_inv) % p  # m = c2 * s^(-1) mod p
    plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    return plaintext


# Tworzenie aplikacji Tkinter
class ElGamalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Szyfrowanie ElGamal")
        self.root.geometry("500x800")
        self.show_menu()

    def show_menu(self):
        """Wyświetla menu główne."""
        self.clear_window()

        tk.Label(self.root, text="Wybierz opcję:").pack(pady=10)

        tk.Button(self.root, text="Wygeneruj nowe klucze", command=self.generate_new_keys).pack(pady=5)
        tk.Button(self.root, text="Wprowadź istniejące klucze", command=self.use_existing_keys).pack(pady=5)

    def generate_new_keys(self):
        """Generuje nowe klucze i przechodzi do głównego interfejsu."""
        self.public_key, self.private_key = generate_keys(bits=128)
        self.show_main_interface()

    def use_existing_keys(self):
        """Przechodzi do interfejsu wprowadzania istniejących kluczy."""
        self.clear_window()
        self.add_back_button()

        tk.Label(self.root, text="Wprowadź klucz publiczny:").pack(pady=5)
        self.entry_public_key = tk.Entry(self.root, width=50)
        self.entry_public_key.pack(pady=5)

        tk.Label(self.root, text="Wprowadź klucz prywatny:").pack(pady=5)
        self.entry_private_key = tk.Entry(self.root, width=50)
        self.entry_private_key.pack(pady=5)

        tk.Button(self.root, text="Zatwierdź", command=self.set_existing_keys).pack(pady=10)

    def set_existing_keys(self):
        """Ustawia istniejące klucze na podstawie wprowadzonych danych."""
        try:
            self.public_key = self.parse_key(self.entry_public_key.get())
            self.private_key = self.parse_key(self.entry_private_key.get())
            if len(self.public_key) != 3 or len(self.private_key) != 2:
                raise ValueError("Nieprawidłowy format kluczy.")
            self.show_main_interface()
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się wprowadzić kluczy: {e}")

    def show_main_interface(self):
        """Wyświetla główny interfejs aplikacji."""
        self.clear_window()
        self.add_back_button()

        # Wyświetlanie wygenerowanych lub wprowadzonych kluczy
        tk.Label(self.root, text="Klucze:").pack(pady=5)
        self.text_keys = tk.Text(self.root, height=6, width=60)
        self.text_keys.pack(pady=5)
        self.text_keys.insert(
            tk.END, f"Klucz publiczny: {self.public_key}\nKlucz prywatny: {self.private_key}"
        )
        self.text_keys.config(state="normal")

        # Sekcja wprowadzania klucza publicznego
        tk.Label(self.root, text="Podaj klucz publiczny odbiorcy (p, g, h):").pack(pady=5)
        self.entry_receiver_public_key = tk.Entry(self.root, width=50)
        self.entry_receiver_public_key.pack(pady=5)

        # Sekcja wprowadzania wiadomości do szyfrowania
        tk.Label(self.root, text="Wprowadź wiadomość do zaszyfrowania:").pack(pady=5)
        self.entry_message_encrypt = tk.Entry(self.root, width=40)
        self.entry_message_encrypt.pack(pady=5)

        # Przycisk szyfrowania
        tk.Button(self.root, text="Szyfruj", command=self.encrypt_message).pack(pady=10)

        # Wyświetlanie zaszyfrowanej wiadomości
        self.text_encrypted = tk.Text(self.root, height=5, width=50, state="disabled")
        self.text_encrypted.pack(pady=5)

        # Sekcja wprowadzania zaszyfrowanej wiadomości do odszyfrowania
        tk.Label(self.root, text="Wprowadź zaszyfrowaną wiadomość (c1, c2):").pack(pady=5)
        self.entry_message_decrypt = tk.Entry(self.root, width=50)
        self.entry_message_decrypt.pack(pady=5)

        # Przycisk deszyfrowania
        tk.Button(self.root, text="Deszyfruj", command=self.decrypt_message).pack(pady=10)

        # Wyświetlanie odszyfrowanej wiadomości
        self.text_decrypted = tk.Text(self.root, height=5, width=50, state="disabled")
        self.text_decrypted.pack(pady=5)

    def encrypt_message(self):
        """Szyfruje wiadomość przy użyciu klucza publicznego odbiorcy."""
        plaintext = self.entry_message_encrypt.get()
        receiver_public_key = self.entry_receiver_public_key.get()
        if not plaintext or not receiver_public_key:
            messagebox.showerror("Błąd", "Wprowadź wiadomość i klucz publiczny odbiorcy.")
            return

        try:
            receiver_public_key = self.parse_key(receiver_public_key)
            if len(receiver_public_key) != 3:
                raise ValueError("Klucz publiczny musi składać się z 3 elementów (p, g, h).")

            ciphertext = encrypt(receiver_public_key, plaintext)
            self.display_result(self.text_encrypted, str(ciphertext))
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się zaszyfrować wiadomości: {e}")

    def decrypt_message(self):
        """Deszyfruje wiadomość przy użyciu klucza prywatnego."""
        ciphertext = self.entry_message_decrypt.get()
        if not ciphertext:
            messagebox.showerror("Błąd", "Wprowadź zaszyfrowaną wiadomość.")
            return
        try:
            ciphertext_tuple = self.parse_key(ciphertext)
            if len(ciphertext_tuple) != 2:
                raise ValueError("Zaszyfrowana wiadomość musi składać się z 2 elementów (c1, c2).")

            decrypted_message = decrypt(self.private_key, ciphertext_tuple)
            self.display_result(self.text_decrypted, decrypted_message)
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się odszyfrować wiadomości: {e}")

    def parse_key(self, key_string):
        """Parsuje klucz wprowadzony jako string i konwertuje go na tuple."""
        try:
            key_string = key_string.strip().strip("()")
            key_parts = tuple(map(int, key_string.split(",")))
            return key_parts
        except ValueError:
            raise ValueError("Klucz musi być w formacie: (element1, element2, element3)")

    def display_result(self, text_widget, content):
        """Wyświetla wynik w polu tekstowym."""
        text_widget.config(state="normal")
        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, content)
        text_widget.config(state="disabled")

    def add_back_button(self):
        """Dodaje przycisk powrotu do menu głównego."""
        tk.Button(self.root, text="Powrót", command=self.show_menu).place(x=10, y=10)

    def clear_window(self):
        """Czyści zawartość okna."""
        for widget in self.root.winfo_children():
            widget.destroy()


# Uruchomienie aplikacji
if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalApp(root)
    root.mainloop()
