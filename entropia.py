import tkinter as tk
from tkinter import messagebox
from sympy import isprime, nextprime
import random
import hashlib
import time

def collect_mouse_entropy(duration=3):
    """Zbiera dane ruchów myszy przez określony czas."""
    mouse_data = []

    def mouse_movement(event):
        """Zapisuje współrzędne kursora i czas."""
        x, y = event.x, event.y
        timestamp = int(time.time() * 1000)
        mouse_data.append((x, y, timestamp))

    root = tk.Tk()
    root.geometry("400x300")
    root.title("Ruchy myszy - Zbieranie entropii")

    label = tk.Label(root, text="Porusz myszą przez kilka sekund...", font=("Arial", 14))
    label.pack(pady=50)

    root.bind("<Motion>", mouse_movement)

    root.after(duration * 1000, root.destroy)  # Zatrzymaj po określonym czasie
    root.mainloop()

    # Przetwarzanie danych ruchów myszy na hash
    data_string = ';'.join(f"{x},{y},{timestamp}" for x, y, timestamp in mouse_data)
    data_bytes = data_string.encode('utf-8')
    sha256_hash = hashlib.sha256(data_bytes).hexdigest()
    return int(sha256_hash[:32], 16)  # Zwróć hash jako liczba całkowita (128 bitów)

def generate_large_prime_with_entropy(bits=128):
    """Generuje dużą liczbę pierwszą z dodatkiem entropii myszy."""
    entropy = collect_mouse_entropy()
    num = random.getrandbits(bits) ^ entropy  # Dodanie entropii do losowej liczby
    return nextprime(num)  # Znajdź najbliższą liczbę pierwszą

# Test funkcji
if __name__ == "__main__":
    print("Generowanie liczby pierwszej z wykorzystaniem entropii myszy...")
    prime = generate_large_prime_with_entropy(bits=128)
    print(f"Wygenerowana liczba pierwsza: {prime}")
