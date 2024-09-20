import tkinter as tk
from tkinter import filedialog, messagebox
import re

class CipherApp:
    def __init__(self, master):
        self.master = master
        master.title("Cipher Program")
        master.geometry("600x400")

        self.label = tk.Label(master, text="Pilih Metode Cipher:")
        self.label.pack()

        self.cipher_var = tk.StringVar()
        self.cipher_var.set("vigenere")
        
        ciphers = [("Vigenere Cipher", "vigenere"),
                   ("Playfair Cipher", "playfair"),
                   ("Hill Cipher", "hill")]
        
        for text, value in ciphers:
            tk.Radiobutton(master, text=text, variable=self.cipher_var, value=value).pack()

        self.input_label = tk.Label(master, text="Masukkan Pesan:")
        self.input_label.pack()

        self.input_text = tk.Text(master, height=5)
        self.input_text.pack()

        self.key_label = tk.Label(master, text="Masukkan Kunci (min. 12 karakter):")
        self.key_label.pack()

        self.key_entry = tk.Entry(master)
        self.key_entry.pack()

        self.upload_button = tk.Button(master, text="Upload File", command=self.upload_file)
        self.upload_button.pack()

        self.encrypt_button = tk.Button(master, text="Enkripsi", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Dekripsi", command=self.decrypt)
        self.decrypt_button.pack()

        self.result_label = tk.Label(master, text="Hasil:")
        self.result_label.pack()

        self.result_text = tk.Text(master, height=5)
        self.result_text.pack()

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                self.input_text.delete('1.0', tk.END)
                self.input_text.insert(tk.END, content)

    def encrypt(self):
        plaintext = self.input_text.get('1.0', tk.END).strip()
        key = self.key_entry.get()

        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter!")
            return

        cipher_method = self.cipher_var.get()
        if cipher_method == "vigenere":
            result = self.vigenere_cipher(plaintext, key, True)
        elif cipher_method == "playfair":
            result = self.playfair_cipher(plaintext, key, True)
        elif cipher_method == "hill":
            result = self.hill_cipher(plaintext, key, True)

        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, result)

    def decrypt(self):
        ciphertext = self.input_text.get('1.0', tk.END).strip()
        key = self.key_entry.get()

        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter!")
            return

        cipher_method = self.cipher_var.get()
        if cipher_method == "vigenere":
            result = self.vigenere_cipher(ciphertext, key, False)
        elif cipher_method == "playfair":
            result = self.playfair_cipher(ciphertext, key, False)
        elif cipher_method == "hill":
            result = self.hill_cipher(ciphertext, key, False)

        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, result)

    def vigenere_cipher(self, text, key, encrypt=True):
        result = ""
        key_length = len(key)
        text = re.sub(r'[^a-zA-Z]', '', text.upper())
        key = key.upper()

        for i in range(len(text)):
            char = text[i]
            key_char = key[i % key_length]
            if encrypt:
                result += chr((ord(char) + ord(key_char) - 2 * ord('A')) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord(key_char) + 26) % 26 + ord('A'))

        return result

    def playfair_cipher(self, text, key, encrypt=True):
        def create_matrix(key):
            key = re.sub(r'[^A-Z]', '', key.upper().replace('J', 'I'))
            matrix = list(dict.fromkeys(key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ'))
            return [matrix[i:i+5] for i in range(0, 25, 5)]

        def find_position(matrix, char):
            for i, row in enumerate(matrix):
                if char in row:
                    return i, row.index(char)

        matrix = create_matrix(key)
        text = re.sub(r'[^A-Z]', '', text.upper().replace('J', 'I'))
        if len(text) % 2 != 0:
            text += 'X'

        result = ""
        for i in range(0, len(text), 2):
            row1, col1 = find_position(matrix, text[i])
            row2, col2 = find_position(matrix, text[i+1])

            if row1 == row2:
                if encrypt:
                    result += matrix[row1][(col1+1)%5] + matrix[row2][(col2+1)%5]
                else:
                    result += matrix[row1][(col1-1)%5] + matrix[row2][(col2-1)%5]
            elif col1 == col2:
                if encrypt:
                    result += matrix[(row1+1)%5][col1] + matrix[(row2+1)%5][col2]
                else:
                    result += matrix[(row1-1)%5][col1] + matrix[(row2-1)%5][col2]
            else:
                result += matrix[row1][col2] + matrix[row2][col1]

        return result

    def hill_cipher(self, text, key, encrypt=True):
        def matrix_mult(matrix1, matrix2):
            result = [[0 for _ in range(len(matrix2[0]))] for _ in range(len(matrix1))]
            for i in range(len(matrix1)):
                for j in range(len(matrix2[0])):
                    for k in range(len(matrix2)):
                        result[i][j] += matrix1[i][k] * matrix2[k][j]
            return result

        def matrix_mod(matrix, m):
            return [[elem % m for elem in row] for row in matrix]

        def matrix_inverse(matrix, m):
            det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % m
            if det == 0 or det % 2 == 0 or det % 13 == 0:
                raise ValueError(f"Matriks kunci tidak dapat diinversikan. Determinan: {det}")
            det_inv = pow(det, -1, m)
            return [
                [(matrix[1][1] * det_inv) % m, (-matrix[0][1] * det_inv) % m],
                [(-matrix[1][0] * det_inv) % m, (matrix[0][0] * det_inv) % m]
            ]

        key = re.sub(r'[^A-Z]', '', key.upper())
        key_matrix = [[ord(key[i]) - ord('A') for i in range(j, j+2)] for j in range(0, 4, 2)]
        text = re.sub(r'[^A-Z]', '', text.upper())
        if len(text) % 2 != 0:
            text += 'X'

        print(f"Key matrix: {key_matrix}")
        print(f"{'Plaintext' if encrypt else 'Ciphertext'}: {text}")

        result = ""
        try:
            if not encrypt:
                inv_key = matrix_inverse(key_matrix, 26)
                print(f"Inverse key matrix: {inv_key}")
            
            for i in range(0, len(text), 2):
                pair = [[ord(text[i]) - ord('A')], [ord(text[i+1]) - ord('A')]]
                if encrypt:
                    encrypted = matrix_mod(matrix_mult(key_matrix, pair), 26)
                else:
                    encrypted = matrix_mod(matrix_mult(inv_key, pair), 26)
                result += chr(encrypted[0][0] + ord('A')) + chr(encrypted[1][0] + ord('A'))
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return ""
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
            return ""

        print(f"{'Ciphertext' if encrypt else 'Plaintext'}: {result}")
        return result

root = tk.Tk()
app = CipherApp(root)
root.mainloop()