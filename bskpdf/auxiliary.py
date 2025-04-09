import dearpygui.dearpygui as dpg
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os
import secrets

RSA_KEY_SIZE = 4096
RSA_PUBLIC_EXPONENT = 65537
SALT_LENGTH = 16
AES_KEY_LENGTH = 32
ITERATIONS = 100000
HASH_ALGORITHM = hashes.SHA256()
PRIVATE_KEY_FILENAME = "klucz_prywatny.key"
PUBLIC_KEY_FILENAME = "klucz_publiczny.key.pub"

class RSAKeys:
    
    def __init__(self):
        self.pin = ""
        self.pendrive_dir = ""
        self.public_key_dir = ""
        
        dpg.create_context()
        dpg.create_viewport(title='Generator Kluczy RSA', width=800, height=600)
        self.setup_ui()
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("Main Window", True)
        dpg.start_dearpygui()
        dpg.destroy_context()

    def setup_ui(self):
        with dpg.window(tag="Main Window", width=800, height=600):
            dpg.add_text("Generator Kluczy RSA", color=(0, 200, 255))
            dpg.add_spacer(height=20)
            
            # Wprowadz PIN
            with dpg.group(horizontal=True):
                dpg.add_text("Wpisz PIN:")
                dpg.add_input_text(tag="pin_input", password=True, width=200)
            dpg.add_spacer(height=15)
            
            # Wybor pendrivea
            dpg.add_button(label="Wybierz pendrive", callback=lambda: dpg.show_item("pendrive_dialog"))
            dpg.add_text(tag="pendrive_path", default_value="Brak wybranego pendrivea")
            dpg.add_spacer(height=20)

             # Wybor lokalizacji klucza publicznego
            dpg.add_button(label="Wybierz lokalizacje zapisu klucza publicznego", callback=lambda: dpg.show_item("file_dialog"))
            dpg.add_text(tag="public_key_path", default_value="Brak wybranej sciezki")
            dpg.add_spacer(height=20)
            
            dpg.add_button(label="Wygeneruj i zapisz klucze", callback=self.generate_keys)
            dpg.add_spacer(height=10)
            
            dpg.add_text(tag="status", default_value="", color=(0, 255, 0))

        # Okno dialogowe do wyboru pendrivea
        with dpg.file_dialog(
            directory_selector=True,
            show=False,
            callback=self.pendrive_dialog_callback,
            tag="pendrive_dialog",
            width=500, 
            height=400
        ):
            dpg.add_file_extension(".*")

        # To samo ale do lokalizacju publicznego klucza
        with dpg.file_dialog(
            directory_selector=True,
            show=False,
            callback=self.file_dialog_callback,
            tag="file_dialog",
            width=500, 
            height=400
        ):
            dpg.add_file_extension(".*")

    def pendrive_dialog_callback(self, _, app_data):
        self.pendrive_dir = app_data['file_path_name']
        dpg.set_value("pendrive_path", f"Wybrane: {self.pendrive_dir}")

    def file_dialog_callback(self, _, app_data):
        self.public_key_dir = app_data['file_path_name']
        dpg.set_value("public_key_path", f"Wybrane: {self.public_key_dir}")

    def generate_keys(self):
        self.pin = dpg.get_value("pin_input")
        
        if len(self.pin) <= 0:
            dpg.set_value("status", "Wpisz PIN")
            dpg.configure_item("status", color=(255, 0, 0))
            return
        
        if not self.pendrive_dir:
            dpg.set_value("status", "Wybierz pendrive")
            dpg.configure_item("status", color=(255, 0, 0))
            return
        
        if not self.public_key_dir:
            dpg.set_value("status", "Wybierz lokalizacje klucza publicznego")
            dpg.configure_item("status", color=(255, 0, 0))
            return

        try:
            # Generuj klucze
            private_key = rsa.generate_private_key(
                public_exponent=self.RSA_PUBLIC_EXPONENT,
                key_size=self.RSA_KEY_SIZE,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Generowanie klucza AES z PINu
            salt = secrets.token_bytes(self.SALT_LENGTH)
            kdf = PBKDF2HMAC(algorithm=self.HASH_ALGORITHM, length=self.AES_KEY_LENGTH, salt=salt, iterations=self.ITERATIONS, backend=default_backend())
            aes_key = base64.urlsafe_b64encode(kdf.derive(self.pin.encode()))

            # Szyfrowanie prywatnego klucza
            pem_private = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
            
            fernet = Fernet(aes_key)
            encrypted_private = fernet.encrypt(pem_private)

            private_key_path = os.path.join(self.pendrive_dir, self.PRIVATE_KEY_FILENAME)
            public_key_path = os.path.join(self.public_key_dir, self.PUBLIC_KEY_FILENAME)
            
            with open(private_key_path, "wb") as f:
                f.write(salt + encrypted_private)
            
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

            dpg.set_value("status", "Klucze wygenerowane")
            dpg.configure_item("status", color=(0, 0, 255))

        except Exception as e:
            dpg.set_value("status", f"Error: {str(e)}")

if __name__ == "__main__":
    app = RSAKeys()