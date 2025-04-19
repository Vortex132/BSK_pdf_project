import io
import os

from pathlib import Path
from typing import Optional, Self

from cryptography.hazmat.primitives import ciphers, hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, utils
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.exceptions import InvalidSignature


class Signer:
    """
    Class to handle signing and verifying files using RSA keys.
    It uses private and public keys to sign and verify documents.
    The private key is used to sign the document, and the public key is used to verify the authenticity of signature.
    The class also allows to generate new keys and save them.
    """
    def __init__(self, private_key: "Optional[rsa.RSAPrivateKey]"=None, public_key: "Optional[rsa.RSAPublicKey]"=None,):
        """
        Initialize the Signer with a private key and a public key.
        If a private key is provided, the public key is derived from it.
        If only a public key is provided, it is used as is.
        
        :param private_key: The private key to use for signing.
        :param public_key: The public key to use for verifying the authenticity of signatures.
        """
        self.private_key = private_key
        if self.private_key is not None:
            self.public_key = self.private_key.public_key()
        else:
            self.public_key = public_key

        if self.public_key is None:
            msg = "Public key doesn't exist"
            raise ValueError(msg)
        
    def __str__(self):
        """
        Return the string representation of the Signer.
        Returns the public key in PEM format.
        """
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return f"{'private' if self.private_key is not None else 'public'}\n {pem.decode()}"

    def can_sign(self) -> bool:
        """
        Check if Signer can sign files.
        Is true if a private key is available.
        """
        return self.private_key is not None

    def sign(self, file: "io.BufferedReader | str | os.PathLike[str]") -> bytes:
        """
        Sign a file using the private key (if available).
        The file is hashed using SHA256 hash and then signed using PSS padding.

        :param file: The path to the file to sign.
        :return: The signature of the file.
        """
        if self.private_key is None:
            msg = "no private key found"
            raise ValueError(msg)
        
        try:
        
            chosen_hash = hashes.SHA256()

            digest = self._hash_file(chosen_hash, file)

            sig = self.private_key.sign(
                digest,
                apadding.PSS(
                    mgf=apadding.MGF1(hashes.SHA256()),
                    salt_length=apadding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(chosen_hash)
            )

            return sig

        except Exception as e:
            msg = "signing failed"
            raise ValueError(msg)

    def easy_sign(self, path: "str | os.PathLike[str]"):
        """
        Sign a file using the private key (if available).
        The signature is saved in a file with the same name as the original file.

        :param path: The path to the file to sign.
        """
        sig_path = self._sig_path(path)
        sig_path.write_bytes(self.sign(path))

    def easy_verify(self, path: "str | os.PathLike[str]") -> bool:
        """
        Verify a file using the public key (if available).
        The signature is read from a file with the same name as the original file.

        :param path: The path to the file to verify the authenticity.
        :return: True if signature is valid, False if not.
        """
        sig_path = self._sig_path(path)
        sig = sig_path.read_bytes()
        return self.verify(path, sig)


    def verify(self, file: "io.BufferedReader | str | os.PathLike[str]", sig: bytes) -> bool:
        """
        Verify a file using the public key (if available).
        The file is hashed using SHA256 hash and then verified using PSS padding.

        :param file: The path to the file to verify the authenticity.
        :param sig: The signature of the file.
        :return: True if signature is valid, False if not.
        """
        try:
            chosen_hash = hashes.SHA256()

            digest = self._hash_file(chosen_hash, file)

            self.public_key.verify(
                sig,
                digest,
                apadding.PSS(
                    mgf=apadding.MGF1(hashes.SHA256()),
                    salt_length=apadding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(chosen_hash)
            )
        except InvalidSignature as e:
            return False
        except Exception as e:
            msg = "verification failed"
            raise ValueError(msg)
        
        return True

    def to_file(self, key_file: "io.BufferedWriter | str | os.PathLike[str]", password: bytes) -> None:
        """
        Serialize the private key to a given file.
        The private key is encrypted using a password.
        The file is saved in PEM format.

        :param key_file: The path to the file to save the private key.
        :param password: The password to encrypt the private key.
        """
        if self.private_key is None:
            msg = "No private key found"
            raise ValueError(msg)

        try:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()
            )

            enc_pem = self._encrypt(pem, password)

            if isinstance(key_file, str) or isinstance(key_file, os.PathLike):
                Path(key_file).write_bytes(enc_pem)
            else:
                key_file.write(enc_pem)
        except Exception as e:
            msg = "serialization failed"
            raise ValueError(msg) from e

    @classmethod
    def from_file(cls, key_file: "io.BufferedReader | str | os.PathLike[str]", password: bytes) -> "Self":
        """
        Deserialize the private key from a given file.
        The private key is decrypted using a password.
        The file is read in PEM format.

        :param key_file: The path to the file to read the private key.
        :param password: The password to the private key.
        """
        try:
            if isinstance(key_file, str) or isinstance(key_file, os.PathLike):
                content = Path(key_file).read_bytes()
            else:
                content = key_file.read()

            pem = cls._decrypt(content, password)

            private_key = serialization.load_ssh_private_key(data=pem, password=None)

            return cls(private_key=private_key)
        except Exception as e:
            msg = "deserialization failed"
            raise ValueError(msg) from e

    def to_file_pub(self, pub_file: "io.BufferedWriter | str | os.PathLike[str]") -> None:
        """
        Serialize the public key to a given file.
        The file is saved in OpenSSH format.

        :param pub_file: The path to the file to save the public key.
        """
        try:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )

            if isinstance(pub_file, str) or isinstance(pub_file, os.PathLike):
                Path(pub_file).write_bytes(pem)
            else:
                pub_file.write(pem)
        except Exception as e:
            msg = "pub serialization failed"
            raise ValueError(msg) from e

    @classmethod
    def from_file_pub(cls, pub_file: "io.BufferedWriter | str | os.PathLike[str]") -> "Self":
        """
        Deserialize the public key from a given file.
        The file is read in OpenSSH format.

        :param pub_file: The path to the file to read the public key.
        :return: The public key.
        """
        try:
            if isinstance(pub_file, str) or isinstance(pub_file, os.PathLike):
                content = Path(pub_file).read_bytes()
            else:
                content = pub_file.read()

            public_key = serialization.load_ssh_public_key(data=content)

            return cls(public_key=public_key)
        except Exception as e:
            msg = "pub deserialization failed"
            raise ValueError(msg) from e
            

    @classmethod
    def generate(cls, key_size=4096) -> "Self":
        """
        Generate a new RSA key.
        The private key is used for signing.
        The key size is set to 4096 bits.

        :param key_size: The size of the key to generate.
        :return: The generated RSA key.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        return cls(private_key=private_key)
    @classmethod
    def _get_kdf(cls, salt) -> pbkdf2.PBKDF2HMAC:
        """
        Get the key derivation function (KDF) for the given salt.
        The KDF is used to get a key from the password.
        The KDF is PBKDF2 with SHA256 hash algorithm.
        The length of the key is set to 32 bytes.
        The number of iterations is set to 1,500,000.

        :param salt: The salt to use for the KDF.
        :return: The KDF.
        """
        return pbkdf2.PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_500_000
        )

    @classmethod
    def _encrypt(cls, plain_text: bytes, password: bytes):
        """
        Encrypt the given plain text using AES256 encryption in CBC mode.
        The key is derived from the password using PBKDF2 KDF.
        The salt and iv is generated randomly.

        :param plain_text: The text to encrypt.
        :param password: The password to use for encryption.
        :return: The encrypted text.
        """
        salt = os.urandom(16)
        kdf = cls._get_kdf(salt)
        pass_key = kdf.derive(password)
        
        iv = os.urandom(16)
        cipher = ciphers.Cipher(algorithms.AES256(pass_key), modes.CBC(iv))

        enc = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plain_text) + padder.finalize()

        cipher_text = enc.update(padded_data) + enc.finalize()
        return salt + iv + cipher_text

    @classmethod
    def _decrypt(cls, cipher_text: bytes, password: bytes):
        """
        Decrypt the given cipher text using AES256 dencryption in CBC mode.
        The key is derived from the password using PBKDF2 KDF.
        The salt and iv is transformed from the cipher text.

        :param cipher_text: The text to decrypt.
        :param password: The password to use for dencryption.
        :return: The decrypted text.
        """
        salt = cipher_text[:16]

        kdf = cls._get_kdf(salt)
        pass_key = kdf.derive(password)

        iv = cipher_text[16:32]
        cipher_text = cipher_text[32:]
        cipher = ciphers.Cipher(algorithms.AES256(pass_key), modes.CBC(iv))

        dec = cipher.decryptor()

        padded_data = dec.update(cipher_text) + dec.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(padded_data) + unpadder.finalize()

        return unpadded_data

    @classmethod
    def _hash_file(cls, hash: hashes.HashAlgorithm, file: "io.BufferedReader | str | os.PathLike[str]"):
        """
        Hash the given file using a given hash algorithm.
        The file is read in chunks and the hash is updated with each chunk.

        :param hash: The hash algorithm to use.
        :param file: The path to the file to hash.
        :return: The hash of the file.
        """
        should_close = False
        if isinstance(file, str) or isinstance(file, os.PathLike):
            file = open(file, "rb")
            should_close = True

        try:
            hasher = hashes.Hash(hash)
            while (chunk := file.read(1_000_000)):
                hasher.update(chunk)
            
            return hasher.finalize()
        finally:
            if should_close:
                file.close()

    @classmethod
    def _sig_path(cls, path: "str | os.PathLike[str]") -> "Path":
        """
        Get the path to the signature file.

        :param path: The path to the original file.
        :return: The path to the signature file.
        """
        
        path = Path(path).resolve()

        if not path.name:
            raise ValueError()

        return path.parent / f"{path.name}.sig"
