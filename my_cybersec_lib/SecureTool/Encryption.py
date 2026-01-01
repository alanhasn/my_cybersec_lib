"""
Encryption and decryption utilities for SecureTool.

This module provides various encryption/decryption methods and cryptographic utilities.
"""

import base64
import hashlib
import secrets
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class Encryption:
    """
    A class for encryption and decryption operations.

    Methods
    -------
    generate_key()
        Generate a new encryption key.

    encrypt_data(data, key)
        Encrypt data using Fernet symmetric encryption.

    decrypt_data(encrypted_data, key)
        Decrypt data using Fernet symmetric encryption.

    hash_data(data, algorithm)
        Hash data using various algorithms.

    generate_key_from_password(password, salt)
        Generate encryption key from a password.
    """

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a new encryption key.

        Returns
        -------
        bytes
            Generated encryption key (base64 encoded).
        """
        return Fernet.generate_key()

    @staticmethod
    def encrypt_data(data: str, key: Optional[bytes] = None) -> dict:
        """
        Encrypt data using Fernet symmetric encryption.

        Parameters
        ----------
        data : str
            Data to encrypt.
        key : bytes, optional
            Encryption key. If None, a new key will be generated.

        Returns
        -------
        dict
            Dictionary containing encrypted data and key.
        """
        if key is None:
            key = Encryption.generate_key()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data.encode('utf-8'))

        return {
            "encrypted_data": base64.b64encode(encrypted).decode('utf-8'),
            "key": base64.b64encode(key).decode('utf-8')
        }

    @staticmethod
    def decrypt_data(encrypted_data: str, key: str) -> dict:
        """
        Decrypt data using Fernet symmetric encryption.

        Parameters
        ----------
        encrypted_data : str
            Base64 encoded encrypted data.
        key : str
            Base64 encoded encryption key.

        Returns
        -------
        dict
            Dictionary containing decrypted data or error message.
        """
        try:
            key_bytes = base64.b64decode(key)
            encrypted_bytes = base64.b64decode(encrypted_data)

            fernet = Fernet(key_bytes)
            decrypted = fernet.decrypt(encrypted_bytes)

            return {
                "decrypted_data": decrypted.decode('utf-8')
            }
        except Exception as e:
            return {
                "error": f"Decryption failed: {str(e)}"
            }

    @staticmethod
    def hash_data(data: str, algorithm: str = "sha256") -> dict:
        """
        Hash data using various algorithms.

        Parameters
        ----------
        data : str
            Data to hash.
        algorithm : str, optional
            Hash algorithm (md5, sha1, sha256, sha512, blake2b). Defaults to "sha256".

        Returns
        -------
        dict
            Dictionary containing hash algorithm and hash value.
        """
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
            "blake2b": hashlib.blake2b
        }

        if algorithm.lower() not in algorithms:
            return {
                "error": f"Unsupported algorithm. Choose from: {list(algorithms.keys())}"
            }

        hash_func = algorithms[algorithm.lower()]()
        hash_func.update(data.encode('utf-8'))
        hash_value = hash_func.hexdigest()

        return {
            "algorithm": algorithm.upper(),
            "hash": hash_value
        }

    @staticmethod
    def generate_key_from_password(password: str, salt: Optional[bytes] = None) -> dict:
        """
        Generate encryption key from a password using PBKDF2.

        Parameters
        ----------
        password : str
            Password to derive key from.
        salt : bytes, optional
            Salt for key derivation. If None, a random salt will be generated.

        Returns
        -------
        dict
            Dictionary containing derived key and salt.
        """
        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

        return {
            "key": base64.b64encode(key).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8')
        }

    @staticmethod
    def verify_hash(data: str, hash_value: str, algorithm: str = "sha256") -> bool:
        """
        Verify data against a hash.

        Parameters
        ----------
        data : str
            Data to verify.
        hash_value : str
            Hash to compare against.
        algorithm : str, optional
            Hash algorithm used. Defaults to "sha256".

        Returns
        -------
        bool
            True if hash matches, False otherwise.
        """
        computed_hash = Encryption.hash_data(data, algorithm)
        if "error" in computed_hash:
            return False
        return computed_hash["hash"].lower() == hash_value.lower()

