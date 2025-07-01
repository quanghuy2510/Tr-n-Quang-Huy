import base64
import hashlib
import os
from Crypto.Cipher import AES, PKCS1_OAEP  # Thay đổi: DES -> AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class CryptoUtils:
    """Utilities for RSA and AES encryption/decryption"""

    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """Tạo cặp khóa RSA"""
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key, key

    @staticmethod
    def generate_aes_key(key_size=32):
        """Tạo khóa AES (16 for AES-128, 24 for AES-192, 32 for AES-256)"""
        return get_random_bytes(key_size)

    @staticmethod
    def encrypt_aes_cbc(data, key):
        """Mã hóa dữ liệu bằng AES-CBC"""
        iv = get_random_bytes(AES.block_size)  # Kích thước khối của AES là 16 bytes
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext

    @staticmethod
    def decrypt_aes_cbc(encrypted_data, key):
        """Giải mã dữ liệu AES-CBC"""
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, AES.block_size)

    @staticmethod
    def encrypt_rsa_oaep(data, public_key):
        """Mã hóa dữ liệu bằng RSA-OAEP"""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        return cipher.encrypt(data)

    @staticmethod
    def decrypt_rsa_oaep(encrypted_data, private_key):
        """Giải mã dữ liệu RSA-OAEP"""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        return cipher.decrypt(encrypted_data)

    @staticmethod
    def sign_rsa_pss(data, private_key):
        """Ký dữ liệu bằng RSA-PSS với SHA-256"""
        rsa_key = RSA.import_key(private_key)
        h = SHA256.new(data)
        signature = pkcs1_15.new(rsa_key).sign(h)
        return signature

    @staticmethod
    def verify_rsa_pss(data, signature, public_key):
        """Xác thực chữ ký RSA-PSS"""
        try:
            rsa_key = RSA.import_key(public_key)
            h = SHA256.new(data)
            pkcs1_15.new(rsa_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def calculate_sha256(data):
        """Tính hash SHA-256"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def encode_base64(data):
        """Encode dữ liệu thành base64"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def decode_base64(encoded_data):
        """Decode dữ liệu từ base64"""
        return base64.b64decode(encoded_data)

class SecureMessageHandler:
    """Xử lý tin nhắn âm thanh bảo mật"""

    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key
        self.session_keys = {}  # {peer_id: aes_key}

    def set_keys(self, private_key, public_key):
        """Thiết lập cặp khóa RSA"""
        self.private_key = private_key
        self.public_key = public_key

    def create_session_key(self, peer_id, key_size=32):
        """Tạo khóa session AES cho peer"""
        aes_key = CryptoUtils.generate_aes_key(key_size)
        self.session_keys[peer_id] = aes_key
        return aes_key

    def encrypt_voice_message(self, audio_data, peer_id):
        """Mã hóa tin nhắn âm thanh"""
        if peer_id not in self.session_keys:
            raise ValueError(f"No session key found for peer {peer_id}")

        aes_key = self.session_keys[peer_id]
        encrypted_audio = CryptoUtils.encrypt_aes_cbc(audio_data, aes_key)
        audio_hash = CryptoUtils.calculate_sha256(encrypted_audio)
        signature = CryptoUtils.sign_rsa_pss(audio_hash.encode(), self.private_key)

        return {
            'cipher': CryptoUtils.encode_base64(encrypted_audio),
            'hash': audio_hash,
            'sig': CryptoUtils.encode_base64(signature)
        }

    def decrypt_voice_message(self, encrypted_message, peer_id, peer_public_key):
        """Giải mã tin nhắn âm thanh"""
        try:
            cipher_data = CryptoUtils.decode_base64(encrypted_message['cipher'])
            signature = CryptoUtils.decode_base64(encrypted_message['sig'])
            received_hash = encrypted_message['hash']

            calculated_hash = CryptoUtils.calculate_sha256(cipher_data)
            if calculated_hash != received_hash:
                print(f"Hash verification failed for message from {peer_id}")
                return None

            if not CryptoUtils.verify_rsa_pss(received_hash.encode(), signature, peer_public_key):
                print(f"Signature verification failed for message from {peer_id}")
                return None

            if peer_id not in self.session_keys:
                print(f"No session key found for peer {peer_id}")
                return None

            aes_key = self.session_keys[peer_id]
            decrypted_audio = CryptoUtils.decrypt_aes_cbc(cipher_data, aes_key)
            return decrypted_audio

        except Exception as e:
            print(f"Error decrypting message from {peer_id}: {e}")
            return None

    def create_key_exchange_package(self, peer_id, peer_public_key, metadata=None):
        """Tạo gói trao đổi khóa"""
        aes_key = self.create_session_key(peer_id)
        if metadata is None:
            import time
            metadata = f"{peer_id}:{int(time.time())}"

        signature = CryptoUtils.sign_rsa_pss(metadata.encode(), self.private_key)
        encrypted_session_key = CryptoUtils.encrypt_rsa_oaep(aes_key, peer_public_key)

        return {
            'signed_info': CryptoUtils.encode_base64(signature),
            'encrypted_session_key': CryptoUtils.encode_base64(encrypted_session_key),
            'metadata': metadata
        }

    def process_key_exchange(self, key_package, peer_id, peer_public_key):
        """Xử lý gói trao đổi khóa từ peer"""
        try:
            signature = CryptoUtils.decode_base64(key_package['signed_info'])
            encrypted_session_key = CryptoUtils.decode_base64(key_package['encrypted_session_key'])
            metadata = key_package['metadata']

            if not CryptoUtils.verify_rsa_pss(metadata.encode(), signature, peer_public_key):
                print(f"Key exchange signature verification failed from {peer_id}")
                return False

            aes_key = CryptoUtils.decrypt_rsa_oaep(encrypted_session_key, self.private_key)
            self.session_keys[peer_id] = aes_key
            print(f"Key exchange successful with {peer_id}")
            return True

        except Exception as e:
            print(f"Error processing key exchange from {peer_id}: {e}")
            return False

    def get_session_key(self, peer_id):
        """Lấy khóa session cho peer"""
        return self.session_keys.get(peer_id)

    def remove_session_key(self, peer_id):
        """Xóa khóa session của peer"""
        if peer_id in self.session_keys:
            del self.session_keys[peer_id]