# client.py - Dosya gönderen istemci
import socket
import os
import hashlib
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes, serialization

def encrypt_file_with_aes(file_path, key):
    # Dosyayı AES ile şifreleme
    iv = secrets.token_bytes(16)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    
    padder = padding.PKCS7(128).padder()
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    padded_data = padder.update(file_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + encrypted_data 

def calculate_sha256(data):
    # SHA-256 özeti hesaplama
    return hashlib.sha256(data).digest()

def start_client(server_address, file_path):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)
    print(f"Sunucuya bağlandı: {server_address}")
    
    # Sunucudan RSA public key al
    server_public_key_pem = client_socket.recv(2048)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem,
        backend=default_backend()
    )
    
    # AES anahtarı oluştur
    aes_key = secrets.token_bytes(32)  # 256-bit AES anahtarı
    
    # AES anahtarını RSA ile şifrele
    encrypted_aes_key = server_public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Şifrelenmiş AES anahtarını gönder
    client_socket.send(encrypted_aes_key)
    
    # Dosyayı AES ile şifrele
    encrypted_file = encrypt_file_with_aes(file_path, aes_key)
    
    # Dosya hash'i hesapla ve gönder
    file_hash = calculate_sha256(open(file_path, 'rb').read())
    
    print("Şifreli dosya gönderiliyor...")

    # Dosya gönder
    client_socket.sendall(encrypted_file)

    print("Dosya gönderimi tamamlandı.")
    client_socket.close()


if __name__ == "__main__":
    server_address = ('localhost', 9999)
    file_path = 'example.txt'  # Gönderilecek dosya
    start_client(server_address, file_path)