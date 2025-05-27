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

def start_client(server_address, file_path, protocol='TCP'):
    """
    Dosyayı belirtilen protokol (TCP veya UDP) ile sunucuya gönderir.
    
    Args:
        server_address: (host, port) tuple
        file_path: Gönderilecek dosyanın yolu
        protocol: 'TCP' veya 'UDP' (varsayılan: 'TCP')
    """
    protocol = protocol.upper()
    
    if protocol == 'TCP':
        return send_file_tcp(server_address, file_path)
    elif protocol == 'UDP':
        return send_file_udp(server_address, file_path)
    else:
        raise ValueError("Protocol 'TCP' veya 'UDP' olmalıdır")

def send_file_tcp(server_address, file_path):
    """TCP ile dosya gönderimi"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect(server_address)
        print(f"TCP sunucusuna bağlandı: {server_address}")
        
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
        
        # Dosya hash'i hesapla
        file_hash = calculate_sha256(open(file_path, 'rb').read())
        
        print("TCP ile şifreli dosya gönderiliyor...")
        
        # Dosya boyutunu önce gönder
        file_size = len(encrypted_file)
        client_socket.send(file_size.to_bytes(8, byteorder='big'))
        
        # Dosyayı gönder
        client_socket.sendall(encrypted_file)
        
        print("TCP dosya gönderimi tamamlandı.")
        
    except Exception as e:
        print(f"TCP gönderim hatası: {e}")
        raise
    finally:
        client_socket.close()

def send_file_udp(server_address, file_path):
    """UDP ile dosya gönderimi (chunk'lar halinde)"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        print(f"UDP sunucusuna bağlanılıyor: {server_address}")
        
        # UDP için handshake başlat
        client_socket.sendto(b"HANDSHAKE_REQUEST", server_address)
        
        # Sunucudan RSA public key al
        server_public_key_pem, _ = client_socket.recvfrom(2048)
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
        client_socket.sendto(encrypted_aes_key, server_address)
        
        # Dosyayı AES ile şifrele
        encrypted_file = encrypt_file_with_aes(file_path, aes_key)
        
        # Dosya hash'i hesapla
        file_hash = calculate_sha256(open(file_path, 'rb').read())
        
        print("UDP ile şifreli dosya gönderiliyor...")
        
        # UDP için dosyayı chunk'lar halinde gönder
        chunk_size = 1024  # UDP için uygun chunk boyutu
        total_chunks = (len(encrypted_file) + chunk_size - 1) // chunk_size
        
        # Toplam chunk sayısını gönder
        client_socket.sendto(f"TOTAL_CHUNKS:{total_chunks}".encode(), server_address)
        
        # Dosyayı chunk'lar halinde gönder
        for i in range(0, len(encrypted_file), chunk_size):
            chunk = encrypted_file[i:i + chunk_size]
            chunk_number = i // chunk_size
            
            # Chunk numarası ve veriyi birlikte gönder
            message = f"CHUNK:{chunk_number}:".encode() + chunk
            client_socket.sendto(message, server_address)
            
            # Küçük bir gecikme ekle (network yoğunluğunu azaltmak için)
            import time
            time.sleep(0.001)
        
        # Gönderim tamamlandı sinyali
        client_socket.sendto(b"TRANSFER_COMPLETE", server_address)
        
        print("UDP dosya gönderimi tamamlandı.")
        
    except Exception as e:
        print(f"UDP gönderim hatası: {e}")
        raise
    finally:
        client_socket.close()



if __name__ == "__main__":
    server_address = ('localhost', 9999)
    file_path = 'example.txt'  # Gönderilecek dosya
    start_client(server_address, file_path)