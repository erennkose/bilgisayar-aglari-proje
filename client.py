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
        file_path: Gönderilecek dosya yolu
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
        
        # Dosya uzantısını gönder
        file_extension = os.path.splitext(file_path)[1]
        if not file_extension:
            file_extension = '.txt'  # Varsayılan uzantı
        client_socket.send(file_extension.encode())
        
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
        
        print("TCP ile şifreli dosya gönderiliyor...")
        
        # Dosyayı gönder
        client_socket.sendall(encrypted_file)
        
        print("TCP dosya gönderimi tamamlandı.")
        
    except Exception as e:
        print(f"TCP gönderim hatası: {e}")
        raise
    finally:
        client_socket.close()

def send_file_udp(server_address, file_path):
    """UDP ile dosya gönderimi"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65507)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65507)
    client_socket.settimeout(30.0)
    
    try:
        print(f"UDP sunucusuna bağlanılıyor: {server_address}")
        
        # Sunucudan public key iste
        client_socket.sendto(b"REQUEST_PUBLIC_KEY", server_address)
        
        # Public key chunk sayısını al
        chunk_count_data, _ = client_socket.recvfrom(1024)
        chunk_count = int(chunk_count_data.decode())
        print(f"Public key {chunk_count} parça halinde alınacak")
        
        # Public key parçalarını al
        chunks = {}
        for _ in range(chunk_count):
            data, _ = client_socket.recvfrom(2048)
            chunk_num = int(data.split(b':')[0])
            chunk_data = data[data.index(b':') + 1:]
            chunks[chunk_num] = chunk_data
        
        # Parçaları birleştir
        server_public_key_pem = b''.join(chunks[i] for i in sorted(chunks.keys()))
        server_public_key = serialization.load_pem_public_key(
            server_public_key_pem,
            backend=default_backend()
        )
        print("Public key başarıyla alındı")
        
        # Dosya uzantısını gönder
        file_extension = os.path.splitext(file_path)[1]
        if not file_extension:
            file_extension = '.txt'  # Varsayılan uzantı
        client_socket.sendto(file_extension.encode(), server_address)
        print(f"Dosya uzantısı gönderildi: {file_extension}")
        
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
        print("AES anahtarı gönderildi")
        
        # Dosyayı AES ile şifrele
        encrypted_file = encrypt_file_with_aes(file_path, aes_key)
        
        print("UDP ile şifreli dosya gönderiliyor...")
        
        # Dosya boyutunu gönder
        file_size = len(encrypted_file)
        client_socket.sendto(str(file_size).encode(), server_address)
        print(f"Dosya boyutu gönderildi: {file_size} bytes")
        
        # Dosyayı chunk'lar halinde gönder
        chunk_size = 4000  # UDP için güvenli boyut
        sent_bytes = 0
        
        for i in range(0, len(encrypted_file), chunk_size):
            chunk = encrypted_file[i:i + chunk_size]
            chunk_num = i // chunk_size
            numbered_chunk = str(chunk_num).encode() + b':' + chunk
            client_socket.sendto(numbered_chunk, server_address)
            
            if sent_bytes % (chunk_size * 10) == 0:  # Her 10 chunk'ta bir bilgi ver
                print(f"Gönderilen: {sent_bytes}/{file_size} bytes ({sent_bytes/file_size*100:.1f}%)")
        
        print("UDP dosya gönderimi tamamlandı.")
        
    except Exception as e:
        print(f"UDP gönderim hatası: {e}")
        raise
    finally:
        client_socket.close()

if __name__ == "__main__":
    import sys
    
    # Varsayılan değerler
    server_host = 'localhost'
    server_port = 8080
    file_path = 'example.txt'
    protocol = 'UDP'
    
    # Komut satırı argümanları
    if len(sys.argv) >= 2:
        protocol = sys.argv[1]
    if len(sys.argv) >= 3:
        server_host = sys.argv[2]  
    if len(sys.argv) >= 4:
        server_port = int(sys.argv[3])
    if len(sys.argv) >= 5:
        file_path = sys.argv[4]
    
    server_address = (server_host, server_port)
    
    # Dosya varlığını kontrol et
    if not os.path.exists(file_path):
        # Test dosyası oluştur
        with open(file_path, 'w') as f:
            f.write("Bu bir test dosyasıdır.\nUDP ile güvenli dosya transferi testi.\n" * 100)
        print(f"Test dosyası oluşturuldu: {file_path}")
    
    print(f"Protokol: {protocol}")
    print(f"Sunucu: {server_address}")
    print(f"Dosya: {file_path}")
    
    try:
        start_client(server_address, file_path, protocol)
    except KeyboardInterrupt:
        print("\nİşlem kullanıcı tarafından iptal edildi.")
    except Exception as e:
        print(f"Hata: {e}")