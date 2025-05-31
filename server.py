# server.py - Dosya alıcı sunucu (TCP/UDP desteği ile)
import socket
import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_keys():
    # RSA anahtar çifti oluşturma
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key_with_rsa(aes_key, public_key):
    # AES anahtarını RSA ile şifreleme
    encrypted_key = public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    # AES anahtarını RSA ile çözme
    decrypted_key = private_key.decrypt(
        encrypted_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# Global değişkenler
server_running = False
server_socket = None

def start_tcp_server(ip, port):
    """TCP sunucusu başlatır"""
    global server_running, server_socket
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    server_running = True
    print(f"TCP Sunucu başlatıldı ({ip}:{port}), bağlantı bekleniyor...")
    
    # RSA anahtar çifti oluştur
    private_key, public_key = generate_keys()
    
    try:
        while server_running:
            try:
                server_socket.settimeout(1.0)
                client_socket, address = server_socket.accept()
                print(f"TCP bağlantı kabul edildi: {address}")
                
                # İstemciye RSA public key gönderme
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                client_socket.send(pem)
                
                # Dosya uzantısını al
                file_extension = client_socket.recv(32).decode().strip()
                print(f"Dosya uzantısı alındı: {file_extension}")
                
                # Şifrelenmiş AES anahtarını alma
                encrypted_aes_key = client_socket.recv(256)
                aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)
                
                # Şifrelenmiş dosyayı alma
                encrypted_data = b''
                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    encrypted_data += chunk

                print("Dosya alındı, şifre çözülüyor...")
                process_encrypted_file(encrypted_data, aes_key, file_extension)
                client_socket.close()
                
            except socket.timeout:
                continue
            except socket.error as e:
                if server_running:
                    print(f"TCP Socket hatası: {e}")
                break
                
    except Exception as e:
        print(f"TCP Sunucu hatası: {e}")
    finally:
        if server_socket:
            server_socket.close()
        print("TCP Sunucu kapatıldı.")

def start_udp_server(ip, port):
    """UDP sunucusu başlatır"""
    global server_running, server_socket
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip, port))
    server_running = True
    print(f"UDP Sunucu başlatıldı ({ip}:{port}), veri bekleniyor...")
    
    # RSA anahtar çifti oluştur
    private_key, public_key = generate_keys()
    
    try:
        while server_running:
            try:
                # İlk paket: public key isteği
                data, client_address = server_socket.recvfrom(1024)
                if data == b"REQUEST_PUBLIC_KEY":
                    print(f"UDP istemci bağlandı: {client_address}")
                    
                    # Public key gönderme
                    pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    
                    # PEM'i parçalara böl (UDP paket boyutu sınırı için)
                    chunk_size = 1024
                    chunks = [pem[i:i+chunk_size] for i in range(0, len(pem), chunk_size)]
                    
                    # Chunk sayısını gönder
                    server_socket.sendto(str(len(chunks)).encode(), client_address)
                    print(f"Public key {len(chunks)} parça halinde gönderiliyor")
                    
                    # Her chunk'ı gönder
                    for i, chunk in enumerate(chunks):
                        server_socket.sendto(f"{i}:".encode() + chunk, client_address)
                    
                    print("Public key gönderildi")
                    
                    # Dosya uzantısını al
                    file_extension, _ = server_socket.recvfrom(32)
                    file_extension = file_extension.decode().strip()
                    print(f"Dosya uzantısı alındı: {file_extension}")
                    
                    # Şifrelenmiş AES anahtarını alma
                    encrypted_aes_key, _ = server_socket.recvfrom(512)
                    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)
                    print("AES anahtarı alındı ve çözüldü")
                    
                    # Dosya boyutunu alma
                    file_size_data, _ = server_socket.recvfrom(1024)
                    file_size = int(file_size_data.decode())
                    print(f"Dosya boyutu: {file_size} bytes")
                    
                    # Şifrelenmiş dosyayı parçalar halinde alma
                    encrypted_data = b''
                    received_bytes = 0
                    packet_count = 0
                    
                    print("Dosya alınıyor...")
                    while received_bytes < file_size:
                        try:
                            chunk, addr = server_socket.recvfrom(4096)
                            if addr == client_address:  # Doğru istemciden gelen paket
                                encrypted_data += chunk
                                received_bytes += len(chunk)
                                packet_count += 1
                                
                                # İlerleme göster
                                if packet_count % 50 == 0:
                                    progress = (received_bytes / file_size) * 100
                                    print(f"Alınan: {received_bytes}/{file_size} bytes ({progress:.1f}%)")
                                    
                        except socket.timeout:
                            if received_bytes >= file_size:
                                break
                            continue
                    
                    print(f"Dosya tamamen alındı ({received_bytes} bytes), şifre çözülüyor...")
                    process_encrypted_file(encrypted_data, aes_key, file_extension)
                
            except socket.timeout:
                continue
            except socket.error as e:
                if server_running:
                    print(f"UDP Socket hatası: {e}")
                break
                
    except Exception as e:
        print(f"UDP Sunucu hatası: {e}")
    finally:
        if server_socket:
            server_socket.close()
        print("UDP Sunucu kapatıldı.")

def process_encrypted_file(encrypted_data, aes_key, file_extension="txt"):
    """Şifrelenmiş dosyayı çözer ve kaydeder"""
    try:
        # Şifre çözme
        iv = encrypted_data[:16] 
        ciphertext = encrypted_data[16:]

        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()

        unpadder = padding.PKCS7(128).unpadder()

        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        # Benzersiz dosya adı oluştur
        import time
        timestamp = int(time.time())
        
        # Uzantıyı düzelt
        if not file_extension.startswith('.'):
            file_extension = '.' + file_extension
            
        filename = f"received_file_{timestamp}{file_extension}"
        
        # Dosyayı kaydetme
        with open(filename, "wb") as f:
            f.write(decrypted_data)

        print(f"Dosya başarıyla kaydedildi: {filename}")
        print(f"Dosya boyutu: {len(decrypted_data)} bytes")
        
    except Exception as e:
        print(f"Dosya işleme hatası: {e}")
        import traceback
        traceback.print_exc()

def start_server(ip="localhost", port=8080, protocol="tcp"):
    """Sunucuyu belirtilen protokol ile başlatır
    
    Args:
        ip (str): Sunucu IP adresi (varsayılan: localhost)
        port (int): Port numarası (varsayılan: 8080)
        protocol (str): Protokol türü - 'tcp' veya 'udp' (varsayılan: tcp)
    """
    protocol = protocol.lower()
    
    if protocol == "tcp":
        start_tcp_server(ip, port)
    elif protocol == "udp":
        start_udp_server(ip, port)
    else:
        print("Hata: Protokol 'tcp' veya 'udp' olmalıdır")
        return

def stop_server():
    """Sunucuyu güvenli bir şekilde durdurur"""
    global server_running, server_socket
    
    if not server_running:
        print("Sunucu zaten çalışmıyor.")
        return
    
    print("Sunucu durduruluyor...")
    server_running = False
    
    # Socket'i kapatma
    if server_socket:
        try:
            server_socket.close()
        except:
            pass

if __name__ == "__main__":
    import sys
    
    # Komut satırı argümanları
    ip = "localhost"
    port = 8080
    protocol = "udp"  # Varsayılan UDP
    
    if len(sys.argv) >= 2:
        protocol = sys.argv[1]
    if len(sys.argv) >= 3:
        ip = sys.argv[2]
    if len(sys.argv) >= 4:
        port = int(sys.argv[3])
    
    print(f"Sunucu parametreleri: {protocol.upper()} - {ip}:{port}")
    
    try:
        start_server(ip, port, protocol)
    except KeyboardInterrupt:
        print("\nSunucu kullanıcı tarafından durduruldu.")
        stop_server()
    except Exception as e:
        print(f"Sunucu hatası: {e}")
        import traceback
        traceback.print_exc()

# 192.168.1.3 --> Server IP --> 192.168.56.1

# python main.py client --file gonderen_dosya.txt --ip 192.168.56.1
# python main.py analyze --analyze latency --ip 8.8.8.8
# python main.py analyze --analyze bandwidth --ip 192.168.56.1
# python main.py analyze --analyze packet_loss --loss 10
# python main.py analyze --analyze security --ip 192.168.1.100 --interface eth0