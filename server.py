# server.py - Dosya alıcı sunucu
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

def start_server():
    global server_running, server_socket
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Port yeniden kullanımı için
    server_socket.bind(('0.0.0.0', 9999))
    server_socket.listen(5)
    server_running = True
    print("Sunucu başlatıldı, bağlantı bekleniyor...")
    
    # RSA anahtar çifti oluştur
    private_key, public_key = generate_keys()
    
    try:
        while server_running:
            try:
                # Timeout ile accept işlemi
                server_socket.settimeout(1.0)
                client_socket, address = server_socket.accept()
                print(f"Bağlantı kabul edildi: {address}")
                
                # İstemciye RSA public key gönderme
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                client_socket.send(pem)
                
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

                # Dosyayı kaydetme
                with open("received_file.txt", "wb") as f:
                    f.write(decrypted_data)

                print("Dosya başarıyla kaydedildi: received_file.txt")
                client_socket.close()
                
            except socket.timeout:
                # Timeout durumunda döngü devam eder, server_running kontrolü yapılır
                continue
            except socket.error as e:
                if server_running:
                    print(f"Socket hatası: {e}")
                break
                
    except Exception as e:
        print(f"Sunucu hatası: {e}")
    finally:
        if server_socket:
            server_socket.close()
        print("Sunucu kapatıldı.")

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
    start_server()


# 192.168.1.3 --> Server IP --> 192.168.56.1

# python main.py client --file gonderen_dosya.txt --ip 192.168.56.1
# python main.py analyze --analyze latency --ip 8.8.8.8
# python main.py analyze --analyze bandwidth --ip 192.168.56.1
# python main.py analyze --analyze packet_loss --loss 10
# python main.py analyze --analyze security --ip 192.168.1.100 --interface eth0