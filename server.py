# server.py - Dosya alıcı sunucu (TCP/UDP desteği ile)

import socket
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_keys():
    """
    RSA anahtar çifti oluşturur
    """
    # 2048 bit RSA anahtar çifti oluşturma
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standart RSA public exponent değeri
        key_size=2048,          # Güvenlik için 2048 bit anahtar boyutu
        backend=default_backend()
    )
    public_key = private_key.public_key()  # Public key'i private key'den türet
    return private_key, public_key

def encrypt_aes_key_with_rsa(aes_key, public_key):
    """
    AES simetrik anahtarını RSA genel anahtarı ile şifreler
    """
    # OAEP padding ile güvenli RSA şifreleme
    encrypted_key = public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function
            algorithm=hashes.SHA256(),  # Hash algoritması
            label=None                  # Opsiyonel etiket
        )
    )
    return encrypted_key

def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    """
    RSA ile şifrelenmiş AES anahtarını çözer
    """
    # OAEP padding ile güvenli RSA şifre çözme
    decrypted_key = private_key.decrypt(
        encrypted_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# Global değişkenler - sunucu durumunu kontrol etmek için
server_running = False  # Sunucunun çalışma durumunu takip eder
server_socket = None    # Aktif socket referansını tutar

def start_tcp_server(ip, port):
    """
    TCP protokolü ile çalışan dosya alıcı sunucusu başlatır
    """
    global server_running, server_socket
    
    # TCP socket oluşturma ve yapılandırma
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Address reuse izni
    server_socket.bind((ip, port))     # IP ve port'a bağlanma
    server_socket.listen(5)            # Maksimum 5 bekleyen bağlantı
    server_running = True
    print(f"TCP Sunucu başlatıldı ({ip}:{port}), bağlantı bekleniyor...")
    
    # Her oturum için yeni RSA anahtar çifti oluştur
    private_key, public_key = generate_keys()
    
    try:
        # Ana sunucu döngüsü
        while server_running:
            try:
                # Timeout ile bağlantı kabul etme
                server_socket.settimeout(1.0)
                client_socket, address = server_socket.accept()
                print(f"TCP bağlantı kabul edildi: {address}")
                
                # İstemciye RSA public key'i PEM formatında gönderme
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                client_socket.send(pem)
                
                # İstemciden dosya uzantısı bilgisini alma
                file_extension = client_socket.recv(32).decode().strip()
                print(f"Dosya uzantısı alındı: {file_extension}")
                
                # RSA ile şifrelenmiş AES anahtarını alma (256 byte sabit boyut)
                encrypted_aes_key = client_socket.recv(256)
                aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)
                
                # Şifrelenmiş dosya verisini parça parça alma
                encrypted_data = b''
                while True:
                    chunk = client_socket.recv(4096)  # 4KB parçalar halinde al
                    if not chunk:  # Veri bittiğinde döngüden çık
                        break
                    encrypted_data += chunk

                print("Dosya alındı, şifre çözülüyor...")
                # Dosyayı işleme ve kaydetme
                process_encrypted_file(encrypted_data, aes_key, file_extension)
                client_socket.close()  # İstemci bağlantısını kapat
                
            except socket.timeout:
                # Timeout durumunda döngüye devam et (server_running kontrol edilsin)
                continue
            except socket.error as e:
                if server_running:
                    print(f"TCP Socket hatası: {e}")
                break
                
    except Exception as e:
        print(f"TCP Sunucu hatası: {e}")
    finally:
        # Temizlik işlemleri
        if server_socket:
            server_socket.close()
        print("TCP Sunucu kapatıldı.")

def receive_fragmented_udp_data(server_socket, client_address, file_size):
    """
    UDP ile parçalı olarak gelen veriyi sıralı şekilde birleştirir
    """
    chunks = {}  # Sıralı chunk'ları saklamak için sözlük (chunk_num: data)
    received_bytes = 0
    expected_chunks = (file_size + 4000 - 1) // 4000  # Toplam chunk sayısını hesapla
    
    # Tüm chunk'lar gelene kadar bekle
    while len(chunks) < expected_chunks:
        try:
            server_socket.settimeout(30.0)  # 30 saniye timeout
            data, addr = server_socket.recvfrom(4096)  # Maksimum 4KB veri al
            
            # Sadece aynı istemciden gelen verileri kabul et
            if addr == client_address:
                # Chunk formatı: "chunk_num:data"
                separator_index = data.index(b':')
                chunk_num = int(data[:separator_index])  # Chunk numarasını ayır
                chunk_data = data[separator_index + 1:]  # Asıl veriyi ayır
                
                chunks[chunk_num] = chunk_data  # Chunk'ı sözlüğe ekle
                received_bytes += len(chunk_data)
                
        except socket.timeout:
            continue  # Timeout durumunda beklemeye devam et
    
    # Chunk'ları sıra numarasına göre birleştir
    return b''.join(chunks[i] for i in sorted(chunks.keys()))

def start_udp_server(ip, port):
    """
    UDP protokolü ile çalışan dosya alıcı sunucusu başlatır
    Parçalı dosya transferini destekler
    """
    global server_running, server_socket
    
    # UDP socket oluşturma ve yapılandırma
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip, port))
    server_socket.settimeout(30.0)  # Genel timeout ayarı
    server_running = True
    print(f"UDP Sunucu başlatıldı ({ip}:{port}), veri bekleniyor...")
    
    # Her oturum için yeni RSA anahtar çifti oluştur
    private_key, public_key = generate_keys()
    
    try:
        # Ana sunucu döngüsü
        while server_running:
            try:
                # İlk paket: public key isteği bekleme
                data, client_address = server_socket.recvfrom(1024)
                
                if data == b"REQUEST_PUBLIC_KEY":
                    print(f"UDP istemci bağlandı: {client_address}")
                    
                    # Public key'i PEM formatında hazırla
                    pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    
                    # PEM verisini UDP paket boyutu sınırı için parçalara böl
                    chunk_size = 1400  # UDP için güvenli boyut
                    chunks = [pem[i:i+chunk_size] for i in range(0, len(pem), chunk_size)]
                    
                    # Önce toplam chunk sayısını gönder
                    server_socket.sendto(str(len(chunks)).encode(), client_address)
                    
                    # Her chunk'ı sıra numarası ile birlikte gönder
                    for i, chunk in enumerate(chunks):
                        server_socket.sendto(f"{i}:".encode() + chunk, client_address)
                    
                    # Dosya uzantısını al
                    file_extension, _ = server_socket.recvfrom(32)
                    file_extension = file_extension.decode().strip()
                    
                    # Şifrelenmiş AES anahtarını al
                    encrypted_aes_key, _ = server_socket.recvfrom(512)
                    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)
                    
                    # Dosya boyutu bilgisini al
                    file_size_data, _ = server_socket.recvfrom(1024)
                    file_size = int(file_size_data.decode())
                    
                    # Parçalı veriyi al ve birleştir
                    encrypted_data = receive_fragmented_udp_data(server_socket, client_address, file_size)
                    
                    if encrypted_data:
                        print("Veri alındı, şifre çözülüyor...")
                        process_encrypted_file(encrypted_data, aes_key, file_extension)
                    else:
                        print("Veri alımı başarısız!")
                
            except socket.timeout:
                continue  # Timeout durumunda döngüye devam et
            except socket.error as e:
                if server_running:
                    print(f"UDP Socket hatası: {e}")
                break
                
    except Exception as e:
        print(f"UDP Sunucu hatası: {e}")
    finally:
        # Temizlik işlemleri
        if server_socket:
            server_socket.close()
        print("UDP Sunucu kapatıldı.")

def process_encrypted_file(encrypted_data, aes_key, file_extension="txt"):
    """
    Şifrelenmiş dosyayı AES ile çözer ve mevcut dizine kaydeder
    """
    try:
        # AES-CBC şifre çözme işlemi
        iv = encrypted_data[:16]   # İlk 16 byte IV (Initialization Vector)
        ciphertext = encrypted_data[16:]  # Geri kalan kısım şifrelenmiş veri

        # AES decryptor oluşturma
        decryptor = Cipher(
            algorithms.AES(aes_key),    # AES algoritması
            modes.CBC(iv),              # CBC modu ile IV
            backend=default_backend()
        ).decryptor()

        # PKCS7 padding çözücü oluşturma
        unpadder = padding.PKCS7(128).unpadder()

        # Şifre çözme işlemi
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        # Dosya kaydetme işlemleri
        current_dir = os.getcwd()  # Mevcut çalışma dizinini al
        
        # Benzersiz dosya adı oluşturmak için timestamp kullan
        import time
        timestamp = int(time.time())
        
        # Dosya uzantısını düzenle (nokta ile başlamazsa ekle)
        if not file_extension.startswith('.'):
            file_extension = '.' + file_extension
            
        # Tam dosya yolu oluştur
        filename = f"received_file_{timestamp}{file_extension}"
        full_path = os.path.join(current_dir, filename)
        
        # Dosyayı binary modda kaydet
        with open(full_path, "wb") as f:
            f.write(decrypted_data)

        # Başarı mesajları
        print(f"Dosya başarıyla kaydedildi: {full_path}")
        print(f"Dosya boyutu: {len(decrypted_data)} bytes")
        
        return full_path
        
    except Exception as e:
        # Hata durumunda detaylı bilgi ver
        print(f"Dosya işleme hatası: {e}")
        import traceback
        traceback.print_exc()  # Stack trace yazdır
        return None

def start_server(ip="localhost", port=8080, protocol="tcp"):
    """
    Sunucuyu belirtilen protokol ile başlatır
    """
    protocol = protocol.lower()  # Büyük/küçük harf duyarsız karşılaştırma
    
    # Protokol türüne göre uygun sunucuyu başlat
    if protocol == "tcp":
        start_tcp_server(ip, port)
    elif protocol == "udp":
        start_udp_server(ip, port)
    else:
        print("Hata: Protokol 'tcp' veya 'udp' olmalıdır")
        return

def stop_server():
    """
    Çalışan sunucuyu güvenli bir şekilde durdurur
    Global değişkenleri sıfırlar ve socket'i kapatır
    """
    global server_running, server_socket
    
    # Sunucu zaten çalışmıyorsa uyarı ver
    if not server_running:
        print("Sunucu zaten çalışmıyor.")
        return
    
    print("Sunucu durduruluyor...")
    server_running = False  # Ana döngüleri durdur
    
    # Socket'i güvenli şekilde kapat
    if server_socket:
        try:
            server_socket.close()
        except:
            pass  # Kapanırken hata olursa göz ardı et