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
    """
    Verilen dosyayı AES-256-CBC algoritması ile şifreler.
    AES (Advanced Encryption Standard) simetrik şifreleme kullanarak
    dosyayı güvenli bir şekilde şifreler. CBC (Cipher Block Chaining) 
    modu kullanılarak her blok bir önceki blokla bağlanır.
    """
    # Rastgele 16 byte IV (Initialization Vector) oluştur
    # IV her şifreleme işleminde farklı olmalı ki aynı veri farklı şifreli metne dönüşsün
    iv = secrets.token_bytes(16)
    
    # AES şifreleyici nesnesini CBC modu ile oluştur
    encryptor = Cipher(
        algorithms.AES(key),      # AES algoritması, 256-bit anahtar
        modes.CBC(iv),            # CBC (Cipher Block Chaining) modu
        backend=default_backend() # Varsayılan kriptografi backend'i
    ).encryptor()
    
    # PKCS7 padding uygulayıcısı oluştur (AES blok boyutu: 128 bit)
    # Padding: Veri blok boyutunun katı olmazsa eksik kısmı doldurur
    padder = padding.PKCS7(128).padder()
    
    # Dosyayı binary modda oku
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Şifrelenecek dosya bulunamadı: {file_path}")
    
    # Veriyi padding ile blok boyutuna tamamla
    padded_data = padder.update(file_data) + padder.finalize()
    
    # Padded veriyi şifrele
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # IV ve şifrelenmiş veriyi birleştirerek döndür
    # Çözme işlemi için IV'ye ihtiyaç olacak
    return iv + encrypted_data


def calculate_sha256(data):
    """
    Verilen verinin SHA-256 hash değerini hesaplar.
    SHA-256, veri bütünlüğünü kontrol etmek için kullanılan
    kriptografik hash fonksiyonudur. Aynı veri her zaman 
    aynı hash değerini üretir.
    """
    return hashlib.sha256(data).digest()


def start_client(server_address, file_path, protocol='TCP'):
    """
    Ana istemci fonksiyonu - Dosyayı belirtilen protokol ile sunucuya gönderir.
    Bu fonksiyon protokol seçimine göre TCP veya UDP ile dosya gönderimi yapar.
    Varsayılan olarak daha güvenilir olan TCP protokolü kullanılır.
    """
    # Protokol adını büyük harfe çevir
    protocol = protocol.upper()
    
    # Protokol seçimine göre ilgili fonksiyonu çağır
    if protocol == 'TCP':
        return send_file_tcp(server_address, file_path)
    elif protocol == 'UDP':
        return send_file_udp(server_address, file_path)
    else:
        raise ValueError("Protocol 'TCP' veya 'UDP' olmalıdır")


def send_file_tcp(server_address, file_path):
    """
    TCP protokolü kullanarak dosyayı güvenli şekilde sunucuya gönderir.
    TCP (Transmission Control Protocol) güvenilir, bağlantı tabanlı protokoldür.
    Veri bütünlüğü ve sıralı teslimat garantisi verir. Büyük dosyalar için idealdir.

    İşlem Adımları:
    1. Sunucuya TCP bağlantısı kur
    2. Sunucudan RSA public key al
    3. Dosya uzantısını gönder
    4. AES anahtarı oluştur ve RSA ile şifrele
    5. Şifrelenmiş AES anahtarını gönder
    6. Dosyayı AES ile şifrele ve gönder
    """
    # TCP socket oluştur (IPv4, Stream-based)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Sunucuya bağlan
        # TCP üçlü el sıkışması (3-way handshake) gerçekleşir
        client_socket.connect(server_address)
        print(f"TCP sunucusuna başarıyla bağlandı: {server_address}")
        
        # Sunucudan RSA public key'i al (PEM formatında)
        # RSA asimetrik şifreleme için gerekli public key
        server_public_key_pem = client_socket.recv(2048)
        
        # PEM formatındaki public key'i Python nesnesi haline getir
        server_public_key = serialization.load_pem_public_key(
            server_public_key_pem,
            backend=default_backend()
        )
        print("Sunucu public key'i başarıyla alındı")
        
        # Dosya uzantısını belirle ve sunucuya gönder
        # Sunucu dosyayı doğru uzantıyla kaydetmek için kullanacak
        file_extension = os.path.splitext(file_path)[1]
        if not file_extension:
            file_extension = '.txt'  # Uzantısız dosyalar için varsayılan
        
        client_socket.send(file_extension.encode())
        print(f"Dosya uzantısı gönderildi: {file_extension}")
        
        # 256-bit (32 byte) AES anahtarı oluştur
        # secrets modülü kriptografik olarak güvenli rastgele sayılar üretir
        aes_key = secrets.token_bytes(32)
        
        # AES anahtarını sunucunun public key'i ile RSA-OAEP ile şifrele
        # OAEP (Optimal Asymmetric Encryption Padding) güvenli padding şeması
        encrypted_aes_key = server_public_key.encrypt(
            aes_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function
                algorithm=hashes.SHA256(),  # Hash algoritması
                label=None  # Opsiyonel etiket
            )
        )
        
        # Şifrelenmiş AES anahtarını sunucuya gönder
        # Sunucu bunu private key ile çözecek
        client_socket.send(encrypted_aes_key)
        print("Şifrelenmiş AES anahtarı gönderildi")
        
        # Dosyayı AES-256-CBC ile şifrele
        encrypted_file = encrypt_file_with_aes(file_path, aes_key)
        
        print("TCP ile şifreli dosya gönderiliyor...")
        
        # Şifrelenmiş dosyayı tamamen gönder
        # sendall() tüm veriyi gönderene kadar devam eder
        client_socket.sendall(encrypted_file)
        
        print("TCP dosya gönderimi başarıyla tamamlandı.")
        print(f"Gönderilen dosya boyutu: {len(encrypted_file)} bytes")
        
    except ConnectionError as e:
        print(f"TCP bağlantı hatası: {e}")
        raise
    except FileNotFoundError as e:
        print(f"Dosya bulunamadı: {e}")
        raise
    except Exception as e:
        print(f"TCP gönderim hatası: {e}")
        raise
    finally:
        # Socket'i her durumda kapat
        client_socket.close()
        print("TCP bağlantısı kapatıldı")


def send_file_udp(server_address, file_path):
    """
    UDP protokolü kullanarak dosyayı güvenli şekilde sunucuya gönderir.
    UDP (User Datagram Protocol) bağlantısız, hızlı protokoldür.
    Veri kaybı olabilir bu yüzden büyük dosyalar parçalara (chunk) bölünür.
    Her parça numaralandırılarak gönderilir.
    
    İşlem Adımları:
    1. UDP socket oluştur ve yapılandır
    2. Sunucudan public key iste ve parçalar halinde al
    3. Dosya uzantısını gönder
    4. AES anahtarı oluştur ve RSA ile şifrele
    5. Dosya boyutunu gönder
    6. Dosyayı küçük parçalar halinde gönder
    """
    # UDP socket oluştur (IPv4, Datagram-based)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Socket buffer boyutlarını artır (büyük dosyalar için)
    # SO_SNDBUF: Gönderme buffer boyutu
    # SO_RCVBUF: Alma buffer boyutu
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65507)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65507)
    
    # 30 saniye timeout ayarla (UDP'de yanıt gelmeyebilir)
    client_socket.settimeout(30.0)
    
    try:
        print(f"UDP sunucusuna bağlanılıyor: {server_address}")
        
        # Sunucudan RSA public key iste
        # UDP bağlantısız olduğu için özel istek mesajı gönderiyoruz
        client_socket.sendto(b"REQUEST_PUBLIC_KEY", server_address)
        
        # Public key'in kaç parçada geleceğini öğren
        # Public key UDP paket boyutu sınırı nedeniyle parçalanabilir
        try:
            chunk_count_data, _ = client_socket.recvfrom(1024)
            chunk_count = int(chunk_count_data.decode())
            print(f"Public key {chunk_count} parça halinde alınacak")
        except socket.timeout:
            raise ConnectionError("Sunucudan yanıt alınamadı (timeout)")
        
        # Public key parçalarını al ve birleştir
        chunks = {}  # {parça_numarası: parça_verisi}
        
        for i in range(chunk_count):
            try:
                # Her parça "numara:veri" formatında gelir
                data, _ = client_socket.recvfrom(2048)
                
                # Parça numarasını ve veriyi ayır
                colon_index = data.index(b':')
                chunk_num = int(data[:colon_index])
                chunk_data = data[colon_index + 1:]
                
                chunks[chunk_num] = chunk_data
                print(f"Public key parçası {chunk_num + 1}/{chunk_count} alındı")
                
            except socket.timeout:
                raise ConnectionError(f"Public key parçası {i+1} alınamadı (timeout)")
        
        # Parçaları sıralı şekilde birleştir
        server_public_key_pem = b''.join(chunks[i] for i in sorted(chunks.keys()))
        
        # PEM formatını Python nesnesine çevir
        server_public_key = serialization.load_pem_public_key(
            server_public_key_pem,
            backend=default_backend()
        )
        print("Public key başarıyla birleştirildi ve yüklendi")
        
        # Dosya uzantısını belirle ve gönder
        file_extension = os.path.splitext(file_path)[1]
        if not file_extension:
            file_extension = '.txt'  # Varsayılan uzantı
            
        client_socket.sendto(file_extension.encode(), server_address)
        print(f"Dosya uzantısı gönderildi: {file_extension}")
        
        # 256-bit AES şifreleme anahtarı oluştur
        aes_key = secrets.token_bytes(32)
        
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
        print("Şifrelenmiş AES anahtarı gönderildi")
        
        # Dosyayı AES ile şifrele
        encrypted_file = encrypt_file_with_aes(file_path, aes_key)
        file_size = len(encrypted_file)
        
        print("UDP ile şifreli dosya gönderiliyor...")
        
        # Dosya boyutunu önce gönder (sunucu beklenen boyutu bilsin)
        client_socket.sendto(str(file_size).encode(), server_address)
        print(f"Dosya boyutu bilgisi gönderildi: {file_size} bytes")
        
        # Dosyayı küçük parçalara böl ve gönder
        chunk_size = 4000  # UDP için güvenli paket boyutu (MTU sınırları)
        sent_bytes = 0
        total_chunks = (file_size + chunk_size - 1) // chunk_size  # Yukarı yuvarlama
        
        print(f"Dosya {total_chunks} parçaya bölünerek gönderiliyor...")
        
        # Her parçayı numaralayarak gönder
        for i in range(0, file_size, chunk_size):
            # Mevcut parçayı al
            chunk = encrypted_file[i:i + chunk_size]
            chunk_num = i // chunk_size
            
            # Parça numarası ile veriyi birleştir: "numara:veri"
            numbered_chunk = str(chunk_num).encode() + b':' + chunk
            
            # Numaralı parçayı gönder
            client_socket.sendto(numbered_chunk, server_address)
            sent_bytes += len(chunk)
            
            # İlerleme bilgisi ver (her 10 parçada bir)
            if chunk_num % 10 == 0 or chunk_num == total_chunks - 1:
                progress = (sent_bytes / file_size) * 100
                print(f"İlerleme: {sent_bytes}/{file_size} bytes ({progress:.1f}%) - "
                      f"Parça {chunk_num + 1}/{total_chunks}")
        
        print("UDP dosya gönderimi başarıyla tamamlandı.")
        print(f"Toplam gönderilen: {sent_bytes} bytes, {total_chunks} parça")
        
    except socket.timeout:
        print("UDP gönderim zaman aşımına uğradı")
        raise ConnectionError("UDP zaman aşımı - sunucu yanıt vermiyor")
    except Exception as e:
        print(f"UDP gönderim hatası: {e}")
        raise
    finally:
        # Socket'i her durumda temizle
        client_socket.close()
        print("UDP socket'i kapatıldı")