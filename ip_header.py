# ip_header.py - Geliştirilmiş IP başlıklarını işleme

from scapy.all import IP, TCP, UDP, Raw, send, sniff
import random
import socket

def create_ip_packet(src_ip, dst_ip, ttl=64, id=None, flags=0, frag=0, tos=0):
    """
    Düşük seviyeli IP paketi oluşturma
    """
    # Eğer paket ID'si belirtilmemişse rastgele bir değer üret
    if id is None:
        id = random.randint(1000, 65535)
    
    # IP paketinin temel parametrelerini ayarla
    ip_packet = IP(
        version=4,  # IPv4'ü açıkça belirt
        ihl=5,      # Standart IPv4 header uzunluğu (20 byte)
        src=src_ip, # Kaynak IP adresi
        dst=dst_ip, # Hedef IP adresi
        ttl=ttl,    # Time to Live - paketin ağda kalma süresi
        id=id,      # Paket kimlik numarası
        flags=flags,# IP başlık bayrakları (DF, MF vb.)
        frag=frag,  # Fragment offset - parçalanmış paketler için
        tos=tos     # Type of Service - hizmet kalitesi belirteci
    )
    
    # Paketi yeniden oluşturarak checksum hesaplamasını tetikle
    return IP(bytes(ip_packet))

def calculate_ip_checksum(packet):
    """
    IP başlığı checksum hesaplama
    Bu fonksiyon Scapy'nin otomatik checksum hesaplamasını kullanır.
    Manuel hesaplama için calculate_ip_checksum_manual fonksiyonunu kullanın.
    """
    # Scapy otomatik olarak checksum hesaplar, ancak manuel tetikleme için:
    # İlk olarak checksum alanını 0 olarak ayarla
    packet.chksum = 0
    
    # Checksum alanını silerek Scapy'nin yeniden hesaplamasını sağla
    del packet.chksum
    return packet.build()

def send_tcp_data(dst_ip, data, port=9999, mtu=1500, **ip_options):
    """
    TCP ile veri gönderme
    Bu fonksiyon standart socket kütüphanesini kullanarak TCP bağlantısı
    kurar ve veriyi güvenilir şekilde gönderir.
    """
    # TCP socket oluştur (IPv4, stream tipi)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Hedef IP ve port'a bağlan
        s.connect((dst_ip, port))
        
        # Veriyi MTU boyutuna göre parçalara ayır
        # Bu, büyük verilerin ağ üzerinden güvenli gönderimini sağlar
        chunks = [data[i:i+mtu] for i in range(0, len(data), mtu)]
        
        # Her parçayı sırayla gönder
        for chunk in chunks:
            s.send(chunk)
        
        # Bağlantıyı temiz şekilde kapat
        s.close()
        return True
    except Exception as e:
        print(f"TCP bağlantı hatası: {e}")
        return False

def send_udp_data(dst_ip, data, port=9999, mtu=1500, **ip_options):
    """
    UDP ile veri gönderme
    UDP bağlantısız protokol olduğu için TCP'den daha hızlı ancak
    veri teslim garantisi yoktur.
    """
    # UDP socket oluştur (IPv4, datagram tipi)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # UDP için de veriyi parçalama gerekebilir
        # Büyük UDP paketleri IP seviyesinde parçalanabilir
        chunks = [data[i:i+mtu] for i in range(0, len(data), mtu)]
        
        # Her parçayı hedef adrese gönder
        for chunk in chunks:
            s.sendto(chunk, (dst_ip, port))
        
        # Socket'i kapat
        s.close()
        return True
    except Exception as e:
        print(f"UDP gönderim hatası: {e}")
        return False

def send_fragmented_data(src_ip, dst_ip, data, port=9999, mtu=1500, protocol="udp", ttl=64, flags=0, tos=0, packet_id=None):
    """
    Scapy ile düşük seviyeli paket gönderimi
    Bu fonksiyon IP seviyesinde manuel paket parçalama işlemi yapar.
    Ağ katmanında tam kontrol sağlar ve özel senaryolar için kullanılır.
    """
    # Paket ID'si belirtilmemişse rastgele üret
    if packet_id is None:
        packet_id = random.randint(1000, 65535)

    # Transport protokolü katmanını oluştur
    if protocol.lower() == "tcp":
        # TCP header oluştur (rastgele kaynak port)
        transport = TCP(sport=random.randint(1024, 65535), dport=port)
    else:
        # UDP header oluştur (rastgele kaynak port)
        transport = UDP(sport=random.randint(1024, 65535), dport=port)

    # Veri parçalama ve gönderim döngüsü
    offset = 0  # Mevcut parçanın başlangıç pozisyonu
    fragment_size = mtu - 20  # IP header boyutunu (20 byte) çıkar
    
    while offset < len(data):
        # Son parça mı kontrol et
        is_last_fragment = (offset + fragment_size >= len(data))
        
        # IP başlık bayraklarını ayarla
        # Bit 1: More Fragments - son parça değilse 1
        current_flags = 0 if is_last_fragment else 2
        
        # Fragment offset hesapla (8 byte'lık birimler halinde)
        frag_offset = offset // 8
        
        # IP paketi oluştur
        ip = IP(
            version=4,     # IPv4 sürümü
            ihl=5,         # Internet Header Length (20 byte)
            id=packet_id,  # Tüm parçalar aynı ID'ye sahip
            flags=current_flags,    # Fragment bayrakları
            frag=frag_offset,      # Fragment offset
            proto={'tcp': 6, 'udp': 17}[protocol.lower()],  # Protokol numarası
            src=src_ip,    # Kaynak IP
            dst=dst_ip,    # Hedef IP
            ttl=ttl,       # Time to Live
            tos=tos        # Type of Service
        )

        # Mevcut parçanın verisini al
        chunk = data[offset:offset + fragment_size]
        
        # Paketi oluştur ve gönder
        if offset == 0:  
            # İlk parça - transport header'ı da içerir
            packet = ip/transport/Raw(load=chunk)
        else:  
            # Sonraki parçalar - sadece IP header ve veri
            packet = ip/Raw(load=chunk)
        
        try:
            # Paketi ağa gönder (verbose=False: çıktı bastırma)
            send(packet, verbose=False)
        except Exception as e:
            print(f"Paket gönderim hatası: {e}")
            return False
            
        # Bir sonraki parça için offset'i güncelle
        offset += fragment_size

    return True

def get_flag_description(flag_value):
    """
    Flag değerinin açıklamasını döndür
    IP başlığındaki flag bitlerini anlaşılır metne çevirir.
    """
    descriptions = []
    
    # Bit 0: Reserved (kullanılmayan, her zaman 0)
    if flag_value & 1:
        descriptions.append("Reserved")
    
    # Bit 1: Don't Fragment - paket parçalanmamalı
    if flag_value & 2:
        descriptions.append("Don't Fragment")
    
    # Bit 2: More Fragments - daha fazla parça var
    if flag_value & 4:
        descriptions.append("More Fragments")
    
    # Açıklamaları birleştir veya "bayrak yok" mesajı döndür
    return " | ".join(descriptions) if descriptions else "No Flags"

def validate_ip_options(ttl=64, flags=0, tos=0):
    """
    IP seçeneklerini doğrula
    IP başlığı parametrelerinin geçerli değer aralıklarında olup
    olmadığını kontrol eder.
    """
    errors = []
    
    # TTL değeri 1-255 arasında olmalı (8 bit unsigned)
    if not (1 <= ttl <= 255):
        errors.append("TTL değeri 1-255 arasında olmalıdır")
    
    # Flags değeri 0-7 arasında olmalı (3 bit)
    if not (0 <= flags <= 7):
        errors.append("Flags değeri 0-7 arasında olmalıdır")
    
    # ToS değeri 0-255 arasında olmalı (8 bit)
    if not (0 <= tos <= 255):
        errors.append("ToS değeri 0-255 arasında olmalıdır")
    
    return errors

def calculate_ip_checksum_manual(ip_header_bytes):
    """
    Manuel IP checksum hesaplama (RFC 791)
    RFC 791 standardına göre IP başlığı checksum'ını manuel olarak hesaplar.
    """
    # Checksum alanını sıfırla (başlıkta 10-11. byte'lar)
    header = bytearray(ip_header_bytes)
    header[10] = 0  # Checksum MSB (Most Significant Byte)
    header[11] = 0  # Checksum LSB (Least Significant Byte)
    
    # 16-bit kelimeler halinde topla
    checksum = 0
    for i in range(0, len(header), 2):
        if i + 1 < len(header):
            # İki byte'ı birleştirerek 16-bit word oluştur
            word = (header[i] << 8) + header[i + 1]
        else:
            # Tek byte kalmışsa high byte olarak al
            word = header[i] << 8
        checksum += word
    
    # Carry bitlerini ana toplama ekle (overflow kontrolü)
    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    # One's complement al (tüm bitleri ters çevir)
    checksum = ~checksum & 0xFFFF
    return checksum

def validate_ip_checksum(packet):
    """
    IP paketinin checksum'ını doğrula
    Gelen paketin checksum değerini yeniden hesaplayarak
    veri bütünlüğünü kontrol eder.
    """
    # Paket IP katmanı içeriyor mu kontrol et
    if not packet.haslayer(IP):
        return False, None, None
    
    # IP katmanını al
    ip_layer = packet[IP]
    received_checksum = ip_layer.chksum
    
    # Paketi bytes'a çevir ve IP başlığını çıkar
    packet_bytes = bytes(packet)
    # IHL (Internet Header Length) * 4 = başlık boyutu
    ip_header_length = (packet_bytes[0] & 0x0F) * 4  
    ip_header = packet_bytes[:ip_header_length]
    
    # Manuel checksum hesapla
    calculated_checksum = calculate_ip_checksum_manual(ip_header)
    
    # Hesaplanan ile alınan checksum'ları karşılaştır
    is_valid = (calculated_checksum == received_checksum)
    
    return is_valid, calculated_checksum, received_checksum

def create_ip_packet_with_custom_checksum(src_ip, dst_ip, ttl=64, id=None, 
                                        flags=0, frag=0, tos=0, custom_checksum=None):
    """
    Manuel checksum ile IP paketi oluşturma
    Test ve debug amaçları için özel checksum değeri ile IP paketi oluşturur.
    """
    # ID belirtilmemişse rastgele üret
    if id is None:
        id = random.randint(1000, 65535)
    
    # Temel IP paketi oluştur
    ip_packet = IP(
        src=src_ip,   # Kaynak IP adresi
        dst=dst_ip,   # Hedef IP adresi
        ttl=ttl,      # Time to Live
        id=id,        # Paket kimlik numarası
        flags=flags,  # IP başlık bayrakları
        frag=frag,    # Fragment offset
        tos=tos       # Type of Service
    )
    
    if custom_checksum is not None:
        # Manuel checksum değeri atanmış - direkt kullan
        ip_packet.chksum = custom_checksum
    else:
        # Otomatik checksum hesaplat
        # Rebuild işlemi checksum'ın yeniden hesaplanmasını sağlar
        ip_packet = IP(bytes(ip_packet))
    
    return ip_packet

def monitor_network_errors(interface=None, count=100, filter_str="ip"):
    """
    Ağ trafiğini izle ve checksum hatalarını tespit et
    Canlı ağ trafiğini dinleyerek checksum hataları olan
    paketleri tespit eder ve raporlar. Ağ kalitesi analizi için kullanılır.
    """
    print(f"Ağ trafiği izleniyor... (Paket sayısı: {count})")
    print("Checksum hataları aranıyor...\n")
    
    # Hatalı paketlerin bilgilerini sakla
    error_packets = []
    
    def packet_handler(packet):
        """
        Her paket için çağrılan işleyici fonksiyon
        """
        # Sadece IP paketlerini işle
        if packet.haslayer(IP):
            # Checksum doğrulaması yap
            is_valid, calc_checksum, recv_checksum = validate_ip_checksum(packet)
            
            if not is_valid:
                # Hatalı paket bilgilerini kaydet
                error_info = {
                    'timestamp': packet.time,           # Paket yakalanma zamanı
                    'src_ip': packet[IP].src,          # Kaynak IP adresi
                    'dst_ip': packet[IP].dst,          # Hedef IP adresi
                    'calculated_checksum': hex(calc_checksum) if calc_checksum else "N/A",
                    'received_checksum': hex(recv_checksum) if recv_checksum else "N/A",
                    'packet_size': len(packet)          # Paket boyutu
                }
                error_packets.append(error_info)
                
                # Hata detaylarını ekrana yazdır
                print(f"   CHECKSUM HATASI:")
                print(f"   Kaynak IP: {error_info['src_ip']}")
                print(f"   Hedef IP: {error_info['dst_ip']}")
                print(f"   Hesaplanan: {error_info['calculated_checksum']}")
                print(f"   Alınan: {error_info['received_checksum']}")
                print(f"   Paket boyutu: {error_info['packet_size']}")
                print("-" * 50)
    
    # Paketleri yakala ve analiz et
    try:
        # Scapy sniff fonksiyonu ile paket yakalama
        sniff(iface=interface,      # Ağ arayüzü
              count=count,          # Paket sayısı
              filter=filter_str,    # Paket filtresi
              prn=packet_handler)   # İşleyici fonksiyon
    except Exception as e:
        print(f"Paket yakalama hatası: {e}")
    
    # Sonuçları özetle ve raporla
    print(f"\n   ÖZET:")
    print(f"Toplam checksum hatası: {len(error_packets)}")
    print(f"Hata oranı: {(len(error_packets)/count)*100:.2f}%")
    
    return error_packets

def test_checksum_manipulation():
    """
    Checksum manipülasyonu test fonksiyonu
    Normal ve bozuk checksum'lu paketler oluşturarak doğrulama fonksiyonlarını test eder.
    """
    print("   Checksum Manipülasyon Testi\n")
    
    # Normal paket oluştur (otomatik checksum)
    normal_packet = create_ip_packet_with_custom_checksum("192.168.1.1", "192.168.1.2")
    print(f"   Normal paket checksum: {hex(normal_packet.chksum)}")
    
    # Bozuk checksum ile paket oluştur (manuel değer)
    corrupted_packet = create_ip_packet_with_custom_checksum(
        "192.168.1.1", "192.168.1.2", custom_checksum=0xDEAD
    )
    print(f"   Bozuk paket checksum: {hex(corrupted_packet.chksum)}")
    
    # Her iki paketi de doğrulama işlemine sok
    is_valid_normal, calc_normal, recv_normal = validate_ip_checksum(normal_packet)
    is_valid_corrupted, calc_corrupted, recv_corrupted = validate_ip_checksum(corrupted_packet)
    
    # Test sonuçlarını rapor et
    print(f"\nDoğrulama Sonuçları:")
    print(f"Normal paket geçerli: {is_valid_normal}")
    print(f"Bozuk paket geçerli: {is_valid_corrupted}")
    
    return normal_packet, corrupted_packet