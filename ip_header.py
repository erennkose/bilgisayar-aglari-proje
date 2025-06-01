# ip_header.py - Geliştirilmiş IP başlıklarını işleme
from scapy.all import IP, TCP, UDP, Raw, send, sniff
import random
import socket

def create_ip_packet(src_ip, dst_ip, ttl=64, id=None, flags=0, frag=0, tos=0):
    """
    Düşük seviyeli IP paketi oluşturma
    """
    if id is None:
        id = random.randint(1000, 65535)
    
    ip_packet = IP(
        version=4,  # IPv4'ü açıkça belirt
        ihl=5,      # Standard IPv4 header length
        src=src_ip,
        dst=dst_ip,
        ttl=ttl,
        id=id,
        flags=flags,
        frag=frag,
        tos=tos
    )
    
    # Paketi yeniden oluştur
    return IP(bytes(ip_packet))

def calculate_ip_checksum(packet):
    """
    IP başlığı checksum hesaplama
    """
    # Scapy otomatik olarak checksum hesaplar, ancak manuel hesaplamak için:
    # İlk olarak checksum alanını 0 olarak ayarla
    packet.chksum = 0
    
    # Scapy'nin hesaplamasını sağlamak için:
    del packet.chksum
    return packet.build()

def send_tcp_data(dst_ip, data, port=9999, mtu=1500, **ip_options):
    """
    TCP ile veri gönderme (Windows uyumlu)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        s.connect((dst_ip, port))
        # Veriyi parçalara ayır ve gönder
        chunks = [data[i:i+mtu] for i in range(0, len(data), mtu)]
        
        for chunk in chunks:
            s.send(chunk)
        
        s.close()
        return True
    except Exception as e:
        print(f"TCP bağlantı hatası: {e}")
        return False

def send_udp_data(dst_ip, data, port=9999, mtu=1500, **ip_options):
    """
    UDP ile veri gönderme (Windows uyumlu)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # UDP için parçalama gerekebilir
        chunks = [data[i:i+mtu] for i in range(0, len(data), mtu)]
        
        for chunk in chunks:
            s.sendto(chunk, (dst_ip, port))
        
        s.close()
        return True
    except Exception as e:
        print(f"UDP gönderim hatası: {e}")
        return False

def send_fragmented_data(src_ip, dst_ip, data, port=9999, mtu=1500, protocol="udp", 
                              ttl=64, flags=0, tos=0, packet_id=None):
    """
    Scapy ile düşük seviyeli paket gönderimi
    """
    if packet_id is None:
        packet_id = random.randint(1000, 65535)

    # Transport protokolü
    if protocol.lower() == "tcp":
        transport = TCP(sport=random.randint(1024, 65535), dport=port)
    else:
        transport = UDP(sport=random.randint(1024, 65535), dport=port)

    # Veriyi parçala ve gönder
    offset = 0
    fragment_size = mtu - 20  # IP header boyutunu çıkar
    
    while offset < len(data):
        # Son parça mı kontrol et
        is_last_fragment = (offset + fragment_size >= len(data))
        
        # Flags ayarla (More Fragments biti)
        current_flags = 0 if is_last_fragment else 2
        
        # Fragment offset (8 byte'lık birimler halinde)
        frag_offset = offset // 8
        
        # IP paketi oluştur
        ip = IP(
            version=4,
            ihl=5,
            id=packet_id,
            flags=current_flags,
            frag=frag_offset,
            proto={'tcp': 6, 'udp': 17}[protocol.lower()],
            src=src_ip,
            dst=dst_ip,
            ttl=ttl,
            tos=tos
        )

        # Parçayı al
        chunk = data[offset:offset + fragment_size]
        
        # Paketi oluştur ve gönder
        if offset == 0:  # İlk parça - transport header'ı içerir
            packet = ip/transport/Raw(load=chunk)
        else:  # Sonraki parçalar - sadece IP ve data
            packet = ip/Raw(load=chunk)
        
        try:
            send(packet, verbose=False)
        except Exception as e:
            print(f"Paket gönderim hatası: {e}")
            return False
            
        offset += fragment_size

    return True

def create_custom_packet(src_ip, dst_ip, src_port, dst_port, data, protocol="tcp", 
                        ttl=64, flags=0, tos=0, packet_id=None):
    """
    Özel paket oluşturma - tüm IP parametreleri ile
    """
    ip_packet = create_ip_packet(src_ip, dst_ip, ttl=ttl, id=packet_id, flags=flags, tos=tos)
    
    if protocol.lower() == "tcp":
        transport_packet = TCP(sport=src_port, dport=dst_port)
    elif protocol.lower() == "udp":
        transport_packet = UDP(sport=src_port, dport=dst_port)
    else:
        raise ValueError(f"Desteklenmeyen protokol: {protocol}")
    
    packet = ip_packet / transport_packet / Raw(load=data)
    return packet

def get_flag_description(flag_value):
    """
    Flag değerinin açıklamasını döndür
    """
    descriptions = []
    if flag_value & 1:
        descriptions.append("Reserved")
    if flag_value & 2:
        descriptions.append("Don't Fragment")
    if flag_value & 4:
        descriptions.append("More Fragments")
    
    return " | ".join(descriptions) if descriptions else "No Flags"

def validate_ip_options(ttl=64, flags=0, tos=0):
    """
    IP seçeneklerini doğrula
    """
    errors = []
    
    if not (1 <= ttl <= 255):
        errors.append("TTL değeri 1-255 arasında olmalıdır")
    
    if not (0 <= flags <= 7):
        errors.append("Flags değeri 0-7 arasında olmalıdır")
    
    if not (0 <= tos <= 255):
        errors.append("ToS değeri 0-255 arasında olmalıdır")
    
    return errors

def calculate_ip_checksum_manual(ip_header_bytes):
    """
    Manuel IP checksum hesaplama (RFC 791)
    ip_header_bytes: IP başlığının byte array'i
    """
    # Checksum alanını sıfırla (10-11. byte'lar)
    header = bytearray(ip_header_bytes)
    header[10] = 0  # Checksum MSB
    header[11] = 0  # Checksum LSB
    
    # 16-bit kelimeler halinde topla
    checksum = 0
    for i in range(0, len(header), 2):
        if i + 1 < len(header):
            word = (header[i] << 8) + header[i + 1]
        else:
            word = header[i] << 8
        checksum += word
    
    # Carry bitlerini ekle
    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    # One's complement al
    checksum = ~checksum & 0xFFFF
    return checksum

def validate_ip_checksum(packet):
    """
    IP paketinin checksum'ını doğrula
    Returns: (is_valid, calculated_checksum, received_checksum)
    """
    if not packet.haslayer(IP):
        return False, None, None
    
    ip_layer = packet[IP]
    received_checksum = ip_layer.chksum
    
    # Paketi bytes'a çevir ve header'ı çıkar
    packet_bytes = bytes(packet)
    ip_header_length = (packet_bytes[0] & 0x0F) * 4  # IHL * 4
    ip_header = packet_bytes[:ip_header_length]
    
    # Checksum hesapla
    calculated_checksum = calculate_ip_checksum_manual(ip_header)
    
    # Doğrula
    is_valid = (calculated_checksum == received_checksum)
    
    return is_valid, calculated_checksum, received_checksum

def create_ip_packet_with_custom_checksum(src_ip, dst_ip, ttl=64, id=None, 
                                        flags=0, frag=0, tos=0, custom_checksum=None):
    """
    Manuel checksum ile IP paketi oluşturma
    custom_checksum: None ise otomatik hesaplar, değer verilirse o kullanılır
    """
    if id is None:
        id = random.randint(1000, 65535)
    
    # IP paketi oluştur
    ip_packet = IP(
        src=src_ip,
        dst=dst_ip,
        ttl=ttl,
        id=id,
        flags=flags,
        frag=frag,
        tos=tos
    )
    
    if custom_checksum is not None:
        # Manuel checksum ata
        ip_packet.chksum = custom_checksum
    else:
        # Otomatik checksum hesaplat
        ip_packet = IP(bytes(ip_packet))  # Rebuild ile checksum hesaplanır
    
    return ip_packet

def detect_transmission_errors(packet_list):
    """
    Paket listesindeki transmission errorları tespit et
    Returns: (total_packets, error_count, error_details)
    """
    total_packets = len(packet_list)
    errors = []
    error_count = 0
    
    for i, packet in enumerate(packet_list):
        if packet.haslayer(IP):
            is_valid, calc_checksum, recv_checksum = validate_ip_checksum(packet)
            
            if not is_valid:
                error_count += 1
                errors.append({
                    'packet_index': i,
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'calculated_checksum': hex(calc_checksum) if calc_checksum else None,
                    'received_checksum': hex(recv_checksum) if recv_checksum else None,
                    'error_type': 'checksum_mismatch'
                })
    
    return total_packets, error_count, errors

def monitor_network_errors(interface=None, count=100, filter_str="ip"):
    """
    Ağ trafiğini izle ve checksum hatalarını tespit et
    """
    print(f"Ağ trafiği izleniyor... (Paket sayısı: {count})")
    print("Checksum hataları aranıyor...\n")
    
    error_packets = []
    
    def packet_handler(packet):
        if packet.haslayer(IP):
            is_valid, calc_checksum, recv_checksum = validate_ip_checksum(packet)
            
            if not is_valid:
                error_info = {
                    'timestamp': packet.time,
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'calculated_checksum': hex(calc_checksum) if calc_checksum else "N/A",
                    'received_checksum': hex(recv_checksum) if recv_checksum else "N/A",
                    'packet_size': len(packet)
                }
                error_packets.append(error_info)
                
                print(f"   CHECKSUM HATASI:")
                print(f"   Kaynak IP: {error_info['src_ip']}")
                print(f"   Hedef IP: {error_info['dst_ip']}")
                print(f"   Hesaplanan: {error_info['calculated_checksum']}")
                print(f"   Alınan: {error_info['received_checksum']}")
                print(f"   Paket boyutu: {error_info['packet_size']}")
                print("-" * 50)
    
    # Paketleri yakala ve analiz et
    try:
        sniff(iface=interface, count=count, filter=filter_str, prn=packet_handler)
    except Exception as e:
        print(f"Paket yakalama hatası: {e}")
    
    # Sonuçları özetle
    print(f"\n   ÖZET:")
    print(f"Toplam checksum hatası: {len(error_packets)}")
    print(f"Hata oranı: {(len(error_packets)/count)*100:.2f}%")
    
    return error_packets

def test_checksum_manipulation():
    """
    Checksum manipülasyonu test fonksiyonu
    """
    print("   Checksum Manipülasyon Testi\n")
    
    # Normal paket oluştur
    normal_packet = create_ip_packet_with_custom_checksum("192.168.1.1", "192.168.1.2")
    print(f"   Normal paket checksum: {hex(normal_packet.chksum)}")
    
    # Bozuk checksum ile paket oluştur
    corrupted_packet = create_ip_packet_with_custom_checksum(
        "192.168.1.1", "192.168.1.2", custom_checksum=0xDEAD
    )
    print(f"   Bozuk paket checksum: {hex(corrupted_packet.chksum)}")
    
    # Doğrulama yap
    is_valid_normal, calc_normal, recv_normal = validate_ip_checksum(normal_packet)
    is_valid_corrupted, calc_corrupted, recv_corrupted = validate_ip_checksum(corrupted_packet)
    
    print(f"\nDoğrulama Sonuçları:")
    print(f"Normal paket geçerli: {is_valid_normal}")
    print(f"Bozuk paket geçerli: {is_valid_corrupted}")
    
    return normal_packet, corrupted_packet
