# ip_header.py - IP başlıklarını işleme
from scapy.all import IP, TCP, UDP, Raw, sr1, send
import random
import socket
import platform

def create_ip_packet(src_ip, dst_ip, ttl=64, id=None, flags=0, frag=0):
    """
    Düşük seviyeli IP paketi oluşturma
    flags: 0 = No flags, 1 = Reserved, 2 = Don't Fragment, 4 = More Fragments
    """
    if id is None:
        id = random.randint(1000, 65535)
    
    ip_packet = IP(
        src=src_ip,
        dst=dst_ip,
        ttl=ttl,
        id=id,
        flags=flags,
        frag=frag
    )
    
    return ip_packet

def fragment_data(data, mtu=1500, header_size=20):
    """
    Veriyi belirtilen MTU'ya göre parçalara ayırma
    """
    max_payload = mtu - header_size
    fragments = []
    
    for i in range(0, len(data), max_payload):
        fragments.append(data[i:i+max_payload])
    
    return fragments

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

def send_tcp_data(dst_ip, data, port=9999, mtu=1500):
    """
    TCP ile veri gönderme (Windows uyumlu)
    """
    if platform.system() == "Windows":
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
    else:
        # Linux/Unix için Scapy kullan
        return send_fragmented_data_scapy(None, dst_ip, data, port, mtu, protocol="tcp")

def send_udp_data(dst_ip, data, port=9999, mtu=1500):
    """
    UDP ile veri gönderme (Windows uyumlu)
    """
    if platform.system() == "Windows":
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
    else:
        # Linux/Unix için Scapy kullan
        return send_fragmented_data_scapy(None, dst_ip, data, port, mtu, protocol="udp")

def send_fragmented_data(src_ip, dst_ip, data, port=9999, mtu=1500, protocol="tcp"):
    """
    Veriyi parçalayarak gönderme (TCP veya UDP)
    """
    if protocol.lower() == "tcp":
        return send_tcp_data(dst_ip, data, port, mtu)
    elif protocol.lower() == "udp":
        return send_udp_data(dst_ip, data, port, mtu)
    else:
        print(f"Desteklenmeyen protokol: {protocol}")
        return False

def send_fragmented_data_scapy(src_ip, dst_ip, data, port=9999, mtu=1500, protocol="tcp"):
    """
    Scapy kullanarak parçalanmış veri gönderme (Linux/Unix için)
    """
    fragments = fragment_data(data, mtu)
    total_fragments = len(fragments)
    packet_id = random.randint(1000, 65535)
    
    for i, fragment in enumerate(fragments):
        # Son parça değilse "More Fragments" bayrağını ayarla
        flags = 1 if i < total_fragments - 1 else 0
        
        # Fragment offset hesaplama (8 byte'lık birimlerle ölçülür)
        frag_offset = i * (mtu - 20) // 8
        
        ip_packet = create_ip_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            ttl=64,
            id=packet_id,  # Tüm parçalar için aynı ID
            flags=flags,
            frag=frag_offset
        )
        
        # Protokol türüne göre paket oluştur
        if protocol.lower() == "tcp":
            transport_packet = TCP(dport=port, sport=random.randint(1024, 65535))
        elif protocol.lower() == "udp":
            transport_packet = UDP(dport=port, sport=random.randint(1024, 65535))
        else:
            print(f"Desteklenmeyen protokol: {protocol}")
            return False
        
        # Paketi hesapla ve gönder
        packet = ip_packet / transport_packet / Raw(load=fragment)
        calculate_ip_checksum(packet)
        send(packet)
    
    return True

def create_custom_packet(src_ip, dst_ip, src_port, dst_port, data, protocol="tcp"):
    """
    Özel paket oluşturma
    """
    ip_packet = create_ip_packet(src_ip, dst_ip)
    
    if protocol.lower() == "tcp":
        transport_packet = TCP(sport=src_port, dport=dst_port)
    elif protocol.lower() == "udp":
        transport_packet = UDP(sport=src_port, dport=dst_port)
    else:
        raise ValueError(f"Desteklenmeyen protokol: {protocol}")
    
    packet = ip_packet / transport_packet / Raw(load=data)
    return packet