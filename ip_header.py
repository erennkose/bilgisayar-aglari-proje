# ip_header.py - IP başlıklarını işleme
from scapy.all import IP, TCP, UDP, Raw, sr1, send
import random

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

def send_fragmented_data(src_ip, dst_ip, data, port=9999, mtu=1500):
    """
    Veriyi parçalayarak gönderme
    """
    import platform
    
    if platform.system() == "Windows":
        import socket
        
        # Windows'ta basit bir socket kullanarak veri gönderme
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
            print(f"Bağlantı hatası: {e}")
            return False
    else:
        fragments = fragment_data(data, mtu)
        total_fragments = len(fragments)
        
        for i, fragment in enumerate(fragments):
            # Son parça değilse "More Fragments" bayrağını ayarla
            flags = 1 if i < total_fragments - 1 else 0
            
            # Fragment offset hesaplama (8 byte'lık birimlerle ölçülür)
            frag_offset = i * (mtu - 20) // 8
            
            ip_packet = create_ip_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                ttl=64,
                id=12345,  # Tüm parçalar için aynı ID
                flags=flags,
                frag=frag_offset
            )
            
            # TCP veya UDP paketini ekle
            tcp_packet = TCP(dport=port, sport=random.randint(1024, 65535))
            
            # Paketi hesapla ve gönder
            packet = ip_packet / tcp_packet / Raw(load=fragment)
            calculate_ip_checksum(packet)
            send(packet)