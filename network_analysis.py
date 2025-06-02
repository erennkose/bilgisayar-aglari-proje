# network_analysis.py - Ağ performansı analizi
import subprocess
import re
import socket
import time
import random
import threading

def measure_latency(target_ip, count=5):
    """Ping kullanarak gecikmeyi ölçme"""
    try:
        output = subprocess.check_output(
            ["ping", "-n", str(count), target_ip],
            universal_newlines=True,
            stderr=subprocess.STDOUT
        )
        
        # Ping istatistiklerinden doğrudan değerleri alalım
        # "Minimum = 0ms, Maximum = 0ms, Average = 0ms" satırını arıyoruz
        stats_pattern = r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms"
        stats_match = re.search(stats_pattern, output)
        
        if stats_match:
            min_latency = float(stats_match.group(1))
            max_latency = float(stats_match.group(2))
            avg_latency = float(stats_match.group(3))
            
            # Örnekleme verileri için her yanıtı ayrı ayrı kontrol edelim
            samples_pattern = r"time[=<](\d+)ms"
            samples = [float(match) for match in re.findall(samples_pattern, output)]
            
            # Eğer "<1ms" formatı varsa, bunları 0.5ms olarak kabul edelim
            if not samples:
                less_than_pattern = r"time<1ms"
                less_than_count = len(re.findall(less_than_pattern, output))
                samples = [0.5] * less_than_count
            
            return {
                'min': min_latency,
                'avg': avg_latency,
                'max': max_latency,
                'samples': samples
            }
        else:
            print("Ping istatistikleri bulunamadı")
    except subprocess.CalledProcessError as e:
        print(f"Ping hatası: {e}")
    
    return None

def run_iperf_client(server_ip, duration=10, port=5201):
    """
    iPerf kullanarak bant genişliğini ölçme
    """
    
    iperf_path = "C:\\iperf\\iperf3.exe"
    
    cmd = f"{iperf_path} -c {server_ip} -p {port} -t {duration} -f m"
    
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        output = output.decode('utf-8')
        
        # Hata çıktısını kontrol edin
        if process.returncode != 0:
            print(f"iPerf hatası: {error.decode('utf-8')}")
            return None
        
        # iPerf çıktısından bant genişliğini çıkarma
        bandwidth_pattern = r"(\d+\.?\d*)\s+Mbits/sec"
        match = re.search(bandwidth_pattern, output)
        
        if match:
            bandwidth = float(match.group(1))
            return bandwidth
        else:
            print("iPerf çıktısından bant genişliği değeri çıkarılamadı")
            print(f"iPerf çıktısı: {output}")
            return None
    except Exception as e:
        print(f"Hata oluştu: {str(e)}")
        return None
    
def simulate_packet_loss_and_retransmission(dst_ip, data, port=9999, loss_rate=0.3, max_retries=3):
    """
    Düzeltilmiş paket kaybı simülasyonu ve yeniden gönderim mekanizması
    """
    print(f"\nPaket Kaybı Simülasyonu Başlatılıyor...")
    print(f"Hedef: {dst_ip}:{port}")
    print(f"Kayıp Oranı: %{loss_rate*100:.1f}")
    print(f"Maksimum Deneme: {max_retries}")
    
    # Önce sunucunun çalışıp çalışmadığını kontrol et
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_socket.settimeout(2.0)
    
    try:
        test_socket.sendto(b"TEST", (dst_ip, port))
        try:
            response, _ = test_socket.recvfrom(1024)
            print("✓ Sunucu bağlantısı başarılı")
        except socket.timeout:
            print("⚠ Sunucu yanıt vermiyor, ancak paket gönderilebilir")
    except Exception as e:
        print(f"⚠ Bağlantı testi hatası: {str(e)}")
    finally:
        test_socket.close()

    # Ana socket oluştur
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    
    chunk_size = 1024
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    stats = {
        'sent': 0,
        'lost': 0,
        'retransmitted': 0,
        'success': 0,
        'timeouts': 0
    }
    
    try:
        for i, chunk in enumerate(chunks):
            packet_sent = False
            retries = 0
            
            print(f"\n--- Paket {i} işleniyor ---")
            
            while not packet_sent and retries <= max_retries:
                # Paket kaybı simülasyonu kontrolü
                packet_lost_simulation = random.random() < loss_rate
                
                if packet_lost_simulation:
                    print(f"! Paket {i} kaybedildi (simülasyon) - Deneme {retries + 1}")
                    stats['lost'] += 1
                else:
                    try:
                        # Paket formatı: "packet_id:data"
                        packet_data = f"{i}:{chunk}"
                        s.sendto(packet_data.encode('utf-8'), (dst_ip, port))
                        stats['sent'] += 1
                        
                        print(f"→ Paket {i} gönderildi - Deneme {retries + 1}")
                        
                        # ACK bekleme (opsiyonel - sunucu ACK göndermiyorsa bu kısmı atlayabilir)
                        try:
                            ack, _ = s.recvfrom(1024)
                            received_id = int(ack.decode())
                            
                            if received_id == i:
                                packet_sent = True
                                stats['success'] += 1
                                print(f"✓ Paket {i} başarıyla onaylandı")
                            else:
                                print(f"⚠ Paket {i} için yanlış ACK alındı: {received_id}")
                                
                        except socket.timeout:
                            # ACK alamadık, ama paket gönderildi
                            print(f"⏰ Paket {i} için ACK alınamadı (timeout)")
                            stats['timeouts'] += 1
                            # ACK alamasak bile, UDP'de paket muhtemelen gitti
                            # Bu durumda başarılı kabul edebiliriz veya yeniden gönderebiliriz
                            packet_sent = True  # Veya False yapıp yeniden gönderim sağlayabilirsiniz
                            stats['success'] += 1
                            
                    except Exception as e:
                        print(f"✗ Paket {i} gönderim hatası: {e}")
                        stats['lost'] += 1
                
                # Yeniden deneme kontrolü
                if not packet_sent:
                    retries += 1
                    if retries <= max_retries:
                        print(f"↺ Paket {i} yeniden gönderilecek (Deneme {retries + 1}/{max_retries + 1})")
                        stats['retransmitted'] += 1
                        time.sleep(0.1)  # Kısa gecikme
                    else:
                        print(f"✗ Paket {i} maksimum deneme sayısına ulaştı")
                        break
    
    except KeyboardInterrupt:
        print("\n⚠ Simülasyon kullanıcı tarafından durduruldu!")
    except Exception as e:
        print(f"✗ Simülasyon hatası: {str(e)}")
        return False
    finally:
        s.close()
    
    # İstatistikleri yazdır
    print(f"\n{'='*50}")
    print("   SİMÜLASYON SONUÇLARI")
    print(f"{'='*50}")
    print(f"Toplam paket                : {len(chunks)}")
    print(f"Gönderilmeye çalışılan      : {stats['sent']}")
    print(f"Kaybolan (simülasyon)       : {stats['lost']}")
    print(f"Zaman aşımı                 : {stats['timeouts']}")
    print(f"Yeniden gönderilen          : {stats['retransmitted']}")
    print(f"Başarılı                    : {stats['success']}")
    
    success_rate = (stats['success'] / len(chunks)) * 100 if chunks else 0
    print(f"Başarı oranı                : %{success_rate:.1f}")
    
    # Genel sonuç
    overall_success = stats['success'] == len(chunks)
    print(f"Genel sonuç                 : {'BAŞARILI' if overall_success else 'BAŞARISIZ'}")
    
    return overall_success

# Test fonksiyonu
def test_packet_loss_simulation():
    """
    Paket kaybı simülasyonunu test eder
    """
    
    def create_simple_udp_server(port=9999):
        """Basit UDP test sunucusu"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('localhost', port))
        server_socket.settimeout(1.0)
        
        print(f"Test sunucusu başlatıldı: localhost:{port}")
        
        try:
            while True:
                try:
                    data, addr = server_socket.recvfrom(2048)
                    
                    if data == b"TEST":
                        server_socket.sendto(b"OK", addr)
                        continue
                    
                    # Paket ID'sini çıkar ve ACK gönder
                    try:
                        packet_info = data.decode('utf-8')
                        if ':' in packet_info:
                            packet_id = packet_info.split(':', 1)[0]
                            server_socket.sendto(packet_id.encode(), addr)
                            print(f"Paket alındı: {packet_id}")
                    except:
                        pass
                        
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            server_socket.close()
            print("Test sunucusu durduruldu")
    
    # Test sunucusunu arka planda başlat
    server_thread = threading.Thread(target=create_simple_udp_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)  # Sunucunun başlaması için bekle
    
    # Test verisi
    test_data = "Bu bir test verisidir. " * 20  # ~500 byte
    
    print("Paket kaybı simülasyonu test ediliyor...")
    
    # Düşük kayıp oranı ile test
    result1 = simulate_packet_loss_and_retransmission(
        dst_ip="localhost",
        data=test_data,
        port=9999,
        loss_rate=0.2,
        max_retries=2
    )
    
    time.sleep(1)
    
    # Yüksek kayıp oranı ile test
    result2 = simulate_packet_loss_and_retransmission(
        dst_ip="localhost", 
        data=test_data,
        port=9999,
        loss_rate=0.5,
        max_retries=3
    )
    
    print(f"\nTest Sonuçları:")
    print(f"Düşük kayıp testi: {'BAŞARILI' if result1 else 'BAŞARISIZ'}")
    print(f"Yüksek kayıp testi: {'BAŞARILI' if result2 else 'BAŞARISIZ'}")
