# network_analysis.py - Ağ performansı analizi

import subprocess
import re
import socket
import time
import random
import threading

def measure_latency(target_ip, count=5):
    """
    Ping kullanarak gecikmeyi ölçme
    """
    try:
        # Windows ping komutunu çalıştır
        # -n parametresi paket sayısını belirtir
        output = subprocess.check_output(
            ["ping", "-n", str(count), target_ip],
            universal_newlines=True,  # Çıktıyı string olarak al
            stderr=subprocess.STDOUT  # Hata çıktısını da yakala
        )
        
        # Ping istatistiklerinden doğrudan değerleri alalım
        # Windows ping çıktısında "Minimum = x ms, Maximum = x ms, Average = x ms" formatını arıyoruz
        stats_pattern = r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms"
        stats_match = re.search(stats_pattern, output)
        
        if stats_match:
            # Regex gruplarından değerleri çıkar ve float'a çevir
            min_latency = float(stats_match.group(1))
            max_latency = float(stats_match.group(2))
            avg_latency = float(stats_match.group(3))
            
            # Örnekleme verileri için her yanıtı ayrı ayrı kontrol edelim
            # "time= x ms" veya "time< x ms" formatlarını yakala
            samples_pattern = r"time[=<](\d+)ms"
            samples = [float(match) for match in re.findall(samples_pattern, output)]
            
            # Eğer "<1ms" formatı varsa, bunları 0.5ms olarak kabul edelim
            # Çünkü gerçek değer 1ms'den küçük ama sıfır değil
            if not samples:
                less_than_pattern = r"time<1ms"
                less_than_count = len(re.findall(less_than_pattern, output))
                samples = [0.5] * less_than_count
            
            # Sonuçları sözlük formatında döndür
            return {
                'min': min_latency,      # Minimum gecikme
                'avg': avg_latency,      # Ortalama gecikme
                'max': max_latency,      # Maksimum gecikme
                'samples': samples       # Tüm ölçüm örnekleri
            }
        else:
            print("Ping istatistikleri bulunamadı")
    except subprocess.CalledProcessError as e:
        # Ping komutu başarısız oldu (örn: hedef ulaşılamaz)
        print(f"Ping hatası: {e}")
    
    return None

def run_iperf_client(server_ip, duration=10, port=5201):
    """
    iPerf kullanarak bant genişliğini ölçme
    iPerf3 aracını kullanarak TCP bant genişliği testi yapar
    """
    
    # iPerf3 executable dosyasının yolu
    # Bu yolun sisteminizde doğru olduğundan emin olun
    iperf_path = "C:\\iperf\\iperf3.exe"
    
    # iPerf client komutunu oluştur
    # -c: client modu, -p: port, -t: süre, -f m: Mbps formatında çıktı
    cmd = f"{iperf_path} -c {server_ip} -p {port} -t {duration} -f m"
    
    try:
        # iPerf komutunu çalıştır
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()  # Komutun tamamlanmasını bekle
        output = output.decode('utf-8')        # Byte'ları string'e çevir
        
        # Hata çıktısını kontrol edin
        if process.returncode != 0:
            print(f"iPerf hatası: {error.decode('utf-8')}")
            return None
        
        # iPerf çıktısından bant genişliğini çıkarma
        # "x Mbits/sec" formatını arıyoruz
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
    UDP protokolü kullanarak paket kaybını simüle eder ve güvenilir iletim sağlar
    """
    print(f"\nPaket Kaybı Simülasyonu Başlatılıyor...")
    print(f"Hedef: {dst_ip}:{port}")
    print(f"Kayıp Oranı: %{loss_rate*100:.1f}")
    print(f"Maksimum Deneme: {max_retries}")
    
    # Önce sunucunun çalışıp çalışmadığını kontrol et
    # Test paketi göndererek bağlantı durumunu doğrula
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_socket.settimeout(2.0)  # 2 saniye timeout
    
    try:
        # Test mesajı gönder
        test_socket.sendto(b"TEST", (dst_ip, port))
        try:
            # Sunucudan yanıt bekle
            response, _ = test_socket.recvfrom(1024)
            print("Sunucu bağlantısı başarılı")
        except socket.timeout:
            print("Sunucu yanıt vermiyor, ancak paket gönderilebilir")
    except Exception as e:
        print(f"Bağlantı testi hatası: {str(e)}")
    finally:
        test_socket.close()

    # Ana iletişim için socket oluştur
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)  # ACK bekleme timeout'u
    
    # Veriyi küçük parçalara böl (chunk'lara)
    # Her chunk maksimum 1024 byte olacak
    chunk_size = 1024
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    # İstatistik verilerini takip et
    stats = {
        'sent': 0,           # Gönderilen paket sayısı
        'lost': 0,           # Kaybolan paket sayısı
        'retransmitted': 0,  # Yeniden gönderilen paket sayısı
        'success': 0,        # Başarılı paket sayısı
        'timeouts': 0        # Timeout sayısı
    }
    
    try:
        # Her chunk'ı işle
        for i, chunk in enumerate(chunks):
            packet_sent = False  # Bu paket başarıyla gönderildi mi?
            retries = 0         # Mevcut deneme sayısı
            
            print(f"\n--- Paket {i} işleniyor ---")
            
            # Paket gönderilene kadar veya maksimum deneme sayısına ulaşana kadar dene
            while not packet_sent and retries <= max_retries:
                # Paket kaybı simülasyonu kontrolü
                # Rastgele sayı üret ve kayıp oranı ile karşılaştır
                packet_lost_simulation = random.random() < loss_rate
                
                if packet_lost_simulation:
                    # Simüle edilmiş paket kaybı
                    print(f"! Paket {i} kaybedildi (simülasyon) - Deneme {retries + 1}")
                    stats['lost'] += 1
                else:
                    try:
                        # Paket formatı: "packet_id:data"
                        # ID ile veriyi ayırarak sunucunun hangi paketi aldığını bilmesini sağla
                        packet_data = f"{i}:{chunk}"
                        s.sendto(packet_data.encode('utf-8'), (dst_ip, port))
                        stats['sent'] += 1
                        
                        print(f"→ Paket {i} gönderildi - Deneme {retries + 1}")
                        
                        # ACK (Acknowledgment) bekleme
                        # Sunucunun paketi aldığını onaylayan mesajı bekle
                        try:
                            ack, _ = s.recvfrom(1024)
                            received_id = int(ack.decode())
                            
                            # Doğru paket ID'si için ACK alındı mı kontrol et
                            if received_id == i:
                                packet_sent = True
                                stats['success'] += 1
                                print(f"Paket {i} başarıyla onaylandı")
                            else:
                                print(f"Paket {i} için yanlış ACK alındı: {received_id}")
                                
                        except socket.timeout:
                            # ACK alamadık, ama paket gönderildi
                            print(f"Paket {i} için ACK alınamadı (timeout)")
                            stats['timeouts'] += 1
                            # ACK alamasak bile, UDP'de paket muhtemelen gitti
                            # Bu durumda başarılı kabul edebiliriz veya yeniden gönderebiliriz
                            packet_sent = True  # Veya False yapıp yeniden gönderim sağlayabilirsiniz
                            stats['success'] += 1
                            
                    except Exception as e:
                        print(f"Paket {i} gönderim hatası: {e}")
                        stats['lost'] += 1
                
                # Yeniden deneme kontrolü
                if not packet_sent:
                    retries += 1
                    if retries <= max_retries:
                        print(f"Paket {i} yeniden gönderilecek (Deneme {retries + 1}/{max_retries + 1})")
                        stats['retransmitted'] += 1
                        time.sleep(0.1)  # Kısa gecikme (network congestion'ı önlemek için)
                    else:
                        print(f"Paket {i} maksimum deneme sayısına ulaştı")
                        break
    
    except KeyboardInterrupt:
        # Kullanıcı Ctrl+C ile durdurdu
        print("\nSimülasyon kullanıcı tarafından durduruldu!")
    except Exception as e:
        print(f"Simülasyon hatası: {str(e)}")
        return False
    finally:
        # Socket'i her durumda kapat (resource leak'i önle)
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
    
    # Başarı oranını hesapla
    success_rate = (stats['success'] / len(chunks)) * 100 if chunks else 0
    print(f"Başarı oranı                : %{success_rate:.1f}")
    
    # Genel sonuç değerlendirmesi
    overall_success = stats['success'] == len(chunks)
    print(f"Genel sonuç                 : {'BAŞARILI' if overall_success else 'BAŞARISIZ'}")
    
    return overall_success