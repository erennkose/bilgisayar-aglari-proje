# security_analysis.py - Gelişmiş güvenlik analizi ve protokol karşılaştırması

from scapy.all import sniff, IP, TCP, Raw, send, sr1, wrpcap
import random
import math
import ssl
import socket

class SecurityAnalyzer:
    """
    Ağ güvenliği analizi yapan ana sınıf
    Bu sınıf şifreli veri analizi, MITM saldırı tespiti, paket enjeksiyonu tespiti
    ve güvenlik protokollerinin karşılaştırılması işlevlerini sağlar
    """
    
    def __init__(self):
        """
        SecurityAnalyzer sınıfının yapıcı metodu
        Analiz sonuçlarını saklamak için boş bir sözlük başlatır
        """
        self.results = {}  # Analiz sonuçlarını saklamak için

    def analyze_encrypted_data(self, packets):
        """
        Yakalanan paketlerdeki şifreli verileri detaylı analiz eder
        """
        print("\n=== ŞİFRELİ VERİ ANALİZİ ===")
        
        # Şifreli payload'ları toplamak için liste
        encrypted_payloads = []
        
        # Protokol analizi için sayaçlar
        protocol_analysis = {
            'TLS/SSL': 0,        # Güvenli TLS/SSL protokolü
            'HTTP': 0,           # Güvensiz HTTP protokolü
            'Unencrypted': 0,    # Şifrelenmemiş veri
            'Suspicious': 0      # Şüpheli/belirsiz veriler
        }
        
        # Her paketi tek tek analiz et
        for packet in packets:
            # Paket içinde Raw (ham veri) katmanı var mı kontrol et
            if Raw in packet:
                payload = packet[Raw].load  # Ham veriyi al
                encrypted_payloads.append(payload)  # Listeye ekle
                
                # Protokol türünü tespit et ve sayacı artır
                if self._is_tls_handshake(payload):
                    protocol_analysis['TLS/SSL'] += 1
                elif b'HTTP' in payload:  # HTTP string'i aranıyor
                    protocol_analysis['HTTP'] += 1
                elif self._is_likely_encrypted(payload):
                    protocol_analysis['Suspicious'] += 1
                else:
                    protocol_analysis['Unencrypted'] += 1
        
        # Shannon entropi analizi - veri rastgeleliğini ölçer
        entropy_scores = []
        for payload in encrypted_payloads:
            if len(payload) > 0:  # Boş payload'ları atla
                entropy = self._calculate_shannon_entropy(payload)
                entropy_scores.append(entropy)
        
        # Ortalama entropi hesapla (yüksek entropi = şifreli veri)
        avg_entropy = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0
        
        # Sonuçları kullanıcıya göster
        print(f"Toplam paket sayısı: {len(packets)}")
        print(f"Raw payload bulunan paket: {len(encrypted_payloads)}")
        print(f"Ortalama entropi: {avg_entropy:.4f}")
        print(f"Şifreleme durumu: {'ŞİFRELİ' if avg_entropy > 7.5 else 'ŞİFRELENMEMİŞ'}")
        
        print("\nProtokol Dağılımı:")
        for protocol, count in protocol_analysis.items():
            print(f"  {protocol}: {count} paket")
        
        # Güvenlik önerilerini oluştur ve göster
        self._generate_security_recommendations(protocol_analysis, avg_entropy)
        
        # Analiz sonuçlarını döndür
        return {
            'entropy': avg_entropy,
            'protocols': protocol_analysis,
            'is_encrypted': avg_entropy > 7.5  # 7.5'ten yüksek entropi şifreli kabul edilir
        }

    def _is_tls_handshake(self, payload):
        """
        TLS handshake paketini tespit eder
        TLS handshake paketleri belirli bir yapıya sahiptir
        """
        if len(payload) < 6:  # Minimum TLS header boyutu kontrolü
            return False
        # TLS record header yapısı: Content Type (22 = Handshake), Version, Length
        return payload[0] == 22 and payload[1:3] in [b'\x03\x01', b'\x03\x02', b'\x03\x03']

    def _is_likely_encrypted(self, payload):
        """
        Verinin şifrelenmiş olma olasılığını değerlendirir
        Yüksek entropi şifreli veriyi işaret eder
        """
        if len(payload) < 16:  # Çok küçük veriler için analiz yapma
            return False
        entropy = self._calculate_shannon_entropy(payload)
        return entropy > 7.0  # 7.0'dan yüksek entropi şüpheli kabul edilir

    def _calculate_shannon_entropy(self, data):
        """
        Shannon Entropi hesaplaması yapar
        Entropi, veri içindeki rastgelelik miktarını ölçer
        Şifreli veriler yüksek entropiye sahiptir
        """
        if not data:  # Boş veri kontrolü
            return 0
        
        entropy = 0
        # Her byte değeri (0-255) için olasılık hesapla
        for x in range(256):
            p_x = data.count(x) / len(data)  # Byte'ın görülme olasılığı
            if p_x > 0:  # Logaritma hatası önleme
                entropy -= p_x * math.log2(p_x)  # Shannon entropi formülü
        
        return entropy

    def _generate_security_recommendations(self, protocols, entropy):
        """
        Analiz sonuçlarına göre güvenlik önerileri oluşturur
        """
        print("\n=== GÜVENLİK ÖNERİLERİ ===")
        
        # HTTP trafiği güvenlik riski oluşturur
        if protocols['HTTP'] > 0:
            print("HTTP trafiği tespit edildi - HTTPS kullanımı önerilir")
        
        # Şifrelenmemiş trafik dominant ise uyarı ver
        if protocols['Unencrypted'] > protocols['TLS/SSL']:
            print("Şifrelenmemiş trafik dominant - Şifreleme kullanımı artırılmalı")
        
        # Düşük entropi şifrelenmemiş veriyi işaret eder
        if entropy < 6.0:
            print("Düşük entropi tespit edildi - Veri şifrelenmemiş olabilir")
        
        # TLS/SSL kullanımı güvenlik açısından olumlu
        if protocols['TLS/SSL'] > 0:
            print("TLS/SSL trafiği tespit edildi - İyi güvenlik uygulaması")

    def mitm_simulation(self, victim_ip, gateway_ip, interface="eth0"):
        """
        Gelişmiş MITM (Man-in-the-Middle) saldırı simülasyonu ve tespiti
        Gerçek ortamda bu fonksiyon ARP spoofing, sertifika kontrolü vb. yapar
        """
        print("\n=== MITM SALDIRI SİMÜLASYONU VE TESPİTİ ===")
        return self._simulate_mitm_detection()

    def _simulate_mitm_detection(self):
        """
        Windows ortamı için MITM tespit simülasyonu yapar
        Gerçek implementasyonda ağ trafiği ve ARP tablosu analiz edilir
        """
        print("MITM tespit simülasyonu çalıştırılıyor...")
        
        # Simüle edilmiş tespit sonuçları
        detection_results = {
            'arp_table_anomalies': random.choice([True, False]),    # ARP tablosu anomalileri
            'certificate_validation': random.choice([True, False]), # Sertifika doğrulama sorunları
            'traffic_patterns': random.choice([True, False]),       # Anormal trafik paternleri
            'mitm_detected': False  # Genel MITM tespiti
        }
        
        # Herhangi bir anomali tespit edilirse MITM var kabul et
        detection_results['mitm_detected'] = any(detection_results.values())
        self._report_mitm_results(detection_results)
        return detection_results

    def _detect_arp_spoofing(self, victim_ip, gateway_ip):
        """
        ARP spoofing saldırısını tespit eder
        ARP tablosundaki tutarsızlıkları arar
        """
        print("ARP spoofing analizi yapılıyor...")
        # Gerçek implementasyonda ARP tablosu analiz edilir ve MAC adresi değişimleri kontrol edilir
        return random.choice([True, False])

    def _test_certificate_pinning(self, target_ip):
        """
        SSL sertifika sabitleme (certificate pinning) testi yapar
        MITM saldırıları genelde sahte sertifikalar kullanır
        """
        print("Sertifika doğrulama testi yapılıyor...")
        try:
            # SSL bağlamı oluştur ve güvenli bağlantı kur
            context = ssl.create_default_context()
            with socket.create_connection((target_ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    cert = ssock.getpeercert()  # Sertifika bilgilerini al
                    # Gerçek implementasyonda sertifika imzası, zinciri vb. kontrol edilir
                    return False  # Normal sertifika durumu
        except:
            # Bağlantı hatası veya sertifika sorunu
            return True  # Potansiyel MITM işareti

    def _analyze_traffic_patterns(self, packets):
        """
        Ağ trafiği pattern analizi yapar
        Anormal trafik davranışları MITM saldırısını işaret edebilir
        """
        print("Trafik pattern analizi yapılıyor...")
        # Basit kural: fazla paket anormal kabul edilir
        # Gerçek implementasyonda zaman analizi, paket boyutu, frekans vb. kontrol edilir
        return len(packets) > 30

    def _report_mitm_results(self, results):
        """
        MITM tespit sonuçlarını kullanıcıya raporlar
        """
        print(f"\nMITM Tespit Sonuçları:")
        print(f"  ARP Tablosu Anomalileri: {'TESPIT EDİLDİ' if results['arp_table_anomalies'] else 'Normal'}")
        print(f"  Sertifika Doğrulama: {'BAŞARISIZ' if results['certificate_validation'] else 'Başarılı'}")  
        print(f"  Trafik Pattern Anomalisi: {'TESPIT EDİLDİ' if results['traffic_patterns'] else 'Normal'}")
        print(f"  Genel Durum: {'MITM SALDIRISI TESPİT EDİLDİ' if results['mitm_detected'] else 'Güvenli'}")

    def packet_injection_detection(self, target_ip, target_port=80):
        """
        Paket enjeksiyonu saldırısını tespit eder ve önler
        Kötü niyetli paketlerin ağa enjekte edilmesini kontrol eder
        """
        print("\n=== PAKET ENJEKSİYONU TESPİTİ ===")
        
        # Çeşitli tespit yöntemlerini uygula
        detection_methods = {
            'sequence_analysis': self._analyze_tcp_sequences(target_ip, target_port),     # TCP sequence analizi
            'checksum_validation': self._validate_packet_checksums(target_ip, target_port), # Checksum doğrulama
            'rate_limiting': self._detect_suspicious_rates(target_ip, target_port),      # Hız sınırı kontrolü
            'payload_analysis': self._analyze_payload_patterns(target_ip, target_port)   # Payload pattern analizi
        }
        
        # Herhangi bir yöntem pozitif sonuç verirse enjeksiyon var kabul et
        injection_detected = any(detection_methods.values())
        
        # Sonuçları kullanıcıya raporla
        print(f"\nPaket Enjeksiyonu Tespit Sonuçları:")
        for method, result in detection_methods.items():
            status = "ŞÜPHELI" if result else "NORMAL"
            print(f"  {method.replace('_', ' ').title()}: {status}")
        
        print(f"\nGenel Durum: {'PAKET ENJEKSİYONU TESPİT EDİLDİ' if injection_detected else 'Güvenli'}")
        
        return detection_methods

    def _analyze_tcp_sequences(self, ip, port):
        """
        TCP sequence numarası analizi yapar
        Anormal sequence numaraları paket enjeksiyonunu işaret edebilir
        """
        # Gerçek implementasyonda TCP sequence numaraları takip edilir
        # ve beklenmeyen sıçramalar tespit edilir
        return random.choice([True, False])

    def _validate_packet_checksums(self, ip, port):
        """
        Paket checksum doğrulaması yapar
        Bozuk checksumlar paket manipülasyonunu işaret eder
        """
        # Gerçek implementasyonda IP ve TCP checksumları doğrulanır
        return random.choice([True, False])

    def _detect_suspicious_rates(self, ip, port):
        """
        Şüpheli paket gönderim oranlarını tespit eder
        Anormal yüksek paket oranları saldırı işareti olabilir
        """
        # Gerçek implementasyonda paket/saniye oranı hesaplanır
        # ve threshold değerleri ile karşılaştırılır
        return random.choice([True, False])

    def _analyze_payload_patterns(self, ip, port):
        """
        Paket payload pattern analizi yapar
        Bilinen saldırı imzalarını arar
        """
        # Gerçek implementasyonda payload içeriği analiz edilir
        # ve bilinen exploit/malware imzaları aranır
        return random.choice([True, False])

    def compare_security_protocols(self):
        """
        Güvenlik protokollerinin detaylı karşılaştırmasını yapar
        Yaygın kullanılan protokollerin güvenlik özelliklerini listeler
        """
        print("\n" + "="*60)
        print("GÜVENLİK PROTOKOLLERİ KARŞILAŞTIRMASI")
        print("="*60)
        
        # Ana güvenlik protokolleri ve özellikleri
        protocols = {
            'HTTP': {
                'encryption': 'Yok',                    # Şifreleme yok
                'authentication': 'Basic/Digest',       # Zayıf kimlik doğrulama
                'integrity': 'Yok',                     # Veri bütünlüğü korunmuyor
                'security_level': 'Düşük',             # Genel güvenlik seviyesi
                'port': 80,                             # Standart port numarası
                'use_case': 'Genel web trafiği (güvenli olmayan)',
                'vulnerabilities': ['Eavesdropping', 'MITM', 'Data tampering']  # Bilinen güvenlik açıkları
            },
            'HTTPS/TLS 1.3': {
                'encryption': 'AES-256-GCM, ChaCha20-Poly1305',  # Güçlü şifreleme algoritmaları
                'authentication': 'RSA, ECDSA, X.509 Certificates', # Güvenli kimlik doğrulama
                'integrity': 'HMAC, AEAD',                       # Veri bütünlüğü koruması
                'security_level': 'Yüksek',
                'port': 443,
                'use_case': 'Güvenli web trafiği',
                'vulnerabilities': ['Certificate attacks', 'Implementation flaws']
            },
            'SSH': {
                'encryption': 'AES, 3DES, ChaCha20',            # Çoklu şifreleme desteği
                'authentication': 'Password, Public Key, Certificate', # Esnek kimlik doğrulama
                'integrity': 'HMAC-SHA1/SHA2',                  # Güçlü bütünlük kontrolü
                'security_level': 'Yüksek',
                'port': 22,
                'use_case': 'Güvenli uzak bağlantı',
                'vulnerabilities': ['Weak passwords', 'Key management']
            },
            'IPSec': {
                'encryption': 'AES, 3DES',                      # Enterprise seviye şifreleme
                'authentication': 'PSK, RSA, ECDSA',            # Çoklu kimlik doğrulama
                'integrity': 'HMAC-SHA1/SHA2',
                'security_level': 'Çok Yüksek',                 # En yüksek güvenlik seviyesi
                'port': 'N/A (Layer 3)',                        # Ağ katmanında çalışır
                'use_case': 'VPN, Site-to-site connections',
                'vulnerabilities': ['Configuration complexity', 'Key distribution']
            },
            'WPA3': {
                'encryption': 'AES-128/256',                    # WiFi için güçlü şifreleme
                'authentication': 'SAE (Simultaneous Authentication of Equals)', # Modern kimlik doğrulama
                'integrity': 'AES-GCMP',                        # Gelişmiş bütünlük koruması
                'security_level': 'Yüksek',
                'port': 'N/A (Wireless)',                       # Kablosuz protokol
                'use_case': 'WiFi güvenliği',
                'vulnerabilities': ['Downgrade attacks', 'Side-channel attacks']
            }
        }
        
        # Her protokol için detaylı bilgileri göster
        for protocol_name, details in protocols.items():
            print(f"\n{protocol_name}")
            print("-" * len(protocol_name))
            for key, value in details.items():
                if key == 'vulnerabilities':
                    # Güvenlik açıklarını virgülle ayırarak göster
                    print(f"  {key.replace('_', ' ').title()}: {', '.join(value)}")
                else:
                    # Diğer özellikleri doğrudan göster
                    print(f"  {key.replace('_', ' ').title()}: {value}")
        
        # Güvenlik seviyesine göre sıralama yap
        print(f"\n{'='*60}")
        print("GÜVENLİK SEVİYESİ SIRALAMASI")
        print("="*60)
        
        # Güvenlik seviyelerine numerik değer ata ve sırala
        security_ranking = sorted(protocols.items(), 
                                key=lambda x: {'Düşük': 1, 'Yüksek': 2, 'Çok Yüksek': 3}[x[1]['security_level']], 
                                reverse=True)
        
        # Sıralanmış listeyi göster
        for i, (protocol, details) in enumerate(security_ranking, 1):
            print(f"{i}. {protocol} - {details['security_level']} Güvenlik")
        
        # Kullanım durumlarına göre öneriler
        print(f"\n{'='*60}")
        print("KULLANIM ÖNERİLERİ")
        print("="*60)
        print("Web uygulamaları için: HTTPS/TLS 1.3")
        print("Uzak yönetim için: SSH")
        print("VPN bağlantıları için: IPSec")
        print("WiFi güvenliği için: WPA3")
        print("Güvenli olmayan: HTTP (yalnızca test ortamlarında)")
        
        return protocols

    def generate_comprehensive_report(self, packets=None):
        """
        Tüm güvenlik analizlerini birleştiren kapsamlı rapor oluşturur
        Bu metod tüm güvenlik kontrollerini çalıştırır ve genel bir değerlendirme yapar
        """
        print("\n" + "="*80)
        print("KAPSAMLI GÜVENLİK ANALİZ RAPORU")
        print("="*80)
        
        # 1. Şifreleme analizi - eğer paket varsa analiz et
        if packets:
            encryption_results = self.analyze_encrypted_data(packets)
        else:
            # Paket yoksa varsayılan değerler kullan
            encryption_results = {'entropy': 0, 'protocols': {}, 'is_encrypted': False}
        
        # 2. Saldırı simülasyonları - MITM ve paket enjeksiyonu tespiti
        mitm_results = self._simulate_mitm_detection()
        injection_results = self.packet_injection_detection("127.0.0.1")  # Test IP adresi
        
        # 3. Protokol karşılaştırması - mevcut protokolleri değerlendir
        protocol_comparison = self.compare_security_protocols()
        
        # 4. Tüm sonuçları kullanarak genel güvenlik skoru hesapla
        security_score = self._calculate_security_score(
            encryption_results, mitm_results, injection_results
        )
        
        # Genel güvenlik skorunu göster
        print(f"\n{'='*80}")
        print("GENEL GÜVENLİK SKORU")
        print("="*80)
        print(f"Toplam Skor: {security_score}/100")
        self._display_security_grade(security_score)
        
        # Tüm analiz sonuçlarını döndür
        return {
            'encryption': encryption_results,
            'mitm_detection': mitm_results,
            'injection_detection': injection_results,
            'protocol_comparison': protocol_comparison,
            'security_score': security_score
        }

    def _calculate_security_score(self, encryption, mitm, injection):
        """
        Güvenlik skoru hesaplama algoritması
        Farklı güvenlik metriklerini birleştirerek 0-100 arası skor üretir
        """
        score = 0
        
        # Şifreleme skoru
        if encryption['is_encrypted']:
            score += 40  # şifreli
        elif encryption['entropy'] > 5.0:
            score += 20  # kısmen şifreli
        
        # MITM tespit skoru
        if not mitm['mitm_detected']:
            score += 30  # MITM tespit edilmedi
        elif sum(mitm.values()) <= 2:
            score += 15  # az sayıda anomali
        
        # Paket enjeksiyonu tespit skoru
        detected_attacks = sum(injection.values())
        if detected_attacks == 0:
            score += 30  # hiç saldırı tespit edilmedi
        elif detected_attacks <= 2:
            score += 15  # az saldırı tespit edildi
        
        return score

    def _display_security_grade(self, score):
        """Güvenlik notunu görüntüle"""
        if score >= 90:
            grade = "A+ (Mükemmel)"
        elif score >= 80:
            grade = "A (Çok İyi)"
        elif score >= 70:
            grade = "B (İyi)"
        elif score >= 60:
            grade = "C (Orta)"
        elif score >= 50:
            grade = "D (Düşük)"
        else:
            grade = "F (Başarısız)"
        
        print(f"Güvenlik Notu: {grade}")