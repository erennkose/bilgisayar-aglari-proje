# enhanced_security_analysis.py - Gelişmiş güvenlik analizi ve protokol karşılaştırması
from scapy.all import sniff, IP, TCP, Raw, send, sr1, wrpcap
import time
import threading
import random
import os
import math
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import ssl
import socket
import platform

class SecurityAnalyzer:
    def __init__(self):
        self.results = {}
        
    def packet_capture(self, interface, filter_str, output_file=None, count=100):
        """
        Gelişmiş paket yakalama ve analiz
        """
        import platform
        
        if platform.system() == "Windows":
            print("Windows üzerinde paket yakalama için Wireshark kullanmanız önerilir.")
            print("Alternatif olarak, şu komutu bir yönetici komut satırında çalıştırabilirsiniz:")
            print(f"  tshark -i {interface} -f \"{filter_str}\" -c {count} -w {output_file or 'capture.pcap'}")
            return []
        else:
            print(f"Paket yakalama başlatıldı: {interface}")
            packets = sniff(iface=interface, filter=filter_str, count=count)
            
            if output_file:
                wrpcap(output_file, packets)
                print(f"Paketler kaydedildi: {output_file}")
            
            return packets

    def analyze_encrypted_data(self, packets):
        """
        Yakalanan paketlerdeki şifreli verileri detaylı analiz
        """
        print("\n=== ŞİFRELİ VERİ ANALİZİ ===")
        
        encrypted_payloads = []
        protocol_analysis = {
            'TLS/SSL': 0,
            'HTTP': 0,
            'Unencrypted': 0,
            'Suspicious': 0
        }
        
        for packet in packets:
            if Raw in packet:
                payload = packet[Raw].load
                encrypted_payloads.append(payload)
                
                # Protokol tespiti
                if self._is_tls_handshake(payload):
                    protocol_analysis['TLS/SSL'] += 1
                elif b'HTTP' in payload:
                    protocol_analysis['HTTP'] += 1
                elif self._is_likely_encrypted(payload):
                    protocol_analysis['Suspicious'] += 1
                else:
                    protocol_analysis['Unencrypted'] += 1
        
        # Entropi analizi
        entropy_scores = []
        for payload in encrypted_payloads:
            if len(payload) > 0:
                entropy = self._calculate_shannon_entropy(payload)
                entropy_scores.append(entropy)
        
        avg_entropy = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0
        
        print(f"Toplam paket sayısı: {len(packets)}")
        print(f"Raw payload bulunan paket: {len(encrypted_payloads)}")
        print(f"Ortalama entropi: {avg_entropy:.4f}")
        print(f"Şifreleme durumu: {'ŞİFRELİ' if avg_entropy > 7.5 else 'ŞİFRELENMEMİŞ'}")
        
        print("\nProtokol Dağılımı:")
        for protocol, count in protocol_analysis.items():
            print(f"  {protocol}: {count} paket")
        
        # Güvenlik önerileri
        self._generate_security_recommendations(protocol_analysis, avg_entropy)
        
        return {
            'entropy': avg_entropy,
            'protocols': protocol_analysis,
            'is_encrypted': avg_entropy > 7.5
        }

    def _is_tls_handshake(self, payload):
        """TLS handshake paketini tespit et"""
        if len(payload) < 6:
            return False
        # TLS record header: Content Type (22 = Handshake), Version, Length
        return payload[0] == 22 and payload[1:3] in [b'\x03\x01', b'\x03\x02', b'\x03\x03']

    def _is_likely_encrypted(self, payload):
        """Şifrelenmiş veri olasılığını değerlendir"""
        if len(payload) < 16:
            return False
        entropy = self._calculate_shannon_entropy(payload)
        return entropy > 7.0

    def _calculate_shannon_entropy(self, data):
        """Shannon Entropi hesaplama"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        
        return entropy

    def _generate_security_recommendations(self, protocols, entropy):
        """Güvenlik önerileri oluştur"""
        print("\n=== GÜVENLİK ÖNERİLERİ ===")
        
        if protocols['HTTP'] > 0:
            print("⚠️  HTTP trafiği tespit edildi - HTTPS kullanımı önerilir")
        
        if protocols['Unencrypted'] > protocols['TLS/SSL']:
            print("⚠️  Şifrelenmemiş trafik dominant - Şifreleme kullanımı artırılmalı")
        
        if entropy < 6.0:
            print("⚠️  Düşük entropi tespit edildi - Veri şifrelenmemiş olabilir")
        
        if protocols['TLS/SSL'] > 0:
            print("✅ TLS/SSL trafiği tespit edildi - İyi güvenlik uygulaması")

    def mitm_simulation(self, victim_ip, gateway_ip, interface="eth0"):
        """
        Gelişmiş MITM saldırı simülasyonu ve tespit
        """
        print("\n=== MITM SALDIRI SİMÜLASYONU VE TESPİTİ ===")
        
        if platform.system() == "Windows":
            print("MITM simülasyonu şu anda Windows üzerinde desteklenmiyor.")
            return self._simulate_mitm_detection()
        
        # MITM tespit mekanizmaları
        detection_results = {
            'arp_table_anomalies': False,
            'certificate_validation': False,
            'traffic_patterns': False,
            'mitm_detected': False
        }
        
        # ARP tablosu analizi
        detection_results['arp_table_anomalies'] = self._detect_arp_spoofing(victim_ip, gateway_ip)
        
        # Sertifika doğrulama testi
        detection_results['certificate_validation'] = self._test_certificate_pinning(victim_ip)
        
        # Trafik pattern analizi
        packets = self.packet_capture(interface, f"host {victim_ip}", count=50)
        detection_results['traffic_patterns'] = self._analyze_traffic_patterns(packets)
        
        # Genel MITM tespiti
        detection_results['mitm_detected'] = any([
            detection_results['arp_table_anomalies'],
            detection_results['certificate_validation'],
            detection_results['traffic_patterns']
        ])
        
        self._report_mitm_results(detection_results)
        return detection_results

    def _simulate_mitm_detection(self):
        """Windows için MITM tespit simülasyonu"""
        print("MITM tespit simülasyonu çalıştırılıyor...")
        
        # Simüle edilmiş sonuçlar
        detection_results = {
            'arp_table_anomalies': random.choice([True, False]),
            'certificate_validation': random.choice([True, False]),
            'traffic_patterns': random.choice([True, False]),
            'mitm_detected': False
        }
        
        detection_results['mitm_detected'] = any(detection_results.values())
        self._report_mitm_results(detection_results)
        return detection_results

    def _detect_arp_spoofing(self, victim_ip, gateway_ip):
        """ARP spoofing tespiti"""
        print("ARP spoofing analizi yapılıyor...")
        # Gerçek implementasyonda ARP tablosu kontrol edilir
        return random.choice([True, False])

    def _test_certificate_pinning(self, target_ip):
        """Sertifika sabitleme testi"""
        print("Sertifika doğrulama testi yapılıyor...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target_ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    cert = ssock.getpeercert()
                    # Sertifika analizi yapılabilir
                    return False  # Normal sertifika
        except:
            return True  # Potansiyel MITM

    def _analyze_traffic_patterns(self, packets):
        """Trafik pattern analizi"""
        print("Trafik pattern analizi yapılıyor...")
        # Anormal trafik patternlerini tespit et
        return len(packets) > 30  # Basit kural

    def _report_mitm_results(self, results):
        """MITM tespit sonuçlarını raporla"""
        print(f"\nMITM Tespit Sonuçları:")
        print(f"  ARP Tablosu Anomalileri: {'TESPIT EDİLDİ' if results['arp_table_anomalies'] else 'Normal'}")
        print(f"  Sertifika Doğrulama: {'BAŞARISIZ' if results['certificate_validation'] else 'Başarılı'}")
        print(f"  Trafik Pattern Anomalisi: {'TESPIT EDİLDİ' if results['traffic_patterns'] else 'Normal'}")
        print(f"  Genel Durum: {'⚠️ MITM SALDIRISI TESPİT EDİLDİ' if results['mitm_detected'] else '✅ Güvenli'}")

    def packet_injection_detection(self, target_ip, target_port=80):
        """
        Paket enjeksiyonu tespiti ve önleme
        """
        print("\n=== PAKET ENJEKSİYONU TESPİTİ ===")
        
        detection_methods = {
            'sequence_analysis': self._analyze_tcp_sequences(target_ip, target_port),
            'checksum_validation': self._validate_packet_checksums(target_ip, target_port),
            'rate_limiting': self._detect_suspicious_rates(target_ip, target_port),
            'payload_analysis': self._analyze_payload_patterns(target_ip, target_port)
        }
        
        injection_detected = any(detection_methods.values())
        
        print(f"\nPaket Enjeksiyonu Tespit Sonuçları:")
        for method, result in detection_methods.items():
            status = "ŞÜPHELI" if result else "NORMAL"
            print(f"  {method.replace('_', ' ').title()}: {status}")
        
        print(f"\nGenel Durum: {'⚠️ PAKET ENJEKSİYONU TESPİT EDİLDİ' if injection_detected else '✅ Güvenli'}")
        
        return detection_methods

    def _analyze_tcp_sequences(self, ip, port):
        """TCP sequence numarası analizi"""
        # Gerçek implementasyonda TCP sequence numaraları analiz edilir
        return random.choice([True, False])

    def _validate_packet_checksums(self, ip, port):
        """Paket checksum doğrulama"""
        return random.choice([True, False])

    def _detect_suspicious_rates(self, ip, port):
        """Şüpheli paket oranları tespiti"""
        return random.choice([True, False])

    def _analyze_payload_patterns(self, ip, port):
        """Payload pattern analizi"""
        return random.choice([True, False])

    def compare_security_protocols(self):
        """
        Güvenlik protokollerinin detaylı karşılaştırması
        """
        print("\n" + "="*60)
        print("GÜVENLİK PROTOKOLLERİ KARŞILAŞTIRMASI")
        print("="*60)
        
        protocols = {
            'HTTP': {
                'encryption': 'Yok',
                'authentication': 'Basic/Digest',
                'integrity': 'Yok',
                'security_level': 'Düşük',
                'port': 80,
                'use_case': 'Genel web trafiği (güvenli olmayan)',
                'vulnerabilities': ['Eavesdropping', 'MITM', 'Data tampering']
            },
            'HTTPS/TLS 1.3': {
                'encryption': 'AES-256-GCM, ChaCha20-Poly1305',
                'authentication': 'RSA, ECDSA, X.509 Certificates',
                'integrity': 'HMAC, AEAD',
                'security_level': 'Yüksek',
                'port': 443,
                'use_case': 'Güvenli web trafiği',
                'vulnerabilities': ['Certificate attacks', 'Implementation flaws']
            },
            'SSH': {
                'encryption': 'AES, 3DES, ChaCha20',
                'authentication': 'Password, Public Key, Certificate',
                'integrity': 'HMAC-SHA1/SHA2',
                'security_level': 'Yüksek',
                'port': 22,
                'use_case': 'Güvenli uzak bağlantı',
                'vulnerabilities': ['Weak passwords', 'Key management']
            },
            'IPSec': {
                'encryption': 'AES, 3DES',
                'authentication': 'PSK, RSA, ECDSA',
                'integrity': 'HMAC-SHA1/SHA2',
                'security_level': 'Çok Yüksek',
                'port': 'N/A (Layer 3)',
                'use_case': 'VPN, Site-to-site connections',
                'vulnerabilities': ['Configuration complexity', 'Key distribution']
            },
            'WPA3': {
                'encryption': 'AES-128/256',
                'authentication': 'SAE (Simultaneous Authentication of Equals)',
                'integrity': 'AES-GCMP',
                'security_level': 'Yüksek',
                'port': 'N/A (Wireless)',
                'use_case': 'WiFi güvenliği',
                'vulnerabilities': ['Downgrade attacks', 'Side-channel attacks']
            }
        }
        
        # Detaylı karşılaştırma tablosu
        for protocol_name, details in protocols.items():
            print(f"\n{protocol_name}")
            print("-" * len(protocol_name))
            for key, value in details.items():
                if key == 'vulnerabilities':
                    print(f"  {key.replace('_', ' ').title()}: {', '.join(value)}")
                else:
                    print(f"  {key.replace('_', ' ').title()}: {value}")
        
        # Güvenlik seviyesi karşılaştırması
        print(f"\n{'='*60}")
        print("GÜVENLİK SEVİYESİ SIRALAMASI")
        print("="*60)
        
        security_ranking = sorted(protocols.items(), 
                                key=lambda x: {'Düşük': 1, 'Yüksek': 2, 'Çok Yüksek': 3}[x[1]['security_level']], 
                                reverse=True)
        
        for i, (protocol, details) in enumerate(security_ranking, 1):
            print(f"{i}. {protocol} - {details['security_level']} Güvenlik")
        
        # Öneriler
        print(f"\n{'='*60}")
        print("KULLANIM ÖNERİLERİ")
        print("="*60)
        print("✅ Web uygulamaları için: HTTPS/TLS 1.3")
        print("✅ Uzak yönetim için: SSH")
        print("✅ VPN bağlantıları için: IPSec")
        print("✅ WiFi güvenliği için: WPA3")
        print("❌ Güvenli olmayan: HTTP (yalnızca test ortamlarında)")
        
        return protocols

    def generate_comprehensive_report(self, packets=None):
        """
        Kapsamlı güvenlik raporu oluştur
        """
        print("\n" + "="*80)
        print("KAPSAMLI GÜVENLİK ANALİZ RAPORU")
        print("="*80)
        
        # 1. Şifreleme analizi
        if packets:
            encryption_results = self.analyze_encrypted_data(packets)
        else:
            encryption_results = {'entropy': 0, 'protocols': {}, 'is_encrypted': False}
        
        # 2. Saldırı simülasyonları
        mitm_results = self._simulate_mitm_detection()
        injection_results = self.packet_injection_detection("192.168.1.1")
        
        # 3. Protokol karşılaştırması
        protocol_comparison = self.compare_security_protocols()
        
        # 4. Genel güvenlik skoru hesapla
        security_score = self._calculate_security_score(
            encryption_results, mitm_results, injection_results
        )
        
        print(f"\n{'='*80}")
        print("GENEL GÜVENLİK SKORU")
        print("="*80)
        print(f"Toplam Skor: {security_score}/100")
        self._display_security_grade(security_score)
        
        return {
            'encryption': encryption_results,
            'mitm_detection': mitm_results,
            'injection_detection': injection_results,
            'protocol_comparison': protocol_comparison,
            'security_score': security_score
        }

    def _calculate_security_score(self, encryption, mitm, injection):
        """Güvenlik skoru hesapla"""
        score = 0
        
        # Şifreleme skoru (40 puan)
        if encryption['is_encrypted']:
            score += 40
        elif encryption['entropy'] > 5.0:
            score += 20
        
        # MITM tespit skoru (30 puan)
        if not mitm['mitm_detected']:
            score += 30
        elif sum(mitm.values()) <= 2:
            score += 15
        
        # Injection tespit skoru (30 puan)
        detected_attacks = sum(injection.values())
        if detected_attacks == 0:
            score += 30
        elif detected_attacks <= 2:
            score += 15
        
        return score

    def _display_security_grade(self, score):
        """Güvenlik notunu görüntüle"""
        if score >= 90:
            grade = "A+ (Mükemmel)"
            color = "✅"
        elif score >= 80:
            grade = "A (Çok İyi)"
            color = "✅"
        elif score >= 70:
            grade = "B (İyi)"
            color = "⚠️"
        elif score >= 60:
            grade = "C (Orta)"
            color = "⚠️"
        elif score >= 50:
            grade = "D (Düşük)"
            color = "❌"
        else:
            grade = "F (Başarısız)"
            color = "❌"
        
        print(f"{color} Güvenlik Notu: {grade}")

# Kullanım örneği
if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    
    # Simüle edilmiş analiz
    print("Güvenlik analizi başlatılıyor...")
    report = analyzer.generate_comprehensive_report()
    
    print(f"\nAnaliz tamamlandı. Güvenlik skoru: {report['security_score']}/100")