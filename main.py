# main.py - Ana program
import os
import sys
import argparse
import time
from server import start_server
from client import start_client, encrypt_file_with_aes, calculate_sha256
from ip_header import send_fragmented_data
from network_analysis import measure_latency, run_iperf_client, simulate_packet_loss, reset_tc_rules
from security_analysis import packet_capture, analyze_encrypted_data, mitm_simulation, packet_injection_simulation

def main():
    parser = argparse.ArgumentParser(description='Gelişmiş Güvenli Dosya Transfer Sistemi')
    parser.add_argument('mode', choices=['server', 'client', 'analyze'], help='Çalışma modu')
    parser.add_argument('--file', help='Gönderilecek dosya (client modunda)')
    parser.add_argument('--ip', help='Hedef IP adresi (client modunda)')
    parser.add_argument('--port', type=int, default=9999, help='Port numarası')
    parser.add_argument('--analyze', choices=['latency', 'bandwidth', 'packet_loss', 'security'], 
                        help='Analiz türü (analyze modunda)')
    parser.add_argument('--interface', default='eth0', help='Ağ arayüzü (analyze modunda)')
    parser.add_argument('--loss', type=int, default=5, help='Simüle edilecek paket kaybı yüzdesi')
    
    args = parser.parse_args()
    
    if args.mode == 'server':
        start_server()
    
    elif args.mode == 'client':
        if not args.file or not args.ip:
            print("Hata: --file ve --ip parametreleri gereklidir")
            parser.print_help()
            sys.exit(1)
        
        if not os.path.exists(args.file):
            print(f"Hata: {args.file} bulunamadı")
            sys.exit(1)
        
        start_client((args.ip, args.port), args.file)
    
    elif args.mode == 'analyze':
        if not args.analyze:
            print("Hata: --analyze parametresi gereklidir")
            parser.print_help()
            sys.exit(1)
        
        if args.analyze == 'latency':
            if not args.ip:
                print("Hata: --ip parametresi gereklidir")
                sys.exit(1)
            
            print(f"{args.ip} adresine gecikme ölçümü yapılıyor...")
            result = measure_latency(args.ip, count=10)
            
            if result:
                print(f"Minimum gecikme: {result['min']:.2f} ms")
                print(f"Ortalama gecikme: {result['avg']:.2f} ms")
                print(f"Maksimum gecikme: {result['max']:.2f} ms")
            else:
                print("Gecikme ölçülemedi")
        
        elif args.analyze == 'bandwidth':
            if not args.ip:
                print("Hata: --ip parametresi gereklidir")
                sys.exit(1)
            
            print(f"{args.ip} adresine bant genişliği ölçümü yapılıyor...")
            bandwidth = run_iperf_client(args.ip, duration=5)
            
            if bandwidth:
                print(f"Bant genişliği: {bandwidth:.2f} Mbits/s")
            else:
                print("Bant genişliği ölçülemedi. iPerf sunucusu çalışıyor mu?")
        
        elif args.analyze == 'packet_loss':
            print(f"Paket kaybı simülasyonu yapılıyor (%{args.loss})...")
            success = simulate_packet_loss(percentage=args.loss)
            
            if success:
                print(f"Paket kaybı simülasyonu başlatıldı (%{args.loss})")
                print("10 saniye sonra sıfırlanacak...")
                time.sleep(10)
                reset_tc_rules()
                print("Ağ ayarları sıfırlandı")
            else:
                print("Paket kaybı simülasyonu başlatılamadı")
        
        elif args.analyze == 'security':
            if not args.ip:
                print("Hata: --ip parametresi gereklidir")
                sys.exit(1)
            
            import platform
            if platform.system() == "Windows":
                print("Güvenlik analizi Windows üzerinde sınırlı çalışabilir.")
                print("Tam analiz için Wireshark ve diğer güvenlik araçlarını kurmanız önerilir.")
            
            print(f"Ağ trafiği izleniyor ({args.interface})...")
            packets = packet_capture(args.interface, f"host {args.ip}", count=50)
            
            if packets:  # Eğer paketler yakalandıysa
                print("Yakalanan paketler analiz ediliyor...")
                entropy = analyze_encrypted_data(packets)
            
            print("MITM saldırısı simülasyonu yapılıyor...")
            gateway = get_default_gateway()
            if gateway:
                mitm_packets = mitm_simulation(args.ip, gateway, args.interface)
                if mitm_packets:
                    print(f"Yakalanan paket sayısı: {len(mitm_packets)}")
            else:
                print("Gateway bulunamadı, MITM simülasyonu atlanıyor")
            
            print("Paket enjeksiyonu simülasyonu yapılıyor...")
            packet_injection_simulation(args.ip, args.port)

def get_default_gateway():
    """
    Varsayılan gateway IP adresini bulma
    """
    import socket
    import struct
    
    try:
        with open('/proc/net/route') as f:
            for line in f:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except:
        return None

if __name__ == "__main__":
    main()