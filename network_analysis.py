# network_analysis.py - Ağ performansı analizi
import time
import subprocess
import re
import platform
import socket
from scapy.all import IP, ICMP, sr1

def measure_latency(target_ip, count=5):
    """Ping kullanarak gecikmeyi ölçme"""
    import platform
    
    if platform.system() == "Windows":
        import subprocess
        import re
        
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