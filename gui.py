import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import subprocess
from client import start_client
from server import start_server, stop_server, server_running, server_socket
from network_analysis import measure_latency, run_iperf_client
from security_analysis import packet_capture, analyze_encrypted_data, mitm_simulation, packet_injection_simulation
from ip_header import send_fragmented_data

IPERF_PATH = "C:\\iperf\\iperf3.exe"
CLUMSY_PATH = "C:\\Program Files\\Clumsy\\clumsy.exe"
WIRESHARK_PATH = "C:\\Program Files\\Wireshark\\Wireshark.exe"

class SecureTransferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Güvenli Dosya Transfer Sistemi")
        self.root.geometry("700x650")

        # Ana notebook (sekmeler)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Sekmeler
        self.server_frame = ttk.Frame(self.notebook)
        self.client_frame = ttk.Frame(self.notebook)
        self.tools_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.server_frame, text="Sunucu")
        self.notebook.add(self.client_frame, text="İstemci")
        self.notebook.add(self.tools_frame, text="Analiz Araçları")

        # Alt kısımda ortak çıktı alanı
        self.create_output_area()
        
        # Her sekme için widget'ları oluştur
        self.create_server_widgets()
        self.create_client_widgets()
        self.create_tools_widgets()

    def create_output_area(self):
        """Ortak çıktı alanını oluştur"""
        output_frame = tk.Frame(self.root)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        tk.Label(output_frame, text="Sistem Çıktıları:", font=("Arial", 10, "bold")).pack(anchor='w')

        text_frame = tk.Frame(output_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)

        self.output_text = tk.Text(text_frame, height=8, wrap=tk.WORD, font=("Consolas", 9))
        scrollbar = tk.Scrollbar(text_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scrollbar.set)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        tk.Button(self.root, text="Çıktıyı Temizle", command=self.clear_output).pack(pady=5)

    def create_server_widgets(self):
        """Sunucu sekmesi widget'ları"""
        main_frame = tk.Frame(self.server_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Başlık
        title_label = tk.Label(main_frame, text="Sunucu Konfigürasyonu", 
                              font=("Arial", 14, "bold"), fg="darkblue")
        title_label.pack(pady=(0, 20))

        # Sunucu ayarları
        config_frame = tk.LabelFrame(main_frame, text="Sunucu Ayarları", font=("Arial", 10, "bold"))
        config_frame.pack(fill=tk.X, pady=(0, 20))

        # IP adresi
        ip_frame = tk.Frame(config_frame)
        ip_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(ip_frame, text="Sunucu IP Adresi:", width=15, anchor='w').pack(side=tk.LEFT)
        self.server_ip_entry = tk.Entry(ip_frame, width=20, font=("Arial", 10))
        self.server_ip_entry.insert(0, "0.0.0.0")
        self.server_ip_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Port
        port_frame = tk.Frame(config_frame)
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(port_frame, text="Port:", width=15, anchor='w').pack(side=tk.LEFT)
        self.server_port_entry = tk.Entry(port_frame, width=20, font=("Arial", 10))
        self.server_port_entry.insert(0, "9999")
        self.server_port_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Protokol seçimi
        protocol_frame = tk.Frame(config_frame)
        protocol_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(protocol_frame, text="Protokol:", width=15, anchor='w').pack(side=tk.LEFT)
        self.server_protocol_var = tk.StringVar(value="tcp")
        protocol_inner_frame = tk.Frame(protocol_frame)
        protocol_inner_frame.pack(side=tk.LEFT, padx=(10, 0))
        tk.Radiobutton(protocol_inner_frame, text="TCP", variable=self.server_protocol_var, value="tcp").pack(side=tk.LEFT)
        tk.Radiobutton(protocol_inner_frame, text="UDP", variable=self.server_protocol_var, value="udp").pack(side=tk.LEFT, padx=(10, 0))

        # Sunucu durumu
        status_frame = tk.LabelFrame(main_frame, text="Sunucu Durumu", font=("Arial", 10, "bold"))
        status_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.server_status_label = tk.Label(status_frame, text="Sunucu durduruldu", 
                                          fg="red", font=("Arial", 10, "bold"))
        self.server_status_label.pack(pady=10)

        # Kontrol butonları
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        self.start_server_btn = tk.Button(button_frame, text="Sunucuyu Başlat", 
                                         command=self.start_server, bg="lightgreen", 
                                         font=("Arial", 10, "bold"), width=15)
        self.start_server_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_server_btn = tk.Button(button_frame, text="Sunucuyu Durdur", 
                                        command=self.stop_server, bg="lightcoral", 
                                        font=("Arial", 10, "bold"), width=15, state=tk.DISABLED)
        self.stop_server_btn.pack(side=tk.LEFT)

        self.server_thread = None

    def create_client_widgets(self):
        """İstemci sekmesi widget'ları"""
        main_frame = tk.Frame(self.client_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Başlık
        title_label = tk.Label(main_frame, text="İstemci Konfigürasyonu", 
                              font=("Arial", 14, "bold"), fg="darkgreen")
        title_label.pack(pady=(0, 20))

        # Bağlantı ayarları
        connection_frame = tk.LabelFrame(main_frame, text="Bağlantı Ayarları", font=("Arial", 10, "bold"))
        connection_frame.pack(fill=tk.X, pady=(0, 20))

        # Hedef IP
        ip_frame = tk.Frame(connection_frame)
        ip_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(ip_frame, text="Hedef IP Adresi:", width=15, anchor='w').pack(side=tk.LEFT)
        self.client_ip_entry = tk.Entry(ip_frame, width=20, font=("Arial", 10))
        self.client_ip_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Port
        port_frame = tk.Frame(connection_frame)
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(port_frame, text="Port:", width=15, anchor='w').pack(side=tk.LEFT)
        self.client_port_entry = tk.Entry(port_frame, width=20, font=("Arial", 10))
        self.client_port_entry.insert(0, "9999")
        self.client_port_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Protokol
        protocol_frame = tk.Frame(connection_frame)
        protocol_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(protocol_frame, text="Protokol:", width=15, anchor='w').pack(side=tk.LEFT)
        self.client_protocol_var = tk.StringVar(value="tcp")
        protocol_inner_frame = tk.Frame(protocol_frame)
        protocol_inner_frame.pack(side=tk.LEFT, padx=(10, 0))
        tk.Radiobutton(protocol_inner_frame, text="TCP", variable=self.client_protocol_var, value="tcp").pack(side=tk.LEFT)
        tk.Radiobutton(protocol_inner_frame, text="UDP", variable=self.client_protocol_var, value="udp").pack(side=tk.LEFT, padx=(10, 0))

        # Dosya seçimi
        file_frame = tk.LabelFrame(main_frame, text="Dosya Seçimi", font=("Arial", 10, "bold"))
        file_frame.pack(fill=tk.X, pady=(0, 20))

        file_inner_frame = tk.Frame(file_frame)
        file_inner_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(file_inner_frame, text="Dosya Yolu:", width=15, anchor='w').pack(side=tk.LEFT)
        self.file_entry = tk.Entry(file_inner_frame, width=30, font=("Arial", 10))
        self.file_entry.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)
        tk.Button(file_inner_frame, text="Gözat", command=self.browse_file, width=8).pack(side=tk.RIGHT)

        # Gelişmiş ayarlar
        advanced_frame = tk.LabelFrame(main_frame, text="Gelişmiş Ayarlar", font=("Arial", 10, "bold"))
        advanced_frame.pack(fill=tk.X, pady=(0, 20))

        # MTU ayarı
        mtu_frame = tk.Frame(advanced_frame)
        mtu_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(mtu_frame, text="MTU Boyutu:", width=15, anchor='w').pack(side=tk.LEFT)
        self.mtu_entry = tk.Entry(mtu_frame, width=20, font=("Arial", 10))
        self.mtu_entry.insert(0, "1500")
        self.mtu_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Gönderim butonları
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        tk.Button(button_frame, text="Normal Gönder", command=self.send_file_normal, 
                 bg="lightblue", font=("Arial", 10, "bold"), width=15).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="IP Header ile Gönder", command=self.send_with_ip_header, 
                 bg="lightcyan", font=("Arial", 10, "bold"), width=18).pack(side=tk.LEFT)

    def create_tools_widgets(self):
        """Analiz araçları sekmesi widget'ları"""
        main_frame = tk.Frame(self.tools_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Başlık
        title_label = tk.Label(main_frame, text="Ağ Analiz Araçları", 
                              font=("Arial", 14, "bold"), fg="darkorange")
        title_label.pack(pady=(0, 20))

        # Hedef IP girişi
        target_frame = tk.LabelFrame(main_frame, text="Hedef Bilgileri", font=("Arial", 10, "bold"))
        target_frame.pack(fill=tk.X, pady=(0, 20))
        
        ip_frame = tk.Frame(target_frame)
        ip_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(ip_frame, text="Hedef IP Adresi:", width=15, anchor='w').pack(side=tk.LEFT)
        self.target_ip_entry = tk.Entry(ip_frame, width=20, font=("Arial", 10))
        self.target_ip_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Ağ analizi araçları
        network_frame = tk.LabelFrame(main_frame, text="Ağ Performans Analizi", font=("Arial", 10, "bold"))
        network_frame.pack(fill=tk.X, pady=(0, 15))
        
        network_buttons_frame = tk.Frame(network_frame)
        network_buttons_frame.pack(padx=10, pady=10)
        
        tk.Button(network_buttons_frame, text="Gecikme Ölç", command=self.run_latency_analysis,
                 width=15, bg="lightsteelblue").pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(network_buttons_frame, text="Bant Genişliği Ölç", command=self.run_bandwidth_analysis,
                 width=18, bg="lightsteelblue").pack(side=tk.LEFT)

        # Güvenlik analizi araçları
        security_frame = tk.LabelFrame(main_frame, text="Güvenlik Analizi", font=("Arial", 10, "bold"))
        security_frame.pack(fill=tk.X, pady=(0, 15))
        
        security_buttons_frame1 = tk.Frame(security_frame)
        security_buttons_frame1.pack(padx=10, pady=5)
        
        tk.Button(security_buttons_frame1, text="Entropi Analizi", command=self.run_entropy_analysis,
                 width=15, bg="lightyellow").pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(security_buttons_frame1, text="MITM Simülasyonu", command=self.run_mitm_simulation,
                 width=18, bg="lightyellow").pack(side=tk.LEFT)
        
        security_buttons_frame2 = tk.Frame(security_frame)
        security_buttons_frame2.pack(padx=10, pady=5)
        
        tk.Button(security_buttons_frame2, text="Paket Enjeksiyonu", command=self.run_packet_injection,
                 width=15, bg="lightyellow").pack()

        # Dış araçlar
        external_frame = tk.LabelFrame(main_frame, text="Dış Araçlar", font=("Arial", 10, "bold"))
        external_frame.pack(fill=tk.X)
        
        external_buttons_frame = tk.Frame(external_frame)
        external_buttons_frame.pack(padx=10, pady=10)
        
        tk.Button(external_buttons_frame, text="Clumsy Başlat", command=self.start_clumsy,
                 width=15, bg="lightpink").pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(external_buttons_frame, text="Wireshark Başlat", command=self.start_wireshark,
                 width=18, bg="lightpink").pack(side=tk.LEFT)

    def clear_output(self):
        """Çıktı alanını temizle"""
        self.output_text.delete(1.0, tk.END)

    def log_message(self, message):
        """Çıktı alanına mesaj ekle"""
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()

    def browse_file(self):
        """Dosya seçim dialogu"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def start_server(self):
        """Sunucuyu başlat"""
        ip = self.server_ip_entry.get().strip()
        port = self.server_port_entry.get().strip()
        protocol = self.server_protocol_var.get()

        if not port.isdigit():
            messagebox.showerror("Hata", "Geçerli bir port numarası girin.")
            return
        
        port = int(port)
        
        def server_wrapper():
            try:
                self.log_message(f"[Sunucu - {protocol.upper()}] Başlatılıyor: {ip}:{port}")
                # Sunucu fonksiyonunu IP ve port parametreleriyle çağırın
                # Not: server.py dosyanızdaki start_server fonksiyonunu güncellemek gerekebilir
                start_server()  # Burayı start_server(ip, port) olarak güncelleyin
                
            except Exception as e:
                self.log_message(f"[Sunucu] Hata: {e}")
        
        self.server_thread = threading.Thread(target=server_wrapper, daemon=True)
        self.server_thread.start()
        
        # UI güncelleme
        self.server_status_label.config(text="Sunucu çalışıyor", fg="green")
        self.start_server_btn.config(state=tk.DISABLED)
        self.stop_server_btn.config(state=tk.NORMAL)

    def stop_server(self):
        """Sunucuyu durdur"""
        stop_server()
        self.log_message("[Sunucu] Durdurma talebi gönderildi")
        self.server_status_label.config(text="Sunucu durduruldu", fg="red")
        self.start_server_btn.config(state=tk.NORMAL)
        self.stop_server_btn.config(state=tk.DISABLED)

    def send_file_normal(self):
        """Normal dosya gönderimi"""
        ip = self.client_ip_entry.get().strip()
        file_path = self.file_entry.get().strip()
        port = self.client_port_entry.get().strip()
        protocol = self.client_protocol_var.get()

        if not ip or not file_path:
            messagebox.showerror("Hata", "Lütfen IP adresi ve dosya seçin.")
            return
        if not port.isdigit():
            messagebox.showerror("Hata", "Geçerli bir port numarası girin.")
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Hata", "Dosya bulunamadı.")
            return

        port = int(port)
        
        def send():
            try:
                self.log_message(f"[İstemci - {protocol.upper()}] Dosya gönderiliyor -> {ip}:{port}")
                start_client((ip, port), file_path)
                self.log_message("[İstemci] Dosya başarıyla gönderildi!")
            except Exception as e:
                self.log_message(f"[İstemci] Hata: {e}")
        
        threading.Thread(target=send, daemon=True).start()

    def send_with_ip_header(self):
        """IP header ile dosya gönderimi"""
        ip = self.client_ip_entry.get().strip()
        file_path = self.file_entry.get().strip()
        port = self.client_port_entry.get().strip()
        mtu = self.mtu_entry.get().strip()
        protocol = self.client_protocol_var.get()

        if not ip or not file_path:
            messagebox.showerror("Hata", "Lütfen IP adresi ve dosya seçin.")
            return
        if not port.isdigit():
            messagebox.showerror("Hata", "Geçerli bir port numarası girin.")
            return
        if not mtu.isdigit():
            messagebox.showerror("Hata", "Geçerli bir MTU değeri girin.")
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Hata", "Dosya bulunamadı.")
            return

        port = int(port)
        mtu = int(mtu)

        def send_file():
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                self.log_message(f"[IP Header - {protocol.upper()}] Dosya gönderiliyor...")
                self.log_message(f"Hedef: {ip}:{port}, MTU: {mtu}, Protokol: {protocol.upper()}")
                self.log_message(f"Dosya boyutu: {len(data)} byte")
                
                success = send_fragmented_data(None, ip, data, port, mtu, protocol)
                if success:
                    self.log_message("[IP Header] Dosya başarıyla gönderildi!")
                else:
                    self.log_message("[IP Header] Dosya gönderimi başarısız!")
            except Exception as e:
                self.log_message(f"[IP Header] Hata: {e}")

        threading.Thread(target=send_file, daemon=True).start()

    # Analiz araçları metodları
    def run_latency_analysis(self):
        """Gecikme analizi"""
        ip = self.target_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen hedef IP adresi girin.")
            return
        
        def analyze():
            self.log_message(f"[Analiz] {ip} için gecikme ölçülüyor...")
            result = measure_latency(ip, count=5)
            if result:
                self.log_message(f"Min: {result['min']:.2f} ms | Avg: {result['avg']:.2f} ms | Max: {result['max']:.2f} ms")
            else:
                self.log_message("Gecikme ölçülemedi.")
        
        threading.Thread(target=analyze, daemon=True).start()

    def run_bandwidth_analysis(self):
        """Bant genişliği analizi"""
        ip = self.target_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen hedef IP adresi girin.")
            return

        def start_iperf_server():
            try:
                subprocess.Popen([IPERF_PATH, "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.log_message("[iPerf] Sunucu arka planda başlatıldı.")
            except Exception as e:
                self.log_message(f"[iPerf] Sunucu başlatılamadı: {e}")

        def analyze():
            start_iperf_server()
            self.log_message(f"[Analiz] {ip} için bant genişliği ölçülüyor...")
            bandwidth = run_iperf_client(ip, duration=5)
            if bandwidth:
                self.log_message(f"Bant Genişliği: {bandwidth:.2f} Mbit/s")
            else:
                self.log_message("Bant genişliği ölçülemedi.")
        
        threading.Thread(target=analyze, daemon=True).start()

    def run_entropy_analysis(self):
        """Entropi analizi"""
        ip = self.target_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen hedef IP girin.")
            return
        
        def analyze():
            self.log_message(f"[Entropi] {ip} adresine ait veri analiz ediliyor...")
            packets = packet_capture(interface="Ethernet", filter_str=f"host {ip}", count=30)
            entropy = analyze_encrypted_data(packets)
            self.log_message(f"Ortalama Entropi: {entropy:.4f}")
        
        threading.Thread(target=analyze, daemon=True).start()

    def run_mitm_simulation(self):
        """MITM simülasyonu"""
        victim_ip = self.target_ip_entry.get().strip()
        if not victim_ip:
            messagebox.showerror("Hata", "Lütfen hedef (kurban) IP girin.")
            return
        
        def simulate():
            self.log_message(f"[MITM] {victim_ip} adresine karşı MITM simülasyonu başlatılıyor...")
            packets = mitm_simulation(victim_ip, "192.168.1.1", interface="Ethernet")
            self.log_message(f"Yakalanan paket sayısı: {len(packets)}")
        
        threading.Thread(target=simulate, daemon=True).start()

    def run_packet_injection(self):
        """Paket enjeksiyonu"""
        ip = self.target_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen hedef IP girin.")
            return
        
        def inject():
            success = packet_injection_simulation(ip, 80)
            if success:
                self.log_message("[Enjeksiyon] Sahte HTTP isteği başarıyla enjekte edildi.")
            else:
                self.log_message("[Enjeksiyon] Paket enjeksiyonu başarısız oldu.")
        
        threading.Thread(target=inject, daemon=True).start()

    def start_clumsy(self):
        """Clumsy aracını başlat"""
        try:
            subprocess.Popen([CLUMSY_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log_message("[Clumsy] Başlatıldı. Paket kaybı simülasyonu yapabilirsiniz.")
        except Exception as e:
            self.log_message(f"[Clumsy] Başlatılamadı: {e}")

    def start_wireshark(self):
        """Wireshark aracını başlat"""
        try:
            subprocess.Popen([WIRESHARK_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log_message("[Wireshark] Başlatıldı. Ağ trafiğini gözlemleyebilirsiniz.")
        except Exception as e:
            self.log_message(f"[Wireshark] Başlatılamadı: {e}")

if __name__ == '__main__':
    root = tk.Tk()
    app = SecureTransferGUI(root)
    root.mainloop()