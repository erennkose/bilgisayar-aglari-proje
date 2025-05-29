import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import subprocess
from client import start_client
from server import start_server, stop_server, server_running, server_socket
from network_analysis import measure_latency, run_iperf_client
from security_analysis import SecurityAnalyzer
from ip_header import (
    send_fragmented_data,
    monitor_network_errors, 
    test_checksum_manipulation,
    detect_transmission_errors,
    validate_ip_checksum
)

IPERF_PATH = "C:\\iperf\\iperf3.exe"
CLUMSY_PATH = "C:\\Program Files\\Clumsy\\clumsy.exe"
WIRESHARK_PATH = "C:\\Program Files\\Wireshark\\Wireshark.exe"

class SecureTransferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Güvenli Dosya Transfer Sistemi")
        self.root.geometry("850x1000")

        # Ana notebook (sekmeler)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.security_analyzer = SecurityAnalyzer()

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
        advanced_frame = tk.LabelFrame(main_frame, text="Gelişmiş IP Ayarları", font=("Arial", 10, "bold"))
        advanced_frame.pack(fill=tk.X, pady=(0, 20))

        # MTU ayarı (mevcut)
        mtu_frame = tk.Frame(advanced_frame)
        mtu_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(mtu_frame, text="MTU Boyutu:", width=15, anchor='w').pack(side=tk.LEFT)
        self.mtu_entry = tk.Entry(mtu_frame, width=20, font=("Arial", 10))
        self.mtu_entry.insert(0, "1500")
        self.mtu_entry.pack(side=tk.LEFT, padx=(10, 0))

        # TTL ayarı
        ttl_frame = tk.Frame(advanced_frame)
        ttl_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(ttl_frame, text="TTL Değeri:", width=15, anchor='w').pack(side=tk.LEFT)
        self.ttl_entry = tk.Entry(ttl_frame, width=20, font=("Arial", 10))
        self.ttl_entry.insert(0, "64")
        self.ttl_entry.pack(side=tk.LEFT, padx=(10, 0))

        # ToS ayarı
        tos_frame = tk.Frame(advanced_frame)
        tos_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(tos_frame, text="ToS/DSCP:", width=15, anchor='w').pack(side=tk.LEFT)
        self.tos_entry = tk.Entry(tos_frame, width=20, font=("Arial", 10))
        self.tos_entry.insert(0, "0")
        self.tos_entry.pack(side=tk.LEFT, padx=(10, 0))

        # IP Flags seçimi
        flags_frame = tk.Frame(advanced_frame)
        flags_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(flags_frame, text="IP Flags:", width=15, anchor='w').pack(side=tk.LEFT)
        
        flags_inner_frame = tk.Frame(flags_frame)
        flags_inner_frame.pack(side=tk.LEFT, padx=(10, 0))
        
        self.df_flag_var = tk.BooleanVar()
        self.mf_flag_var = tk.BooleanVar()
        
        tk.Checkbutton(flags_inner_frame, text="Don't Fragment", variable=self.df_flag_var).pack(side=tk.LEFT)
        tk.Checkbutton(flags_inner_frame, text="More Fragments", variable=self.mf_flag_var).pack(side=tk.LEFT, padx=(10, 0))

        # Kaynak IP ayarı (opsiyonel)
        src_ip_frame = tk.Frame(advanced_frame)
        src_ip_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(src_ip_frame, text="Kaynak IP:", width=15, anchor='w').pack(side=tk.LEFT)
        self.src_ip_entry = tk.Entry(src_ip_frame, width=20, font=("Arial", 10))
        self.src_ip_entry.insert(0, "auto")  # otomatik IP seçimi için
        self.src_ip_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Zorla parçalama seçeneği
        force_frag_frame = tk.Frame(advanced_frame)
        force_frag_frame.pack(fill=tk.X, padx=10, pady=5)
        self.force_fragment_var = tk.BooleanVar()
        tk.Checkbutton(force_frag_frame, text="Zorla Parçalama Yap", 
                    variable=self.force_fragment_var).pack(anchor='w')

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
                width=15, bg="lightyellow").pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(security_buttons_frame2, text="Protokol Karşılaştır", command=self.compare_protocols,
                width=18, bg="lightyellow").pack(side=tk.LEFT)
        
        security_buttons_frame3 = tk.Frame(security_frame)
        security_buttons_frame3.pack(padx=10, pady=5)
        
        tk.Button(security_buttons_frame3, text="Kapsamlı Rapor", command=self.generate_security_report,
                width=15, bg="lightgreen").pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(security_buttons_frame3, text="Paket Yakalama", command=self.start_packet_capture,
                width=18, bg="lightcyan").pack(side=tk.LEFT)
        
        security_buttons_frame4 = tk.Frame(security_frame)
        security_buttons_frame4.pack(padx=10, pady=5)

        tk.Button(security_buttons_frame4, text="Checksum Analizi", command=self.run_checksum_analysis,
                width=15, bg="lightyellow").pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(security_buttons_frame4, text="Hata Tespiti", command=self.run_error_detection,
                width=18, bg="lightyellow").pack(side=tk.LEFT)

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
                start_server(ip, port, protocol)  # Burayı start_server(ip, port) olarak güncelleyin
                
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
                start_client((ip, port), file_path, protocol)  # ← Sadece bu satır değişti
                self.log_message("[İstemci] Dosya başarıyla gönderildi!")
            except Exception as e:
                self.log_message(f"[İstemci] Hata: {e}")
    
        threading.Thread(target=send, daemon=True).start()

    def send_with_ip_header(self):
        """IP header ile dosya gönderimi - Gelişmiş parametrelerle"""
        ip = self.client_ip_entry.get().strip()
        file_path = self.file_entry.get().strip()
        port = self.client_port_entry.get().strip()
        mtu = self.mtu_entry.get().strip()
        protocol = self.client_protocol_var.get()
        
        # Yeni parametreler
        ttl = self.ttl_entry.get().strip()
        tos = self.tos_entry.get().strip()
        src_ip = self.src_ip_entry.get().strip()

        # Validasyon
        if not ip or not file_path:
            messagebox.showerror("Hata", "Lütfen IP adresi ve dosya seçin.")
            return
        if not port.isdigit():
            messagebox.showerror("Hata", "Geçerli bir port numarası girin.")
            return
        if not mtu.isdigit():
            messagebox.showerror("Hata", "Geçerli bir MTU değeri girin.")
            return
        if not ttl.isdigit() or not (1 <= int(ttl) <= 255):
            messagebox.showerror("Hata", "TTL değeri 1-255 arasında olmalıdır.")
            return
        if not tos.isdigit() or not (0 <= int(tos) <= 255):
            messagebox.showerror("Hata", "ToS değeri 0-255 arasında olmalıdır.")
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Hata", "Dosya bulunamadı.")
            return

        port = int(port)
        mtu = int(mtu)
        ttl = int(ttl)
        tos = int(tos)
        
        # IP flags hesaplama
        flags = 0
        if self.df_flag_var.get():
            flags |= 2  # Don't Fragment
        if self.mf_flag_var.get():
            flags |= 4  # More Fragments
        
        # Kaynak IP kontrolü
        if src_ip.lower() == "auto" or not src_ip:
            src_ip = None  # Otomatik IP seçimi için

        def send_file():
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                self.log_message(f"[IP Header - {protocol.upper()}] Dosya gönderiliyor...")
                self.log_message(f"Hedef: {ip}:{port}")
                self.log_message(f"MTU: {mtu}, TTL: {ttl}, ToS: {tos}")
                self.log_message(f"Flags: {self.get_flag_description(flags)}")
                self.log_message(f"Dosya boyutu: {len(data)} byte")
                self.log_message(f"Zorla parçalama: {'Evet' if self.force_fragment_var.get() else 'Hayır'}")
                
                # ip_header.py'deki güncellenmiş fonksiyonu çağır
                success = send_fragmented_data(
                    src_ip=src_ip,
                    dst_ip=ip,
                    data=data,
                    port=port,
                    mtu=mtu,
                    protocol=protocol,
                    ttl=ttl,
                    flags=flags,
                    tos=tos,
                    force_fragment=self.force_fragment_var.get()
                )
                
                if success:
                    self.log_message("[IP Header] Dosya başarıyla gönderildi!")
                else:
                    self.log_message("[IP Header] Dosya gönderimi başarısız!")
                    
            except Exception as e:
                self.log_message(f"[IP Header] Hata: {e}")

        threading.Thread(target=send_file, daemon=True).start()

    def run_checksum_analysis(self):
        """IP checksum analizi ve test"""
        def analyze():
            self.log_message("[Checksum] IP checksum analiz ve test başlatılıyor...")
            try:
                # Checksum manipülasyon testi
                self.log_message("Checksum manipülasyon testi yapılıyor...")
                normal_packet, corrupted_packet = test_checksum_manipulation()
                
                # Sonuçları logla
                self.log_message(f"Normal paket checksum: {hex(normal_packet.chksum)}")
                self.log_message(f"Bozuk paket checksum: {hex(corrupted_packet.chksum)}")
                
                # Doğrulama sonuçları
                is_valid_normal, calc_normal, recv_normal = validate_ip_checksum(normal_packet)
                is_valid_corrupted, calc_corrupted, recv_corrupted = validate_ip_checksum(corrupted_packet)
                
                self.log_message(f"Normal paket geçerli: {'✅ EVET' if is_valid_normal else '❌ HAYIR'}")
                self.log_message(f"Bozuk paket geçerli: {'✅ EVET' if is_valid_corrupted else '❌ HAYIR'}")
                
                self.log_message("[Checksum] Analiz tamamlandı.")
                
            except Exception as e:
                self.log_message(f"[Checksum] Hata: {e}")
        
        threading.Thread(target=analyze, daemon=True).start()

    def run_error_detection(self):
        """Ağ hata tespiti"""
        def detect():
            self.log_message("[Hata Tespiti] Ağ trafiği izleniyor...")
            try:
                # Windows için interface belirleme
                interface = None  # Otomatik seçim
                
                self.log_message("50 paket yakalanacak ve checksum hataları aranacak...")
                self.log_message("Bu işlem birkaç dakika sürebilir...")
                
                # Hata tespiti başlat
                error_packets = monitor_network_errors(
                    interface=interface, 
                    count=50, 
                    filter_str="ip"
                )
                
                # Sonuçları özetle
                if error_packets:
                    self.log_message(f"⚠️ {len(error_packets)} checksum hatası tespit edildi!")
                    for i, error in enumerate(error_packets[:5]):  # İlk 5 hatayı göster
                        self.log_message(f"  {i+1}. {error['src_ip']} -> {error['dst_ip']} "
                                    f"(Hesaplanan: {error['calculated_checksum']}, "
                                    f"Alınan: {error['received_checksum']})")
                else:
                    self.log_message("✅ Checksum hatası tespit edilmedi.")
                    
            except Exception as e:
                self.log_message(f"[Hata Tespiti] Hata: {e}")
                self.log_message("Not: Bu özellik için yönetici yetkileri gerekebilir.")
        
        threading.Thread(target=detect, daemon=True).start()

    def get_flag_description(self, flag_value):
        """Flag değerinin açıklamasını döndür"""
        descriptions = []
        if flag_value & 1:
            descriptions.append("Reserved")
        if flag_value & 2:
            descriptions.append("Don't Fragment")
        if flag_value & 4:
            descriptions.append("More Fragments")
        
        return " | ".join(descriptions) if descriptions else "Flags Yok"

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
        """Gelişmiş entropi analizi"""
        ip = self.target_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen hedef IP girin.")
            return
        
        def analyze():
            self.log_message(f"[Entropi] {ip} adresine ait veri analiz ediliyor...")
            try:
                # Paket yakalama simülasyonu (Windows için)
                self.log_message("[Entropi] Paket yakalama simüle ediliyor...")
                packets = self.security_analyzer.packet_capture("Ethernet", f"host {ip}", count=30)
                
                # Entropi analizi
                results = self.security_analyzer.analyze_encrypted_data(packets)
                
                self.log_message(f"Ortalama Entropi: {results['entropy']:.4f}")
                self.log_message(f"Şifreleme Durumu: {'ŞİFRELİ' if results['is_encrypted'] else 'ŞİFRELENMEMİŞ'}")
                
                # Protokol dağılımı
                for protocol, count in results['protocols'].items():
                    if count > 0:
                        self.log_message(f"{protocol}: {count} paket")
                        
            except Exception as e:
                self.log_message(f"[Entropi] Hata: {e}")
        
        threading.Thread(target=analyze, daemon=True).start()

    def run_mitm_simulation(self):
        """Gelişmiş MITM simülasyonu"""
        victim_ip = self.target_ip_entry.get().strip()
        if not victim_ip:
            messagebox.showerror("Hata", "Lütfen hedef (kurban) IP girin.")
            return
        
        def simulate():
            self.log_message(f"[MITM] {victim_ip} adresine karşı MITM tespiti başlatılıyor...")
            try:
                results = self.security_analyzer.mitm_simulation(victim_ip, "192.168.1.1", interface="Ethernet")
                
                # Sonuçları logla
                self.log_message(f"ARP Anomalileri: {'TESPIT EDİLDİ' if results['arp_table_anomalies'] else 'Normal'}")
                self.log_message(f"Sertifika Doğrulama: {'BAŞARISIZ' if results['certificate_validation'] else 'Başarılı'}")
                self.log_message(f"Trafik Anomalileri: {'TESPIT EDİLDİ' if results['traffic_patterns'] else 'Normal'}")
                
                if results['mitm_detected']:
                    self.log_message("⚠️ MITM SALDIRISI TESPİT EDİLDİ!")
                else:
                    self.log_message("✅ MITM tespiti: Güvenli")
                    
            except Exception as e:
                self.log_message(f"[MITM] Hata: {e}")
        
        threading.Thread(target=simulate, daemon=True).start()

    def run_packet_injection(self):
        """Paket enjeksiyonu tespiti"""
        ip = self.target_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen hedef IP girin.")
            return
        
        def detect():
            self.log_message(f"[Enjeksiyon] {ip} adresine paket enjeksiyonu tespiti...")
            try:
                results = self.security_analyzer.packet_injection_detection(ip, 80)
                
                # Tespit sonuçlarını logla
                detection_count = sum(results.values())
                self.log_message(f"TCP Sequence Analizi: {'ŞÜPHELI' if results['sequence_analysis'] else 'NORMAL'}")
                self.log_message(f"Checksum Doğrulama: {'ŞÜPHELI' if results['checksum_validation'] else 'NORMAL'}")
                self.log_message(f"Rate Limiting: {'ŞÜPHELI' if results['rate_limiting'] else 'NORMAL'}")
                self.log_message(f"Payload Analizi: {'ŞÜPHELI' if results['payload_analysis'] else 'NORMAL'}")
                
                if detection_count > 0:
                    self.log_message(f"⚠️ {detection_count} farklı tespit metodu şüpheli aktivite buldu!")
                else:
                    self.log_message("✅ Paket enjeksiyonu tespiti: Güvenli")
                    
            except Exception as e:
                self.log_message(f"[Enjeksiyon] Hata: {e}")
        
        threading.Thread(target=detect, daemon=True).start()

    def compare_protocols(self):
        """Protokol karşılaştırması"""
        def compare():
            self.log_message("[Protokol] Güvenlik protokolleri karşılaştırılıyor...")
            try:
                protocols = self.security_analyzer.compare_security_protocols()
                
                self.log_message("=== GÜVENLİK PROTOKOLLERİ KARŞILAŞTIRMASI ===")
                
                # Sadece temel bilgileri logla
                for protocol_name, details in protocols.items():
                    self.log_message(f"{protocol_name}:")
                    self.log_message(f"  Güvenlik Seviyesi: {details['security_level']}")
                    self.log_message(f"  Şifreleme: {details['encryption']}")
                    self.log_message(f"  Kullanım Alanı: {details['use_case']}")
                    self.log_message("")
                
                self.log_message("Detaylı karşılaştırma konsol çıktısında görüntüleniyor.")
                
            except Exception as e:
                self.log_message(f"[Protokol] Hata: {e}")
        
        threading.Thread(target=compare, daemon=True).start()

    def generate_security_report(self):
        """Kapsamlı güvenlik raporu"""
        def generate():
            self.log_message("[Rapor] Kapsamlı güvenlik raporu oluşturuluyor...")
            try:
                report = self.security_analyzer.generate_comprehensive_report()
                
                self.log_message("=== KAPSAMLI GÜVENLİK RAPORU ===")
                self.log_message(f"Toplam Güvenlik Skoru: {report['security_score']}/100")
                
                # Skor kategorisi
                score = report['security_score']
                if score >= 90:
                    grade = "A+ (Mükemmel) ✅"
                elif score >= 80:
                    grade = "A (Çok İyi) ✅"
                elif score >= 70:
                    grade = "B (İyi) ⚠️"
                elif score >= 60:
                    grade = "C (Orta) ⚠️"
                elif score >= 50:
                    grade = "D (Düşük) ❌"
                else:
                    grade = "F (Başarısız) ❌"
                
                self.log_message(f"Güvenlik Notu: {grade}")
                
                # Kısa özet
                self.log_message(f"Şifreleme Durumu: {'Güvenli' if report['encryption']['is_encrypted'] else 'Risk'}")
                self.log_message(f"MITM Tespiti: {'Risk' if report['mitm_detection']['mitm_detected'] else 'Güvenli'}")
                
                attack_count = sum(report['injection_detection'].values())
                self.log_message(f"Paket Enjeksiyonu: {attack_count} şüpheli aktivite")
                
                self.log_message("Detaylı rapor konsol çıktısında görüntüleniyor.")
                
            except Exception as e:
                self.log_message(f"[Rapor] Hata: {e}")
        
        threading.Thread(target=generate, daemon=True).start()

    def start_packet_capture(self):
        """Paket yakalama başlat"""
        ip = self.target_ip_entry.get().strip()
        
        def capture():
            self.log_message("[Paket Yakalama] Başlatılıyor...")
            try:
                interface = "Ethernet"  # Windows için tipik interface
                filter_str = f"host {ip}" if ip else ""
                
                self.log_message(f"Interface: {interface}")
                self.log_message(f"Filter: {filter_str or 'Tüm trafik'}")
                self.log_message("50 paket yakalanıyor...")
                
                packets = self.security_analyzer.packet_capture(
                    interface=interface,
                    filter_str=filter_str,
                    output_file="capture.pcap",
                    count=50
                )
                
                if packets:
                    self.log_message(f"Toplam {len(packets)} paket yakalandı")
                    self.log_message("Paketler 'capture.pcap' dosyasına kaydedildi")
                else:
                    self.log_message("Windows sistemde Wireshark kullanmanız önerilir")
                    self.log_message("Alternatif: tshark komut satırı aracını kullanın")
                    
            except Exception as e:
                self.log_message(f"[Paket Yakalama] Hata: {e}")

        threading.Thread(target=capture, daemon=True).start()
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