import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import subprocess
from client import start_client
from server import start_server
from network_analysis import measure_latency, run_iperf_client
from security_analysis import packet_capture, analyze_encrypted_data, mitm_simulation, packet_injection_simulation

IPERF_PATH = "C:\\iperf\\iperf3.exe"
CLUMSY_PATH = "C:\\Program Files\\Clumsy\\clumsy.exe"
WIRESHARK_PATH = "C:\\Program Files\\Wireshark\\Wireshark.exe"

class SecureTransferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Güvenli Dosya Transfer Sistemi")
        self.root.geometry("600x550")

        self.mode_var = tk.StringVar(value="client")

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Çalışma Modu:").pack(pady=5)
        tk.Radiobutton(self.root, text="Sunucu", variable=self.mode_var, value="server").pack()
        tk.Radiobutton(self.root, text="İstemci", variable=self.mode_var, value="client").pack()

        self.client_frame = tk.Frame(self.root)
        self.client_frame.pack(pady=10)

        tk.Label(self.client_frame, text="Hedef IP:").grid(row=0, column=0, sticky='e')
        self.ip_entry = tk.Entry(self.client_frame)
        self.ip_entry.grid(row=0, column=1)

        tk.Label(self.client_frame, text="Dosya:").grid(row=1, column=0, sticky='e')
        self.file_entry = tk.Entry(self.client_frame, width=40)
        self.file_entry.grid(row=1, column=1)
        tk.Button(self.client_frame, text="Gözat", command=self.browse_file).grid(row=1, column=2)

        tk.Button(self.root, text="Başlat", command=self.run_mode).pack(pady=10)
        tk.Button(self.root, text="Gecikme Ölç", command=self.run_latency_analysis).pack(pady=5)
        tk.Button(self.root, text="Bant Genişliği Ölç", command=self.run_bandwidth_analysis).pack(pady=5)
        tk.Button(self.root, text="Clumsy Başlat (Paket Kaybı)", command=self.start_clumsy).pack(pady=5)
        tk.Button(self.root, text="Wireshark Başlat", command=self.start_wireshark).pack(pady=5)
        tk.Button(self.root, text="Entropi Analizi Yap", command=self.run_entropy_analysis).pack(pady=5)
        tk.Button(self.root, text="MITM Simülasyonu", command=self.run_mitm_simulation).pack(pady=5)
        tk.Button(self.root, text="Paket Enjeksiyonu", command=self.run_packet_injection).pack(pady=5)

        self.output_text = tk.Text(self.root, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def run_mode(self):
        mode = self.mode_var.get()
        if mode == "server":
            self.output_text.insert(tk.END, "[Sunucu] Başlatılıyor...\n")
            threading.Thread(target=start_server, daemon=True).start()
        elif mode == "client":
            ip = self.ip_entry.get().strip()
            file_path = self.file_entry.get().strip()

            if not ip or not file_path:
                messagebox.showerror("Hata", "Lütfen IP adresi ve dosya seçin.")
                return

            if not os.path.exists(file_path):
                messagebox.showerror("Hata", "Dosya bulunamadı.")
                return

            self.output_text.insert(tk.END, f"[İstemci] Dosya gönderiliyor -> {ip}\n")
            threading.Thread(target=lambda: start_client((ip, 9999), file_path), daemon=True).start()

    def run_latency_analysis(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen IP adresi girin.")
            return
        self.output_text.insert(tk.END, f"[Analiz] {ip} için gecikme ölçülüyor...\n")
        result = measure_latency(ip, count=5)
        if result:
            self.output_text.insert(tk.END, f"Min: {result['min']:.2f} ms | Avg: {result['avg']:.2f} ms | Max: {result['max']:.2f} ms\n")
        else:
            self.output_text.insert(tk.END, "Gecikme ölçülemedi.\n")

    def run_bandwidth_analysis(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen IP adresi girin.")
            return

        def start_iperf_server():
            try:
                subprocess.Popen([IPERF_PATH, "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.output_text.insert(tk.END, "[iPerf] Sunucu arka planda başlatıldı.\n")
            except Exception as e:
                self.output_text.insert(tk.END, f"[iPerf] Sunucu başlatılamadı: {e}\n")

        threading.Thread(target=start_iperf_server, daemon=True).start()

        self.output_text.insert(tk.END, f"[Analiz] {ip} için bant genişliği ölçülüyor...\n")
        bandwidth = run_iperf_client(ip, duration=5)
        if bandwidth:
            self.output_text.insert(tk.END, f"Bant Genişliği: {bandwidth:.2f} Mbit/s\n")
        else:
            self.output_text.insert(tk.END, "Bant genişliği ölçülemedi.\n")

    def start_clumsy(self):
        try:
            subprocess.Popen([CLUMSY_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.output_text.insert(tk.END, "[Clumsy] Başlatıldı. Paket kaybı simülasyonu yapabilirsiniz.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"[Clumsy] Başlatılamadı: {e}\n")

    def start_wireshark(self):
        try:
            subprocess.Popen([WIRESHARK_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.output_text.insert(tk.END, "[Wireshark] Başlatıldı. Ağ trafiğini gözlemleyebilirsiniz.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"[Wireshark] Başlatılamadı: {e}\n")

    def run_entropy_analysis(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen hedef IP girin.")
            return
        self.output_text.insert(tk.END, f"[Entropi] {ip} adresine ait veri analiz ediliyor...\n")
        packets = packet_capture(interface="Ethernet", filter_str=f"host {ip}", count=30)
        entropy = analyze_encrypted_data(packets)
        self.output_text.insert(tk.END, f"Ortalama Entropi: {entropy:.4f}\n")

    def run_mitm_simulation(self):
        victim_ip = self.ip_entry.get().strip()
        if not victim_ip:
            messagebox.showerror("Hata", "Lütfen hedef (kurban) IP girin.")
            return
        self.output_text.insert(tk.END, f"[MITM] {victim_ip} adresine karşı MITM simülasyonu başlatılıyor...\n")
        packets = mitm_simulation(victim_ip, "192.168.1.1", interface="Ethernet")
        self.output_text.insert(tk.END, f"Yakalanan paket sayısı: {len(packets)}\n")

    def run_packet_injection(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen hedef IP girin.")
            return
        success = packet_injection_simulation(ip, 80)
        if success:
            self.output_text.insert(tk.END, "[Enjeksiyon] Sahte HTTP isteği başarıyla enjekte edildi.\n")
        else:
            self.output_text.insert(tk.END, "[Enjeksiyon] Paket enjeksiyonu başarısız oldu.\n")

if __name__ == '__main__':
    root = tk.Tk()
    app = SecureTransferGUI(root)
    root.mainloop()
