# Final Project Berdampak VINIX7 - Divisi Cybercrime & Digital Forensic
Prototipe Dashboard Keamanan Arsip Digital, Analitik Produksi, dan Deteksi Anomali Log Berbasis Simulasi untuk CV. Pendawa Kencana Multi Farm, Desa Cangkringan

* **Mitra:** CV. Pendawa Kencana Multi Farm (Cangkringan, Sleman, DIY)  & VINIX7
* **Program:** Studi Independen / Final Project

## Deskripsi Proyek
Proyek ini mengembangkan dashboard berbasis web untuk mendukung pengelolaan arsip digital, analisis data produksi, dan evaluasi keamanan melalui pemeriksaan integritas file serta analisis anomali log akses. Sistem mengintegrasikan tiga komponen utama:

1. Kriptografi dan Integritas File: Menggunakan SHA-256 checksum untuk membandingkan integritas file dengan hash referensi atau catatan hash yang tersedia. Hasil verifikasi membantu mengidentifikasi perubahan isi file, tetapi tidak dengan sendirinya membuktikan keaslian sumber atau mencegah manipulasi.

2. Analisis Log dan Deteksi Anomali: Menggunakan Isolation Forest dan indikator berbasis aturan untuk mengidentifikasi pola yang perlu diperiksa, seperti akses di luar jam operasional, alamat IP yang tidak biasa, dan kegagalan login beruntun. Pengujian menggunakan data log simulasi, bukan pemantauan jaringan aktual mitra.

3. Analitik Produksi dan Pengelolaan Arsip Berbasis Cloud: Menyediakan visualisasi data produksi dan fitur pengelolaan arsip sesuai kemampuan yang telah diimplementasikan pada aplikasi, termasuk integrasi penyimpanan hash apabila dikonfigurasi.

## Modul & Teknologi yang Digunakan
* Language: Python 3
* Frontend/Web: Streamlit
* Data Processing: Pandas, NumPy
* Machine Learning: Scikit-Learn (Isolation Forest)
* Security & Crypto: Hashlib (SHA-256)
* Penyimpanan cloud: Sipabase

## Batas Pengujian
Fitur deteksi anomali jaringan diuji menggunakan data simulasi untuk mengevaluasi fungsi deteksi, indikator berbasis aturan, penyaringan log, dan penyajian hasil analisis. Hasilnya tidak merepresentasikan kondisi keamanan jaringan aktual dan belum membuktikan efektivitas deteksi pada lingkungan operasional nyata.

## Link Product
https://audit-keamanan-arsip-pendawa-cangkringan-mnmzbsufuuxsasgvdzcmr.streamlit.app/

## Repository
https://github.com/Alyciaaa11/audit-keamanan-arsip-pendawa-cangkringan

## Tim Penyusun (Mahasiswa Prodi Sains Data)
* Audy Alycia (24031554179)
* Rizqi Wahyu Gusniadi (24031554203)
