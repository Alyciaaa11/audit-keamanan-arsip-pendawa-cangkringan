from pathlib import Path
from io import BytesIO
import hashlib
import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="Agribusiness Secure Archive", layout="wide")
st.title("Agribusiness Secure Archive")
st.caption("Secure Digital Archive & Anomaly Detection Dashboard for Agribusiness Data")


# =========================================================
# CLOUD HASH REGISTRY (SUPABASE)
# =========================================================
def get_secret_or_env(name):
    try:
        value = st.secrets.get(name)
        if value:
            return str(value).strip()
    except Exception:
        pass
    return os.getenv(name, "").strip()


@st.cache_resource(show_spinner=False)
def get_cloud_client():
    url = get_secret_or_env("SUPABASE_URL")
    key = get_secret_or_env("SUPABASE_SERVICE_ROLE_KEY") or get_secret_or_env("SUPABASE_KEY")
    if not url or not key:
        return None
    try:
        from supabase import create_client
        return create_client(url, key)
    except ImportError as exc:
        raise RuntimeError("Paket supabase belum terpasang. Jalankan: pip install supabase") from exc


def filename_key(filename):
    return Path(str(filename)).name.strip().casefold()


def find_cloud_record(client, filename):
    result = (
        client.table("file_hash_registry")
        .select("id,file_name,file_name_key,sha256,created_at")
        .eq("file_name_key", filename_key(filename))
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def save_initial_hash(client, filename, sha256_hash, file_size):
    existing = find_cloud_record(client, filename)
    if existing:
        if existing["sha256"].lower() == sha256_hash.lower():
            return "same", existing
        return "conflict", existing

    record = {
        "file_name": Path(filename).name,
        "file_name_key": filename_key(filename),
        "sha256": sha256_hash,
        "file_size": int(file_size),
    }
    try:
        client.table("file_hash_registry").insert(record).execute()
    except Exception:
        existing = find_cloud_record(client, filename)
        if existing and existing["sha256"].lower() == sha256_hash.lower():
            return "same", existing
        if existing:
            return "conflict", existing
        raise
    return "saved", find_cloud_record(client, filename)


def validate_file_against_cloud(client, filename, sha256_hash):
    record = find_cloud_record(client, filename)
    if not record:
        return True, "new", None
    if record["sha256"].lower() == sha256_hash.lower():
        return True, "match", record
    return False, "mismatch", record


tab1, tab2, tab3 = st.tabs([
    "1. Digital Archive & Integrity",
    "2. Production Analytics",
    "3. Network Log Forensics"
])


# =========================================================
# HELPERS: READ CLEAN, RAW, AND PRODUCTION FILES
# =========================================================
def normalise_text(value):
    return " ".join(str(value).strip().lower().replace("_", " ").split())


def parse_year(value):
    try:
        number = float(str(value).strip())
        if number.is_integer() and 1900 <= number <= 2100:
            return int(number)
    except (ValueError, TypeError):
        pass
    return None


def standardise_long_table(df):
    df = df.copy()
    original_columns = list(df.columns)
    normalised = {c: normalise_text(c) for c in original_columns}

    aliases = {
        "produk": {"produk", "product", "varian produk", "nama produk", "commodity", "komoditas"},
        "satuan": {"satuan", "unit", "units", "keterangan"},
        "tahun": {"tahun", "year", "periode tahun"},
        "produksi": {"produksi", "production", "jumlah produksi", "nilai produksi", "value", "hasil produksi"},
    }

    rename = {}
    for target, candidates in aliases.items():
        for col in original_columns:
            if normalised[col] in candidates:
                rename[col] = target
                break
    df = df.rename(columns=rename)

    if {"produk", "tahun", "produksi"}.issubset(df.columns):
        if "satuan" not in df.columns:
            df["satuan"] = "Tidak diketahui"
        df = df[["produk", "satuan", "tahun", "produksi"]].copy()
        df["produk"] = df["produk"].astype("string").str.strip()
        df["satuan"] = df["satuan"].astype("string").str.strip()
        df["tahun"] = pd.to_numeric(df["tahun"], errors="coerce")
        df["produksi"] = pd.to_numeric(df["produksi"], errors="coerce")
        df = df.dropna(subset=["produk", "tahun", "produksi"])
        df = df[(df["produk"] != "") & (df["tahun"] % 1 == 0)].copy()
        df["tahun"] = df["tahun"].astype(int)
        return df
    return None


def parse_wide_excel_sheet(raw):
    raw = raw.copy()
    raw = raw.dropna(axis=1, how="all")
    if raw.empty:
        return None

    product_header_row = None
    product_col = None
    unit_col = None
    for r in range(min(15, len(raw))):
        vals = [normalise_text(v) if pd.notna(v) else "" for v in raw.iloc[r].tolist()]
        for c, val in enumerate(vals):
            if val in {"varian produk", "produk", "nama produk", "product"}:
                product_header_row, product_col = r, c
            if val in {"keterangan", "satuan", "unit"}:
                unit_col = c
        if product_header_row is not None:
            break

    if product_header_row is None:
        return None

    year_columns = {}
    for r in range(product_header_row + 1, min(product_header_row + 5, len(raw))):
        found = {}
        for c, val in enumerate(raw.iloc[r].tolist()):
            year = parse_year(val)
            if year is not None:
                found[c] = year
        if len(found) >= 1:
            year_row, year_columns = r, found
            break
    if year_row is None:
        return None

    if unit_col is None:
        for r in range(max(0, product_header_row - 1), min(product_header_row + 2, len(raw))):
            for c, val in enumerate(raw.iloc[r].tolist()):
                if normalise_text(val) in {"keterangan", "satuan", "unit"}:
                    unit_col = c
                    break

    rows = []
    for r in range(year_row + 1, len(raw)):
        product = raw.iat[r, product_col] if product_col < raw.shape[1] else None
        if pd.isna(product) or not str(product).strip():
            continue
        product_text = str(product).strip()
        if normalise_text(product_text) in {"varian produk", "produk", "nama produk", "total"}:
            continue
        unit = raw.iat[r, unit_col] if unit_col is not None and unit_col < raw.shape[1] else "Tidak diketahui"
        if pd.isna(unit) or not str(unit).strip():
            unit = "Tidak diketahui"
        for c, year in year_columns.items():
            if c >= raw.shape[1]:
                continue
            value = raw.iat[r, c]
            numeric_value = pd.to_numeric(value, errors="coerce")
            if pd.notna(numeric_value):
                rows.append({
                    "produk": product_text,
                    "satuan": str(unit).strip(),
                    "tahun": year,
                    "produksi": float(numeric_value),
                })

    if not rows:
        return None
    return pd.DataFrame(rows)


def load_production_file(uploaded_file, default_path=None):
    filename = uploaded_file.name.lower() if uploaded_file is not None else str(default_path).lower()

    if uploaded_file is None:
        if default_path is None or not Path(default_path).exists():
            raise ValueError("Tidak ada file yang diunggah dan file default tidak ditemukan.")
        content = Path(default_path).read_bytes()
    else:
        content = uploaded_file.getvalue()

    if filename.endswith(".csv"):
        errors = []
        for sep in [",", ";", "\t"]:
            try:
                df = pd.read_csv(BytesIO(content), sep=sep)
                parsed = standardise_long_table(df)
                if parsed is not None and not parsed.empty:
                    return parsed, "CSV"
            except Exception as exc:
                errors.append(str(exc))
        for header in range(0, 8):
            try:
                df = pd.read_csv(BytesIO(content), header=header)
                parsed = standardise_long_table(df)
                if parsed is not None and not parsed.empty:
                    return parsed, "CSV"
            except Exception:
                pass
        raise ValueError("CSV tidak dikenali sebagai tabel produksi dengan kolom produk/tahun/produksi.")

    if not filename.endswith((".xlsx", ".xlsm", ".xls")):
        raise ValueError("Format file belum didukung. Gunakan XLSX, XLSM, XLS, atau CSV.")

    xls = pd.ExcelFile(BytesIO(content))
    failures = []
    sheet_names = sorted(
        xls.sheet_names,
        key=lambda name: ("catatan" in normalise_text(name) or "note" in normalise_text(name), xls.sheet_names.index(name))
    )

    for sheet in sheet_names:
        for header in range(0, 8):
            try:
                df = pd.read_excel(BytesIO(content), sheet_name=sheet, header=header)
                parsed = standardise_long_table(df)
                if parsed is not None and not parsed.empty:
                    return parsed, sheet
            except Exception as exc:
                failures.append(f"{sheet}: {exc}")

        try:
            raw = pd.read_excel(BytesIO(content), sheet_name=sheet, header=None)
            parsed = parse_wide_excel_sheet(raw)
            if parsed is not None and not parsed.empty:
                return parsed, sheet
        except Exception as exc:
            failures.append(f"{sheet}: {exc}")

    raise ValueError(
        "Belum bisa mengenali tabel produksi di sheet mana pun. "
        "Pastikan workbook berisi kolom produk/komoditas, tahun, dan nilai produksi. "
        "Sheet yang diperiksa: " + ", ".join(xls.sheet_names)
    )


# =========================================================
# TAB 1 — DIGITAL ARCHIVE & INTEGRITY
# =========================================================
with tab1:
    st.header("Digital Archive & Integrity Verification")
    st.write("Unggah arsip untuk menghitung SHA-256 dan memeriksa integritas file.")

    archive_file = st.file_uploader(
        "Pilih file arsip Excel atau CSV",
        type=["xlsx", "xlsm", "xls", "csv"],
        key="archive_upload"
    )

    if archive_file is not None:
        file_bytes = archive_file.getvalue()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        st.success("File berhasil diterima.")
        st.write("Nama file:", archive_file.name)
        st.write("Ukuran file:", f"{len(file_bytes):,} byte")
        st.caption("SHA-256")
        st.code(sha256_hash)

        reference_hash = st.text_input(
            "Hash SHA-256 tepercaya untuk dibandingkan",
            placeholder="Tempelkan hash referensi di sini"
        )
        if reference_hash.strip():
            if sha256_hash.lower() == reference_hash.strip().lower():
                st.success("Hash cocok dengan referensi.")
            else:
                st.error("Hash tidak cocok dengan referensi.")

        st.caption(
            "Waktu pemeriksaan: "
            + datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        )
        st.divider()
        st.subheader("Simpan hash awal ke cloud")
        cloud_client = None
        cloud_error = None
        try:
            cloud_client = get_cloud_client()
        except Exception as exc:
            cloud_error = str(exc)

        if cloud_client is None:
            if cloud_error:
                st.error(f"Koneksi cloud gagal disiapkan: {cloud_error}")
            else:
                st.warning(
                    "Cloud belum dikonfigurasi. Hash baru terlihat di sesi ini dan belum tersimpan permanen. "
                    "Tambahkan SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY di Streamlit Secrets atau environment."
                )
        else:
            try:
                existing_record = find_cloud_record(cloud_client, archive_file.name)
                if existing_record:
                    if existing_record["sha256"].lower() == sha256_hash.lower():
                        st.success("File ini sudah terdaftar di cloud dan hash-nya cocok dengan hash awal.")
                    else:
                        st.error(
                            "Nama file ini sudah memiliki hash awal yang berbeda di cloud. "
                            "Hash awal tidak ditimpa otomatis. Periksa file sebelum menggunakannya."
                        )
                        st.caption(f"Hash terdaftar: {existing_record['sha256']}")
                else:
                    st.caption("File belum terdaftar. Simpan hash ini sebagai hash awal tepercaya.")
                    if st.button("Simpan hash awal ke cloud", key="save_initial_cloud_hash"):
                        status, record = save_initial_hash(
                            cloud_client, archive_file.name, sha256_hash, len(file_bytes)
                        )
                        if status == "saved":
                            st.success("Hash awal berhasil disimpan di cloud dan tidak akan ditimpa otomatis.")
                        elif status == "same":
                            st.success("Hash yang sama sudah tercatat di cloud.")
                        else:
                            st.error("Penyimpanan ditolak: nama file sudah terdaftar dengan isi berbeda.")
            except Exception as exc:
                st.error(f"Tidak dapat memeriksa registry cloud: {exc}")
                st.caption("Pastikan tabel file_hash_registry sudah dibuat dan kredensial cloud benar.")


# =========================================================
# TAB 2 — PRODUCTION ANALYTICS
# =========================================================
with tab2:
    st.header("Production Analytics & Anomaly Detection")
    st.write(
        "Unggah file asli, file hasil preprocessing, atau file dummy. "
        "Dashboard akan mencoba mengenali format tabel dan mengubahnya otomatis."
    )

    production_file = st.file_uploader(
        "Pilih dataset produksi untuk dianalisis",
        type=["xlsx", "xlsm", "xls", "csv"],
        key="production_upload"
    )

    use_default = st.checkbox(
        "Jika tidak mengunggah file, gunakan data_produksi_bersih.csv dari folder aplikasi",
        value=production_file is None
    )

    df = None
    if production_file is not None:
        # Validate the original uploaded bytes before parsing or analysing the dataset.
        production_hash = hashlib.sha256(production_file.getvalue()).hexdigest()
        cloud_client = None
        cloud_error = None
        try:
            cloud_client = get_cloud_client()
        except Exception as exc:
            cloud_error = str(exc)

        integrity_allowed = True
        if cloud_client is None:
            if cloud_error:
                st.error(f"Validasi cloud gagal: {cloud_error}")
                integrity_allowed = False
            else:
                st.warning(
                    "Validasi cloud belum aktif karena kredensial Supabase belum dikonfigurasi. "
                    "Mode demo mengizinkan analisis, tetapi pemeriksaan nama/hash cloud belum berlaku."
                )
        else:
            try:
                integrity_allowed, integrity_status, record = validate_file_against_cloud(
                    cloud_client, production_file.name, production_hash
                )
                if integrity_status == "match":
                    st.success("Integritas terverifikasi: hash cocok dengan catatan awal di cloud.")
                elif integrity_status == "mismatch":
                    st.error(
                        "ANALISIS DIBLOKIR: nama file ini sudah terdaftar di cloud, "
                        "tetapi hash berbeda dari hash awal. File mungkin telah diubah."
                    )
                    st.caption(f"Hash awal cloud: {record['sha256']}")
                    st.caption(f"Hash file sekarang: {production_hash}")
                else:
                    st.info(
                        "File dengan nama ini belum tercatat di cloud. Sesuai aturan sistem, "
                        "file baru boleh dianalisis; unggah juga ke Tab 1 jika ingin mencatat hash awalnya."
                    )
            except Exception as exc:
                st.error(f"Validasi registry cloud gagal; analisis dihentikan demi keamanan: {exc}")
                integrity_allowed = False

        if integrity_allowed:
            try:
                df, source_sheet = load_production_file(production_file)
                st.success(f"File berhasil dibaca. Sheet/sumber data: {source_sheet}")
            except Exception as exc:
                st.error(f"File belum berhasil diproses: {exc}")
                st.info(
                    "Dashboard mendukung format long (produk, satuan, tahun, produksi), "
                    "format wide dengan satu kolom per tahun, dan workbook dengan header "
                    "bertingkat seperti rekap laporan mitra."
                )
    elif use_default:
        default_path = Path(__file__).parent / "data_produksi_bersih.csv"
        try:
            df, source_sheet = load_production_file(None, default_path=default_path)
            st.info("Menampilkan data default hasil preprocessing.")
        except Exception as exc:
            st.warning(f"Data default belum tersedia atau tidak terbaca: {exc}")

    if df is not None and not df.empty:
        df = df.copy()
        df["tahun"] = pd.to_numeric(df["tahun"], errors="coerce")
        df["produksi"] = pd.to_numeric(df["produksi"], errors="coerce")
        df = df.dropna(subset=["produk", "tahun", "produksi"]).copy()
        df = df[df["tahun"] % 1 == 0].copy()
        df["tahun"] = df["tahun"].astype(int)
        df["produk"] = df["produk"].astype(str).str.strip()
        df["satuan"] = df["satuan"].fillna("Tidak diketahui").astype(str).str.strip()
        df = df[(df["produk"] != "") & (df["produk"].str.lower() != "nan")]

        if df.empty:
            st.warning("File terbaca, tetapi tidak ada baris produksi valid.")
        else:
            st.success(f"Berhasil menyiapkan {len(df)} catatan produksi.")
            st.caption(f"Tahun terdeteksi: {df['tahun'].min()}–{df['tahun'].max()}")

            st.sidebar.header("Filter Produksi")
            min_year, max_year = int(df["tahun"].min()), int(df["tahun"].max())
            if min_year < max_year:
                year_range = st.sidebar.slider(
                    "Rentang tahun",
                    min_value=min_year,
                    max_value=max_year,
                    value=(min_year, max_year),
                    step=1,
                    key="production_year_range"
                )
            else:
                year_range = (min_year, max_year)
                st.sidebar.write("Tahun data:", min_year)

            product_options = sorted(df["produk"].unique().tolist())
            selected_products = st.sidebar.multiselect(
                "Pilih produk",
                options=product_options,
                default=product_options,
                key="production_products"
            )

            filtered = df[
                df["tahun"].between(year_range[0], year_range[1])
                & df["produk"].isin(selected_products)
            ].copy()

            if filtered.empty:
                st.warning("Tidak ada data untuk filter yang dipilih.")
            else:
                c1, c2, c3 = st.columns(3)
                c1.metric("Jumlah produk", filtered["produk"].nunique())
                c2.metric("Jumlah catatan", len(filtered))
                c3.metric("Rentang tahun", f"{filtered['tahun'].min()}–{filtered['tahun'].max()}")

                st.info(
                    "Produksi ditampilkan menurut satuannya. Nilai dengan satuan berbeda "
                    "(misalnya Liter, Kg, dan Zak) tidak dijumlahkan menjadi satu total."
                )

                st.subheader("Tren Produksi per Produk")
                trend = filtered.groupby(
                    ["tahun", "produk", "satuan"], as_index=False
                )["produksi"].sum()
                fig = px.line(
                    trend, x="tahun", y="produksi", color="produk", markers=True,
                    hover_data=["satuan"],
                    labels={
                        "tahun": "Tahun", "produksi": "Jumlah produksi",
                        "produk": "Produk", "satuan": "Satuan"
                    }
                )
                st.plotly_chart(fig, use_container_width=True)

                st.subheader("Perbandingan Produksi")
                available_years = sorted(filtered["tahun"].unique().tolist(), reverse=True)
                comparison_year = st.selectbox(
                    "Pilih tahun",
                    available_years,
                    key="production_comparison_year"
                )
                comparison = filtered[filtered["tahun"] == comparison_year]
                bar = px.bar(
                    comparison, x="produk", y="produksi", color="satuan",
                    labels={
                        "produk": "Produk", "produksi": "Jumlah produksi",
                        "satuan": "Satuan"
                    },
                    title=f"Produksi Tahun {comparison_year}"
                )
                st.plotly_chart(bar, use_container_width=True)

                st.subheader("Pemeriksaan Perubahan Produksi")
                threshold = st.slider(
                    "Tandai perubahan tahunan di atas (%)",
                    min_value=10, max_value=200, value=50, step=10,
                    key="production_change_threshold"
                )
                yearly = filtered.groupby(
                    ["produk", "satuan", "tahun"], as_index=False
                )["produksi"].sum().sort_values(["produk", "satuan", "tahun"])
                yearly["perubahan_persen"] = (
                    yearly.groupby(["produk", "satuan"])["produksi"].pct_change() * 100
                )
                alerts = yearly[yearly["perubahan_persen"].abs() > threshold]
                if alerts.empty:
                    st.success("Tidak ditemukan perubahan yang melewati ambang pada data terpilih.")
                else:
                    st.warning(f"Ditemukan {len(alerts)} perubahan yang perlu ditinjau.")
                    st.dataframe(alerts, use_container_width=True, hide_index=True)
                st.caption(
                    "Pemeriksaan perubahan persentase adalah penanda eksploratif, "
                    "bukan bukti kesalahan atau hasil model machine learning."
                )

                with st.expander("Lihat data produksi yang sudah distandardisasi"):
                    st.dataframe(
                        filtered.sort_values(["tahun", "produk"]),
                        use_container_width=True,
                        hide_index=True
                    )

                csv_data = filtered.to_csv(index=False).encode("utf-8-sig")
                st.download_button(
                    "Unduh data hasil standardisasi (CSV)",
                    data=csv_data,
                    file_name="data_produksi_standard.csv",
                    mime="text/csv"
                )


# =========================================================
# TAB 3 — NETWORK LOG FORENSICS & AUDIT
# =========================================================
with tab3:
    st.header("Network Log Forensics & Audit")
    st.write(
        "Area ini untuk integrasi modul log jaringan dan deteksi anomali aktivitas."
    )
    st.info(
        "Tempat integrasi modul rekan: tabel log, filter IP, deteksi login gagal, "
        "lonjakan unduhan, Isolation Forest, dan ringkasan alert."
    )
