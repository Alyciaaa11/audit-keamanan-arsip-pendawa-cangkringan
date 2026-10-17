import random
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from pathlib import Path
from io import BytesIO
import hashlib
import os
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np

from network_page import render_network_page

st.set_page_config(
    page_title="Agribusiness Secure Archive",
    layout="wide"
)

# =========================================================
# DASHBOARD STATE & NOTIFICATIONS
# =========================================================

if "dashboard_files" not in st.session_state:
    st.session_state["dashboard_files"] = {}

if "dashboard_verified_files" not in st.session_state:
    st.session_state["dashboard_verified_files"] = set()

if "dashboard_production" not in st.session_state:
    st.session_state["dashboard_production"] = None

if "dashboard_production_anomalies" not in st.session_state:
    st.session_state["dashboard_production_anomalies"] = 0

if "dashboard_network_anomalies" not in st.session_state:
    st.session_state["dashboard_network_anomalies"] = None

if "dashboard_network_source" not in st.session_state:
    st.session_state["dashboard_network_source"] = None

if "dashboard_notifications" not in st.session_state:
    st.session_state["dashboard_notifications"] = []


def add_dashboard_notification(message, category="info"):
    """Simpan notifikasi tanpa mengulang event terakhir."""
    notifications = st.session_state["dashboard_notifications"]

    event = {
        "message": message,
        "category": category,
        "time": datetime.now().astimezone().strftime("%H:%M:%S"),
    }

    if not notifications or notifications[-1]["message"] != message:
        notifications.append(event)

    # Batasi riwayat notifikasi dalam sesi.
    st.session_state["dashboard_notifications"] = notifications[-20:]


st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
:root {
  --sage-bg: #f7f4fc;
  --sage-soft: #eee7f8;
  --sage: #8064a8;
  --sage-dark: #40334f;
  --sage-text: #62566f;
  --sage-border: #e5ddef;
}
html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
.stApp { background: linear-gradient(135deg, #f7f4fc 0%, #f1ebf9 55%, #fbfaff 100%); color: var(--sage-dark); }
/* Reserve space below Streamlit's native top bar so app controls never sit underneath it. */
.block-container { padding-top: 4.6rem !important; padding-bottom: 2.5rem; max-width: 1500px; }
[data-testid="stHeader"] {
  height: 3.75rem;
  background: rgba(247, 244, 252, 0.97) !important;
  border-bottom: 1px solid #e5ddef;
  z-index: 100;
}
[data-testid="stToolbar"] { z-index: 101; }
[data-testid="stDecoration"] { background: #8064a8 !important; }
/* Give the app's own header row enough vertical breathing room. */
.main .block-container > div:first-child { padding-top: .2rem; }

h1, h2, h3 { color: var(--sage-dark) !important; letter-spacing: -0.025em; }
h1 { font-size: 2rem !important; font-weight: 700 !important; }
h2 { font-size: 1.45rem !important; font-weight: 700 !important; }
h3 { font-size: 1.12rem !important; font-weight: 650 !important; }
[data-testid="stCaptionContainer"] { color: var(--sage-text); }
[data-testid="stTabs"] [data-baseweb="tab-list"] { gap: .55rem; background: rgba(238,231,248,.8); padding: .45rem; border: 1px solid var(--sage-border); border-radius: 16px; }
[data-testid="stTabs"] button[role="tab"] { border-radius: 11px; padding: .65rem 1rem; color: #62566f; font-weight: 600; border: 0; }
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] { background: #fff; color: #5b407e; box-shadow: 0 2px 10px rgba(91,64,126,.12); }
[data-testid="stTabs"] [data-baseweb="tab-highlight"] { background: #6d9873; height: 0; }
[data-testid="stMetric"] { background: rgba(255,255,255,.94); border: 1px solid var(--sage-border); padding: 1.05rem 1.1rem; border-radius: 17px; box-shadow: 0 5px 18px rgba(39,78,48,.055); }
[data-testid="stMetricLabel"] { color: var(--sage-text); font-weight: 600; }
[data-testid="stMetricValue"] { color: #40334f; font-weight: 700; }
[data-testid="stVerticalBlockBorderWrapper"] { border-color: var(--sage-border) !important; border-radius: 17px !important; }
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #f0eafb 0%, #faf8fe 100%);
  border-right: 1px solid var(--sage-border);
  min-width: 285px !important;
}
[data-testid="stSidebar"] > div:first-child { padding: 1.2rem .85rem 1.5rem; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { font-size: 1rem; line-height: 1.45; }
[data-testid="stSidebar"] [role="radiogroup"] { gap: .42rem; }
[data-testid="stSidebar"] [role="radiogroup"] label {
  padding: .72rem .7rem !important;
  border-radius: 12px !important;
  min-height: 48px;
  align-items: center !important;
  font-size: 1rem !important;
  font-weight: 550;
}
[data-testid="stSidebar"] [role="radiogroup"] label p { font-size: 1rem !important; }
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
  background: #e4d8f4 !important;
  border: 1px solid #cdbbe7 !important;
}
[data-testid="stSidebar"] [role="radiogroup"] label > div:first-child { display: none; }
[data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 { color: #40334f !important; }
.stButton > button, .stDownloadButton > button { border-radius: 11px; border: 1px solid #d9c9f0; background: #eee7f8; color: #5b407e; font-weight: 650; transition: all .18s ease; }
.stButton > button:hover, .stDownloadButton > button:hover { background: #e4d8f4; border-color: #b8a2d6; color: #40334f; }
[data-testid="stFileUploader"] section { background: rgba(255,255,255,.75); border: 1.5px dashed #b9a6d5; border-radius: 15px; }
[data-testid="stDataFrame"], [data-testid="stTable"] { border: 1px solid var(--sage-border); border-radius: 13px; overflow: hidden; }
[data-testid="stAlert"] { border-radius: 13px; }
hr { border-color: var(--sage-border); }
[data-testid="stButton"] button { min-height: 2.45rem; }
[data-testid="stSidebar"] [data-testid="stRadio"] { margin-top: .3rem; }
[data-testid="stSidebar"] [data-testid="stRadio"] label { color: #40334f; }
@media (max-width: 768px) {
  .block-container { padding: 4.25rem .8rem 2rem !important; }
  h1 { font-size: 1.6rem !important; }
  [data-testid="stTabs"] [data-baseweb="tab-list"] { gap: .15rem; }
  [data-testid="stTabs"] button[role="tab"] { padding: .55rem .55rem; font-size: .82rem; }
}
</style>
""", unsafe_allow_html=True)

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


class StoredUpload:
    def __init__(self, name, content):
        self.name = name
        self._content = content

    def getvalue(self):
        return self._content


def persist_archive_upload():
    uploaded = st.session_state.get("archive_upload_widget")
    if uploaded is not None:
        st.session_state["saved_archive_name"] = uploaded.name
        st.session_state["saved_archive_bytes"] = uploaded.getvalue()


def persist_reference_hash():
    st.session_state["trusted_reference_hash"] = st.session_state.get("trusted_reference_hash_input", "")


with st.sidebar:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:12px;padding:8px 6px 22px;">
      <div style="width:44px;height:44px;border-radius:14px;background:#e4d8f4;color:#6f5297;display:flex;align-items:center;justify-content:center;font-size:25px;font-weight:600;">A</div>
      <div style="font-size:1.08rem;font-weight:750;color:#40334F;line-height:1.3;">Agribusiness<br>Secure Archive</div>
    </div>
    """, unsafe_allow_html=True)
    selected_page = st.radio(
        "Navigasi",
        ["Dashboard", "Digital Archive & Integrity", "Production Analytics", "Network Log Forensics", "Settings"],
        label_visibility="collapsed",
        key="main_navigation",
        format_func=lambda page: {
            "Dashboard": "⌂   Dashboard",
            "Digital Archive & Integrity": "▱   Digital Archive & Integrity",
            "Production Analytics": "▥   Production Analytics",
            "Network Log Forensics": "⌘   Network Log Forensics",
            "Settings": "⚙   Settings",
        }[page],
    )
    st.markdown("<hr style='margin:18px 0;border-color:#E5DDEF;'>", unsafe_allow_html=True)
    st.caption("Pastel workspace · Agribusiness")

head_title, head_spacer, head_notifications, head_settings = st.columns([5, 3, 0.8, 0.8])
with head_title:
    st.markdown("<div style='padding-top:8px;font-weight:700;font-size:1.08rem;color:#40334F;'>Agribusiness Secure Archive</div>", unsafe_allow_html=True)

def toggle_notifications():
    st.session_state["show_notifications"] = not st.session_state.get("show_notifications", False)
    st.session_state["main_navigation"] = "Dashboard"

def go_to_settings():
    st.session_state["main_navigation"] = "Settings"

with head_notifications:
    st.button("♧", help="Lihat notifikasi", key="header_notifications", on_click=toggle_notifications)
with head_settings:
    st.button("⚙", help="Buka pengaturan", key="header_settings", on_click=go_to_settings)

archive_file = None
if st.session_state.get("saved_archive_bytes") is not None:
    archive_file = StoredUpload(
        st.session_state.get("saved_archive_name", "uploaded_file.csv"),
        st.session_state["saved_archive_bytes"],
    )
reference_hash = st.session_state.get("trusted_reference_hash", "")


if selected_page == "Dashboard":
    st.markdown("""
    <div style="
        background: linear-gradient(105deg,#FFFFFF 0%,#FAF7FF 65%,#EEE7F8 100%);
        border: 1px solid #E5DDEF;
        border-radius: 20px;
        padding: 25px 28px;
        margin: .3rem 0 1.2rem;
        box-shadow: 0 7px 22px rgba(91,64,126,.06);
    ">
        <div style="font-size:1.55rem;font-weight:750;color:#40334F;">
            🌿 Welcome back, Admin!
        </div>
        <div style="color:#706879;margin-top:8px;max-width:700px;">
            Pantau integritas arsip, ringkasan produksi, dan indikasi anomali
            agribisnis dalam satu dashboard.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # =========================================
    # AMBIL DATA RINGKASAN DARI SESSION STATE
    # =========================================
    files = st.session_state["dashboard_files"]
    verified_files = st.session_state["dashboard_verified_files"]

    total_files = len(files)

    # Hanya hitung file terverifikasi yang masih tercatat sebagai arsip.
    total_verified = len(set(files.keys()) & set(verified_files))

    production_df = st.session_state["dashboard_production"]
    production_anomalies = st.session_state["dashboard_production_anomalies"]
    network_anomalies = st.session_state["dashboard_network_anomalies"]

    # Total produksi hanya boleh dijumlahkan jika satuannya sama.
    production_label = "Belum dianalisis"
    production_help = "Jalankan Production Analytics untuk membaca data produksi."

    if production_df is not None and not production_df.empty:
        if {"produksi", "satuan"}.issubset(production_df.columns):
            units = (
                production_df["satuan"]
                .fillna("Tidak diketahui")
                .astype(str)
                .str.strip()
                .replace("", "Tidak diketahui")
                .unique()
                .tolist()
            )

            if len(units) == 1:
                total_production = pd.to_numeric(
                    production_df["produksi"], errors="coerce"
                ).sum()
                production_label = f"{total_production:,.2f} {units[0]}"
                production_help = "Total produksi dari data yang telah dianalisis."
            else:
                production_label = "Multi-satuan"
                production_help = (
                    "Data memiliki beberapa satuan. Nilai tidak dijumlahkan "
                    "karena satuan berbeda tidak bisa dibandingkan langsung."
                )

    # Jumlah anomali yang sudah terdeteksi.
    if network_anomalies is None:
        anomaly_display = str(production_anomalies)
        anomaly_help = (
            f"Anomali produksi: {production_anomalies}. "
            "Pemindaian jaringan belum dilakukan."
        )
    else:
        anomaly_display = str(production_anomalies + network_anomalies)
        network_source_note = (
            " (data simulasi, bukan log nyata)"
            if st.session_state.get("dashboard_network_source") == "simulation" else ""
        )
        anomaly_help = (
            f"Anomali produksi: {production_anomalies}; "
            f"indikasi anomali jaringan{network_source_note}: {network_anomalies}. "
            "Angka ini merupakan indikasi untuk ditinjau, bukan bukti serangan."
        )

    # =========================================
    # LAYOUT UTAMA DASHBOARD
    # =========================================
    left, right = st.columns([1.5, 1], gap="large")

    with left:
        st.markdown("### Ringkasan Project")
        st.caption("Status arsip dan analisis selama sesi aplikasi ini.")

        metric1, metric2 = st.columns(2)
        metric3, metric4 = st.columns(2)

        metric1.metric(
            "Total Files",
            total_files,
            help="Jumlah arsip unik yang diproses selama sesi ini."
        )

        metric2.metric(
            "Integrity Verified",
            f"{total_verified} / {total_files}",
            help=(
                "Jumlah arsip yang telah cocok dengan hash referensi "
                "manual atau hash tepercaya di cloud."
            )
        )

        metric3.metric(
            "Total Production",
            production_label,
            help=production_help
        )

        metric4.metric(
            "Detected Anomalies",
            anomaly_display,
            help=anomaly_help
        )

        st.caption(
            "Catatan: data dan riwayat pada ringkasan ini mengikuti "
            "aktivitas yang tersimpan selama sesi aplikasi."
        )

        if (
            network_anomalies is not None
            and st.session_state.get("dashboard_network_source") == "simulation"
        ):
            st.caption(
                f"⚠️ {network_anomalies} dari angka Detected Anomalies berasal dari "
                "pemindaian log jaringan simulasi (Tab 3), bukan log nyata."
            )

    
    with right:
        st.markdown("### Notifications")

        notifications = st.session_state.get(
            "dashboard_notifications", []
        )

        # Satu kotak riwayat dengan area scroll tetap.
        with st.container(height=440, border=True):
            if not notifications:
                st.caption(
                    "Belum ada notifikasi. Aktivitas akan muncul "
                    "di sini setelah arsip diproses atau analisis dijalankan."
                )
            else:
                for event in reversed(notifications):
                    category = event.get("category", "info")

                    if category == "success":
                        icon = "✅"
                    elif category == "warning":
                        icon = "⚠️"
                    else:
                        icon = "ℹ️"

                    st.caption(event.get("time", "--:--:--"))
                    st.markdown(
                        f"{icon} **{event['message']}**"
                    )
                    st.divider()


if selected_page == "Settings":
    st.markdown("### Settings")
    st.write("Pengaturan tampilan dashboard dan koneksi layanan.")
    st.selectbox("Tema dashboard", ["Pastel ungu & putih"], index=0, disabled=True)
    st.caption("Kredensial Supabase dibaca dari Streamlit Secrets atau environment variable. Jangan menaruh secrets di GitHub.")
    st.info("Untuk mengubah kredensial deployment, buka Settings → Secrets pada Streamlit Community Cloud.")



# =========================================================
# HELPERS: READ CLEAN, RAW, AND DUMMY PRODUCTION FILES
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

    year_row = None
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
if selected_page == "Digital Archive & Integrity":
        st.header("Digital Archive & Integrity Verification")
        st.write("Unggah arsip untuk menghitung SHA-256 dan memeriksa integritas file.")
        st.caption("File yang diunggah akan tetap tersedia saat berpindah halaman selama sesi browser ini aktif.")

        archive_file = st.file_uploader(
            "Pilih file arsip Excel atau CSV",
            type=["xlsx", "xlsm", "xls", "csv"],
            key="archive_upload_widget",
            on_change=persist_archive_upload,
        )

        if st.session_state.get("archive_upload_widget") is not None:
            uploaded_now = st.session_state["archive_upload_widget"]
            archive_file = StoredUpload(uploaded_now.name, uploaded_now.getvalue())
            st.session_state["saved_archive_name"] = uploaded_now.name
            st.session_state["saved_archive_bytes"] = uploaded_now.getvalue()
        elif st.session_state.get("saved_archive_bytes") is not None:
            archive_file = StoredUpload(
                st.session_state.get("saved_archive_name", "uploaded_file.csv"),
                st.session_state["saved_archive_bytes"],
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
                placeholder="Tempelkan hash referensi di sini",
                value=st.session_state.get("trusted_reference_hash", ""),
                key="trusted_reference_hash_input",
                on_change=persist_reference_hash,
            )
            st.session_state["trusted_reference_hash"] = reference_hash
           
            if reference_hash.strip():
                if sha256_hash.lower() == reference_hash.strip().lower():
                    st.success("Hash cocok dengan referensi.")
        
                else:
                    st.error("Hash tidak cocok dengan referensi.")
                    st.session_state["dashboard_verified_files"].discard(
                        filename_key(archive_file.name)
                    )
                    add_dashboard_notification(
                        f"Hash tidak cocok: {archive_file.name}",
                        "warning"
                    )
            else:
                st.session_state["dashboard_verified_files"].discard(
                    filename_key(archive_file.name)
                )


            # Catat arsip yang diproses selama sesi.
            st.session_state["dashboard_files"][filename_key(archive_file.name)] = {
                "name": archive_file.name,
                "sha256": sha256_hash,
                "size": len(file_bytes),
            }

            add_dashboard_notification(
                f"Arsip diproses: {archive_file.name}",
                "info"
            )

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

            st.session_state["dashboard_verified_files"].add(
                filename_key(archive_file.name)
            )

            add_dashboard_notification(
                f"Integritas terverifikasi: {archive_file.name}",
                "success"
            )
            

# =========================================================
# TAB 2 — PRODUCTION ANALYTICS
# =========================================================
if selected_page == "Production Analytics":
        st.header("Production Analytics & Anomaly Detection")
        st.write(
            "Tab ini memakai file yang sama dengan Tab 1. Upload cukup sekali, lalu "
            "hasil verifikasi integritas menjadi gerbang sebelum analisis produksi."
        )

        production_file = archive_file
        use_default = False
        df = None

        if production_file is not None:
            file_bytes = production_file.getvalue()
            production_hash = hashlib.sha256(file_bytes).hexdigest()
            integrity_allowed = True
            verification_status = "unverified"
            cloud_client = None
            cloud_error = None

            if reference_hash.strip():
                if production_hash.lower() == reference_hash.strip().lower():
                    verification_status = "match_manual"
                    st.success("Verifikasi Tab 1: SHA-256 cocok dengan referensi yang dimasukkan.")
                else:
                    verification_status = "mismatch_manual"
                    integrity_allowed = False
                    st.error("ANALISIS DIBLOKIR: SHA-256 file tidak cocok dengan referensi di Tab 1.")

            try:
                cloud_client = get_cloud_client()
            except Exception as exc:
                cloud_error = str(exc)

            if integrity_allowed:
                if cloud_client is None:
                    if cloud_error:
                        st.error(f"Validasi registry cloud gagal: {cloud_error}")
                        integrity_allowed = False
                    elif verification_status != "match_manual":
                        st.warning(
                            "Status file BELUM TERVERIFIKASI: registry cloud belum tersedia dan "
                            "hash referensi tepercaya belum cocok/dimasukkan. Demi keamanan, "
                            "analisis normal tidak dibuka otomatis."
                        )
                        allow_unverified = st.checkbox(
                            "Saya memahami file belum terverifikasi dan ingin menjalankan analisis terbatas (mode demo)",
                            value=False,
                            key="allow_unverified_production"
                        )
                        integrity_allowed = allow_unverified
                        if allow_unverified:
                            verification_status = "unverified_demo"
                            st.warning("Mode demo aktif: hasil analisis bukan berarti file telah dinyatakan aman.")
                else:
                    try:
                        cloud_allowed, cloud_status, record = validate_file_against_cloud(
                            cloud_client, production_file.name, production_hash
                        )
                        if cloud_status == "match":
                            verification_status = "match_cloud"
                            st.success("Verifikasi integritas berhasil: hash cocok dengan hash tepercaya di cloud.")
                        elif cloud_status == "mismatch":
                            verification_status = "mismatch_cloud"
                            integrity_allowed = False
                            st.error(
                                "ANALISIS DIBLOKIR: nama file ini terdaftar di cloud, tetapi isi file "
                                "berbeda dari hash tepercaya. Periksa versi file atau minta otorisasi pemilik data."
                            )
                            st.caption(f"Hash tepercaya: {record['sha256']}")
                            st.caption(f"Hash file saat ini: {production_hash}")
                        elif verification_status == "match_manual":
                            st.info("Referensi manual cocok; file dapat dianalisis meskipun belum terdaftar di cloud.")
                        else:
                            st.warning(
                                "File belum memiliki hash tepercaya di cloud. Simpan hash awal melalui Tab 1 "
                                "setelah memastikan file ini memang merupakan versi resmi."
                            )
                            allow_unverified = st.checkbox(
                                "Lanjutkan analisis terbatas untuk file yang belum terdaftar (mode demo)",
                                value=False,
                                key="allow_unregistered_production"
                            )
                            integrity_allowed = allow_unverified
                            if allow_unverified:
                                verification_status = "unverified_demo"
                                st.warning("Mode demo aktif: file belum terverifikasi oleh registry.")
                    except Exception as exc:
                        st.error(f"Validasi registry cloud gagal; analisis dihentikan demi keamanan: {exc}")
                        integrity_allowed = False

            if integrity_allowed:
                try:
                    df, source_sheet = load_production_file(production_file)
                    st.success(f"File yang sama dari Tab 1 berhasil dibaca. Sumber data: {source_sheet}")
                    st.caption(f"SHA-256 sumber analisis: {production_hash}")
                    if verification_status.startswith("match"):
                        st.caption("Status integritas: terverifikasi cocok.")
                    else:
                        st.caption("Status integritas: BELUM TERVERIFIKASI — gunakan hasil dengan kehati-hatian.")
                except Exception as exc:
                    st.error(f"File belum berhasil diproses: {exc}")
                    st.info(
                        "Format yang didukung: tabel long (produk, satuan, tahun, produksi), "
                        "format wide dengan kolom tahun, atau workbook dengan header bertingkat."
                    )
        else:
            st.info("Upload file di Tab 1 terlebih dahulu. Tab 2 akan menggunakan file yang sama tanpa upload ulang.")
            default_path = Path(__file__).parent / "data_produksi_bersih.csv"
            if default_path.exists():
                use_default = st.checkbox(
                    "Gunakan data demo lokal karena belum ada file yang di-upload di Tab 1",
                    value=False,
                    key="use_default_production_demo"
                )
                if use_default:
                    try:
                        df, source_sheet = load_production_file(None, default_path=default_path)
                        st.warning("Data demo lokal digunakan; data ini tidak melalui verifikasi file Tab 1.")
                    except Exception as exc:
                        st.warning(f"Data demo belum bisa dibaca: {exc}")

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

                st.sidebar.markdown("---")
                st.sidebar.subheader("Filter Produksi")
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

                # Data produksi yang valid untuk ringkasan Dashboard.
                st.session_state["dashboard_production"] = df.copy()

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
                    fig.update_layout(
                        template="plotly_white", paper_bgcolor="rgba(255,255,255,0)",
                        plot_bgcolor="rgba(255,255,255,0.72)", font=dict(family="DM Sans, sans-serif", color="#35533d"),
                        margin=dict(l=15, r=15, t=35, b=15), legend_title_text="Produk",
                    )
                    fig.update_xaxes(showgrid=False, linecolor="#e5ddef")
                    fig.update_yaxes(gridcolor="#e6eee4", zerolinecolor="#e5ddef")
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
                    bar.update_layout(
                        template="plotly_white", paper_bgcolor="rgba(255,255,255,0)",
                        plot_bgcolor="rgba(255,255,255,0.72)", font=dict(family="DM Sans, sans-serif", color="#35533d"),
                        margin=dict(l=15, r=15, t=45, b=15), showlegend=False,
                    )
                    bar.update_xaxes(showgrid=False, linecolor="#e5ddef")
                    bar.update_yaxes(gridcolor="#e6eee4", zerolinecolor="#e5ddef")
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
                    yearly["produksi_sebelumnya"] = yearly.groupby(
                        ["produk", "satuan"]
                    )["produksi"].shift(1)
                    yearly["perubahan_persen"] = (
                        (yearly["produksi"] - yearly["produksi_sebelumnya"])
                        / yearly["produksi_sebelumnya"].where(yearly["produksi_sebelumnya"] != 0)
                        * 100
                    )

                    def alasan_trigger(row):
                        sebelumnya = row["produksi_sebelumnya"]
                        sekarang = row["produksi"]
                        perubahan = row["perubahan_persen"]
                        if pd.isna(sebelumnya):
                            return "Belum ada data tahun sebelumnya untuk pembanding."
                        if sebelumnya == 0 and sekarang != 0:
                            return "Produksi berubah dari 0 menjadi nilai nonzero; persentase perubahan tidak dapat dihitung."
                        if pd.isna(perubahan):
                            return "Perubahan persentase tidak dapat dihitung dari data yang tersedia."
                        if abs(perubahan) > threshold:
                            arah = "naik" if perubahan > 0 else "turun"
                            return f"Produksi {arah} {abs(perubahan):.1f}% dibanding tahun sebelumnya (ambang {threshold}%)."
                        return "Tidak melewati ambang perubahan yang ditetapkan."

                    yearly["alasan_tinjau"] = yearly.apply(alasan_trigger, axis=1)
                    yearly["perlu_ditinjau"] = (
                        (yearly["perubahan_persen"].abs() > threshold)
                        | ((yearly["produksi_sebelumnya"] == 0) & (yearly["produksi"] != 0))
                    )
                    alerts = yearly[yearly["perlu_ditinjau"]].copy()
                    if alerts.empty:
                        st.success("Tidak ada nilai yang melewati aturan trigger pada data terpilih.")
                    else:
                        st.warning(f"Ditemukan {len(alerts)} catatan yang perlu ditinjau.")
                        st.dataframe(
                            alerts[["produk", "satuan", "tahun", "produksi_sebelumnya", "produksi", "perubahan_persen", "alasan_tinjau"]],
                            use_container_width=True,
                            hide_index=True
                        )

                    st.session_state["dashboard_production_anomalies"] = len(alerts)
                    if len(alerts) > 0:
                        add_dashboard_notification(
                            f"Ditemukan {len(alerts)} catatan perubahan produksi yang perlu ditinjau.",
                            "warning"
                        )
                    else:
                        add_dashboard_notification(
                            "Analisis perubahan produksi selesai: tidak ada trigger pada data terpilih.",
                            "success"
                        )

                    st.caption(
                        f"Metode: aturan perubahan tahunan. Trigger aktif jika perubahan absolut melebihi {threshold}% "
                        "atau produksi berubah dari 0 menjadi nilai nonzero. Ini hanya penanda untuk pemeriksaan admin, "
                        "bukan bukti otomatis adanya kesalahan, manipulasi, atau kecurangan."
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
# (logika: network_forensics.py, tampilan: network_page.py)
# =========================================================
if selected_page == "Network Log Forensics":
    render_network_page(add_dashboard_notification)