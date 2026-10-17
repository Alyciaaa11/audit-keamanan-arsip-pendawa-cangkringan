from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# ---------------------------------------------------------------------------
# Konstanta
# ---------------------------------------------------------------------------
DEFAULT_OP_START = 8          # jam operasional mulai (inklusif)
DEFAULT_OP_END = 18           # jam operasional selesai
DEFAULT_CONTAMINATION = 0.03  # perkiraan proporsi aktivitas yang dianggap anomali
DEFAULT_TRUSTED_NETWORKS = "192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12"
DEFAULT_BURST_THRESHOLD = 3   # minimal kegagalan dari IP yang sama dalam jendela waktu
DEFAULT_BURST_WINDOW_MIN = 30
MAX_UPLOAD_ROWS = 50_000
RANDOM_STATE = 42

CANONICAL_COLUMNS = [
    "Timestamp", "IP_Address", "Pengguna", "User_Action", "File_Accessed", "Status",
]
REQUIRED_COLUMNS = ["Timestamp", "IP_Address", "User_Action", "Status"]

_ALIASES = {
    "Timestamp": {"timestamp", "time", "waktu", "datetime", "date_time", "tanggal"},
    "IP_Address": {"ip_address", "ip", "src_ip", "source_ip", "ipaddress", "alamat_ip"},
    "User_Action": {"user_action", "action", "aktivitas", "event", "activity"},
    "File_Accessed": {"file_accessed", "file", "filename", "file_name", "nama_file"},
    "Status": {"status", "result", "outcome", "hasil"},
    "Pengguna": {"pengguna", "user", "username", "user_name", "akun"},
}
_SUCCESS_WORDS = {"success", "successful", "ok", "berhasil", "sukses", "200", "allowed"}
_FAILED_WORDS = {"failed", "fail", "failure", "gagal", "denied", "error", "ditolak", "401", "403"}

# Nama kelompok fitur masuk ke kolom model. Dipakai untuk penjelasan (atribusi).
GROUP_JAM = "Jam akses"
GROUP_IP = "Alamat IP"
GROUP_GAGAL = "Status gagal"
GROUP_BURST = "Gagal beruntun"
GROUP_AKSI = "Jenis aktivitas"
GROUP_FILE = "File diakses"

FLAG_COLUMNS = {
    "Flag_Luar_Jam": "Luar jam operasional",
    "Flag_IP_Tidak_Biasa": "IP tidak biasa",
    "Flag_Gagal_Beruntun": "Gagal beruntun",
}
PRIORITY_ORDER = ["Tinggi", "Sedang", "Rendah", "Normal"]

ANOMALY_MODES = ("Semua", "Hanya anomali", "Hanya normal")


class LogValidationError(ValueError):
    """Log tidak memenuhi skema yang dibutuhkan."""


# ---------------------------------------------------------------------------
# Normalisasi & validasi log
# ---------------------------------------------------------------------------
def normalise_log_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    notes: list[str] = []
    if df is None or len(df) == 0:
        raise LogValidationError("Log kosong.")

    lowered = {c: str(c).strip().lower().replace(" ", "_") for c in df.columns}
    rename = {}
    for target, names in _ALIASES.items():
        for col, low in lowered.items():
            if low in names and col not in rename and target not in rename.values():
                rename[col] = target
                break
    out = df.rename(columns=rename).copy()

    missing = [c for c in REQUIRED_COLUMNS if c not in out.columns]
    if missing:
        raise LogValidationError(
            "Kolom wajib tidak ditemukan: " + ", ".join(missing)
            + ". Kolom yang dibutuhkan: " + ", ".join(REQUIRED_COLUMNS)
            + " (opsional: Pengguna, File_Accessed)."
        )
    if len(out) > MAX_UPLOAD_ROWS:
        raise LogValidationError(
            f"Log terlalu besar ({len(out):,} baris). Batas aplikasi: {MAX_UPLOAD_ROWS:,} baris."
        )

    # Waktu
    ts = pd.to_datetime(out["Timestamp"], errors="coerce")
    if ts.dtype == object:  # offset zona waktu campuran
        ts = pd.to_datetime(out["Timestamp"], errors="coerce", utc=True)
        notes.append("Zona waktu campuran dikonversi ke UTC.")
    if getattr(ts.dt, "tz", None) is not None:
        ts = ts.dt.tz_localize(None)  # pertahankan jam dinding lokal
    out["Timestamp"] = ts
    bad_time = int(out["Timestamp"].isna().sum())
    if bad_time:
        out = out[out["Timestamp"].notna()].copy()
        notes.append(f"{bad_time} baris dibuang karena Timestamp tidak valid.")
    if out.empty:
        raise LogValidationError("Tidak ada baris dengan Timestamp valid.")

    # Status
    status_raw = out["Status"].astype(str).str.strip().str.lower()
    mapped = status_raw.map(
        lambda s: "Success" if s in _SUCCESS_WORDS else ("Failed" if s in _FAILED_WORDS else None)
    )
    unknown = sorted(set(status_raw[mapped.isna()]))
    if unknown:
        raise LogValidationError(
            "Nilai Status tidak dikenali: " + ", ".join(unknown[:5])
            + ". Gunakan Success/Failed (atau berhasil/gagal)."
        )
    out["Status"] = mapped

    out["IP_Address"] = out["IP_Address"].astype(str).str.strip()
    out["User_Action"] = out["User_Action"].astype(str).str.strip()
    for col in ("File_Accessed", "Pengguna"):
        if col not in out.columns:
            out[col] = "-"
        out[col] = out[col].fillna("-").astype(str).str.strip().replace("", "-")

    keep = CANONICAL_COLUMNS + [c for c in out.columns if c.startswith("Sim_")]
    out = out[keep].sort_values("Timestamp", kind="stable").reset_index(drop=True)
    return out, notes


# ---------------------------------------------------------------------------
# Log simulasi (sintetis)
# ---------------------------------------------------------------------------
_USERS = {
    "admin": (["192.168.1.10"], 0.15),
    "staf_arsip": (["192.168.1.21", "192.168.1.22"], 0.30),
    "staf_produksi": (["192.168.1.31", "192.168.1.32", "192.168.1.33"], 0.30),
    "manajer": (["192.168.1.41", "192.168.1.42"], 0.15),
    "operator_lapangan": (["192.168.1.51", "192.168.1.52"], 0.10),
}
_NORMAL_FILES = {
    "Rekap_Laporan_5_Tahun.xlsx": 0.45,
    "data_produksi_bersih.csv": 0.30,
    "Laporan_Produksi_Bulanan.xlsx": 0.20,
    "cangkringan_dataset_clean.xlsx": 0.05,   # sah tetapi jarang
}
_SENSITIVE_FILE = "cangkringan_dataset_clean.xlsx"
_ACTIONS = {"View Dashboard": 0.40, "Login": 0.20, "Upload Arsip": 0.20, "Download Arsip": 0.20}
_WFH_IPS = ["114.125.40.12", "36.72.18.201"]   # staf sah yang bekerja dari luar kantor

SIM_NORMAL = "Normal"
SIM_OVERTIME = "Normal (lembur)"
SIM_WFH = "Normal (kerja dari luar kantor)"
SIM_NIGHT = "Anomali: akses malam hari"
SIM_BRUTE = "Anomali: brute force login"
SIM_FOREIGN = "Anomali: unduh arsip oleh IP asing"
SIM_ANOMALY_SCENARIOS = (SIM_NIGHT, SIM_BRUTE, SIM_FOREIGN)


def _random_external_ip(rng: np.random.Generator) -> str:
    first = int(rng.choice([36, 45, 61, 103, 114, 139, 180, 185, 193, 201, 218]))
    return f"{first}.{rng.integers(1, 255)}.{rng.integers(1, 255)}.{rng.integers(1, 255)}"


def _pick(rng: np.random.Generator, weights: dict[str, float]) -> str:
    keys = list(weights)
    p = np.array([weights[k] for k in keys], dtype=float)
    return str(rng.choice(keys, p=p / p.sum()))


def generate_simulated_logs(
    seed: int = RANDOM_STATE,
    days: int = 30,
    end_date: str | pd.Timestamp | None = None,
    n_normal: int = 1900,
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    end = (pd.Timestamp(end_date) if end_date is not None else pd.Timestamp.now()).normalize()
    day_list = [end - pd.Timedelta(days=k) for k in range(days)]
    weekday_w = np.array([1.0 if d.dayofweek < 5 else (0.4 if d.dayofweek == 5 else 0.1) for d in day_list])
    weekday_w /= weekday_w.sum()

    rows: list[dict] = []

    def add(ts, ip, user, action, file, status, scenario):
        rows.append({
            "Timestamp": ts, "IP_Address": ip, "Pengguna": user, "User_Action": action,
            "File_Accessed": file, "Status": status,
            "Sim_Skenario": scenario, "Sim_Anomali_Sebenarnya": scenario in SIM_ANOMALY_SCENARIOS,
        })

    def work_ts():
        day = day_list[int(rng.choice(len(day_list), p=weekday_w))]
        hour = int(rng.choice(np.arange(8, 18), p=np.array([2, 4, 4, 3, 2, 3, 4, 4, 3, 1]) / 30))
        return day + pd.Timedelta(hours=hour, minutes=int(rng.integers(0, 60)), seconds=int(rng.integers(0, 60)))

    user_names = list(_USERS)
    user_w = np.array([_USERS[u][1] for u in user_names])
    user_w = user_w / user_w.sum()

    # aktivitas normal
    for _ in range(n_normal):
        user = str(rng.choice(user_names, p=user_w))
        ip = str(rng.choice(_USERS[user][0]))
        action = _pick(rng, _ACTIONS)
        file = _pick(rng, _NORMAL_FILES) if action in ("Upload Arsip", "Download Arsip") else "-"
        fail_p = 0.08 if action == "Login" else 0.02
        ts = work_ts()
        if rng.random() < fail_p:
            add(ts, ip, user, action, file, "Failed", SIM_NORMAL)
            if action == "Login":  # salah ketik, lalu berhasil
                add(ts + pd.Timedelta(seconds=int(rng.integers(15, 90))), ip, user, "Login", "-", "Success", SIM_NORMAL)
        else:
            add(ts, ip, user, action, file, "Success", SIM_NORMAL)

    # normal tetapi mirip anomali: lembur
    for _ in range(60):
        user = str(rng.choice(user_names, p=user_w))
        ip = str(rng.choice(_USERS[user][0]))
        hour = int(rng.choice([18, 19, 20, 21, 6, 7], p=[.25, .25, .2, .15, .08, .07]))
        day = day_list[int(rng.choice(len(day_list), p=weekday_w))]
        ts = day + pd.Timedelta(hours=hour, minutes=int(rng.integers(0, 60)), seconds=int(rng.integers(0, 60)))
        action = str(rng.choice(["View Dashboard", "Upload Arsip", "Download Arsip"]))
        file = _pick(rng, _NORMAL_FILES) if action != "View Dashboard" else "-"
        add(ts, ip, user, action, file, "Success", SIM_OVERTIME)

    # normal tetapi mirip anomali: kerja dari luar kantor
    for _ in range(25):
        ts = work_ts()
        action = str(rng.choice(["View Dashboard", "Download Arsip"]))
        file = "Rekap_Laporan_5_Tahun.xlsx" if action == "Download Arsip" else "-"
        add(ts, str(rng.choice(_WFH_IPS)), "manajer", action, file, "Success", SIM_WFH)

    # anomali 1: akses malam hari oleh IP eksternal
    for _ in range(25):
        day = day_list[int(rng.integers(0, len(day_list)))]
        ts = day + pd.Timedelta(hours=int(rng.integers(0, 5)), minutes=int(rng.integers(0, 60)), seconds=int(rng.integers(0, 60)))
        user = str(rng.choice(["admin", "staf_arsip"]))
        if rng.random() < 0.8:
            add(ts, _random_external_ip(rng), user, "Download Arsip", _SENSITIVE_FILE, "Success", SIM_NIGHT)
        else:
            add(ts, _random_external_ip(rng), user, "Login", "-", "Success", SIM_NIGHT)

    # anomali 2: brute force login (rentetan gagal dari satu IP)
    guess_users = ["admin", "root", "administrator", "staf_arsip", "test", "manajer"]
    for b in range(3):
        ip = _random_external_ip(rng)
        day = day_list[int(rng.integers(0, len(day_list)))]
        start = day + pd.Timedelta(hours=int(rng.integers(0, 6)), minutes=int(rng.integers(0, 60)))
        n_try = int(rng.integers(9, 14))
        t = start
        for _ in range(n_try):
            add(t, ip, str(rng.choice(guess_users)), "Login", "-", "Failed", SIM_BRUTE)
            t = t + pd.Timedelta(seconds=int(rng.integers(5, 40)))
        if b == 0:  # satu rentetan berakhir dengan login berhasil lalu unduh arsip
            add(t, ip, "admin", "Login", "-", "Success", SIM_BRUTE)
            add(t + pd.Timedelta(minutes=2), ip, "admin", "Download Arsip", _SENSITIVE_FILE, "Success", SIM_BRUTE)

    # anomali 3: unduh arsip oleh IP asing pada jam kerja
    foreign_ips = [_random_external_ip(rng) for _ in range(6)]
    for _ in range(12):
        ts = work_ts()
        add(ts, str(rng.choice(foreign_ips)), str(rng.choice(["admin", "staf_arsip"])), "Download Arsip", _SENSITIVE_FILE, "Success", SIM_FOREIGN)

    df = pd.DataFrame(rows)
    return df.sort_values("Timestamp", kind="stable").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Fitur & indikator
# ---------------------------------------------------------------------------
def parse_networks(text: str) -> list:
    nets = []
    for part in str(text or "").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise LogValidationError(f"Jaringan tepercaya tidak valid: '{part}'.") from exc
    return nets


def _ip_trusted(ip_text: str, nets: list) -> tuple[bool, bool]:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False, False
    return any(ip in net for net in nets), True


def hour_distance_outside(hour_decimal: np.ndarray, op_start: float, op_end: float) -> np.ndarray:
    t = np.asarray(hour_decimal, dtype=float)
    inside = (t >= op_start) & (t <= op_end)
    to_start = (op_start - t) % 24
    to_end = (t - op_end) % 24
    return np.where(inside, 0.0, np.minimum(to_start, to_end))


def count_failures_nearby(df: pd.DataFrame, window_minutes: int) -> np.ndarray:
    result = np.zeros(len(df), dtype=int)
    ts = df["Timestamp"].to_numpy(dtype="datetime64[ns]")
    failed = (df["Status"] == "Failed").to_numpy().astype(int)
    window = np.timedelta64(int(window_minutes * 60), "s")
    for _, idx in df.groupby("IP_Address", sort=False).indices.items():
        idx = np.asarray(idx)
        order = idx[np.argsort(ts[idx], kind="stable")]
        t = ts[order]
        csum = np.concatenate([[0], np.cumsum(failed[order])])
        lo = np.searchsorted(t, t - window, side="left")
        hi = np.searchsorted(t, t + window, side="right")
        result[order] = csum[hi] - csum[lo]
    return result


@dataclass
class ScanResult:
    logs: pd.DataFrame
    contributions: pd.DataFrame          # kontribusi relatif per kelompok fitur (hanya baris anomali)
    threshold: float                     # skor di atas ini = anomali
    params: dict
    summary: dict
    feature_matrix: pd.DataFrame = field(repr=False, default_factory=pd.DataFrame)
    notes: list[str] = field(default_factory=list)


def _build_features(df: pd.DataFrame, op_start: int, op_end: int, nets: list, burst_window: int):
    n = len(df)
    hour_dec = (df["Timestamp"].dt.hour + df["Timestamp"].dt.minute / 60.0).to_numpy()
    dist = hour_distance_outside(hour_dec, op_start, op_end)

    trusted_valid = [_ip_trusted(ip, nets) for ip in df["IP_Address"]]
    trusted = np.array([t for t, _ in trusted_valid], dtype=bool)
    valid = np.array([v for _, v in trusted_valid], dtype=bool)

    ip_count = df.groupby("IP_Address")["IP_Address"].transform("size").to_numpy()
    ip_rare = (ip_count <= 2) & (n >= 200)

    failed = (df["Status"] == "Failed").to_numpy()
    fail_near = count_failures_nearby(df, burst_window)

    has_file = (df["File_Accessed"] != "-").to_numpy()
    file_count = df.groupby("File_Accessed")["File_Accessed"].transform("size").to_numpy()
    max_fc = file_count[has_file].max() if has_file.any() else 1
    file_rare = np.where(has_file, 1.0 - file_count / max_fc, 0.0)

    X = pd.DataFrame({
        "Jarak_Luar_Jam": dist,
        "IP_Eksternal": (~trusted).astype(float),
        "IP_Frekuensi_Log": np.log1p(ip_count),
        "Gagal": failed.astype(float),
        "Gagal_Sekitar": np.clip(fail_near, 0, 15).astype(float),
        "File_Langka": file_rare,
    })
    action_dummies = pd.get_dummies(df["User_Action"], prefix="Aksi", dtype=float)
    X = pd.concat([X.reset_index(drop=True), action_dummies.reset_index(drop=True)], axis=1)

    extra = pd.DataFrame({
        "Jam_Desimal": hour_dec, "Jarak_Luar_Jam": dist, "IP_Tepercaya": trusted, "IP_Valid": valid,
        "IP_Count": ip_count, "IP_Jarang": ip_rare, "Gagal_Sekitar": fail_near,
        "File_Count": np.where(has_file, file_count, 0),
    })
    return X, extra, list(action_dummies.columns)


def _group_columns(action_cols: list[str]) -> dict[str, list[str]]:
    return {
        GROUP_JAM: ["Jarak_Luar_Jam"],
        GROUP_IP: ["IP_Eksternal", "IP_Frekuensi_Log"],
        GROUP_GAGAL: ["Gagal"],
        GROUP_BURST: ["Gagal_Sekitar"],
        GROUP_AKSI: action_cols,
        GROUP_FILE: ["File_Langka"],
    }


def _typical_values(X: pd.DataFrame, group_cols: dict[str, list[str]]) -> dict[str, pd.Series]:
    typical = {}
    for group, cols in group_cols.items():
        if group == GROUP_AKSI:
            typical[group] = X[cols].mode().iloc[0]
        else:
            typical[group] = X[cols].median()
    return typical


def _describe_group(group: str, row: pd.Series, ctx: dict) -> str:
    if group == GROUP_JAM:
        return (f"akses pukul {row['Timestamp']:%H:%M} di luar jam operasional "
                f"({ctx['op_start']:02d}:00-{ctx['op_end']:02d}:00)")
    if group == GROUP_IP:
        status = "di luar jaringan tepercaya" if not row["IP_Tepercaya"] else "jarang muncul"
        return f"IP {row['IP_Address']} {status}, hanya {int(row['IP_Count'])} aktivitas dari IP ini di log"
    if group == GROUP_GAGAL:
        return f"status gagal pada aktivitas {row['User_Action']}"
    if group == GROUP_BURST:
        return (f"{int(row['Gagal_Sekitar'])} kegagalan dari IP yang sama dalam "
                f"+/-{ctx['burst_window']} menit")
    if group == GROUP_AKSI:
        return f"aktivitas '{row['User_Action']}' pada kombinasi kondisi yang jarang"
    if group == GROUP_FILE:
        share = 100.0 * row["File_Count"] / max(ctx["n_file_events"], 1)
        return f"file '{row['File_Accessed']}' jarang diakses ({share:.1f}% dari semua akses file)"
    return group


def analyze_logs(
    raw: pd.DataFrame,
    op_start: int = DEFAULT_OP_START,
    op_end: int = DEFAULT_OP_END,
    contamination: float = DEFAULT_CONTAMINATION,
    trusted_networks: str = DEFAULT_TRUSTED_NETWORKS,
    burst_threshold: int = DEFAULT_BURST_THRESHOLD,
    burst_window_min: int = DEFAULT_BURST_WINDOW_MIN,
    random_state: int = RANDOM_STATE,
    source: str = "simulation",
) -> ScanResult:
    if not (0 <= op_start < op_end <= 24):
        raise LogValidationError("Jam operasional tidak valid: mulai harus lebih kecil dari selesai (0-24).")
    if not (0.0 < contamination <= 0.5):
        raise LogValidationError("Sensitivitas (contamination) harus di antara 0 dan 0.5.")
    if burst_threshold < 2:
        raise LogValidationError("Ambang gagal beruntun minimal 2.")

    df, notes = normalise_log_frame(raw)
    if len(df) < 50:
        raise LogValidationError("Minimal 50 baris log diperlukan agar Isolation Forest bermakna.")
    nets = parse_networks(trusted_networks)

    X, extra, action_cols = _build_features(df, op_start, op_end, nets, burst_window_min)
    n_invalid_ip = int((~extra["IP_Valid"]).sum())
    if n_invalid_ip:
        notes.append(f"{n_invalid_ip} baris memiliki IP tidak valid dan diperlakukan sebagai IP tidak biasa.")

    # Isolation Forest
    clf = IsolationForest(n_estimators=200, contamination=contamination, random_state=random_state)
    clf.fit(X)
    pred = clf.predict(X)
    score = -clf.score_samples(X)          # makin besar = makin anomali
    threshold = float(-clf.offset_)
    is_anom = pred == -1

    # indikator berbasis aturan
    out = df.copy()
    out.insert(0, "No", np.arange(1, len(out) + 1))
    out["Jam_Desimal"] = extra["Jam_Desimal"].to_numpy()
    out["Jarak_Luar_Jam"] = extra["Jarak_Luar_Jam"].to_numpy()
    out["IP_Tepercaya"] = extra["IP_Tepercaya"].to_numpy()
    out["IP_Count"] = extra["IP_Count"].to_numpy()
    out["File_Count"] = extra["File_Count"].to_numpy()
    out["Gagal_Sekitar"] = extra["Gagal_Sekitar"].to_numpy()
    out["Flag_Luar_Jam"] = out["Jarak_Luar_Jam"] > 0
    out["Flag_IP_Tidak_Biasa"] = (~extra["IP_Tepercaya"]) | extra["IP_Jarang"]
    out["Flag_Gagal_Beruntun"] = (out["Status"] == "Failed") & (out["Gagal_Sekitar"] >= burst_threshold)
    flag_cols = list(FLAG_COLUMNS)
    out["Jumlah_Indikator"] = out[flag_cols].sum(axis=1).astype(int)
    out["Indikator"] = out[flag_cols].apply(
        lambda r: ", ".join(FLAG_COLUMNS[c] for c in flag_cols if r[c]) or "-", axis=1
    )
    out["Is_Anomaly"] = is_anom
    out["Skor_Anomali"] = np.round(score, 4)

    # Poin prioritas: tiap indikator aturan = 1, ditandai Isolation Forest = 2, dan
    # akses file dari IP di luar jaringan tepercaya = +1 (kasus yang layak ditinjau
    # walau terjadi pada jam kerja).
    external_file_access = (~extra["IP_Tepercaya"]).to_numpy() & (out["File_Accessed"] != "-").to_numpy()
    points = out["Jumlah_Indikator"] + 2 * out["Is_Anomaly"].astype(int) + external_file_access.astype(int)
    out["Prioritas"] = np.select(
        [points >= 4, points >= 2, points == 1], ["Tinggi", "Sedang", "Rendah"], default="Normal"
    )

    # penjelasan (atribusi counterfactual pada baris anomali)
    groups = _group_columns(action_cols)
    typical = _typical_values(X, groups)
    anom_idx = np.flatnonzero(is_anom)
    contrib = pd.DataFrame(np.nan, index=out.index, columns=list(groups))
    reasons = pd.Series("", index=out.index, dtype=object)
    main_reason = pd.Series("", index=out.index, dtype=object)

    if len(anom_idx):
        Xa = X.iloc[anom_idx]
        base = clf.decision_function(Xa)
        raw_contrib = {}
        for group, cols in groups.items():
            Xm = Xa.copy()
            for c in cols:
                Xm[c] = typical[group][c]
            raw_contrib[group] = clf.decision_function(Xm) - base   # >0: fitur ini membuat baris lebih anomali
        rc = pd.DataFrame(raw_contrib, index=out.index[anom_idx])
        pos = rc.clip(lower=0)
        total = pos.sum(axis=1)
        share = pos.div(total.where(total > 0), axis=0)
        contrib.loc[share.index, :] = share.fillna(0.0).to_numpy()

        ctx = {
            "op_start": op_start, "op_end": op_end, "burst_window": burst_window_min,
            "n_file_events": int((df["File_Accessed"] != "-").sum()),
        }
        for i in share.index:
            row = out.loc[i]
            ranked = share.loc[i].sort_values(ascending=False)
            picked = [g for g, v in ranked.items() if v >= 0.15][:3]
            if picked:
                parts = [f"{_describe_group(g, row, ctx)} [{share.loc[i, g]:.0%}]" for g in picked]
                reasons.loc[i] = "; ".join(parts)
                main_reason.loc[i] = picked[0]
            else:
                reasons.loc[i] = "kombinasi nilai fitur yang jarang (tidak ada satu faktor dominan)"
                main_reason.loc[i] = "Kombinasi fitur"
    out["Alasan"] = reasons
    out["Faktor_Utama"] = main_reason

    # ringkasan
    an = out[out["Is_Anomaly"]]
    summary = {
        "total_events": int(len(out)),
        "n_anomalies": int(len(an)),
        "n_high": int((out["Prioritas"] == "Tinggi").sum()),
        "n_off_hours": int(out["Flag_Luar_Jam"].sum()),
        "n_unusual_ip": int(out["Flag_IP_Tidak_Biasa"].sum()),
        "n_failed": int((out["Status"] == "Failed").sum()),
        "n_burst": int(out["Flag_Gagal_Beruntun"].sum()),
        "anomalies_with_off_hours": int(an["Flag_Luar_Jam"].sum()),
        "anomalies_with_unusual_ip": int(an["Flag_IP_Tidak_Biasa"].sum()),
        "anomalies_with_burst": int(an["Flag_Gagal_Beruntun"].sum()),
        "anomalies_without_rule": int((an["Jumlah_Indikator"] == 0).sum()),
        "period_start": out["Timestamp"].min(),
        "period_end": out["Timestamp"].max(),
        "unique_ips": int(out["IP_Address"].nunique()),
    }
    params = {
        "op_start": op_start, "op_end": op_end, "contamination": contamination,
        "trusted_networks": trusted_networks, "burst_threshold": burst_threshold,
        "burst_window_min": burst_window_min, "random_state": random_state, "source": source,
    }
    return ScanResult(out, contrib, threshold, params, summary, X, notes)


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------
def apply_filters(
    df: pd.DataFrame,
    date_range: tuple | None = None,
    hour_range: tuple[int, int] = (0, 23),
    actions: list[str] | None = None,
    statuses: list[str] | None = None,
    anomaly_mode: str = "Semua",
    indicators: list[str] | None = None,
    query: str = "",
) -> pd.DataFrame:
    mask = pd.Series(True, index=df.index)
    if date_range:
        start = pd.Timestamp(date_range[0]).normalize()
        end = (pd.Timestamp(date_range[1]) if len(date_range) > 1 else pd.Timestamp(date_range[0])).normalize()
        mask &= (df["Timestamp"] >= start) & (df["Timestamp"] < end + pd.Timedelta(days=1))
    lo, hi = hour_range
    hours = df["Timestamp"].dt.hour
    mask &= (hours >= lo) & (hours <= hi)
    if actions is not None:
        mask &= df["User_Action"].isin(actions)
    if statuses is not None:
        mask &= df["Status"].isin(statuses)
    if anomaly_mode == "Hanya anomali":
        mask &= df["Is_Anomaly"]
    elif anomaly_mode == "Hanya normal":
        mask &= ~df["Is_Anomaly"]
    if indicators:
        inverse = {v: k for k, v in FLAG_COLUMNS.items()}
        ind_mask = pd.Series(False, index=df.index)
        for label in indicators:
            ind_mask |= df[inverse[label]]
        mask &= ind_mask
    q = (query or "").strip().lower()
    if q:
        hay = (df["IP_Address"] + " " + df["Pengguna"] + " " + df["File_Accessed"]).str.lower()
        mask &= hay.str.contains(q, regex=False)
    return df[mask]


# ---------------------------------------------------------------------------
# Evaluasi (hanya valid untuk data simulasi yang punya kunci jawaban)
# ---------------------------------------------------------------------------
def evaluate_against_simulation(logs: pd.DataFrame) -> dict | None:
    if "Sim_Anomali_Sebenarnya" not in logs.columns:
        return None
    truth = logs["Sim_Anomali_Sebenarnya"].astype(bool)

    def metrics(pred: pd.Series) -> dict:
        tp = int((pred & truth).sum())
        fp = int((pred & ~truth).sum())
        fn = int((~pred & truth).sum())
        return {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else float("nan"),
            "recall": tp / (tp + fn) if tp + fn else float("nan"),
        }

    per_scenario = (
        logs.groupby("Sim_Skenario")
        .agg(jumlah=("Is_Anomaly", "size"), ditandai_if=("Is_Anomaly", "sum"),
             ditandai_aturan=("Jumlah_Indikator", lambda s: int((s >= 2).sum())))
        .reset_index()
    )
    return {
        "isolation_forest": metrics(logs["Is_Anomaly"]),
        "aturan_2_indikator": metrics(logs["Jumlah_Indikator"] >= 2),
        "prioritas_sedang_ke_atas": metrics(logs["Prioritas"].isin(["Tinggi", "Sedang"])),
        "per_skenario": per_scenario,
    }
