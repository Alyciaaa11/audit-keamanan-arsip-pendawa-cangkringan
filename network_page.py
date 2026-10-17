from __future__ import annotations

import hashlib
from datetime import datetime
from io import BytesIO

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from packaging.version import Version

import network_forensics as nf

SOURCE_SIM = "Data simulasi (sintetis)"
SOURCE_UPLOAD = "Unggah log CSV/Excel"

NORMAL_COLOR = "#9b86bd"
ANOMALY_COLOR = "#d6455d"
ROW_COLORS = {"Tinggi": "#fde2e4", "Sedang": "#fff3d6"}
SORT_OPTIONS = ["Terbaru dulu", "Terlama dulu", "Skor anomali tertinggi"]
FONT = dict(family="DM Sans, sans-serif", color="#40334f")

_NEW_WIDTH_API = Version(st.__version__) >= Version("1.50.0")


def _stretch() -> dict:
    return {"width": "stretch"} if _NEW_WIDTH_API else {"use_container_width": True}


def _show_chart(fig: go.Figure) -> None:
    st.plotly_chart(fig, **_stretch())


def _show_table(data, **kwargs) -> None:
    st.dataframe(data, **_stretch(), **kwargs)


# ---------------------------------------------------------------------------
# State widget yang tetap ada saat pengguna berpindah menu
# ---------------------------------------------------------------------------
def _store() -> dict:
    return st.session_state.setdefault("net_ui_state", {})


def _persisted(widget, name, default, sanitize=None, **kwargs):
    key = f"net_w_{name}"
    store = _store()
    if key not in st.session_state:
        st.session_state[key] = store.get(name, default)
    if sanitize is not None:
        current = st.session_state[key]
        fixed = sanitize(current)
        if fixed != current:
            st.session_state[key] = fixed
    value = widget(key=key, **kwargs)
    store[name] = value
    return value


def _clear_filter_state() -> None:
    store = _store()
    for name in [n for n in store if n.startswith("f_")]:
        store.pop(name, None)
    for key in [k for k in st.session_state if str(k).startswith("net_w_f_")]:
        del st.session_state[key]


def _persist_upload() -> None:
    up = st.session_state.get("net_upload_widget")
    if up is not None:
        st.session_state["net_upload_name"] = up.name
        st.session_state["net_upload_bytes"] = up.getvalue()


def _read_upload(name: str, data: bytes) -> pd.DataFrame:
    buf = BytesIO(data)
    if name.lower().endswith((".xlsx", ".xlsm", ".xls")):
        return pd.read_excel(buf)
    try:
        return pd.read_csv(buf, sep=None, engine="python", encoding="utf-8-sig")
    except UnicodeDecodeError:
        return pd.read_csv(BytesIO(data), sep=None, engine="python", encoding="latin-1")


# ---------------------------------------------------------------------------
# Pemindaian
# ---------------------------------------------------------------------------
def _execute_scan(cfg: dict, add_notification) -> bool:
    """Jalankan pemindaian, simpan hasil, dan kirim notifikasi ke Dashboard."""
    try:
        with st.spinner("Memindai log jaringan..."):
            if cfg["source"] == SOURCE_SIM:
                raw = nf.generate_simulated_logs(seed=cfg["seed"], end_date=pd.Timestamp.now().normalize())
                source_key, label = "simulation", "Data simulasi (sintetis)"
            else:
                name = st.session_state.get("net_upload_name")
                data = st.session_state.get("net_upload_bytes")
                if not data:
                    raise nf.LogValidationError("Belum ada file log yang diunggah.")
                raw = _read_upload(name, data)
                source_key, label = "upload", f"Log unggahan: {name}"
            result = nf.analyze_logs(
                raw,
                op_start=cfg["op_start"], op_end=cfg["op_end"],
                contamination=cfg["contamination"], trusted_networks=cfg["trusted"],
                burst_threshold=cfg["burst"], random_state=cfg["seed"], source=source_key,
            )
    except nf.LogValidationError as exc:
        st.error(f"Pemindaian tidak dapat dijalankan: {exc}")
        return False
    except Exception as exc:  # noqa: BLE001, jangan sampai seluruh aplikasi berhenti
        st.error(f"Terjadi kesalahan saat memproses log ({type(exc).__name__}): {exc}")
        return False

    count = st.session_state.get("network_scan_count", 0) + 1
    st.session_state.update(
        network_scan=result, network_scan_count=count, network_scan_label=label,
        network_scan_source=source_key, network_scan_cfg=cfg,
        network_scan_time=datetime.now().astimezone(),
    )
    _clear_filter_state()

    s = result.summary
    st.session_state["dashboard_network_anomalies"] = s["n_anomalies"]
    st.session_state["dashboard_network_source"] = source_key
    origin = "data simulasi" if source_key == "simulation" else "log unggahan"
    suffix = ", bukan log nyata" if source_key == "simulation" else ""
    add_notification(
        f"Pemindaian jaringan nomor {count} ({origin}{suffix}): {s['n_anomalies']} indikasi anomali "
        f"dari {s['total_events']:,} aktivitas, {s['n_high']} berprioritas tinggi.",
        "warning" if s["n_anomalies"] > 0 else "success",
    )
    return True


def _current_cfg() -> dict:
    op = st.session_state.get("net_w_s_op", (nf.DEFAULT_OP_START, nf.DEFAULT_OP_END))
    return {
        "source": st.session_state.get("net_w_s_source", SOURCE_SIM),
        "op_start": int(op[0]), "op_end": int(op[1]),
        "contamination": st.session_state.get("net_w_s_cont", int(nf.DEFAULT_CONTAMINATION * 100)) / 100,
        "trusted": st.session_state.get("net_w_s_trusted", nf.DEFAULT_TRUSTED_NETWORKS),
        "burst": int(st.session_state.get("net_w_s_burst", nf.DEFAULT_BURST_THRESHOLD)),
        "seed": int(st.session_state.get("net_w_s_seed", nf.RANDOM_STATE)),
    }


# ---------------------------------------------------------------------------
# Bagian-bagian halaman
# ---------------------------------------------------------------------------
def _banner(source_key: str, label: str) -> None:
    if source_key == "simulation":
        st.warning(
            "**MODE SIMULASI.** Log di tab ini **sintetis** (dibangkitkan oleh program), bukan lalu lintas "
            "jaringan CV. Pendawa Kencana Multi Farm. Hasil hanya memperagakan cara kerja metode dan "
            "**belum membuktikan** sistem dapat mendeteksi serangan nyata."
        )
    else:
        st.info(
            f"📄 **{label}.** Hasil adalah indikasi statistik untuk ditinjau manual oleh pemeriksa, "
            "bukan bukti serangan."
        )


def _settings_panel(add_notification) -> None:
    with st.expander("⚙ Sumber data & pengaturan pemindaian", expanded=False):
        source = _persisted(
            st.radio, "s_source", SOURCE_SIM,
            sanitize=lambda v: v if v in (SOURCE_SIM, SOURCE_UPLOAD) else SOURCE_SIM,
            label="Sumber data log", options=[SOURCE_SIM, SOURCE_UPLOAD], horizontal=True,
        )
        if source == SOURCE_UPLOAD:
            st.file_uploader(
                "Pilih file log (CSV atau Excel)", type=["csv", "xlsx", "xls"],
                key="net_upload_widget", on_change=_persist_upload,
            )
            if st.session_state.get("net_upload_name"):
                st.caption(f"File tersimpan untuk sesi ini: {st.session_state['net_upload_name']}")
            st.caption(
                "Kolom wajib: Timestamp, IP_Address, User_Action, Status (Success/Failed). "
                "Opsional: Pengguna, File_Accessed. Maksimal "
                f"{nf.MAX_UPLOAD_ROWS:,} baris."
            )
        else:
            st.caption("Log sintetis dibangkitkan ulang dengan seed yang sama, jadi hasilnya dapat diulang.")

        c1, c2 = st.columns(2)
        with c1:
            _persisted(
                st.slider, "s_op", (nf.DEFAULT_OP_START, nf.DEFAULT_OP_END),
                label="Jam operasional", min_value=0, max_value=24, step=1,
                help="Aktivitas di luar rentang ini dihitung sebagai akses di luar jam operasional.",
            )
        with c2:
            _persisted(
                st.slider, "s_cont", int(nf.DEFAULT_CONTAMINATION * 100),
                label="Sensitivitas Isolation Forest (% aktivitas ditandai)", min_value=1, max_value=10, step=1,
                help="Perkiraan persentase aktivitas yang dianggap paling tidak biasa. Makin besar, makin banyak yang ditandai.",
            )
        _persisted(
            st.text_input, "s_trusted", nf.DEFAULT_TRUSTED_NETWORKS,
            label="Jaringan tepercaya (CIDR, pisahkan dengan koma)",
            help="IP di luar daftar ini dianggap tidak biasa. Persempit ke subnet kantor untuk pemeriksaan lebih ketat.",
        )
        c3, c4 = st.columns(2)
        with c3:
            _persisted(
                st.number_input, "s_burst", nf.DEFAULT_BURST_THRESHOLD,
                label="Ambang gagal beruntun (kali dalam ±30 menit dari IP yang sama)",
                min_value=2, max_value=20, step=1,
            )
        with c4:
            _persisted(
                st.number_input, "s_seed", nf.RANDOM_STATE,
                label="Seed (simulasi & model)", min_value=0, max_value=10_000, step=1,
            )

        cfg = _current_cfg()
        if st.button("Jalankan pemindaian", type="primary", key="net_run_scan"):
            _execute_scan(cfg, add_notification)
        last = st.session_state.get("network_scan_cfg")
        if last is not None and last != cfg:
            st.caption("Pengaturan sudah diubah. Klik **Jalankan pemindaian** untuk menerapkannya.")


def _kpis(result: nf.ScanResult) -> None:
    s = result.summary
    cols = st.columns(5)
    cols[0].metric("Total aktivitas", f"{s['total_events']:,}", help="Seluruh baris log yang dipindai.")
    cols[1].metric("Anomali (IF)", f"{s['n_anomalies']:,}",
                   help="IF = Isolation Forest. Aktivitas yang paling jarang/berbeda menurut model. Ini indikasi, bukan bukti serangan.")
    cols[2].metric("Luar jam operasional", f"{s['n_off_hours']:,}",
                   help=f"Aktivitas di luar {result.params['op_start']:02d}:00-{result.params['op_end']:02d}:00.")
    cols[3].metric("IP tidak biasa", f"{s['n_unusual_ip']:,}",
                   help="IP di luar jaringan tepercaya atau sangat jarang muncul di log.")
    cols[4].metric("Gagal beruntun", f"{s['n_burst']:,}",
                   help=f"Kegagalan ≥{result.params['burst_threshold']} kali dari IP yang sama dalam ±{result.params['burst_window_min']} menit.")
    t = st.session_state.get("network_scan_time")
    st.caption(
        f"Periode log: {s['period_start']:%d %b %Y} - {s['period_end']:%d %b %Y} · "
        f"Sumber: {st.session_state.get('network_scan_label')} · "
        f"Pemindaian nomor {st.session_state.get('network_scan_count')}"
        + (f" pukul {t:%H:%M:%S}" if t else "")
        + f" · Ambang skor anomali: {result.threshold:.3f}"
    )
    for note in result.notes:
        st.caption(f"ℹ️ {note}")


def _filters(result: nf.ScanResult) -> pd.DataFrame:
    logs = result.logs
    dmin, dmax = logs["Timestamp"].min().date(), logs["Timestamp"].max().date()
    actions = sorted(logs["User_Action"].unique())
    statuses = ["Success", "Failed"]
    status_labels = {"Success": "Berhasil", "Failed": "Gagal"}

    def clamp_dates(v):
        try:
            vals = tuple(v) if isinstance(v, (list, tuple)) else (v,)
            fixed = tuple(min(max(d, dmin), dmax) for d in vals)
            return fixed if fixed else (dmin, dmax)
        except TypeError:
            return (dmin, dmax)

    def keep_options(options):
        def _fix(v):
            kept = [x for x in v if x in options]
            return kept if (kept or not v) else list(options)
        return _fix

    with st.container(border=True):
        st.markdown("**Filter hasil**")
        r1 = st.columns([1.3, 1.2, 1.3, 1])
        with r1[0]:
            dates = _persisted(st.date_input, "f_date", (dmin, dmax), sanitize=clamp_dates,
                               label="Rentang tanggal", min_value=dmin, max_value=dmax)
        with r1[1]:
            hours = _persisted(st.slider, "f_hour", (0, 23), label="Jam akses (0-23)", min_value=0, max_value=23)
        with r1[2]:
            acts = _persisted(st.multiselect, "f_actions", actions, sanitize=keep_options(actions),
                              label="Jenis aktivitas", options=actions)
        with r1[3]:
            stats = _persisted(st.multiselect, "f_status", statuses, sanitize=keep_options(statuses),
                               label="Status login/aktivitas", options=statuses,
                               format_func=lambda s: status_labels[s])
        r2 = st.columns([1.3, 1.3, 1.2, 0.8])
        with r2[0]:
            mode = _persisted(st.radio, "f_mode", "Semua",
                              sanitize=lambda v: v if v in nf.ANOMALY_MODES else "Semua",
                              label="Status anomali", options=list(nf.ANOMALY_MODES), horizontal=True)
        with r2[1]:
            inds = _persisted(st.multiselect, "f_ind", [],
                              sanitize=keep_options(list(nf.FLAG_COLUMNS.values())),
                              label="Hanya yang memiliki indikator", options=list(nf.FLAG_COLUMNS.values()))
        with r2[2]:
            query = _persisted(st.text_input, "f_query", "", label="Cari IP / pengguna / file")
        with r2[3]:
            st.markdown("<div style='height:1.7rem'></div>", unsafe_allow_html=True)
            st.button("Reset filter", key="net_reset_filters", on_click=_clear_filter_state)

    filtered = nf.apply_filters(
        logs, date_range=tuple(dates) if dates else None, hour_range=tuple(hours),
        actions=list(acts), statuses=list(stats), anomaly_mode=mode,
        indicators=list(inds), query=query,
    )
    n_an = int(filtered["Is_Anomaly"].sum())
    st.caption(f"Menampilkan **{len(filtered):,}** dari {len(logs):,} aktivitas · {n_an:,} di antaranya anomali.")
    return filtered


def _style_layout(fig: go.Figure, height: int = 380) -> go.Figure:
    fig.update_layout(
        template="plotly_white", height=height, font=FONT,
        paper_bgcolor="rgba(255,255,255,0)", plot_bgcolor="rgba(255,255,255,0.72)",
        margin=dict(l=15, r=15, t=30, b=15), legend_title_text="",
    )
    return fig


def _tab_visual(result: nf.ScanResult, f: pd.DataFrame) -> None:
    p = result.params
    plot = f.assign(
        Kategori=np.where(f["Is_Anomaly"], "Anomali", "Normal"),
        Hasil=np.where(f["Status"] == "Failed", "Gagal", "Berhasil"),
    )
    st.markdown("##### Waktu akses: titik merah adalah anomali, area merah muda adalah luar jam operasional")
    fig = px.scatter(
        plot, x="Timestamp", y="Jam_Desimal", color="Kategori", symbol="Hasil",
        color_discrete_map={"Normal": NORMAL_COLOR, "Anomali": ANOMALY_COLOR},
        symbol_map={"Berhasil": "circle", "Gagal": "x"},
        category_orders={"Kategori": ["Normal", "Anomali"]},
        hover_data={"IP_Address": True, "Pengguna": True, "User_Action": True, "Indikator": True,
                    "Skor_Anomali": ":.3f", "Jam_Desimal": False, "Kategori": False, "Hasil": False},
        labels={"Jam_Desimal": "Jam akses", "Timestamp": "Waktu"},
    )
    for trace in fig.data:
        is_anom = trace.name.startswith("Anomali")
        trace.update(marker=dict(size=11 if is_anom else 6, opacity=0.95 if is_anom else 0.45,
                                 line=dict(width=0)))
    if p["op_start"] > 0:
        fig.add_hrect(y0=0, y1=p["op_start"], fillcolor=ANOMALY_COLOR, opacity=0.07, line_width=0)
    if p["op_end"] < 24:
        fig.add_hrect(y0=p["op_end"], y1=24, fillcolor=ANOMALY_COLOR, opacity=0.07, line_width=0)
    fig.update_yaxes(range=[0, 24], dtick=4, title="Jam akses", gridcolor="#eee7f8")
    fig.update_xaxes(showgrid=False, title="")
    _show_chart(_style_layout(fig, 400))

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("##### Aktivitas per jam")
        per_hour = (
            plot.assign(Jam=plot["Timestamp"].dt.hour)
            .groupby(["Jam", "Kategori"]).size().unstack(fill_value=0)
            .reindex(range(24), fill_value=0)
        )
        for col in ("Normal", "Anomali"):
            if col not in per_hour:
                per_hour[col] = 0
        bar = go.Figure()
        bar.add_bar(x=per_hour.index, y=per_hour["Normal"], name="Normal", marker_color=NORMAL_COLOR)
        bar.add_bar(x=per_hour.index, y=per_hour["Anomali"], name="Anomali", marker_color=ANOMALY_COLOR)
        bar.update_layout(barmode="stack")
        if p["op_start"] > 0:
            bar.add_vrect(x0=-0.5, x1=p["op_start"] - 0.5, fillcolor=ANOMALY_COLOR, opacity=0.07, line_width=0)
        if p["op_end"] < 24:
            bar.add_vrect(x0=p["op_end"] - 0.5, x1=23.5, fillcolor=ANOMALY_COLOR, opacity=0.07, line_width=0)
        bar.update_xaxes(title="Jam (0-23)", dtick=2)
        bar.update_yaxes(title="Jumlah aktivitas", gridcolor="#eee7f8")
        _show_chart(_style_layout(bar, 330))
    with c2:
        st.markdown("##### IP dengan anomali terbanyak")
        an = f[f["Is_Anomaly"]]
        if an.empty:
            st.info("Tidak ada anomali pada data yang sedang ditampilkan.")
        else:
            top = an.groupby("IP_Address").size().nlargest(10).sort_values()
            ipfig = go.Figure(go.Bar(x=top.values, y=top.index, orientation="h",
                                     marker_color=ANOMALY_COLOR, text=top.values, textposition="outside"))
            ipfig.update_xaxes(title="Jumlah anomali", gridcolor="#eee7f8")
            _show_chart(_style_layout(ipfig, 330))


def _reason_bullets(text: str) -> list[str]:
    return [part.strip() for part in text.split(";") if part.strip()]


def _tab_explain(result: nf.ScanResult, f: pd.DataFrame) -> None:
    st.markdown(
        "Isolation Forest memberi **skor anomali** pada tiap aktivitas: makin mudah sebuah aktivitas "
        "'dipisahkan' dari mayoritas, makin tinggi skornya. Aktivitas dengan skor di atas ambang "
        f"(**{result.threshold:.3f}**) ditandai anomali. Karena model hanya menghitung seberapa *jarang* "
        "suatu pola, penjelasan di bawah memperlihatkan **fitur mana yang paling membuat** aktivitas itu tampak jarang."
    )
    an = f[f["Is_Anomaly"]].sort_values("Skor_Anomali", ascending=False)
    if an.empty:
        st.info("Tidak ada anomali pada data yang sedang ditampilkan. Longgarkan filter atau naikkan sensitivitas.")
        return

    contrib = result.contributions.loc[an.index]
    c1, c2 = st.columns([1.1, 1])
    with c1:
        st.markdown("##### Faktor yang paling sering menjadi alasan")
        mean_share = (contrib.mean() * 100).sort_values()
        top1 = an["Faktor_Utama"].value_counts()
        fig = go.Figure(go.Bar(
            x=mean_share.values, y=mean_share.index, orientation="h", marker_color=NORMAL_COLOR,
            text=[f"{v:.0f}%" for v in mean_share.values], textposition="outside",
        ))
        fig.update_xaxes(title="Rata-rata kontribusi relatif pada anomali (%)", gridcolor="#eee7f8", range=[0, max(100, mean_share.max() + 10)])
        _show_chart(_style_layout(fig, 320))
    with c2:
        st.markdown("##### Anomali menurut indikator aturan")
        s = result.summary
        tbl = pd.DataFrame({
            "Indikator": ["Luar jam operasional", "IP tidak biasa", "Gagal beruntun", "Tanpa indikator aturan"],
            "Jumlah anomali": [
                int(an["Flag_Luar_Jam"].sum()), int(an["Flag_IP_Tidak_Biasa"].sum()),
                int(an["Flag_Gagal_Beruntun"].sum()), int((an["Jumlah_Indikator"] == 0).sum()),
            ],
        })
        _show_table(tbl, hide_index=True)
        st.caption("Satu anomali bisa memiliki lebih dari satu indikator. "
                   f"Faktor utama terbanyak: **{top1.index[0]}** ({int(top1.iloc[0])} anomali).")

    st.markdown("##### Anomali dengan skor tertinggi")
    show = pd.DataFrame({
        "Waktu": an["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S"), "IP": an["IP_Address"],
        "Aktivitas": an["User_Action"], "Status": an["Status"].map({"Success": "Berhasil", "Failed": "Gagal"}),
        "Skor": an["Skor_Anomali"], "Prioritas": an["Prioritas"], "Alasan": an["Alasan"],
    }).head(15)
    _show_table(show, hide_index=True,
                column_config={"Alasan": st.column_config.TextColumn("Alasan (kontribusi relatif)", width="large"),
                               "Skor": st.column_config.NumberColumn(format="%.3f")})

    st.markdown("##### Periksa satu anomali")
    options = list(an.index[:200])
    label = lambda i: (f"#{int(an.loc[i, 'No'])} · {an.loc[i, 'Timestamp']:%d %b %H:%M} · "
                       f"{an.loc[i, 'IP_Address']} · {an.loc[i, 'User_Action']} · skor {an.loc[i, 'Skor_Anomali']:.3f}")
    chosen = _persisted(
        st.selectbox, "f_inspect", options[0], sanitize=lambda v: v if v in options else options[0],
        label="Pilih anomali", options=options, format_func=label,
    )
    row = an.loc[chosen]
    d1, d2 = st.columns([1.2, 1])
    with d1:
        m1, m2, m3 = st.columns(3)
        m1.metric("Skor anomali", f"{row['Skor_Anomali']:.3f}", help="Makin tinggi makin tidak biasa.")
        m2.metric("Ambang", f"{result.threshold:.3f}")
        m3.metric("Prioritas", row["Prioritas"])
        st.markdown("**Mengapa ditandai:**")
        for bullet in _reason_bullets(row["Alasan"]):
            st.markdown(f"- {bullet}")
        st.caption(f"Indikator aturan: {row['Indikator']}")
        facts = pd.DataFrame({
            "Rincian": ["Waktu", "Pengguna", "IP", "Aktivitas", "File", "Status",
                        "Aktivitas dari IP ini di log", "Kegagalan IP ini (±30 mnt)"],
            "Nilai": [f"{row['Timestamp']:%Y-%m-%d %H:%M:%S}", row["Pengguna"], row["IP_Address"], row["User_Action"],
                      row["File_Accessed"], "Berhasil" if row["Status"] == "Success" else "Gagal",
                      str(int(row["IP_Count"])), str(int(row["Gagal_Sekitar"]))],
        })
        _show_table(facts, hide_index=True)
    with d2:
        shares = (result.contributions.loc[chosen] * 100).sort_values()
        fig = go.Figure(go.Bar(x=shares.values, y=shares.index, orientation="h", marker_color=ANOMALY_COLOR,
                               text=[f"{v:.0f}%" for v in shares.values], textposition="outside"))
        fig.update_xaxes(title="Kontribusi relatif (%)", range=[0, 110], gridcolor="#eee7f8")
        _show_chart(_style_layout(fig, 300))
        st.caption("Kontribusi dihitung dengan mengganti satu kelompok fitur ke nilai tipikal (median; "
                   "modus untuk jenis aktivitas) lalu melihat seberapa turun skor anomalinya.")


def _audit_frame(f: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "No": f["No"],
        "Waktu": f["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S"),
        "IP": f["IP_Address"],
        "Pengguna": f["Pengguna"],
        "Aktivitas": f["User_Action"],
        "File": f["File_Accessed"],
        "Status": np.where(f["Status"] == "Failed", "❌ Gagal", "✅ Berhasil"),
        "Anomali": np.where(f["Is_Anomaly"], "🚨 Anomali", "Normal"),
        "Prioritas": f["Prioritas"],
        "Skor": f["Skor_Anomali"],
        "Indikator": f["Indikator"],
        "Alasan": f["Alasan"].replace("", "-"),
    })


def _row_style(row: pd.Series) -> list[str]:
    color = ROW_COLORS.get(row["Prioritas"], "")
    return [f"background-color: {color}" if color else ""] * len(row)


def _tab_audit(result: nf.ScanResult, f: pd.DataFrame) -> None:
    source_key = st.session_state.get("network_scan_source", "simulation")
    order = _persisted(st.radio, "f_sort", "Terbaru dulu", sanitize=lambda v: v if v in SORT_OPTIONS else "Terbaru dulu",
                      label="Urutkan", options=SORT_OPTIONS,
                     horizontal=True)
    if order == "Terbaru dulu":
        g = f.sort_values("Timestamp", ascending=False)
    elif order == "Terlama dulu":
        g = f.sort_values("Timestamp")
    else:
        g = f.sort_values(["Skor_Anomali", "Timestamp"], ascending=[False, False])
    table = _audit_frame(g)
    if table.empty:
        st.info("Tidak ada aktivitas yang cocok dengan filter.")
        return
    if len(table) <= 5000:
        shown = table.style.apply(_row_style, axis=1).format({"Skor": "{:.3f}"})
    else:
        shown = table
        st.caption("Pewarnaan baris dinonaktifkan karena data lebih dari 5.000 baris. Gunakan filter untuk mempersempit.")
    _show_table(shown, hide_index=True, height=460,
                column_config={"Alasan": st.column_config.TextColumn(width="large"),
                               "Indikator": st.column_config.TextColumn(width="medium")})
    st.caption("Baris merah muda: prioritas tinggi. Baris kuning: prioritas sedang. "
               "Prioritas menggabungkan penanda Isolation Forest dan indikator aturan.")

    export = table.drop(columns=["Status", "Anomali"]).assign(
        Status=g["Status"].to_numpy(), Anomali=np.where(g["Is_Anomaly"], "Ya", "Tidak"),
        Sumber_Data="SIMULASI (bukan log nyata)" if source_key == "simulation" else "Log unggahan",
    )
    csv_bytes = export.to_csv(index=False).encode("utf-8-sig")
    digest = hashlib.sha256(csv_bytes).hexdigest()
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    prefix = "audit_trail_simulasi" if source_key == "simulation" else "audit_trail"
    st.download_button("Unduh audit trail terfilter (CSV)", csv_bytes, file_name=f"{prefix}_{stamp}.csv",
                       mime="text/csv", key="net_download_csv")
    st.caption(f"SHA-256 file ekspor ini: `{digest}`. Simpan untuk membuktikan file tidak berubah setelah diunduh.")


def _tab_method(result: nf.ScanResult) -> None:
    p, s = result.params, result.summary
    st.markdown(
        f"""
**Cara kerja pemindaian**

1. **Fitur.** Tiap aktivitas diubah menjadi angka: jarak ke jam operasional ({p['op_start']:02d}:00-{p['op_end']:02d}:00),
   apakah IP berada di luar jaringan tepercaya, seberapa sering IP itu muncul, status gagal, jumlah kegagalan dari IP yang
   sama dalam ±{p['burst_window_min']} menit, jenis aktivitas, dan seberapa jarang file yang diakses.
2. **Isolation Forest** (200 pohon, sensitivitas {p['contamination']:.0%}) memisahkan aktivitas yang jarang. Skor di atas
   **{result.threshold:.3f}** ditandai anomali.
3. **Indikator aturan** (transparan, tanpa machine learning): *luar jam operasional*, *IP tidak biasa* (di luar jaringan
   tepercaya atau muncul ≤2 kali di log yang cukup besar), dan *gagal beruntun* (≥{p['burst_threshold']} kegagalan dari IP yang sama).
4. **Prioritas** = poin dari tiap indikator (1), penanda Isolation Forest (2), dan akses file dari IP di luar jaringan
   tepercaya (1). Poin ≥4 Tinggi, 2-3 Sedang, 1 Rendah.

**Batasan yang perlu dipahami**

- Anomali berarti *jarang*, bukan *berbahaya*. Lembur sah atau kerja dari luar kantor bisa ikut ditandai.
- Model tidak mengenal kebiasaan tiap pengguna dan tidak memakai geolokasi IP.
- Persentase sensitivitas adalah asumsi, bukan hasil pengukuran.
- Pada log nyata tidak ada kunci jawaban, jadi akurasi tidak bisa diukur seperti pada simulasi.
"""
    )
    ev = nf.evaluate_against_simulation(result.logs)
    if ev is not None:
        st.markdown("##### Evaluasi pada data simulasi")
        st.warning(
            "Angka ini hanya bisa dihitung karena kita yang menyuntikkan skenario anomali ke data sintetis. "
            "Angka ini **tidak** menjamin kinerja pada log jaringan sungguhan."
        )
        names = {"isolation_forest": "Isolation Forest saja",
                 "aturan_2_indikator": "Aturan (≥2 indikator)",
                 "prioritas_sedang_ke_atas": "Prioritas Sedang ke atas (IF + aturan)"}
        rows = []
        for key, name in names.items():
            m = ev[key]
            rows.append({"Metode": name, "Benar ditandai": m["tp"], "Salah tandai": m["fp"], "Terlewat": m["fn"],
                         "Presisi": f"{m['precision']:.0%}", "Recall": f"{m['recall']:.0%}"})
        _show_table(pd.DataFrame(rows), hide_index=True)
        sk = ev["per_skenario"].rename(columns={
            "Sim_Skenario": "Skenario simulasi", "jumlah": "Jumlah aktivitas",
            "ditandai_if": "Ditandai Isolation Forest", "ditandai_aturan": "Ditandai aturan (≥2 indikator)"})
        _show_table(sk, hide_index=True)
        st.caption("Perhatikan skenario 'unduh arsip oleh IP asing' pada jam kerja: Isolation Forest bisa melewatkannya "
                   "karena mirip aktivitas 'kerja dari luar kantor' yang sah. Itulah alasan indikator aturan dan prioritas dipakai bersama.")
    else:
        st.info("Evaluasi akurasi tidak tersedia untuk log unggahan karena tidak ada label kebenaran.")

    st.markdown("##### Menghubungkan ke log nyata")
    st.markdown(
        "Gunakan sumber **Unggah log CSV/Excel**, atau ambil log dari database lalu berikan sebagai tabel dengan kolom "
        "`Timestamp, IP_Address, User_Action, Status` (opsional `Pengguna, File_Accessed`). Setelah memakai log "
        "nyata, tampilan 'MODE SIMULASI' otomatis berganti dan hasil tetap diperlakukan sebagai indikasi untuk ditinjau."
    )


# ---------------------------------------------------------------------------
# Titik masuk
# ---------------------------------------------------------------------------
def render_network_page(add_notification) -> None:
    st.header("Network Log Forensics & Audit")
    st.write(
        "Prototype ini menerapkan **Isolation Forest** dan indikator aturan pada log akses untuk menandai "
        "aktivitas yang layak diperiksa: akses di luar jam operasional, IP tidak biasa, dan kegagalan login beruntun."
    )

    if "network_scan" not in st.session_state:
        _execute_scan(_current_cfg(), add_notification)
    _settings_panel(add_notification)

    result = st.session_state.get("network_scan")
    if result is None:
        st.info("Belum ada hasil pemindaian. Buka pengaturan di atas lalu klik **Jalankan pemindaian**.")
        return

    _banner(st.session_state.get("network_scan_source", "simulation"), st.session_state.get("network_scan_label", ""))
    _kpis(result)
    filtered = _filters(result)

    tab_vis, tab_exp, tab_audit, tab_method = st.tabs(
        ["Visualisasi", "Penjelasan anomali", "Audit trail", "Metode & evaluasi"]
    )
    with tab_vis:
        if filtered.empty:
            st.info("Tidak ada aktivitas yang cocok dengan filter. Klik **Reset filter** untuk menampilkan semuanya.")
        else:
            _tab_visual(result, filtered)
    with tab_exp:
        _tab_explain(result, filtered)
    with tab_audit:
        _tab_audit(result, filtered)
    with tab_method:
        _tab_method(result)
