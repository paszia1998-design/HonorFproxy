#!/usr/bin/env python3
"""
Honor Firmware Proxy + Finder  v1.2.0
=======================================
All-in-one MITM proxy + firmware finder for Honor devices.
Supports English and Hungarian. Default language: English.

Build to EXE:
    pip install cryptography pyinstaller
    pyinstaller --onefile --noconsole --name "HonorFProxy" honor_proxy_app.py

Python 3.10+  |  Requires: cryptography
"""

import datetime, gzip, io, ipaddress, json, logging, os, queue, re, select
import socket, ssl, subprocess, sys, tempfile, threading
import tkinter as tk, urllib.request, xml.etree.ElementTree as ET, zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib    import Path
from tkinter    import filedialog, messagebox, scrolledtext, ttk

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ── Constants ─────────────────────────────────────────────────────────────────

APP_VERSION = "1.5.0"

PROXY_HOST  = "127.0.0.1"
PROXY_PORT  = 8080
SOCKS5_PORT = 8081
BUFFER      = 8192

CERT_DIR    = Path(os.environ.get("APPDATA", ".")) / "HonorFProxy"
CA_KEY_FILE = CERT_DIR / "ca.key"
CA_CRT_FILE = CERT_DIR / "ca.crt"
LOG_FILE    = CERT_DIR / "honor_traffic.log"
STATE_FILE  = CERT_DIR / "state.json"

HONOR_HOSTS = [
    "update.hihonorcdn.com",
    "update.platform.hihonorcloud.com",
    "query.hihonorcloud.com",
    "grs.hihonorcloud.com",
    "grs.hihonorcloud.cn",
    "grs.hihonorcloud.asia",
]

CDN_BASE    = "http://update.hihonorcdn.com"
# Valódi CDN struktúra (Fiddlerrel elfogva):
# https://update.hihonorcdn.com/TDS/data/bl/files/v753724/f1/full/filelist.xml
CDN_PATTERN = re.compile(
    r"/TDS/data/bl/files/v(\d+)/f1/full/filelist\.xml"
)
# Régi struktúra (fallback, egyes régiókban még aktív lehet)
CDN_PATTERN_OLD = re.compile(
    r"/TDS/data/files/p1/s15/(G\d+)/(g\d+)/v(\d+)/f1/full/filelist\.xml"
)
UA = "HonorSuite/9.0 (Windows NT 10.0; Win64; x64)"

CERT_DIR.mkdir(parents=True, exist_ok=True)

# Theme colours
BG, BG2, BG3   = "#1e1e2e", "#313244", "#181825"
FG, FG_DIM     = "#cdd6f4", "#6c7086"
BLUE, GREEN     = "#89b4fa", "#a6e3a1"
YELLOW, RED     = "#f9e2af", "#f38ba8"
FONT, MONO      = ("Segoe UI", 9), ("Consolas", 9)

# ── Translations ──────────────────────────────────────────────────────────────

STRINGS: dict[str, dict[str, str]] = {
    # ── App ──────────────────────────────────────────────────────────────────
    "app_title":         {"EN": "Honor Firmware Proxy",          "HU": "Honor Firmware Proxy"},
    "status_stopped":    {"EN": "Stopped",                       "HU": "Leállítva"},
    "lang_label":        {"EN": "Language:",                     "HU": "Nyelv:"},

    # ── Tabs ─────────────────────────────────────────────────────────────────
    "tab_proxy":         {"EN": "  🏠 Proxy  ",                  "HU": "  🏠 Proxy  "},
    "tab_finder":        {"EN": "  🔍 Firmware Finder  ",        "HU": "  🔍 Firmware Finder  "},
    "tab_cert":          {"EN": "  🔐 Certificate  ",            "HU": "  🔐 Tanúsítvány  "},
    "tab_about":         {"EN": "  ℹ️ About  ",                  "HU": "  ℹ️ Info  "},

    # ── Proxy tab ─────────────────────────────────────────────────────────────
    "card_phase":        {"EN": "Phase",                         "HU": "Fázis"},
    "card_target":       {"EN": "Target version",                "HU": "Cél verzió"},
    "card_cdn":          {"EN": "CDN URL",                       "HU": "CDN URL"},
    "cdn_unknown":       {"EN": "Unknown – connect your phone",  "HU": "Ismeretlen – csatlakoztasd a telefont"},
    "btn_start_proxy":   {"EN": "▶  Start Proxy",               "HU": "▶  Proxy indítása"},
    "btn_stop_proxy":    {"EN": "⏹  Stop Proxy",                "HU": "⏹  Proxy leállítása"},
    "proxy_hint":        {"EN": f"→  Set Windows proxy: 127.0.0.1 : {PROXY_PORT}  |  SOCKS5: 127.0.0.1 : {SOCKS5_PORT}",
                          "HU": f"→  Windows proxy: 127.0.0.1 : {PROXY_PORT}  |  SOCKS5: 127.0.0.1 : {SOCKS5_PORT}"},
    "log_label":         {"EN": "Traffic log:",                  "HU": "Forgalom napló:"},
    "btn_clear_log":     {"EN": "Clear log",                     "HU": "Log törlése"},
    "phase1_lbl":        {"EN": "1 – Discovery (CDN search)",    "HU": "1 – Felfedező (CDN keresés)"},
    "phase2_lbl":        {"EN": "2 – Proxy mode",                "HU": "2 – Proxy mód"},
    "no_target":         {"EN": "–",                             "HU": "–"},
    "status_running":    {"EN": "Running  →  127.0.0.1:{port}",  "HU": "Fut  →  127.0.0.1:{port}"},
    "status_target":     {"EN": "  │  Target: {ver}",            "HU": "  │  Cél: {ver}"},
    "status_phase1":     {"EN": "  │  Phase 1 – CDN discovery",  "HU": "  │  1. fázis – CDN keresés"},
    "log_connect_phone": {"EN": "Connect your phone in HonorSuite and search for updates!",
                          "HU": "Csatlakoztasd a telefont HonorSuite-ban → keress frissítést!"},

    # ── Proxy errors ──────────────────────────────────────────────────────────
    "err_no_crypto":     {"EN": "Missing package!\n\npip install cryptography",
                          "HU": "Hiányzó csomag!\n\npip install cryptography"},
    "err_ca_failed":     {"EN": "CA generation failed!",         "HU": "CA generálás sikertelen!"},
    "err_proxy_start":   {"EN": "Proxy failed to start.\nPort {port} already in use?",
                          "HU": "Proxy nem indult el.\nA {port} port foglalt?"},

    # ── Firmware Finder tab ───────────────────────────────────────────────────
    "finder_title":      {"EN": "Search for a specific firmware version:",
                          "HU": "Konkrét firmware verzió keresése:"},
    "fw_ver_label":      {"EN": "Firmware version:",             "HU": "Firmware verzió:"},
    "fw_ver_hint":       {"EN": "e.g. 10.0.0.120",               "HU": "pl. 10.0.0.120"},
    "model_label":       {"EN": "Model code:",                   "HU": "Modellkód:"},
    "model_hint":        {"EN": "e.g. ELP-N39",                  "HU": "pl. ELP-N39"},
    "region_label":      {"EN": "Region code:",                  "HU": "Régiókód:"},
    "region_hint":       {"EN": "e.g. C431  (just the code, not the full C431E1R3P1)",
                          "HU": "pl. C431  (csak ez kell, nem kell az egész C431E1R3P1)"},
    "pkg_type_label":    {"EN": "Package type:",                 "HU": "Csomag típus:"},
    "suffix_label":      {"EN": "Build suffix:",                 "HU": "Build suffix:"},
    "suffix_hint":       {"EN": "e.g. R2  or  E4R2P1",          "HU": "pl. R2  vagy  E4R2P1"},
    "adv_toggle":        {"EN": "Advanced: custom ID range (optional)",
                          "HU": "Haladó: egyéni ID tartomány (opcionális)"},
    "adv_from":          {"EN": "Start ID:",                     "HU": "Kezdő ID:"},
    "adv_to":            {"EN": "End ID:",                       "HU": "Záró ID:"},
    "adv_step":          {"EN": "Step:",                         "HU": "Lépés:"},
    "adv_hint":          {"EN": "If left empty, the app searches around the ID captured in Phase 1.",
                          "HU": "Ha üresen hagyod, az app az 1. fázisban elfogott ID körül keres."},
    "btn_search":        {"EN": "🔍  Search",                    "HU": "🔍  Keresés"},
    "btn_stop_scan":     {"EN": "⏹  Stop",                      "HU": "⏹  Leállítás"},
    "btn_clear_list":    {"EN": "🗑  Clear list",                "HU": "🗑  Lista törlése"},
    "btn_set_target":    {"EN": "✅  Set selected as proxy target",
                          "HU": "✅  Kiválasztott sor beállítása proxy célként"},
    "sel_hint":          {"EN": "← Click a row, then this button",
                          "HU": "← Kattints egy sorra, majd ide"},
    "col_version":       {"EN": "Firmware version",              "HU": "Firmware verzió"},
    "col_id":            {"EN": "CDN ID",                        "HU": "CDN ID"},
    "col_type":          {"EN": "Type",                          "HU": "Típus"},
    "col_region":        {"EN": "Region",                        "HU": "Régió"},
    "col_size":          {"EN": "Size MB",                       "HU": "Méret MB"},
    "col_url":           {"EN": "Download URL",                  "HU": "Letöltési URL"},
    "scan_progress":     {"EN": "Searching... {i}/{total}  (ID: {vid})",
                          "HU": "Keresés... {i}/{total}  (ID: {vid})"},
    "scan_done":         {"EN": "✓ Done.",                       "HU": "✓ Kész."},
    "scan_log_start":    {"EN": "Firmware search – {filter}",    "HU": "Firmware keresés – {filter}"},
    "scan_log_range":    {"EN": "ID range: {s}–{e} (step: {step})",
                          "HU": "ID tartomány: {s}–{e} (lépés: {step})"},
    "scan_done_log":     {"EN": "Search done – {n} matching packages found.",
                          "HU": "Keresés kész – {n} egyező csomag találva."},
    "filter_ver":        {"EN": "version: {v}",                  "HU": "verzió: {v}"},
    "filter_region":     {"EN": "region: {r}",                   "HU": "régió: {r}"},
    "filter_none":       {"EN": "no filter",                     "HU": "szűrés nélkül"},

    # Finder warnings/info
    "warn_no_cdn_title": {"EN": "Warning",                       "HU": "Figyelem"},
    "warn_no_cdn":       {"EN": "CDN URL not yet known!\n\n"
                                "Steps:\n"
                                "  1. Start the proxy (Proxy tab)\n"
                                "  2. Connect your phone in HonorSuite\n"
                                "  3. Search for updates – proxy auto-detects the CDN URL\n"
                                "  4. Come back here to search",
                          "HU": "A CDN URL még nem ismert!\n\n"
                                "Lépések:\n"
                                "  1. Indítsd el a proxyt (Proxy fül)\n"
                                "  2. Csatlakoztasd a telefont HonorSuite-ban\n"
                                "  3. Keress frissítést – a proxy megtalálja a CDN URL-t\n"
                                "  4. Visszajöhetsz ide keresni"},
    "warn_no_filter":    {"EN": "No version or region code entered.\n"
                                "This will list ALL available firmware – may take a while.\n\n"
                                "Continue?",
                          "HU": "Nem adtál meg verziót vagy régiókódot.\n"
                                "Az összes firmware listázása – sok időbe telhet.\n\n"
                                "Folytatod?"},
    "warn_no_filter_title": {"EN": "Confirm",                    "HU": "Megerősítés"},
    "warn_select_row":   {"EN": "Select a row from the list first!",
                          "HU": "Válassz ki egy sort a listából!"},
    "info_set_target":   {"EN": "Target set ✅",                 "HU": "Beállítva ✅"},
    "info_set_target_body": {
        "EN": "Firmware target:\n\n"
              "  Version:  {ver}\n"
              "  Type:     {type}\n"
              "  Region:   {region}\n"
              "  CDN ID:   {id}\n\n"
              "The proxy will now request this version from HonorSuite.\n"
              "Start the proxy, then open HonorSuite and search for updates.",
        "HU": "Firmware cél:\n\n"
              "  Verzió:  {ver}\n"
              "  Típus:   {type}\n"
              "  Régió:   {region}\n"
              "  CDN ID:  {id}\n\n"
              "A proxy mostantól ezt a verziót kéri a HonorSuite-nak.\n"
              "Indítsd el a proxyt, majd nyiss frissítést HonorSuite-ban."},
    "selected_row":      {"EN": "Selected: {ver}  [{type}]  Region: {region}  ID: {id}",
                          "HU": "Kiválasztva: {ver}  [{type}]  Régió: {region}  ID: {id}"},

    # ── Certificate tab ───────────────────────────────────────────────────────
    "cert_intro":        {"EN": "A custom CA certificate is required to intercept HTTPS traffic.\n"
                                "Export it BEFORE updating – you can import it back if needed!",
                          "HU": "HTTPS elfogáshoz saját CA tanúsítvány kell.\n"
                                "Exportáld el frissítés ELŐTT – ha baj van, visszaimportálhatod!"},
    "btn_gen_ca":        {"EN": "🔑  Generate CA",               "HU": "🔑  CA generálása"},
    "btn_install_ca":    {"EN": "🖥   Install to Windows store",  "HU": "🖥   Telepítés Windows tárolóba"},
    "btn_export_ca":     {"EN": "📤  Export backup ZIP",         "HU": "📤  Exportálás backup ZIP-be"},
    "btn_import_ca":     {"EN": "📥  Import backup ZIP",         "HU": "📥  Importálás backup ZIP-ből"},
    "btn_remove_ca":     {"EN": "🗑   Remove from Windows store", "HU": "🗑   Eltávolítás Windows tárolóból"},
    "cert_order_title":  {"EN": "Steps:",                        "HU": "Sorrend:"},
    "cert_order":        {"EN": "  1. Generate CA\n  2. Install to Windows store\n"
                                "  3. Export backup\n  4. Start proxy",
                          "HU": "  1. CA generálása\n  2. Telepítés Windows tárolóba\n"
                                "  3. Exportálás (backup!)\n  4. Proxy indítása"},
    "cert_gen_ok":       {"EN": "CA certificate generated!",     "HU": "CA tanúsítvány generálva!"},
    "cert_gen_err":      {"EN": "Generation failed.",            "HU": "Generálás sikertelen."},
    "cert_install_ok":   {"EN": "CA installed! You can now start the proxy.",
                          "HU": "CA telepítve! Most már indíthatod a proxyt."},
    "cert_install_err":  {"EN": "Installation failed.\nTry running as Administrator!",
                          "HU": "Telepítés sikertelen.\nFuttasd rendszergazdaként!"},
    "cert_no_ca":        {"EN": "Generate a CA first!",          "HU": "Először generálj CA-t!"},
    "cert_export_title": {"EN": "Save CA backup",                "HU": "CA backup mentése"},
    "cert_export_ok":    {"EN": "Exported:\n{path}",             "HU": "Exportálva:\n{path}"},
    "cert_export_err":   {"EN": "Export failed.",                "HU": "Export sikertelen."},
    "cert_import_title": {"EN": "Import CA backup",              "HU": "CA backup importálása"},
    "cert_import_ok":    {"EN": "CA imported!\nReinstall to Windows store if needed.",
                          "HU": "CA importálva!\nTelepítsd újra ha szükséges."},
    "cert_import_err":   {"EN": "Import failed.",                "HU": "Import sikertelen."},
    "cert_remove_q":     {"EN": "Remove the CA from Windows store?\nHTTPS interception will stop.",
                          "HU": "Eltávolítod a CA-t a Windows tárolóból?\nA HTTPS elfogás megszűnik."},
    "cert_remove_title": {"EN": "Confirm",                       "HU": "Megerősítés"},

    # ── About tab ─────────────────────────────────────────────────────────────
    "about_text":        {
        "EN": "Honor Firmware Proxy + Finder  v{ver}\n\n"
              "Open-source MITM proxy for accessing Honor device\n"
              "firmware updates earlier than official OTA.\n\n"
              "ELP-NX9 (Honor 200 Pro) – C431 EEA\n\n"
              "Workflow:\n"
              "  1. Certificate: generate → install → export\n"
              "  2. Start proxy + set Windows proxy 127.0.0.1:{port}\n"
              "  3. HonorSuite + phone → CDN URL auto-detected\n"
              "  4. Firmware Finder: enter version + region → Search\n"
              "     (use version known from HonorFirmwareFinder app)\n"
              "  5. Select row → Set as target → proxy requests that version\n\n"
              "Data folder: {dir}\n"
              "Log file:    {log}",
        "HU": "Honor Firmware Proxy + Finder  v{ver}\n\n"
              "Nyílt forráskódú MITM proxy Honor eszközök firmware\n"
              "frissítéseinek korábbi eléréséhez.\n\n"
              "ELP-NX9 (Honor 200 Pro) – C431 EEA\n\n"
              "Workflow:\n"
              "  1. Tanúsítvány: generálás → telepítés → export\n"
              "  2. Proxy indítása + Windows proxy 127.0.0.1:{port}\n"
              "  3. HonorSuite + telefon → CDN URL auto-detektálás\n"
              "  4. Firmware Finder: verzió + régió → Keresés\n"
              "     (HonorFirmwareFinder Android appból ismert verzió)\n"
              "  5. Sor kiválasztása → Cél beállítása → proxy azt kéri\n\n"
              "Adatok: {dir}\n"
              "Log:    {log}"},
    "btn_open_folder":   {"EN": "📂  Open data folder",          "HU": "📂  Adatok mappa megnyitása"},

    # ── Local firmware server ─────────────────────────────────────────────────
    "btn_local_zip":     {"EN": "📂  Select local ZIP file",      "HU": "📂  Helyi ZIP fájl kiválasztása"},
    "btn_local_stop":    {"EN": "⏹  Stop local server",          "HU": "⏹  Helyi szerver leállítása"},
    "local_zip_hint":    {"EN": "No file selected",               "HU": "Nincs fájl kiválasztva"},
    "local_srv_ok":      {"EN": "✅ Local server started!\n\n"
                                "The proxy will serve this ZIP to HonorSuite.\n"
                                "Start proxy + Proxifier, then search for updates in HonorSuite.",
                          "HU": "✅ Helyi szerver elindult!\n\n"
                                "A proxy ezt a ZIP-et szolgálja ki a HonorSuite-nak.\n"
                                "Indítsd el a proxyt + Proxifiert, majd keress frissítést."},
    "local_srv_err":     {"EN": "Failed to start local server.",  "HU": "Helyi szerver indítása sikertelen."},
    "local_srv_no_file": {"EN": "Select a ZIP file first!",       "HU": "Először válassz ki egy ZIP fájlt!"},
    "local_srv_running": {"EN": "🟢 Local server: {file}  →  http://127.0.0.1:{port}/firmware.zip",
                          "HU": "🟢 Helyi szerver: {file}  →  http://127.0.0.1:{port}/firmware.zip"},
    "local_srv_stopped": {"EN": "Local server stopped.",          "HU": "Helyi szerver leállítva."},

    # ── Local firmware server ─────────────────────────────────────────────────
    "local_srv_title":   {"EN": "🖥  Local Firmware Server",      "HU": "🖥  Helyi Firmware Szerver"},
    "btn_pick_zip":      {"EN": "📂  Select ZIP file...",         "HU": "📂  ZIP fájl kiválasztása..."},
    "btn_serve_start":   {"EN": "▶  Start local server",         "HU": "▶  Helyi szerver indítása"},
    "btn_serve_stop":    {"EN": "⏹  Stop local server",          "HU": "⏹  Helyi szerver leállítása"},
    "no_zip_selected":   {"EN": "No ZIP selected",               "HU": "Nincs ZIP kiválasztva"},
    "zip_selected":      {"EN": "Selected: {name}  ({size} MB)", "HU": "Kiválasztva: {name}  ({size} MB)"},
    "serve_running":     {"EN": "✅ Server running → http://127.0.0.1:{port}/{name}",
                          "HU": "✅ Szerver fut → http://127.0.0.1:{port}/{name}"},
    "serve_stopped":     {"EN": "Server stopped.",               "HU": "Szerver leállítva."},
    "serve_no_zip":      {"EN": "Select a ZIP file first!",      "HU": "Először válassz ZIP fájlt!"},
    "serve_log_start":   {"EN": "Local server started → {url}",  "HU": "Helyi szerver elindult → {url}"},
    "serve_log_stop":    {"EN": "Local server stopped.",         "HU": "Helyi szerver leállítva."},
    "serve_hint":        {"EN": "The proxy will replace CDN URLs with the local server URL.\n"
                                "HonorSuite will download from your PC instead of the internet.",
                          "HU": "A proxy a CDN URL-eket a helyi szerver URL-jére cseréli.\n"
                                "A HonorSuite a saját gépedről tölti le a firmware-t."},

    # ── External proxy mode ───────────────────────────────────────────────────
    "ext_proxy_label":   {"EN": "I use an external proxy app (e.g. Proxifier)",
                          "HU": "Külső proxy appot használok (pl. Proxifier)"},
    "ext_proxy_hint":    {"EN": "⚠ When enabled, system proxy and hosts redirect buttons are disabled\n"
                                "  to prevent network loops.",
                          "HU": "⚠ Bekapcsolva a rendszer proxy és hosts gombok letiltva\n"
                                "  a hálózati hurok elkerülése érdekében."},

    # ── Threads ───────────────────────────────────────────────────────────────
    "threads_label":     {"EN": "Parallel threads:",             "HU": "Párhuzamos szálak:"},

    # ── System proxy ──────────────────────────────────────────────────────────
    "btn_force_proxy":   {"EN": "🔒  Force system proxy (Admin)", "HU": "🔒  Rendszer proxy kényszerítése (Admin)"},
    "btn_clear_proxy":   {"EN": "🔓  Remove system proxy",        "HU": "🔓  Rendszer proxy eltávolítása"},
    "sysproxy_ok":       {"EN": "System proxy set!\n\n"
                                "Set on all levels:\n"
                                "  ✓ WinHTTP (system level)\n"
                                "  ✓ WinInet (browser/app level)\n"
                                "  ✓ Environment variables\n\n"
                                "Now start HonorSuite and search for updates.",
                          "HU": "Rendszer proxy beállítva!\n\n"
                                "Minden szinten beállítva:\n"
                                "  ✓ WinHTTP (rendszer szint)\n"
                                "  ✓ WinInet (böngésző/app szint)\n"
                                "  ✓ Környezeti változók\n\n"
                                "Most indítsd el a HonorSuite-ot és keress frissítést."},
    "sysproxy_err":      {"EN": "Failed to set system proxy.\nTry running as Administrator!",
                          "HU": "Nem sikerült beállítani a rendszer proxyt.\nFuttasd rendszergazdaként!"},
    "sysproxy_clear_ok": {"EN": "System proxy removed.",          "HU": "Rendszer proxy eltávolítva."},
    "sysproxy_clear_err":{"EN": "Failed to remove proxy.",        "HU": "Eltávolítás sikertelen."},
    "sysproxy_log_set":  {"EN": "System proxy forced: {addr}",    "HU": "Rendszer proxy kényszerítve: {addr}"},
    "sysproxy_log_clear":{"EN": "System proxy removed.",          "HU": "Rendszer proxy eltávolítva."},
    "sysproxy_no_admin": {"EN": "⚠ Admin rights required!\n\n"
                                "Right-click HonorFProxy.exe → Run as administrator",
                          "HU": "⚠ Rendszergazda jog szükséges!\n\n"
                                "Jobb klikk HonorFProxy.exe → Futtatás rendszergazdaként"},

    # ── Hosts file redirect ───────────────────────────────────────────────────
    "btn_hosts_set":     {"EN": "🌐  Redirect Honor hosts (most reliable)",
                          "HU": "🌐  Honor hosts átirányítása (legmegbízhatóbb)"},
    "btn_hosts_clear":   {"EN": "🌐  Remove hosts redirect",
                          "HU": "🌐  Hosts átirányítás eltávolítása"},
    "hosts_ok":          {"EN": "Hosts file updated!\n\n"
                                "Honor CDN hostnames now point to 127.0.0.1.\n"
                                "The proxy listens directly on port 443.\n\n"
                                "Now start HonorSuite and search for updates.\n"
                                "(No Windows proxy setting needed!)",
                          "HU": "Hosts fájl frissítve!\n\n"
                                "A Honor CDN hostok most 127.0.0.1-re mutatnak.\n"
                                "A proxy közvetlenül a 443-as porton figyel.\n\n"
                                "Most indítsd el a HonorSuite-ot és keress frissítést.\n"
                                "(Nem kell Windows proxy beállítás!)"},
    "hosts_err":         {"EN": "Failed to update hosts file.\nRun as Administrator!",
                          "HU": "Hosts fájl módosítása sikertelen.\nFuttasd rendszergazdaként!"},
    "hosts_clear_ok":    {"EN": "Hosts redirect removed.",    "HU": "Hosts átirányítás eltávolítva."},
    "hosts_clear_err":   {"EN": "Failed to remove hosts redirect.", "HU": "Eltávolítás sikertelen."},
    "hosts_log_set":     {"EN": "Hosts redirect active – {n} hosts → 127.0.0.1",
                          "HU": "Hosts átirányítás aktív – {n} host → 127.0.0.1"},
    "hosts_log_clear":   {"EN": "Hosts redirect removed.",   "HU": "Hosts átirányítás eltávolítva."},
    "direct_started":    {"EN": "Direct SSL proxy started on port 443.",
                          "HU": "Közvetlen SSL proxy elindult a 443-as porton."},
    "direct_err":        {"EN": "Port 443 unavailable. Run as Administrator!",
                          "HU": "443-as port nem elérhető. Futtasd rendszergazdaként!"},

    # ── CDN log messages ──────────────────────────────────────────────────────
    "cdn_found_banner":  {"EN": "FIRMWARE CDN URL FOUND!",       "HU": "FIRMWARE CDN URL MEGTALÁLVA!"},
    "cdn_found":         {"EN": "CDN found → {url}",             "HU": "CDN megtalálva → {url}"},
    "ota_modified":      {"EN": "✅ OTA response modified → {ver}",
                          "HU": "✅ OTA módosítva → {ver}"},
    "proxy_started":     {"EN": "Proxy running → http://{host}:{port}",
                          "HU": "Proxy fut → http://{host}:{port}"},
    "proxy_stopped":     {"EN": "Proxy stopped.",                "HU": "Proxy leállítva."},
    "ca_generated":      {"EN": "CA certificate generated.",     "HU": "CA tanúsítvány generálva."},
    "ca_installed":      {"EN": "CA installed.",                 "HU": "CA telepítve."},
    "ca_removed":        {"EN": "CA removed.",                   "HU": "CA eltávolítva."},
    "ca_exported":       {"EN": "CA exported → {path}",          "HU": "CA exportálva → {path}"},
    "ca_imported":       {"EN": "CA imported → {path}",          "HU": "CA importálva → {path}"},
    "target_set_log":    {"EN": "Target set: {ver}  [{type}]  {region}  (ID: {id})",
                          "HU": "Cél beállítva: {ver}  [{type}]  {region}  (ID: {id})"},
}

# ── i18n engine ───────────────────────────────────────────────────────────────

_current_lang = "EN"   # default


def set_lang(lang: str):
    global _current_lang
    _current_lang = lang if lang in ("EN", "HU") else "EN"


def t(key: str, **kwargs) -> str:
    """Return translated string, optionally formatted with kwargs."""
    entry = STRINGS.get(key, {})
    s = entry.get(_current_lang) or entry.get("EN") or key
    if kwargs:
        try:
            s = s.format(**kwargs)
        except KeyError:
            pass
    return s


# ── Logging ───────────────────────────────────────────────────────────────────

log_queue: queue.Queue = queue.Queue()
_fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log = logging.getLogger("HFP")
log.setLevel(logging.DEBUG)
log.addHandler(_fh)


def qlog(level: str, msg: str):
    getattr(log, level.lower(), log.info)(msg)
    log_queue.put((level.upper(), msg))


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class FirmwareEntry:
    version_id: str
    fw_version: str
    region:     str
    pkg_type:   str
    url:        str
    size_mb:    float = 0.0
    sha256:     str   = ""
    vendor_pkg: str   = ""


# ── App state ─────────────────────────────────────────────────────────────────

class AppState:
    def __init__(self):
        self.phase          = 1
        self.cdn_base_url   = ""
        self.g_number       = ""
        self.g_sub          = ""
        self.known_ids:  list[str]           = []
        self.fw_list:    list[FirmwareEntry] = []
        self.target_version = ""
        self.target_id      = ""
        self.language       = "EN"
        self.ext_proxy_mode = False
        self.scan_threads   = 16
        self.load()

    def load(self):
        if not STATE_FILE.exists():
            return
        try:
            d = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            self.phase          = d.get("phase", 1)
            self.cdn_base_url   = d.get("cdn_base_url", "")
            self.g_number       = d.get("g_number", "")
            self.g_sub          = d.get("g_sub", "")
            self.known_ids      = d.get("known_ids", [])
            self.target_version = d.get("target_version", "")
            self.target_id      = d.get("target_id", "")
            self.language       = d.get("language", "EN")
            self.ext_proxy_mode = d.get("ext_proxy_mode", False)
            self.scan_threads   = d.get("scan_threads", 16)
            self.fw_list = []
            for e in d.get("fw_list", []):
                # vendor_pkg mező kompatibilitás – régi state.json-ban nincs
                e.setdefault("vendor_pkg", "")
                try:
                    self.fw_list.append(FirmwareEntry(**e))
                except Exception:
                    pass
        except Exception:
            pass

    def save(self):
        try:
            STATE_FILE.write_text(json.dumps({
                "phase":          self.phase,
                "cdn_base_url":   self.cdn_base_url,
                "g_number":       self.g_number,
                "g_sub":          self.g_sub,
                "known_ids":      self.known_ids,
                "target_version": self.target_version,
                "target_id":      self.target_id,
                "language":       self.language,
                "ext_proxy_mode": self.ext_proxy_mode,
                "scan_threads":   self.scan_threads,
                "fw_list":        [e.__dict__ for e in self.fw_list],
            }, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def set_cdn_found(self, g_number, g_sub, version_id):
        """Régi CDN struktúra."""
        self.g_number     = g_number
        self.g_sub        = g_sub
        self.cdn_base_url = f"{CDN_BASE}/TDS/data/files/p1/s15/{g_number}/{g_sub}/"
        if version_id not in self.known_ids:
            self.known_ids.append(version_id)
        self.phase = 2
        self.save()
        qlog("info", t("cdn_found", url=self.cdn_base_url))

    def set_cdn_found_new(self, version_id):
        """Új CDN struktúra: /TDS/data/bl/files/v{ID}/f1/full/filelist.xml"""
        self.cdn_base_url = f"{CDN_BASE}/TDS/data/bl/files/"
        if version_id not in self.known_ids:
            self.known_ids.append(version_id)
        self.phase = 2
        self.save()
        qlog("info", t("cdn_found", url=f"{CDN_BASE}/TDS/data/bl/files/v{version_id}/f1/full/filelist.xml"))

    @property
    def cdn_known(self):
        return bool(self.cdn_base_url)


state = AppState()
set_lang(state.language)


# ── CDN client ────────────────────────────────────────────────────────────────

class CDNClient:
    _ctx = ssl.create_default_context()

    def _get(self, url: str, timeout: int = 10) -> bytes:
        """HTTP és HTTPS-t is megpróbál."""
        urls_to_try = [url]
        # Ha HTTP-vel próbál, HTTPS-t is megpróbál és fordítva
        if url.startswith("http://"):
            urls_to_try.append("https://" + url[7:])
        elif url.startswith("https://"):
            urls_to_try.append("http://" + url[8:])

        for u in urls_to_try:
            try:
                req = urllib.request.Request(
                    u, headers={"User-Agent": UA})
                if u.startswith("https://"):
                    ctx = ssl.create_default_context()
                    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                        return r.read()
                else:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        return r.read()
            except Exception as e:
                qlog("debug", f"Fetch error ({u}): {e}")
                continue
        return b""

    def filelist_url(self, vid: str) -> str:
        """Honor CDN – HTTP (a HonorSuite is HTTP-t használ a CDN fele)."""
        base = state.cdn_base_url or "http://update.hihonorcdn.com/TDS/data/bl/files/"
        if not base.endswith("/"):
            base += "/"
        if base.startswith("https://"):
            base = "http://" + base[8:]
        return f"{base}v{vid}/f1/full/filelist.xml"

    def fetch_filelist(self, vid: str) -> list[FirmwareEntry]:
        url = self.filelist_url(vid)

        headers = {
            "User-Agent": UA,
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Host": "update.hihonorcdn.com",
            "Accept-Encoding": "gzip, deflate",
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                enc = resp.headers.get("Content-Encoding", "")
                if enc == "gzip":
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                elif not raw:
                    return []
                # Ha gzip magic bytes vannak de nincs header
                elif raw[:2] == b"\x1f\x8b":
                    try:
                        raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                    except Exception:
                        pass
        except Exception as e:
            qlog("debug", f"Fetch error vid={vid}: {e}")
            return []

        try:
            root = ET.fromstring(raw)
        except Exception as e:
            qlog("debug", f"XML parse error vid={vid}: {e}")
            return []

        # CDN base for download URL (always ends with /)
        base = state.cdn_base_url or "https://update.hihonorcdn.com/TDS/data/bl/files/"
        if not base.endswith("/"):
            base += "/"

        # packageSolution → pkg_type
        sol = (root.findtext("packageSolution") or "").strip().lower()
        if "preload" in sol:
            pkg_type = "PRELOAD"
        elif "cust" in sol:
            pkg_type = "CUST"
        else:
            pkg_type = (root.findtext("packageType") or "BASE").strip().upper()

        # vendorInfo: package attribútum → fájlnév, name attribútum → típus hint
        vendor = root.find("vendorInfo")
        vendor_pkg  = vendor.get("package", "")  if vendor is not None else ""
        vendor_name = vendor.get("name",    "")  if vendor is not None else ""
        if vendor_name and pkg_type == "BASE":
            if "preload" in vendor_name.lower():
                pkg_type = "PRELOAD"

        entries = []

        # Fájlok iterálása – <files><file>...</file></files>
        file_nodes = list(root.iter("file"))
        if not file_nodes:
            qlog("debug", f"vid={vid}: nincs <file> tag")
            return []

        for node in file_nodes:
            spath = (node.findtext("spath") or node.findtext("dpath") or "").strip()
            if not spath:
                continue

            download_url = f"{base}v{vid}/f1/full/{spath}"

            size_s = (node.findtext("size") or "0").strip()
            size   = int(size_s) if size_s.isdigit() else 0
            sha    = (node.findtext("sha256") or "").strip()

            # Verzió kinyerése a fájlnévből: pl. 10.0.0.120
            fv_m   = re.search(r"(\d+\.\d+\.\d+\.\d+)", spath)
            fw_ver = fv_m.group(1) if fv_m else "?"

            # Régiókód kinyerése az URL-ből
            region = "N/A"
            # 1. _def_REGION_ vagy _def_REGION.zip
            reg_m = re.search(r"_def_([A-Za-z0-9]+?)(?:_|\.zip)", spath)
            if reg_m:
                region = reg_m.group(1)
            else:
                # 2. _opr_REGION_ vagy _opr_REGION.zip
                reg_m = re.search(r"_opr_([A-Za-z0-9]+?)(?:_|\.zip)", spath)
                if reg_m:
                    region = reg_m.group(1)
                else:
                    # 3. C### operátor kód
                    reg_m = re.search(r"\b(C\d{3,4})\b", spath + " " + vendor_pkg)
                    if reg_m:
                        region = reg_m.group(1)
                    else:
                        # 4. Ismert régió rövidítések
                        reg_m = re.search(
                            r"\b(eea|cee|mea|ssa|lac|anz|sea|row|global|meafnaf|tr)\b",
                            spath.lower())
                        if reg_m:
                            region = reg_m.group(1).upper()

            # Típus finomítás a fájlnév alapján
            fname = spath.upper()
            if   "PRELOAD" in fname: ft = "PRELOAD"
            elif "CUST"    in fname: ft = "CUST"
            elif "BASE"    in fname: ft = "BASE"
            else:                    ft = pkg_type

            entries.append(FirmwareEntry(
                version_id=vid,
                fw_version=fw_ver,
                region=region,
                pkg_type=ft,
                url=download_url,
                size_mb=round(size / 1024 / 1024, 1),
                sha256=sha,
                vendor_pkg=vendor_pkg,
            ))

        return entries

    def scan_versions(self, fw_version, build_code,
                      start_id, end_id, step,
                      progress_cb, result_cb, stop_event,
                      threads: int = 16, model_filter: str = "",
                      pkg_type_filter: str = "", suffix_filter: str = ""):
        ids             = list(range(start_id, end_id + 1, step))
        total           = len(ids)
        fw_filter       = fw_version.strip()
        build_filter    = build_code.strip().upper()
        mod_filter      = model_filter.strip().upper()
        pkg_filter      = pkg_type_filter.strip().upper()
        sfx_filter      = suffix_filter.strip().upper()
        found           = 0
        completed       = 0
        lock            = threading.Lock()

        CHUNK = max(threads * 4, 200)

        def check_one(vid):
            if stop_event.is_set():
                return []
            entries = self.fetch_filelist(str(vid))
            if not entries:
                return []
            filtered = []
            for e in entries:
                ver_unknown = e.fw_version in ("?", "PRELOAD", "N/A", "")
                if fw_filter and not ver_unknown and fw_filter not in e.fw_version:
                    continue
                reg_unknown = e.region in ("N/A", "")
                if build_filter and not reg_unknown and build_filter not in e.region.upper() and build_filter not in e.url.upper():
                    continue
                if mod_filter and mod_filter not in e.url.upper() and mod_filter not in e.vendor_pkg.upper():
                    continue
                if pkg_filter and pkg_filter not in e.pkg_type.upper():
                    continue
                if sfx_filter and sfx_filter not in e.url.upper() and sfx_filter not in e.vendor_pkg.upper():
                    continue
                filtered.append(e)
            return filtered

        # Darabosított feldolgozás: CHUNK méretű szeletekben submit-álunk
        # → soha nem él egyszerre 100 000 Future a memóriában
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for chunk_start in range(0, len(ids), CHUNK):
                if stop_event.is_set():
                    break
                chunk = ids[chunk_start:chunk_start + CHUNK]
                future_map = {executor.submit(check_one, vid): vid
                              for vid in chunk}
                for future in as_completed(future_map):
                    if stop_event.is_set():
                        break
                    vid = future_map[future]
                    with lock:
                        completed += 1
                    progress_cb(completed, total, vid)
                    try:
                        filtered = future.result()
                        if filtered:
                            with lock:
                                found += len(filtered)
                            result_cb(filtered)
                    except Exception as e:
                        qlog("debug", f"Scan error vid={vid}: {e}")

        progress_cb(total, total, 0)
        qlog("info", t("scan_done_log", n=found))


cdn_client = CDNClient()


# ── Certificate manager ───────────────────────────────────────────────────────

class CertManager:
    _cache: dict[str, tuple[str, str]] = {}

    def ensure_ca(self):
        if not CRYPTO_OK: return False
        if CA_KEY_FILE.exists() and CA_CRT_FILE.exists(): return True
        return self.generate_ca()

    def generate_ca(self):
        try:
            key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subj = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME,      "HU"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HonorFProxy"),
                x509.NameAttribute(NameOID.COMMON_NAME,       "HonorFProxy Root CA"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subj).issuer_name(subj)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256())
            )
            CA_KEY_FILE.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
            CA_CRT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            qlog("info", t("ca_generated"))
            return True
        except Exception as e:
            qlog("error", f"CA generation error: {e}")
            return False

    def install_ca(self):
        try:
            r  = subprocess.run(
                ["certutil", "-addstore", "-user", "Root", str(CA_CRT_FILE)],
                capture_output=True, text=True)
            ok = r.returncode == 0
            qlog("info" if ok else "error", t("ca_installed") if ok else f"certutil: {r.stderr}")
            return ok
        except FileNotFoundError:
            qlog("error", "certutil not found."); return False

    def uninstall_ca(self):
        try:
            r  = subprocess.run(
                ["certutil", "-delstore", "-user", "Root", "HonorFProxy Root CA"],
                capture_output=True, text=True)
            ok = r.returncode == 0
            qlog("info" if ok else "error", t("ca_removed") if ok else f"Error: {r.stderr}")
            return ok
        except FileNotFoundError:
            qlog("error", "certutil not found."); return False

    def export_ca(self, dest):
        try:
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.write(CA_CRT_FILE, "honorfproxy_ca.crt")
                zf.write(CA_KEY_FILE, "honorfproxy_ca.key")
                if STATE_FILE.exists():
                    zf.write(STATE_FILE, "state.json")
            qlog("info", t("ca_exported", path=dest))
            return True
        except Exception as e:
            qlog("error", f"Export error: {e}"); return False

    def import_ca(self, src):
        try:
            with zipfile.ZipFile(src, "r") as zf:
                if "honorfproxy_ca.crt" not in zf.namelist():
                    qlog("error", "Invalid backup!"); return False
                CA_CRT_FILE.write_bytes(zf.read("honorfproxy_ca.crt"))
                CA_KEY_FILE.write_bytes(zf.read("honorfproxy_ca.key"))
                if "state.json" in zf.namelist():
                    STATE_FILE.write_bytes(zf.read("state.json"))
                    state.load()
            qlog("info", t("ca_imported", path=src))
            return True
        except Exception as e:
            qlog("error", f"Import error: {e}"); return False

    def host_cert(self, hostname):
        if hostname in self._cache:
            return self._cache[hostname]
        ca_key  = serialization.load_pem_private_key(CA_KEY_FILE.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(CA_CRT_FILE.read_bytes())
        key     = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sans    = [x509.DNSName(hostname)]
        try: sans.append(x509.IPAddress(ipaddress.ip_address(hostname)))
        except ValueError: pass
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        tf_c = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
        tf_k = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
        tf_c.write(cert.public_bytes(serialization.Encoding.PEM)); tf_c.close()
        tf_k.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())); tf_k.close()
        self._cache[hostname] = (tf_c.name, tf_k.name)
        return self._cache[hostname]


cert_mgr = CertManager()


# ── System Proxy Manager ──────────────────────────────────────────────────────

import ctypes
import winreg

def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class SystemProxyManager:
    """
    Rendszer szintű proxy beállítás Windows-on.
    Három szinten állítja be egyszerre:
      1. WinHTTP  – netsh winhttp (rendszer szint, sok app ezt használja)
      2. WinInet  – registry (böngésző/app szint)
      3. Env vars – HTTP_PROXY, HTTPS_PROXY (Python/Java alapú appok)
    """

    PROXY_ADDR = f"{PROXY_HOST}:{PROXY_PORT}"
    WININET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def set_proxy(self) -> bool:
        ok = True
        ok &= self._set_winhttp()
        ok &= self._set_wininet(True)
        self._set_env(True)
        if ok:
            qlog("info", t("sysproxy_log_set", addr=self.PROXY_ADDR))
        return ok

    def clear_proxy(self) -> bool:
        ok = True
        ok &= self._clear_winhttp()
        ok &= self._set_wininet(False)
        self._set_env(False)
        qlog("info", t("sysproxy_log_clear"))
        return ok

    def _set_winhttp(self) -> bool:
        """netsh winhttp set proxy – rendszer szintű, admin kell."""
        try:
            r = subprocess.run(
                ["netsh", "winhttp", "set", "proxy",
                 self.PROXY_ADDR, "bypass-list=<local>"],
                capture_output=True, text=True, timeout=10,
            )
            return r.returncode == 0
        except Exception as e:
            qlog("error", f"WinHTTP proxy hiba: {e}")
            return False

    def _clear_winhttp(self) -> bool:
        try:
            r = subprocess.run(
                ["netsh", "winhttp", "reset", "proxy"],
                capture_output=True, text=True, timeout=10,
            )
            return r.returncode == 0
        except Exception as e:
            qlog("error", f"WinHTTP reset hiba: {e}")
            return False

    def _set_wininet(self, enable: bool) -> bool:
        """Registry WinInet proxy – felhasználó szintű, admin nem kell."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                self.WININET_KEY, 0,
                                winreg.KEY_SET_VALUE) as key:
                if enable:
                    winreg.SetValueEx(key, "ProxyEnable",  0, winreg.REG_DWORD,  1)
                    winreg.SetValueEx(key, "ProxyServer",  0, winreg.REG_SZ,     self.PROXY_ADDR)
                    winreg.SetValueEx(key, "ProxyOverride",0, winreg.REG_SZ,     "<local>")
                else:
                    winreg.SetValueEx(key, "ProxyEnable",  0, winreg.REG_DWORD,  0)
                    winreg.SetValueEx(key, "ProxyServer",  0, winreg.REG_SZ,     "")
            # Internet Explorer / WinInet értesítése a változásról
            try:
                import ctypes
                ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
                ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_REFRESH
            except Exception:
                pass
            return True
        except Exception as e:
            qlog("error", f"WinInet registry hiba: {e}")
            return False

    def _set_env(self, enable: bool):
        """Környezeti változók beállítása az aktuális folyamathoz."""
        if enable:
            os.environ["HTTP_PROXY"]  = f"http://{self.PROXY_ADDR}"
            os.environ["HTTPS_PROXY"] = f"http://{self.PROXY_ADDR}"
            os.environ["http_proxy"]  = f"http://{self.PROXY_ADDR}"
            os.environ["https_proxy"] = f"http://{self.PROXY_ADDR}"
        else:
            for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                os.environ.pop(k, None)


sys_proxy = SystemProxyManager()


# ── Hosts file manager ────────────────────────────────────────────────────────

HOSTS_FILE  = Path(r"C:\Windows\System32\drivers\etc\hosts")
HOSTS_MARK  = "# HonorFProxy"


class HostsManager:
    """
    Átírja a Windows hosts fájlt úgy, hogy a Honor CDN hostok
    127.0.0.1-re mutassanak. Ez DNS szinten kényszeríti az átirányítást –
    egyetlen app sem tud kibújni alóla.
    """

    def set_redirect(self) -> bool:
        if not _is_admin():
            return False
        try:
            content = HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
            content = self._strip(content)
            lines   = [f"\n{HOSTS_MARK} - DO NOT EDIT THIS BLOCK MANUALLY"]
            for host in HONOR_HOSTS:
                lines.append(f"127.0.0.1\t{host}")   # IPv4
                lines.append(f"::1\t\t{host}")        # IPv6
            lines.append(f"{HOSTS_MARK}_END\n")
            HOSTS_FILE.write_text(content + "\n".join(lines), encoding="utf-8")
            subprocess.run(["ipconfig", "/flushdns"],
                           capture_output=True, timeout=5)
            qlog("info", t("hosts_log_set", n=len(HONOR_HOSTS)))
            return True
        except Exception as e:
            qlog("error", f"Hosts write error: {e}")
            return False

    def clear_redirect(self) -> bool:
        try:
            content = HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
            content = self._strip(content)
            HOSTS_FILE.write_text(content, encoding="utf-8")
            subprocess.run(["ipconfig", "/flushdns"],
                           capture_output=True, timeout=5)
            qlog("info", t("hosts_log_clear"))
            return True
        except Exception as e:
            qlog("error", f"Hosts clear error: {e}")
            return False

    def _strip(self, content: str) -> str:
        """Eltávolítja a korábban hozzáadott HonorFProxy blokkot."""
        lines  = content.splitlines()
        result = []
        skip   = False
        for line in lines:
            if HOSTS_MARK in line and "_END" not in line:
                skip = True
            elif HOSTS_MARK + "_END" in line:
                skip = False
                continue
            if not skip:
                result.append(line)
        return "\n".join(result)

    @property
    def is_active(self) -> bool:
        try:
            return HOSTS_MARK in HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return False


hosts_mgr = HostsManager()


# ── Direct SSL proxy (port 443) ───────────────────────────────────────────────

class DirectSSLProxy:
    """
    Közvetlenül a 443-as porton figyel.
    Ha a hosts fájl a Honor hostokat 127.0.0.1-re irányítja,
    a HonorSuite ide fog csatlakozni – nincs szükség rendszer proxy beállításra.
    """

    def __init__(self):
        self._srv: socket.socket | None = None
        self._running = False

    def start(self) -> bool:
        if not _is_admin():
            return False
        try:
            # IPv6 socket, ami IPv4-et is kezel (dual-stack)
            self._srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            self._srv.bind(("::", 443))
            self._srv.listen(50)
            self._running = True
            threading.Thread(target=self._loop, daemon=True).start()
            qlog("info", t("direct_started"))
            return True
        except OSError as e:
            qlog("error", f"Direct SSL start error: {e}")
            return False

    def stop(self):
        self._running = False
        if self._srv:
            try: self._srv.close()
            except Exception: pass

    def _loop(self):
        while self._running:
            try:
                self._srv.settimeout(1.0)
                client, addr = self._srv.accept()
                # Melyik host csatlakozott? Az SNI-ből derítjük ki
                threading.Thread(
                    target=self._handle, args=(client,), daemon=True).start()
            except socket.timeout: continue
            except Exception: break

    def _handle(self, client: socket.socket):
        """
        Közvetlenül SSL handshake-et végez a kliensssel,
        az SNI hostname alapján generál tanúsítványt,
        majd továbbítja a forgalmat a valódi Honor szervernek.
        """
        try:
            # Először peek-eljük az SNI-t a ClientHello-ból
            hostname = self._peek_sni(client) or "update.hihonorcdn.com"

            if not any(h in hostname for h in HONOR_HOSTS):
                # Nem Honor host – visszadobjuk
                client.close()
                return

            cf, kf = cert_mgr.host_cert(hostname)
            ctx_c  = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx_c.load_cert_chain(cf, kf)

            with ctx_c.wrap_socket(client, server_side=True) as sc:
                req = sc.recv(BUFFER * 4)
                if not req: return

                path = self._path(req)

                # MITM proxy _analyze és _modify
                proxy._analyze(hostname, path)
                ctx_s = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as raw:
                    with ctx_s.wrap_socket(raw, server_hostname=hostname) as ss:
                        ss.sendall(req)
                        resp = proxy._recv_all(ss)
                        resp = proxy._modify(hostname, path, resp)
                        sc.sendall(resp)

        except ssl.SSLError as e: qlog("debug", f"DirectSSL SSL error: {e}")
        except Exception   as e: qlog("debug", f"DirectSSL error: {e}")
        finally:
            try: client.close()
            except Exception: pass

    def _peek_sni(self, sock: socket.socket) -> str:
        """Kinyeri a hostname-t a TLS ClientHello SNI extension-ből."""
        try:
            sock.settimeout(3.0)
            data = sock.recv(1024, socket.MSG_PEEK)
            if not data or data[0] != 0x16:  # nem TLS
                return ""
            # TLS record → Handshake → ClientHello → extensions → SNI
            i = 5   # record header átugrása
            if data[i] != 0x01: return ""  # nem ClientHello
            i += 4  # handshake header
            i += 2  # version
            i += 32 # random
            sid_len = data[i]; i += 1 + sid_len
            cs_len  = int.from_bytes(data[i:i+2], "big"); i += 2 + cs_len
            cm_len  = data[i]; i += 1 + cm_len
            ext_len = int.from_bytes(data[i:i+2], "big"); i += 2
            end = i + ext_len
            while i < end:
                ext_type = int.from_bytes(data[i:i+2], "big"); i += 2
                ext_len2 = int.from_bytes(data[i:i+2], "big"); i += 2
                if ext_type == 0:  # SNI
                    i += 2  # list length
                    i += 1  # name type
                    name_len = int.from_bytes(data[i:i+2], "big"); i += 2
                    return data[i:i+name_len].decode("utf-8", errors="replace")
                i += ext_len2
        except Exception:
            pass
        return ""

    def _path(self, raw: bytes) -> str:
        try: return raw.split(b"\r\n")[0].decode("utf-8", errors="replace").split(" ")[1]
        except Exception: return "/"


direct_proxy = DirectSSLProxy()


# ── SOCKS5 Proxy ──────────────────────────────────────────────────────────────

# Honor IP cache – egyszer töltjük be, nem minden kérésnél
_honor_ip_cache: set[str] = set()
_honor_ip_cache_lock = threading.Lock()

def _get_honor_ips() -> set[str]:
    global _honor_ip_cache
    with _honor_ip_cache_lock:
        if not _honor_ip_cache:
            for h in HONOR_HOSTS:
                try:
                    _honor_ip_cache.add(socket.gethostbyname(h))
                except Exception:
                    pass
        return _honor_ip_cache

class SOCKS5Proxy:
    """
    Egyszerű SOCKS5 proxy listener a 8081-es porton.
    Proxifier SOCKS5 módban használja – nincs TLS wrapping,
    a forgalom tisztán érkezik és a MITMProxy dolgozza fel.
    """
    def __init__(self):
        self._srv: socket.socket | None = None
        self._running = False

    def start(self) -> bool:
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.bind((PROXY_HOST, SOCKS5_PORT))
            self._srv.listen(50)
            self._running = True
            threading.Thread(target=self._loop, daemon=True).start()
            qlog("info", f"SOCKS5 proxy running → {PROXY_HOST}:{SOCKS5_PORT}")
            return True
        except OSError as e:
            qlog("error", f"SOCKS5 start error: {e}")
            return False

    def stop(self):
        self._running = False
        if self._srv:
            try: self._srv.close()
            except Exception: pass

    def _loop(self):
        while self._running:
            try:
                self._srv.settimeout(1.0)
                client, _ = self._srv.accept()
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
            except socket.timeout: continue
            except Exception: break

    def _handle(self, client: socket.socket):
        try:
            client.settimeout(10.0)
            # SOCKS5 handshake
            data = client.recv(2)
            if not data or data[0] != 5: return
            nmethods = data[1]
            client.recv(nmethods)
            client.sendall(b"\x05\x00")  # No auth

            # Client request
            req = client.recv(4)
            if not req or req[0] != 5: return
            cmd, atyp = req[1], req[3]

            # Cél host kinyerése
            if atyp == 1:    # IPv4
                host = socket.inet_ntoa(client.recv(4))
            elif atyp == 3:  # Domain
                dlen = client.recv(1)[0]
                host = client.recv(dlen).decode("utf-8", errors="replace")
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            port_bytes = client.recv(2)
            port = int.from_bytes(port_bytes, "big")

            # Success response
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            if cmd != 1: return  # Csak CONNECT

            # Honor host felismerés – cache-elt IP lista
            honor_ips = _get_honor_ips()
            is_honor = any(h in host for h in HONOR_HOSTS) or host in honor_ips

            if is_honor and port == 80:
                # HTTP kérés beolvasása és módosítása
                qlog("info", f"[SOCKS5-HTTP] {host}:{port}")
                req_data = b""
                client.settimeout(5.0)
                while b"\r\n\r\n" not in req_data:
                    chunk = client.recv(BUFFER)
                    if not chunk: break
                    req_data += chunk
                if req_data:
                    line  = req_data.split(b"\r\n")[0].decode("utf-8", errors="replace")
                    parts = line.split(" ")
                    if len(parts) >= 2:
                        path = parts[1] if parts[1].startswith("/") else "/" + parts[1]
                        proxy._analyze(host, path)
                        with socket.create_connection((host, 80), timeout=10) as srv:
                            srv.sendall(req_data)
                            resp = proxy._recv_all(srv)
                        resp = proxy._modify(host, path, resp)
                        client.sendall(resp)
            elif is_honor and port == 443:
                # HTTPS MITM
                qlog("info", f"[SOCKS5-HTTPS] {host}:{port}")
                proxy._mitm_or_tunnel(client, host, port)
            else:
                # Nem Honor → egyszerű tunnel
                proxy._tunnel(client, host, port)

        except Exception as e:
            qlog("debug", f"SOCKS5 error: {e}")
        finally:
            try: client.close()
            except Exception: pass


socks5_proxy = SOCKS5Proxy()


# ── Local Firmware Server ─────────────────────────────────────────────────────

import http.server
import urllib.parse

LOCAL_SRV_PORT = 9090


class LocalFirmwareServer:
    """
    Beépített mini HTTP szerver – a kiválasztott ZIP fájlt szolgálja ki.
    A proxy a CDN filelist.xml válaszában kicseréli az URL-t erre.
    Így a HonorSuite a saját gépről tölti le a firmware-t.
    """

    def __init__(self):
        self._srv       = None
        self._thread    = None
        self._running   = False
        self.zip_path   = ""   # kiválasztott ZIP teljes elérési útja
        self.zip_name   = ""   # csak a fájlnév
        self.serve_url  = ""   # http://127.0.0.1:9090/fájlnév.zip

    def set_zip(self, path: str):
        self.zip_path  = path
        self.zip_name  = Path(path).name
        self.serve_url = f"http://127.0.0.1:{LOCAL_SRV_PORT}/{self.zip_name}"

    def start(self) -> bool:
        if not self.zip_path or not Path(self.zip_path).exists():
            return False
        try:
            zip_dir  = str(Path(self.zip_path).parent)
            handler  = self._make_handler(zip_dir)
            self._srv = http.server.HTTPServer(("127.0.0.1", LOCAL_SRV_PORT), handler)
            self._running = True
            self._thread  = threading.Thread(target=self._srv.serve_forever, daemon=True)
            self._thread.start()
            qlog("info", t("serve_log_start", url=self.serve_url))
            return True
        except Exception as e:
            qlog("error", f"Local server error: {e}")
            return False

    def stop(self):
        if self._srv:
            try:
                self._srv.shutdown()
                self._srv = None
            except Exception:
                pass
        self._running = False
        qlog("info", t("serve_log_stop"))

    @property
    def is_running(self) -> bool:
        return self._running

    def _make_handler(self, directory: str):
        class ZipHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(inner_self, *args, **kwargs):
                super().__init__(*args, directory=directory, **kwargs)

            def log_message(inner_self, fmt, *args):
                qlog("info", f"[LOCAL-SRV] {fmt % args}")

            def log_error(inner_self, fmt, *args):
                qlog("debug", f"[LOCAL-SRV-ERR] {fmt % args}")
        return ZipHandler


local_srv = LocalFirmwareServer()


# ── MITM Proxy ────────────────────────────────────────────────────────────────

class MITMProxy:
    def __init__(self):
        self._srv: socket.socket | None = None
        self._running = False

    def start(self):
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.bind((PROXY_HOST, PROXY_PORT))
            self._srv.listen(50)
            self._running = True
            threading.Thread(target=self._loop, daemon=True).start()
            qlog("info", t("proxy_started", host=PROXY_HOST, port=PROXY_PORT))
            socks5_proxy.start()
            return True
        except OSError as e:
            qlog("error", f"Proxy start error: {e}"); return False

    def stop(self):
        self._running = False
        if self._srv:
            try: self._srv.close()
            except Exception: pass
        socks5_proxy.stop()
        qlog("info", t("proxy_stopped"))

    def _loop(self):
        while self._running:
            try:
                self._srv.settimeout(1.0)
                client, _ = self._srv.accept()
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
            except socket.timeout: continue
            except Exception: break

    def _handle(self, client):
        try:
            client.settimeout(5.0)
            # Első byte peek – TLS vagy HTTP?
            first = client.recv(1, socket.MSG_PEEK)
            if not first: return

            if first[0] == 0x16:
                # TLS ClientHello – Proxifier közvetlen SSL módban küld
                # Megpróbáljuk kideríteni a target hostot az SNI-ből
                hostname = direct_proxy._peek_sni(client) or ""
                # Ha Honor CDN host és nem 443-as port → HTTP tunnel
                # (Proxifier TLS-ben küldi a port 80-as kérést is)
                if any(h in hostname for h in HONOR_HOSTS):
                    try:
                        cf, kf = cert_mgr.host_cert(hostname)
                        ctx_c  = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        ctx_c.load_cert_chain(cf, kf)
                        with ctx_c.wrap_socket(client, server_side=True) as sc:
                            data = b""
                            sc.settimeout(5.0)
                            while b"\r\n\r\n" not in data:
                                chunk = sc.recv(BUFFER)
                                if not chunk: break
                                data += chunk
                            if data:
                                line  = data.split(b"\r\n")[0].decode("utf-8", errors="replace")
                                parts = line.split(" ")
                                if len(parts) >= 2:
                                    path = parts[1] if parts[1].startswith("/") else "/" + parts[1]
                                    qlog("debug", f"[TLS_TUNNEL] {hostname}{path}")
                                    self._analyze(hostname, path)
                                    with socket.create_connection((hostname, 80), timeout=10) as srv:
                                        srv.sendall(data)
                                        resp = self._recv_all(srv)
                                    resp = self._modify(hostname, path, resp)
                                    sc.sendall(resp)
                    except Exception as e:
                        qlog("debug", f"TLS tunnel error ({hostname}): {e}")
                else:
                    direct_proxy._handle(client)
                return

            # HTTP – olvassuk a teljes fejlécet
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(BUFFER)
                if not chunk: return
                data += chunk

            line  = data.split(b"\r\n")[0].decode("utf-8", errors="replace")
            parts = line.split(" ")
            if len(parts) < 2: return
            method, target = parts[0], parts[1]
            if method == "CONNECT": self._connect(client, target, data)
            else:                   self._http(client, target, data)
        except Exception as e:
            qlog("debug", f"Handle error: {e}")
        finally:
            try: client.close()
            except Exception: pass

    def _http(self, client, target, data):
        try:
            if target.startswith("http://"): target = target[7:]
            host, _, path = target.partition("/"); path = "/" + path
            port = 80
            if ":" in host: host, p = host.rsplit(":", 1); port = int(p)
            if any(h in host for h in HONOR_HOSTS): self._analyze(host, path)
            with socket.create_connection((host, port), timeout=10) as srv:
                srv.sendall(data)
                resp = self._recv_all(srv)
            resp = self._modify(host, path, resp)
            client.sendall(resp)
        except Exception as e:
            qlog("debug", f"HTTP error: {e}")
            try: client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception: pass

    def _connect(self, client, target, data=None):
        host, _, port_str = target.rpartition(":")
        port = int(port_str) if port_str else 443
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # Port 80 → HTTP tunnel (Proxifier CONNECT-et küld de HTTP GET jön utána)
        if port == 80:
            if any(h in host for h in HONOR_HOSTS):
                self._http_tunnel(client, host)
            else:
                self._tunnel(client, host, port)
            return
        # Honor host → logoljuk a CONNECT kérést, majd tunnel
        if any(h in host for h in HONOR_HOSTS):
            qlog("info", f"[CONNECT] {host}:{port}")
            self._mitm_or_tunnel(client, host, port)
        else:
            self._tunnel(client, host, port)

    def _http_tunnel(self, client, host):
        """Port 80-as CONNECT tunnel után HTTP GET kezelése."""
        try:
            client.settimeout(10.0)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(BUFFER)
                if not chunk: return
                data += chunk
            line  = data.split(b"\r\n")[0].decode("utf-8", errors="replace")
            parts = line.split(" ")
            if len(parts) < 2: return
            path = parts[1] if parts[1].startswith("/") else "/" + parts[1].split("/", 3)[-1]
            qlog("debug", f"[HTTP_TUNNEL] {host}{path}")
            self._analyze(host, path)
            with socket.create_connection((host, 80), timeout=10) as srv:
                srv.sendall(data)
                resp = self._recv_all(srv)
            resp = self._modify(host, path, resp)
            client.sendall(resp)
        except Exception as e:
            qlog("debug", f"HTTP tunnel error ({host}): {e}")

    def _mitm_or_tunnel(self, client, host, port):
        """
        Megpróbálja MITM-elni. Ha az SSL handshake sikertelen
        (pl. certificate pinning), visszaesik egyszerű tunnelre
        és csak a CONNECT URL-t logoljuk.
        """
        try:
            cf, kf = cert_mgr.host_cert(host)
            ctx_c  = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx_c.load_cert_chain(cf, kf)
            with ctx_c.wrap_socket(client, server_side=True) as sc:
                ctx_s = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=10) as raw:
                    with ctx_s.wrap_socket(raw, server_hostname=host) as ss:
                        req = sc.recv(BUFFER * 4)
                        if not req: return
                        path = self._path(req)
                        self._analyze(host, path)
                        ss.sendall(req)
                        resp = self._recv_all(ss)
                        resp = self._modify(host, path, resp)
                        sc.sendall(resp)
        except ssl.SSLError:
            # Certificate pinning vagy más SSL hiba → egyszerű tunnel
            # A CONNECT URL-t már logoltuk fent
            qlog("debug", f"SSL MITM sikertelen ({host}) → tunnel mód")
            self._tunnel(client, host, port)
        except Exception as e:
            qlog("debug", f"MITM ({host}): {e}")
            self._tunnel(client, host, port)

    def _tunnel(self, client, host, port):
        try:
            with socket.create_connection((host, port), timeout=10) as srv:
                socks = [client, srv]
                while True:
                    r, _, ex = select.select(socks, [], socks, 5)
                    if ex: break
                    for s in r:
                        d = s.recv(BUFFER)
                        if not d: return
                        (srv if s is client else client).sendall(d)
        except Exception: pass

    def _recv_all(self, sock) -> bytes:
        data = b""; sock.settimeout(5.0)
        try:
            while True:
                chunk = sock.recv(BUFFER)
                if not chunk: break
                data += chunk
        except socket.timeout: pass
        return data

    def _path(self, raw: bytes) -> str:
        try: return raw.split(b"\r\n")[0].decode("utf-8", errors="replace").split(" ")[1]
        except Exception: return "/"

    def _analyze(self, host, path):
        url = f"https://{host}{path}"

        # Új CDN struktúra: /TDS/data/bl/files/v{ID}/f1/full/filelist.xml
        m = CDN_PATTERN.search(path)
        if m:
            vid = m.group(1)
            qlog("info", "═" * 50)
            qlog("info", f"🎯 {t('cdn_found_banner')}")
            qlog("info", f"   {url}")
            qlog("info", f"   ID: {vid}")
            qlog("info", "═" * 50)
            state.set_cdn_found_new(vid)
            return

        # Régi CDN struktúra fallback
        m2 = CDN_PATTERN_OLD.search(path)
        if m2:
            g, gsub, vid = m2.group(1), m2.group(2), m2.group(3)
            qlog("info", "═" * 50)
            qlog("info", f"🎯 {t('cdn_found_banner')} (old structure)")
            qlog("info", f"   {url}")
            qlog("info", f"   G: {g}/{gsub}  │  ID: {vid}")
            qlog("info", "═" * 50)
            state.set_cdn_found(g, gsub, vid)
            return

        if "CheckNewVersion" in path or "onestopCheck" in path:
            qlog("info",  f"[OTA_CHECK] {url}")
        elif "authorize" in path: qlog("info", f"[AUTH] {url}")
        elif "erecovery" in path: qlog("info", f"[ERECOVERY] {url}")
        elif path and path != "/": qlog("info", f"[HONOR] {url}")
        else:                      qlog("info", f"[HONOR] {host}")

    def _modify(self, host, path, resp):
        if state.phase != 2 or not state.target_version: return resp
        if "onestopCheck" not in path and "filelist.xml" not in path: return resp

        try:
            hdr, _, body = resp.partition(b"\r\n\r\n")
            bs = orig = body.decode("utf-8", errors="replace")

            # ── filelist.xml URL csere helyi szerverre ────────────────────────
            if "filelist.xml" in path and local_srv.is_running and local_srv.zip_name:
                # Minden CDN URL-t kicserélünk a helyi szerver URL-jére
                bs = re.sub(
                    r"http://update\.hihonorcdn\.com/TDS/data/bl/files/v\d+/f1/full/[^\s<\"]+\.zip",
                    local_srv.url,
                    bs
                )
                if bs != orig:
                    qlog("info", f"[LOCAL-SRV] filelist.xml URL → {local_srv.url}")

            # ── OTA check verzió csere ────────────────────────────────────────
            if "onestopCheck" in path:
                for pat, rep in [
                    (r"<Version>[^<]+</Version>",  f"<Version>{state.target_version}</Version>"),
                    (r"<version>[^<]+</version>",  f"<version>{state.target_version}</version>"),
                    (r'"version"\s*:\s*"[^"]*"',   f'"version": "{state.target_version}"'),
                ]:
                    bs = re.sub(pat, rep, bs)
                if bs != orig:
                    qlog("info", t("ota_modified", ver=state.target_version))

            if bs != orig:
                nb = bs.encode("utf-8")
                hs = re.sub(rb"Content-Length:\s*\d+",
                            f"Content-Length: {len(nb)}".encode(), hdr)
                return hs + b"\r\n\r\n" + nb
        except Exception as e:
            qlog("debug", f"Modify error: {e}")
        return resp


proxy = MITMProxy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.geometry("920x700")
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._proxy_running = False
        self._scan_stop     = threading.Event()
        self._scan_running  = False
        self._setup_style()
        self._build_ui()
        self._poll_log()

    def _setup_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TNotebook",       background=BG,   borderwidth=0)
        s.configure("TNotebook.Tab",   background=BG2,  foreground=FG, padding=[14, 6])
        s.map("TNotebook.Tab",         background=[("selected", BLUE)])
        s.configure("TFrame",          background=BG)
        s.configure("TLabel",          background=BG,   foreground=FG)
        s.configure("TButton",         background=BG2,  foreground=FG, padding=[10, 5])
        s.map("TButton",               background=[("active", "#45475a")])
        s.configure("Accent.TButton",  background=BLUE, foreground=BG,
                    padding=[10, 5], font=("Segoe UI", 9, "bold"))
        s.configure("TEntry",          fieldbackground=BG2, foreground=FG, insertcolor=FG)
        s.configure("Treeview",        background=BG3,  foreground=FG,
                    fieldbackground=BG3, rowheight=22)
        s.configure("Treeview.Heading", background=BG2, foreground=BLUE)
        s.map("Treeview",              background=[("selected", BLUE)])
        s.configure("TProgressbar",    troughcolor=BG2, background=BLUE)
        s.configure("TCombobox",       fieldbackground=BG2, foreground=FG,
                    selectbackground=BLUE, selectforeground=BG)

    def _build_ui(self):
        # ── Language selector (top bar) ───────────────────────────────────────
        top = tk.Frame(self, bg=BG2, pady=4)
        top.pack(fill=tk.X)
        tk.Label(top, text=t("lang_label"), bg=BG2, fg=FG_DIM,
                 font=FONT).pack(side=tk.RIGHT, padx=(0, 6))
        self._lang_var = tk.StringVar(value=state.language)
        lang_cb = ttk.Combobox(top, textvariable=self._lang_var,
                               values=["EN", "HU"], width=5, state="readonly")
        lang_cb.pack(side=tk.RIGHT, padx=(0, 4))
        lang_cb.bind("<<ComboboxSelected>>", self._on_lang_change)

        # ── Notebook ──────────────────────────────────────────────────────────
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self._tab_proxy(self._nb)
        self._tab_finder(self._nb)
        self._tab_cert(self._nb)
        self._tab_about(self._nb)

        # ── Status bar ────────────────────────────────────────────────────────
        self._status_var = tk.StringVar(value=t("status_stopped"))
        ttk.Label(self, textvariable=self._status_var,
                  relief=tk.SUNKEN, anchor=tk.W,
                  background=BG2, foreground=GREEN).pack(
            side=tk.BOTTOM, fill=tk.X, padx=2, pady=2)

        self._update_title()

    def _on_lang_change(self, _event=None):
        lang = self._lang_var.get()
        set_lang(lang)
        state.language = lang
        state.save()
        # Újraépítjük a teljes UI-t
        for w in self.winfo_children():
            w.destroy()
        self._setup_style()
        self._build_ui()
        self._poll_log()

    def _update_title(self):
        self.title(f"{t('app_title')} v{APP_VERSION}")

    # ─────────────────────────────────────────────────────────────────────────
    # Proxy tab
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_proxy(self, nb):
        tab = ttk.Frame(nb); nb.add(tab, text=t("tab_proxy"))
        f = ttk.Frame(tab, padding=12); f.pack(fill=tk.BOTH, expand=True)

        row = ttk.Frame(f); row.pack(fill=tk.X, pady=(0, 10))
        self._phase_var = tk.StringVar(value=self._phase_lbl())
        self._tgt_var   = tk.StringVar(value=state.target_version or t("no_target"))
        self._cdn_var   = tk.StringVar(
            value=state.cdn_base_url or t("cdn_unknown"))

        self._card(row, t("card_phase"),  self._phase_var, BLUE  ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,4))
        self._card(row, t("card_target"), self._tgt_var,   GREEN ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,4))
        self._card(row, t("card_cdn"),    self._cdn_var,   FG_DIM, wrap=380).pack(side=tk.LEFT, fill=tk.X, expand=True)

        br = ttk.Frame(f); br.pack(fill=tk.X, pady=6)
        self._start_btn = ttk.Button(br, text=t("btn_start_proxy"),
                                     style="Accent.TButton",
                                     command=self._toggle_proxy)
        self._start_btn.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(br, text=t("proxy_hint"), foreground=FG_DIM).pack(side=tk.LEFT)

        # Külső proxy mód pipa
        ep = ttk.Frame(f); ep.pack(fill=tk.X, pady=(4, 2))
        self._ext_proxy_var = tk.BooleanVar(value=state.ext_proxy_mode)
        self._ext_cb = ttk.Checkbutton(ep, text=t("ext_proxy_label"),
                                        variable=self._ext_proxy_var,
                                        command=self._on_ext_proxy_toggle)
        self._ext_cb.pack(side=tk.LEFT)
        self._ext_hint_lbl = tk.Label(ep, text=t("ext_proxy_hint"),
                                       bg=BG, fg=YELLOW, font=("Segoe UI", 8),
                                       justify=tk.LEFT)
        self._ext_hint_lbl.pack(side=tk.LEFT, padx=(10, 0))

        # Force system proxy sor
        fr = ttk.Frame(f); fr.pack(fill=tk.X, pady=(0, 2))
        self._force_proxy_btn = ttk.Button(fr, text=t("btn_force_proxy"),
                                            command=self._force_sys_proxy)
        self._force_proxy_btn.pack(side=tk.LEFT, padx=(0, 8))
        self._clear_proxy_btn = ttk.Button(fr, text=t("btn_clear_proxy"),
                                            command=self._clear_sys_proxy)
        self._clear_proxy_btn.pack(side=tk.LEFT)

        # Hosts redirect sor
        hr = ttk.Frame(f); hr.pack(fill=tk.X, pady=(0, 4))
        self._hosts_set_btn = ttk.Button(hr, text=t("btn_hosts_set"),
                                          style="Accent.TButton",
                                          command=self._set_hosts)
        self._hosts_set_btn.pack(side=tk.LEFT, padx=(0, 8))
        self._hosts_clear_btn = ttk.Button(hr, text=t("btn_hosts_clear"),
                                            command=self._clear_hosts)
        self._hosts_clear_btn.pack(side=tk.LEFT)

        # Gombok állapota a pipa szerint
        self._apply_ext_proxy_state()

        # ── Local Firmware Server szekció ────────────────────────────────────
        lfs = tk.Frame(f, bg=BG2, padx=10, pady=8)
        lfs.pack(fill=tk.X, pady=(4, 0))

        tk.Label(lfs, text=t("local_srv_title"), bg=BG2, fg=BLUE,
                 font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, pady=(0, 4))
        tk.Label(lfs, text=t("serve_hint"), bg=BG2, fg=FG_DIM,
                 font=("Segoe UI", 8), justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 6))

        # ZIP kiválasztás sor
        zr = tk.Frame(lfs, bg=BG2); zr.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(zr, text=t("btn_pick_zip"),
                   command=self._pick_zip).pack(side=tk.LEFT, padx=(0, 8))
        self._zip_lbl = tk.StringVar(value=t("no_zip_selected"))
        tk.Label(zr, textvariable=self._zip_lbl,
                 bg=BG2, fg=GREEN, font=FONT).pack(side=tk.LEFT)

        # Szerver indítás sor
        sr = tk.Frame(lfs, bg=BG2); sr.pack(fill=tk.X)
        self._serve_btn = ttk.Button(sr, text=t("btn_serve_start"),
                                      command=self._toggle_local_server)
        self._serve_btn.pack(side=tk.LEFT, padx=(0, 8))
        self._serve_status = tk.StringVar(value="")
        tk.Label(sr, textvariable=self._serve_status,
                 bg=BG2, fg=YELLOW, font=FONT).pack(side=tk.LEFT)

        ttk.Label(f, text=t("log_label"), foreground=BLUE).pack(anchor=tk.W, pady=(6, 2))
        self._log_box = scrolledtext.ScrolledText(
            f, height=20, bg=BG3, fg=FG, font=MONO,
            insertbackground=FG, state=tk.DISABLED)
        self._log_box.pack(fill=tk.BOTH, expand=True)
        for tag, color in [("CDN", GREEN), ("ERROR", RED),
                            ("WARN", YELLOW), ("INFO", FG), ("DEBUG", FG_DIM)]:
            self._log_box.tag_config(tag, foreground=color)
        ttk.Button(f, text=t("btn_clear_log"),
                   command=self._clear_log).pack(anchor=tk.E, pady=4)

    def _card(self, parent, label, var, fg, wrap=250):
        c = tk.Frame(parent, bg=BG2, padx=10, pady=8)
        tk.Label(c, text=label, bg=BG2, fg=FG_DIM,
                 font=("Segoe UI", 8)).pack(anchor=tk.W)
        tk.Label(c, textvariable=var, bg=BG2, fg=fg,
                 font=("Segoe UI", 9, "bold"),
                 wraplength=wrap, justify=tk.LEFT).pack(anchor=tk.W)
        return c

    # ─────────────────────────────────────────────────────────────────────────
    # Firmware Finder tab
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_finder(self, nb):
        tab = ttk.Frame(nb); nb.add(tab, text=t("tab_finder"))
        f = ttk.Frame(tab, padding=12); f.pack(fill=tk.BOTH, expand=True)

        cfg = tk.Frame(f, bg=BG2, padx=14, pady=12); cfg.pack(fill=tk.X, pady=(0, 8))

        tk.Label(cfg, text=t("finder_title"), bg=BG2, fg=FG_DIM,
                 font=("Segoe UI", 8)).pack(anchor=tk.W, pady=(0, 6))

        for lbl_key, attr, hint_key, default in [
            ("fw_ver_label", "_fw_ver_var",  "fw_ver_hint",  ""),
            ("model_label",  "_model_var",   "model_hint",   "ELP-N39"),
            ("region_label", "_build_var",   "region_hint",  ""),
        ]:
            row = tk.Frame(cfg, bg=BG2); row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=t(lbl_key), bg=BG2, fg=FG,
                     width=18, anchor=tk.W).pack(side=tk.LEFT)
            var = tk.StringVar(value=default)
            setattr(self, attr, var)
            ttk.Entry(row, textvariable=var, width=18).pack(side=tk.LEFT, padx=(0, 8))
            tk.Label(row, text=t(hint_key), bg=BG2, fg=FG_DIM,
                     font=("Segoe UI", 8)).pack(side=tk.LEFT)

        # Package type szűrő
        pkg_row = tk.Frame(cfg, bg=BG2); pkg_row.pack(fill=tk.X, pady=2)
        tk.Label(pkg_row, text=t("pkg_type_label"), bg=BG2, fg=FG,
                 width=18, anchor=tk.W).pack(side=tk.LEFT)
        self._pkg_type_var = tk.StringVar(value="Any")
        pkg_cb = ttk.Combobox(pkg_row, textvariable=self._pkg_type_var,
                              values=["Any", "PRELOAD", "CUST", "BASE", "FULL", "DELTA"],
                              width=10, state="readonly")
        pkg_cb.pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(pkg_row,
                 text={"EN": "PRELOAD=factory  CUST=operator  BASE/FULL=OTA  DELTA=incremental",
                       "HU": "PRELOAD=gyári  CUST=operátor  BASE/FULL=OTA  DELTA=különbségi"
                       }.get(_current_lang, ""),
                 bg=BG2, fg=FG_DIM, font=("Segoe UI", 8)).pack(side=tk.LEFT)

        # Build suffix szűrő
        sfx_row = tk.Frame(cfg, bg=BG2); sfx_row.pack(fill=tk.X, pady=2)
        tk.Label(sfx_row, text=t("suffix_label"), bg=BG2, fg=FG,
                 width=18, anchor=tk.W).pack(side=tk.LEFT)
        self._suffix_var = tk.StringVar(value="")
        ttk.Entry(sfx_row, textvariable=self._suffix_var,
                  width=12).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(sfx_row, text=t("suffix_hint"), bg=BG2, fg=FG_DIM,
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)

        ttk.Separator(cfg, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)

        # Advanced toggle
        self._adv_open = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg, text=t("adv_toggle"),
                        variable=self._adv_open,
                        command=self._toggle_adv).pack(anchor=tk.W)

        self._adv_frame = tk.Frame(cfg, bg=BG2)
        rng = tk.Frame(self._adv_frame, bg=BG2); rng.pack(anchor=tk.W, pady=4)
        for lbl_key, attr, default, w in [
            ("adv_from", "scan_from", "750000", 8),
            ("adv_to",   "scan_to",   "760000", 8),
            ("adv_step", "scan_step", "1",      6),
        ]:
            tk.Label(rng, text=t(lbl_key), bg=BG2, fg=FG).pack(side=tk.LEFT)
            var = tk.StringVar(value=default)
            setattr(self, f"_{attr}", var)
            ttk.Entry(rng, textvariable=var, width=w).pack(side=tk.LEFT, padx=(4, 14))

        # Szálak száma
        thr = tk.Frame(self._adv_frame, bg=BG2); thr.pack(anchor=tk.W, pady=(0, 4))
        tk.Label(thr, text=t("threads_label"), bg=BG2, fg=FG).pack(side=tk.LEFT)
        self._threads_var = tk.StringVar(value=str(state.scan_threads))
        ttk.Spinbox(thr, from_=1, to=32, width=5,
                    textvariable=self._threads_var).pack(side=tk.LEFT, padx=(4, 0))
        tk.Label(thr, text="  (4–16 ajánlott)", bg=BG2, fg=FG_DIM,
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)

        tk.Label(self._adv_frame, text=t("adv_hint"), bg=BG2, fg=FG_DIM,
                 font=("Segoe UI", 8)).pack(anchor=tk.W)

        btn_r = tk.Frame(cfg, bg=BG2); btn_r.pack(anchor=tk.W, pady=(10, 0))
        self._scan_btn = ttk.Button(btn_r, text=t("btn_search"),
                                    style="Accent.TButton",
                                    command=self._start_scan)
        self._scan_btn.pack(side=tk.LEFT)
        ttk.Button(btn_r, text=t("btn_clear_list"),
                   command=self._clear_tree).pack(side=tk.LEFT, padx=8)

        # Progress
        self._prog_var = tk.DoubleVar(value=0)
        self._prog_lbl = tk.StringVar(value="")
        ttk.Progressbar(f, variable=self._prog_var, maximum=100).pack(fill=tk.X, pady=(0, 2))
        ttk.Label(f, textvariable=self._prog_lbl, foreground=FG_DIM).pack(anchor=tk.W, pady=(0, 6))

        # Gombsor – a lista ELŐTT, hogy mindig látszódjon
        sel_f = ttk.Frame(f, padding=(0, 4)); sel_f.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(sel_f, text=t("btn_set_target"),
                   style="Accent.TButton",
                   command=self._select_version).pack(side=tk.LEFT)
        ttk.Button(sel_f, text="📋  Copy URL",
                   command=self._copy_url).pack(side=tk.LEFT, padx=(8, 0))
        self._sel_lbl = tk.StringVar(value=t("sel_hint"))
        tk.Label(sel_f, textvariable=self._sel_lbl,
                 bg=BG, fg=FG_DIM, font=FONT).pack(side=tk.LEFT, padx=10)

        # Table
        frm = tk.Frame(f, bg=BG); frm.pack(fill=tk.BOTH, expand=True)
        cols = ("version", "id", "type", "region", "size", "url")
        self._tree = ttk.Treeview(frm, columns=cols, show="headings", height=12)
        for col, lbl_key, w in [
            ("version", "col_version", 130),
            ("id",      "col_id",       70),
            ("type",    "col_type",     70),
            ("region",  "col_region",   60),
            ("size",    "col_size",     80),
            ("url",     "col_url",     360),
        ]:
            self._tree.heading(col, text=t(lbl_key),
                               command=lambda c=col: self._sort_tree(c))
            self._tree.column(col, width=w, minwidth=w)

        sb = ttk.Scrollbar(frm, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.LEFT, fill=tk.Y)

        # Jobb klikk context menu
        self._tree_menu = tk.Menu(self, tearoff=0, bg=BG2, fg=FG,
                                   activebackground=BLUE, activeforeground=BG)
        self._tree_menu.add_command(label="📋  Copy URL",
                                    command=self._copy_url)
        self._tree_menu.add_command(label="📋  Copy all columns",
                                    command=self._copy_row)
        self._tree.bind("<Button-3>", self._show_tree_menu)

        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        if state.fw_list:
            self._load_entries(state.fw_list)

    def _toggle_adv(self):
        if self._adv_open.get(): self._adv_frame.pack(fill=tk.X, pady=(4, 0))
        else:                    self._adv_frame.pack_forget()

    def _show_tree_menu(self, event):
        row = self._tree.identify_row(event.y)
        if row:
            self._tree.selection_set(row)
            self._tree_menu.post(event.x_root, event.y_root)

    def _copy_url(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("Warning", t("warn_select_row")); return
        url = self._tree.item(sel[0], "values")[5]
        self.clipboard_clear()
        self.clipboard_append(url)
        self._sel_lbl.set("✅  URL copied!")
        self.after(2000, lambda: self._sel_lbl.set(t("sel_hint")))

    def _copy_row(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("Warning", t("warn_select_row")); return
        vals = self._tree.item(sel[0], "values")
        row_str = "\t".join(str(v) for v in vals)
        self.clipboard_clear()
        self.clipboard_append(row_str)
        self._sel_lbl.set("✅  Row copied!")
        self.after(2000, lambda: self._sel_lbl.set(t("sel_hint")))

    def _start_scan(self):
        if self._scan_running:
            self._scan_stop.set()
            self._scan_btn.configure(text=t("btn_search"))
            self._scan_running = False
            return

        fw_ver   = self._fw_ver_var.get().strip()
        build    = self._build_var.get().strip()
        model    = self._model_var.get().strip()
        pkg_type = self._pkg_type_var.get().strip()
        suffix   = self._suffix_var.get().strip()
        if pkg_type == "Any":
            pkg_type = ""

        if self._adv_open.get():
            try:
                s    = int(self._scan_from.get())
                e    = int(self._scan_to.get())
                step = max(1, int(self._scan_step.get()))
            except ValueError:
                messagebox.showerror("Error", "Invalid ID range!"); return
        else:
            if state.known_ids:
                base = int(state.known_ids[-1])
                s, e, step = base - 2000, base + 5000, 1
            else:
                # Ismert ID: 753724 (Fiddlerrel elfogva 2026.04.03)
                s, e, step = 750000, 760000, 1

        if not fw_ver and not build and not model and not pkg_type and not suffix:
            if not messagebox.askyesno(t("warn_no_filter_title"), t("warn_no_filter")):
                return

        self._scan_stop.clear()
        self._scan_running = True
        self._scan_btn.configure(text=t("btn_stop_scan"))
        self._prog_var.set(0)

        parts = []
        if fw_ver:   parts.append(t("filter_ver",    v=fw_ver))
        if model:    parts.append(f"model: {model}")
        if build:    parts.append(t("filter_region", r=build))
        if pkg_type: parts.append(f"type: {pkg_type}")
        if suffix:   parts.append(f"suffix: {suffix}")
        filter_str = ", ".join(parts) if parts else t("filter_none")
        qlog("info", t("scan_log_start", filter=filter_str))
        qlog("info", t("scan_log_range", s=s, e=e, step=step))

        def progress(i, total, vid):
            self.after(0, lambda c=i, tt=total, v=vid:
                       self._update_scan_progress(c, tt, v))

        def result(entries):
            state.fw_list.extend(entries)
            state.save()
            for entry in entries:
                self.after(0, lambda e=entry: self._add_to_treeview(e))

        def run():
            try:
                threads = max(1, min(32, int(self._threads_var.get())))
            except ValueError:
                threads = 16
            state.scan_threads = threads
            state.save()
            cdn_client.scan_versions(
                fw_ver, build, s, e, step, progress, result, self._scan_stop,
                threads=threads, model_filter=model, pkg_type_filter=pkg_type,
                suffix_filter=suffix)
            self._scan_running = False
            self.after(0, lambda: self._scan_btn.configure(text=t("btn_search")))

        threading.Thread(target=run, daemon=True).start()

    def _update_scan_progress(self, completed, total, vid):
        """Thread-safe progress frissítés – mindig főszálon hívódik via after(0,...)."""
        pct = (completed / max(total, 1)) * 100
        self._prog_var.set(pct)
        if vid:
            self._prog_lbl.set(t("scan_progress", i=completed, total=total, vid=vid))
        else:
            self._prog_lbl.set(t("scan_done"))

    def _add_to_treeview(self, entry):
        """Thread-safe treeview beszúrás – mindig főszálon hívódik via after(0,...)."""
        self._tree.insert("", tk.END, values=(
            entry.fw_version, entry.version_id, entry.pkg_type,
            entry.region, str(entry.size_mb), entry.url))

    def _load_entries(self, entries):
        """Több entry egyszerre – főszálon belülről hívható."""
        for e in entries:
            self._tree.insert("", tk.END, values=(
                e.fw_version, e.version_id, e.pkg_type,
                e.region, str(e.size_mb), e.url))

    def _clear_tree(self):
        self._tree.delete(*self._tree.get_children())
        state.fw_list.clear(); state.save()
        self._prog_var.set(0); self._prog_lbl.set("")

    def _on_tree_select(self, _event):
        sel = self._tree.selection()
        if sel:
            v = self._tree.item(sel[0], "values")
            self._sel_lbl.set(t("selected_row",
                ver=v[0], type=v[2], region=v[3], id=v[1]))

    def _select_version(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Info", t("warn_select_row")); return
        vals = self._tree.item(sel[0], "values")
        fw_ver, ver_id, pkg_type, region = vals[0], vals[1], vals[2], vals[3]
        state.target_version = fw_ver
        state.target_id      = ver_id
        state.phase          = 2
        state.save()
        self._refresh_cards()
        qlog("info", t("target_set_log", ver=fw_ver, type=pkg_type, region=region, id=ver_id))
        messagebox.showinfo(t("info_set_target"),
            t("info_set_target_body", ver=fw_ver, type=pkg_type, region=region, id=ver_id))

    def _sort_tree(self, col):
        data = [(self._tree.set(k, col), k) for k in self._tree.get_children("")]
        data.sort()
        for i, (_, k) in enumerate(data):
            self._tree.move(k, "", i)

    # ─────────────────────────────────────────────────────────────────────────
    # Certificate tab
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_cert(self, nb):
        tab = ttk.Frame(nb); nb.add(tab, text=t("tab_cert"))
        f = ttk.Frame(tab, padding=16); f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text=t("cert_intro"), foreground=FG_DIM).pack(anchor=tk.W, pady=(0, 16))

        for key, cmd in [
            ("btn_gen_ca",     self._gen_ca),
            ("btn_install_ca", self._install_ca),
            ("btn_export_ca",  self._export_ca),
            ("btn_import_ca",  self._import_ca),
            ("btn_remove_ca",  self._uninstall_ca),
        ]:
            ttk.Button(f, text=t(key), command=cmd, width=44).pack(anchor=tk.W, pady=3)

        ttk.Separator(f).pack(fill=tk.X, pady=12)
        tk.Label(f, text=t("cert_order_title") + "\n" + t("cert_order"),
                 bg=BG, fg=YELLOW, font=FONT, justify=tk.LEFT).pack(anchor=tk.W)

    # ─────────────────────────────────────────────────────────────────────────
    # About tab
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_about(self, nb):
        tab = ttk.Frame(nb); nb.add(tab, text=t("tab_about"))
        f = ttk.Frame(tab, padding=16); f.pack(fill=tk.BOTH, expand=True)
        tk.Label(f, text=t("about_text", ver=APP_VERSION, port=PROXY_PORT,
                            dir=CERT_DIR, log=LOG_FILE),
                 bg=BG, fg=FG, font=FONT, justify=tk.LEFT).pack(anchor=tk.W)
        ttk.Button(f, text=t("btn_open_folder"),
                   command=lambda: os.startfile(str(CERT_DIR))).pack(anchor=tk.W, pady=12)

    # ─────────────────────────────────────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────────────────────────────────────
    def _pick_zip(self):
        path = filedialog.askopenfilename(
            title="Select firmware ZIP",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")])
        if path:
            local_srv.set_zip(path)
            size = round(Path(path).stat().st_size / 1024 / 1024, 1)
            self._zip_lbl.set(t("zip_selected",
                                name=local_srv.zip_name, size=size))
            qlog("info", f"ZIP selected: {local_srv.zip_name} ({size} MB)")

    def _toggle_local_server(self):
        if local_srv.is_running:
            local_srv.stop()
            self._serve_btn.configure(text=t("btn_serve_start"))
            self._serve_status.set(t("serve_stopped"))
        else:
            if not local_srv.zip_path:
                messagebox.showwarning("Warning", t("serve_no_zip"))
                return
            if local_srv.start():
                self._serve_btn.configure(text=t("btn_serve_stop"))
                self._serve_status.set(t("serve_running",
                    port=LOCAL_SRV_PORT,
                    name=local_srv.zip_name))
            else:
                messagebox.showerror("Error",
                    f"Port {LOCAL_SRV_PORT} already in use!")

    def _on_ext_proxy_toggle(self):
        state.ext_proxy_mode = self._ext_proxy_var.get()
        state.save()
        self._apply_ext_proxy_state()

    def _apply_ext_proxy_state(self):
        """Gombok engedélyezése/tiltása külső proxy mód szerint."""
        enabled = not state.ext_proxy_mode
        state_str = tk.NORMAL if enabled else tk.DISABLED
        for btn in [self._force_proxy_btn, self._clear_proxy_btn,
                    self._hosts_set_btn, self._hosts_clear_btn]:
            try: btn.configure(state=state_str)
            except Exception: pass
        # Hint láthatósága
        if state.ext_proxy_mode:
            self._ext_hint_lbl.pack(side=tk.LEFT, padx=(10, 0))
        else:
            self._ext_hint_lbl.pack_forget()

    def _set_hosts(self):
        if not _is_admin():
            messagebox.showwarning("Warning", t("sysproxy_no_admin")); return
        if not self._proxy_running:
            messagebox.showwarning("Warning",
                "Start the proxy first!" if _current_lang == "EN"
                else "Először indítsd el a proxyt!"); return
        # Indítjuk a közvetlen 443-as proxy-t is
        direct_proxy.start()
        ok = hosts_mgr.set_redirect()
        if ok:
            messagebox.showinfo("OK", t("hosts_ok"))
        else:
            messagebox.showerror("Error", t("hosts_err"))

    def _clear_hosts(self):
        direct_proxy.stop()
        ok = hosts_mgr.clear_redirect()
        (messagebox.showinfo if ok else messagebox.showerror)(
            "OK" if ok else "Error",
            t("hosts_clear_ok") if ok else t("hosts_clear_err"))

    def _force_sys_proxy(self):
        if not self._proxy_running:
            messagebox.showwarning("Warning",
                "Start the proxy first!" if _current_lang == "EN"
                else "Először indítsd el a proxyt!")
            return
        if not _is_admin():
            messagebox.showwarning("Warning", t("sysproxy_no_admin"))
            return
        ok = sys_proxy.set_proxy()
        if ok:
            messagebox.showinfo("OK", t("sysproxy_ok"))
        else:
            messagebox.showerror("Error", t("sysproxy_err"))

    def _clear_sys_proxy(self):
        ok = sys_proxy.clear_proxy()
        (messagebox.showinfo if ok else messagebox.showerror)(
            "OK" if ok else "Error",
            t("sysproxy_clear_ok") if ok else t("sysproxy_clear_err"))

    def _toggle_proxy(self):
        if self._proxy_running:
            proxy.stop()
            socks5_proxy.stop()
            self._proxy_running = False
            self._start_btn.configure(text=t("btn_start_proxy"))
            self._status_var.set(t("status_stopped"))
        else:
            if not CRYPTO_OK:
                messagebox.showerror("Error", t("err_no_crypto")); return
            if not cert_mgr.ensure_ca():
                messagebox.showerror("Error", t("err_ca_failed")); return
            if proxy.start():
                socks5_proxy.start()   # SOCKS5 is indul
                self._proxy_running = True
                self._start_btn.configure(text=t("btn_stop_proxy"))
                status = t("status_running", port=PROXY_PORT)
                status += (t("status_target", ver=state.target_version)
                           if state.target_version else t("status_phase1"))
                self._status_var.set(status)
                qlog("info", t("log_connect_phone"))
            else:
                messagebox.showerror("Error", t("err_proxy_start", port=PROXY_PORT))

    def _gen_ca(self):
        ok = cert_mgr.generate_ca()
        (messagebox.showinfo if ok else messagebox.showerror)(
            "OK" if ok else "Error",
            t("cert_gen_ok") if ok else t("cert_gen_err"))

    def _install_ca(self):
        if not CA_CRT_FILE.exists():
            messagebox.showwarning("Warning", t("cert_no_ca")); return
        ok = cert_mgr.install_ca()
        (messagebox.showinfo if ok else messagebox.showerror)(
            "OK" if ok else "Error",
            t("cert_install_ok") if ok else t("cert_install_err"))

    def _export_ca(self):
        p = filedialog.asksaveasfilename(
            title=t("cert_export_title"), defaultextension=".zip",
            filetypes=[("ZIP", "*.zip")], initialfile="HonorFProxy_backup.zip")
        if p:
            ok = cert_mgr.export_ca(p)
            (messagebox.showinfo if ok else messagebox.showerror)(
                "OK" if ok else "Error",
                t("cert_export_ok", path=p) if ok else t("cert_export_err"))

    def _import_ca(self):
        p = filedialog.askopenfilename(
            title=t("cert_import_title"), filetypes=[("ZIP", "*.zip")])
        if p:
            ok = cert_mgr.import_ca(p)
            if ok:
                self._refresh_cards()
                messagebox.showinfo("OK", t("cert_import_ok"))
            else:
                messagebox.showerror("Error", t("cert_import_err"))

    def _uninstall_ca(self):
        if messagebox.askyesno(t("cert_remove_title"), t("cert_remove_q")):
            cert_mgr.uninstall_ca()

    def _phase_lbl(self):
        return (t("phase1_lbl") if state.phase == 1
                else f"{t('phase2_lbl')}  [{state.g_number}]")

    def _refresh_cards(self):
        if hasattr(self, "_phase_var"):
            self._phase_var.set(self._phase_lbl())
            self._tgt_var.set(state.target_version or t("no_target"))
            self._cdn_var.set(state.cdn_base_url or t("cdn_unknown"))

    def _clear_log(self):
        self._log_box.configure(state=tk.NORMAL)
        self._log_box.delete("1.0", tk.END)
        self._log_box.configure(state=tk.DISABLED)

    def _poll_log(self):
        try:
            while True:
                level, msg = log_queue.get_nowait()
                self._append_log(level, msg)
                if "CDN URL" in msg and ("FOUND" in msg or "MEGTALÁLVA" in msg):
                    self.after(100, self._refresh_cards)
        except queue.Empty:
            pass
        self.after(150, self._poll_log)

    def _append_log(self, level, msg):
        tag = "CDN" if ("FOUND" in msg or "MEGTALÁLVA" in msg or "🎯" in msg) else level
        self._log_box.configure(state=tk.NORMAL)
        self._log_box.insert(tk.END, msg + "\n", tag)
        self._log_box.see(tk.END)
        self._log_box.configure(state=tk.DISABLED)

    def _on_close(self):
        if self._proxy_running:
            proxy.stop()
            socks5_proxy.stop()
        local_srv.stop()
        direct_proxy.stop()
        hosts_mgr.clear_redirect()
        sys_proxy.clear_proxy()
        self.destroy()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    if not CRYPTO_OK:
        r = tk.Tk(); r.withdraw()
        messagebox.showerror("Missing package",
            "pip install cryptography\n\nThen restart the app.")
        sys.exit(1)
    App().mainloop()


if __name__ == "__main__":
    main()
