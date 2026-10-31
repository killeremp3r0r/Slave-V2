"""
Slave v2.0 - PC check tool (Windows)  |  TR / EN / RU / UK
Developed by killeremperor

Nine pages in one app:
  1) Browse Tool       : searches files with Everything (es.exe or HTTP server)
  2) Data usage check  : per-application Windows SRUM network history (last 30 days)
  3) Traces            : Windows execution traces that survive deletion
                         (Prefetch, BAM, MUICache, UserAssist, ShimCache, Amcache, USN journal)
  4) DLL / Memory      : ONLY while Roblox is open:
                           - unsigned modules (DLLs) loaded into Roblox + unusual background programs
                           - other processes holding read/write handles to Roblox memory
                           - config names found as strings (min length 4, ASCII + Unicode) in
                             Roblox's Mapped / Image memory regions (like System Informer's string search)
                         The handle + memory scan runs in a separate helper process (this same file,
                         started with --rbscan) so a failure there can never take the app down.
  5) Launch history    : Roblox-adjacent app starts and available process-creation logs
  6) USN file traces   : recent executable create/delete/rename journal entries
  7) Unsigned EXEs     : recent unsigned executables and file provenance
  8) Private memory    : Roblox threads and private executable memory regions
  9) Risk score        : combines the findings of the tools into one 0-100 score

Each tool has its OWN configs (Default config is built in and read-only).
Everything is stored in slave_config.json next to this file.
Known cheat hashes go in slave_hashes.txt (one SHA-256 per line, '#' for comments).

Requirements:
  - Windows, 64-bit Python 3.9+, Pillow (pip install pillow) for background images
  - dissect.database (Python 3.10+) or dissect.esedb (Python 3.9) for Windows SRUM history
  - Everything + es.exe (or Everything's HTTP server on port 8080) for the Browse Tool
  - Run as ADMINISTRATOR for the Traces / DLL-Memory pages

Run: python slave.py
"""

import codecs
import csv
import ctypes
import faulthandler
import hashlib
import hmac
import html
import importlib
import json
import math
import ntpath
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.parse
import urllib.request
import wave
import webbrowser
from datetime import datetime, timedelta, timezone
from tkinter import filedialog, messagebox, ttk

try:
    import winsound
except ImportError:
    winsound = None
try:
    import winreg
except ImportError:
    winreg = None

Image = ImageFilter = ImageTk = None
PIL_OK = False
PIL_ERR = ""


def try_import_pil():
    global Image, ImageFilter, ImageTk, PIL_OK, PIL_ERR
    try:
        importlib.invalidate_caches()
        from PIL import Image as _I, ImageFilter as _F, ImageTk as _T
        Image, ImageFilter, ImageTk = _I, _F, _T
        PIL_OK, PIL_ERR = True, ""
    except Exception as e:
        PIL_OK, PIL_ERR = False, f"{type(e).__name__}: {e}"
    return PIL_OK


try_import_pil()

# ============================== CONSTANTS ==============================
VERSION = "2.0"
AUTHOR = "killeremperor"
CREDIT = f"developed by {AUTHOR}"
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "slave_config.json")
HASH_FILE = os.path.join(HERE, "slave_hashes.txt")
DEFAULT_CFG = "Default"
DEFAULT_NAMES = [
    "Potassium", "Volt", "Matcha", "Velocity", "Real", "Solara", "Xeno", "Wave",
    "Serotonin", "Lumen", "Macsploit", "Severe", "Delta", "Madium", "Vega X",
    "Seliware", "Aimmy", "Exoliner", "dx9ware",
    "Mapper", "bootstrapper", "loader", "loader.exe", "updater", "updater.exe",
    "loader.zip", "vexor", "matrix", "imgui", "ronix", "drift", "drift_executor",
    "photon", "bauix",
]
MAX_RESULTS = 300
HTTP_URL = "http://127.0.0.1:8080"
PER_ROW = 6
AUTO_SECONDS = 60
LANGS = ("tr", "en", "ru", "uk")
SYS_RE = re.compile(r"^[a-z]:\\(windows|program files\\windowsapps)\\", re.I)
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
DISCORD_URL = "https://discord.gg/UdeMUMmVMB"
NICK_MAX = 24
AVATAR_FILE = "killeremperor.png"
GUNS_URL = "https://guns.lol/killeremperor"

# ============================== TRANSLATIONS ==============================
# every entry is (tr, en, ru, uk)
S = {
    "status_ready": ("hazır", "ready", "готово", "готово"),
    "status_error": ("hata", "error", "ошибка", "помилка"),
    "status_scanning": ("taranıyor · {0} ({1}/{2})", "scanning · {0} ({1}/{2})",
                        "сканирование · {0} ({1}/{2})", "сканування · {0} ({1}/{2})"),
    "scan": ("Tara", "Scan", "Скан", "Скан"),
    "stop": ("Durdur", "Stop", "Стоп", "Стоп"),
    "logs_title": ("LOGS",) * 4,
    "close": ("Kapat", "Close", "Закрыть", "Закрити"),
    "copy": ("Kopyala", "Copy", "Копировать", "Копіювати"),
    "clear": ("Temizle", "Clear", "Очистить", "Очистити"),
    "tab_browse": ("Browse Tool",) * 4,
    "tab_data": ("Data usage check",) * 4,
    "tab_trace": ("İzler", "Traces", "Следы", "Сліди"),
    "tab_persist": ("DLL / Bellek", "DLL / Memory", "DLL / Память", "DLL / Пам'ять"),
    "tab_session": ("Başlatma geçmişi", "Launch history", "История запусков", "Історія запусків"),
    "tab_usn": ("USN dosya izi", "USN file traces", "Файловые следы USN", "Файлові сліди USN"),
    "tab_newexe": ("İmzasız EXE klasörleri", "Unsigned EXE folders", "Папки с неподписанными EXE", "Теки з непідписаними EXE"),
    "tab_memory": ("Özel bellek", "Private memory", "Частная память", "Приватна пам'ять"),
    "tab_roblox": ("Roblox",) * 4,
    "tab_boot": ("Önyükleme ortamı", "Boot environment", "Среда загрузки", "Середовище завантаження"),
    "tab_credits": ("Krediler", "Credits", "Авторы", "Автори"),
    "gw_need": ("Sayfayı uygulama içinde açmak için 'pywebview' gerekli. Şimdi yüklensin mi?\n(Hayır dersen sayfa tarayıcıda açılır.)",
                "'pywebview' is needed to open the page inside the app. Install it now?\n(If you say No, the page opens in your browser.)",
                "Для открытия страницы внутри приложения нужен 'pywebview'. Установить сейчас?\n(Если нет — страница откроется в браузере.)",
                "Для відкриття сторінки всередині застосунку потрібен 'pywebview'. Встановити зараз?\n(Якщо ні — сторінка відкриється в браузері.)"),
    "gw_copy": ("Site linkini kopyala", "Copy site link", "Копировать ссылку", "Копіювати посилання"),
    "gw_copied": ("Kopyalandı ✓", "Copied ✓", "Скопировано ✓", "Скопійовано ✓"),
    "cr_title": ("KREDİLER", "CREDITS", "АВТОРЫ", "АВТОРИ"),
    "cr_solo": ("Bu uygulama tek bir geliştirici tarafından geliştirildi.",
                "This app is developed by a solo developer",
                "Это приложение разработано одним разработчиком",
                "Цей застосунок розроблений одним розробником"),
    "cr_socials": ("Sosyal medya hesaplarını görmek için aşağıdaki guns.lol hesabına bak.",
                   "To see his socials check his guns.lol account below.",
                   "Чтобы увидеть его соцсети, загляните на его аккаунт guns.lol ниже.",
                   "Щоб побачити його соцмережі, зазирніть на його акаунт guns.lol нижче."),
    "tab_forensic": ("Adli kanıt", "Forensic", "Форензика", "Форензика"),
    "fe_scan": ("Kanıt topla", "Collect evidence", "Собрать данные", "Зібрати дані"),
    "fe_filter_hint": ("Sonuçları filtrele (virgülle ayır) · isimle eşleşmeyen sistem kayıtları (çökme, Defender, günlük temizleme) her zaman gösterilir",
                       "Filter results (comma separated) · system records that match no name (crashes, Defender, log clearing) are always shown",
                       "Фильтр результатов (через запятую) · системные записи без совпадения имён (сбои, Defender, очистка журналов) показываются всегда",
                       "Фільтр результатів (через кому) · системні записи без збігу імен (збої, Defender, очищення журналів) показуються завжди"),
    "fe_note": (
        "Salt okunur, sadece bu bilgisayarda çalışır: (1) işlem ve dosya metadata'sı, (2) dosya zaman damgaları ve çalıştırma izleri, (3) son uygulama çökmeleri ve şüpheli günlük kayıtları, (4) geçmiş kanıtlar (Geri Dönüşüm Kutusu, temizlenmiş olay günlükleri). Kişisel dosya içeriği okunmaz. Bulgular kanıt değil göstergedir: elle incele. Çoğu kaynak için YÖNETİCİ olarak çalıştır.",
        "Read-only, runs on this computer only: (1) process and file metadata, (2) file timestamps and execution artifacts, (3) recent application crashes and suspicious log entries, (4) historical evidence (Recycle Bin, cleared event logs). Personal file contents are never read. Findings are indications, not proof: review them manually. Run as ADMINISTRATOR for most sources.",
        "Только чтение, работает лишь на этом компьютере: (1) метаданные процессов и файлов, (2) временные метки файлов и следы запуска, (3) недавние сбои приложений и подозрительные записи журналов, (4) историческое свидетельство (Корзина, очищенные журналы событий). Содержимое личных файлов не читается. Находки — признак, а не доказательство: проверяйте вручную. Для большинства источников запустите от ИМЕНИ АДМИНИСТРАТОРА.",
        "Лише читання, працює тільки на цьому комп'ютері: (1) метадані процесів і файлів, (2) часові мітки файлів і сліди запуску, (3) недавні збої застосунків і підозрілі записи журналів, (4) історичні докази (Кошик, очищені журнали подій). Вміст особистих файлів не читається. Знахідки — ознака, а не доказ: перевіряйте вручну. Для більшості джерел запустіть від ІМЕНІ АДМІНІСТРАТОРА."),
    "fc_kind": ("Tür", "Type", "Тип", "Тип"),
    "fc_name": ("Ad", "Name", "Имя", "Ім'я"),
    "fc_detail": ("Detay", "Detail", "Детали", "Деталі"),
    "fc_when": ("Zaman", "Time", "Время", "Час"),
    "fc_flag": ("Bulgu", "Finding", "Находка", "Знахідка"),
    "fk_meta": ("İşlem / dosya metadata", "Process / file metadata", "Метаданные процесса/файла", "Метадані процесу/файлу"),
    "fk_time": ("Zaman damgası / çalıştırma izi", "Timestamp / execution trace", "Временная метка / след запуска", "Часова мітка / слід запуску"),
    "fk_crash": ("Çökme / şüpheli kayıt", "Crash / suspicious log", "Сбой / подозрительная запись", "Збій / підозрілий запис"),
    "fk_hist": ("Geçmiş kanıt", "Historical evidence", "Историческое свидетельство", "Історичний доказ"),
    "ff_proc_name": ("Hile ismiyle eşleşen çalışan işlem", "Running process matching a cheat name",
                     "Запущенный процесс с именем чита", "Запущений процес з ім'ям чита"),
    "ff_proc_path": ("Şüpheli konumda imzasız işlem", "Unsigned process in a suspicious location",
                     "Неподписанный процесс в подозрительном месте", "Непідписаний процес у підозрілому місці"),
    "ff_pf": ("Prefetch çalıştırma kaydı", "Prefetch execution record", "Запись Prefetch о запуске", "Запис Prefetch про запуск"),
    "ff_lnk": ("Son kullanılan öğe kaydı", "Recent item record", "Запись о недавнем элементе", "Запис про нещодавній елемент"),
    "ff_crash": ("Uygulama çökme kaydı", "Application crash record", "Запись о сбое приложения", "Запис про збій застосунку"),
    "ff_def": ("Defender tespiti", "Defender detection", "Обнаружение Defender", "Виявлення Defender"),
    "ff_svc": ("Yeni servis kurulumu", "New service installed", "Установлена новая служба", "Встановлено нову службу"),
    "ff_clear": ("Olay günlüğü temizlenmiş", "Event log was cleared", "Журнал событий очищен", "Журнал подій очищено"),
    "ff_rblog": ("Roblox günlüğünde isim geçiyor", "Name appears in Roblox log", "Имя встречается в журнале Roblox", "Ім'я трапляється в журналі Roblox"),
    "ff_recycle": ("Geri Dönüşüm Kutusu'nda silinmiş dosya", "Deleted file in Recycle Bin", "Удалённый файл в Корзине", "Видалений файл у Кошику"),
    "fe_summary": ("{0} kayıt", "{0} records", "Записей: {0}", "Записів: {0}"),
    "fe_none": ("Eşleşen kanıt bulunamadı.", "No matching evidence found.", "Совпадающих данных не найдено.", "Збіжних даних не знайдено."),
    "log_fe_start": ("Adli kanıt toplanıyor...", "Collecting forensic evidence...", "Сбор форензик-данных...", "Збір форензик-даних..."),
    "log_fe_done": ("Adli kanıt toplama bitti: {0} kayıt ({1}s)", "Forensic collection finished: {0} records ({1}s)",
                    "Сбор форензик-данных завершён: {0} ({1}с)", "Збір форензик-даних завершено: {0} ({1}с)"),
    "r_cat_forensic": ("Adli kanıt", "Forensic evidence", "Форензик-данные", "Форензик-дані"),
    "tab_risk": ("Risk puanı", "Risk score", "Оценка риска", "Оцінка ризику"),
    "cfg_label": ("CONFIG (yükle)", "CONFIG (load)", "КОНФИГ (загрузить)", "КОНФІГ (завантажити)"),
    "cfg_new": ("Yeni oluştur", "Create new", "Создать", "Створити"),
    "cfg_edit": ("Listeyi düzenle", "Edit list", "Изменить список", "Змінити список"),
    "cfg_del": ("Sil", "Delete", "Удалить", "Видалити"),
    "names_head": ("ARANACAK İSİMLER", "NAMES TO SEARCH", "ИМЕНА ДЛЯ ПОИСКА", "ІМЕНА ДЛЯ ПОШУКУ"),
    "names_hint": ("kutu açık = bu config'te aranır", "box on = searched in this config",
                   "галочка = ищется в этом конфиге", "галочка = шукається в цьому конфігу"),
    "all_on": ("Hepsini aç", "All on", "Включить все", "Увімкнути все"),
    "all_off": ("Hepsini kapat", "All off", "Выключить все", "Вимкнути все"),
    "search": ("Ara", "Search", "Искать", "Шукати"),
    "entry_hint": (
        "«Ara» sadece yazdığını arar (hiçbir config'e eklemez) · birden fazlası için virgülle ayır · liste değiştirmek için «Listeyi düzenle»",
        "«Search» looks up only what you typed (not added to any config) · separate several with commas · use «Edit list» to change a config's list",
        "«Искать» ищет только введённое (в конфиги не добавляет) · несколько имён через запятую · список конфига меняется через «Изменить список»",
        "«Шукати» шукає лише введене (до конфігів не додає) · кілька імен через кому · список конфігу змінюється через «Змінити список»"),
    "ck_sys": ("Windows sistem klasörlerini gizle", "Hide Windows system folders",
               "Скрыть системные папки Windows", "Сховати системні папки Windows"),
    "ck_whole": ("Tam kelime eşleşmesi (yeniden tarar)", "Whole word match (rescans)",
                 "Только целое слово (пересканирует)", "Лише ціле слово (пересканує)"),
    "col_kw": ("İsim", "Name", "Имя", "Ім'я"),
    "col_name": ("Dosya", "File", "Файл", "Файл"),
    "col_path": ("Konum", "Location", "Расположение", "Розташування"),
    "col_size": ("Boyut", "Size", "Размер", "Розмір"),
    "col_date": ("Tarih", "Date", "Дата", "Дата"),
    "show": ("Klasörde göster", "Show in folder", "Показать в папке", "Показати в папці"),
    "copy_path": ("Yolu kopyala", "Copy path", "Копировать путь", "Копіювати шлях"),
    "export": ("TXT'ye aktar", "Export TXT", "Экспорт в TXT", "Експорт у TXT"),
    "summary": ("{0} sonuç gösteriliyor  ·  toplam {1}", "{0} results shown  ·  {1} total",
                "Показано: {0}  ·  всего {1}", "Показано: {0}  ·  усього {1}"),
    "notice_none": (
        "Aranacak isim seçili değil.\n\nYukarıdan bir ismi aç ya da bir şey yazıp 'Ara'ya bas.",
        "No names selected.\n\nTurn a name on above, or type something and press 'Search'.",
        "Не выбрано ни одного имени.\n\nВключите имя выше или введите текст и нажмите «Искать».",
        "Не вибрано жодного імені.\n\nУвімкніть ім'я вище або введіть текст і натисніть «Шукати»."),
    "notice_nomatch": ("Hiçbir eşleşme bulunamadı.", "No matches found.",
                       "Совпадений не найдено.", "Збігів не знайдено."),
    "notice_setup": (
        "Everything'e ulaşılamadı.\n\n1) Everything programını aç (arka planda çalışıyor olmalı)\n2) es.exe'yi (voidtools.com → ES) bu programın klasörüne koy\n    ya da Everything → Seçenekler → HTTP Sunucusu'nu aç (port 8080)\n\nSonra sağ üstteki 'Tara' düğmesine bas.\nAyrıntı için Logs panelinden bak.",
        "Can't reach Everything.\n\n1) Open Everything (it must be running in the background)\n2) Put es.exe (voidtools.com → ES) in this program's folder\n    or enable Everything → Options → HTTP Server (port 8080)\n\nThen press the 'Scan' button at the top right.\nSee the Logs panel for details.",
        "Не удаётся подключиться к Everything.\n\n1) Запустите Everything (он должен работать в фоне)\n2) Положите es.exe (voidtools.com → ES) в папку программы\n    или включите Everything → Параметры → HTTP-сервер (порт 8080)\n\nЗатем нажмите «Скан» справа вверху.\nПодробности — на панели Logs.",
        "Не вдається підключитися до Everything.\n\n1) Запустіть Everything (він має працювати у фоні)\n2) Покладіть es.exe (voidtools.com → ES) у папку програми\n    або увімкніть Everything → Параметри → HTTP-сервер (порт 8080)\n\nПотім натисніть «Скан» праворуч угорі.\nДокладніше — на панелі Logs."),
    "ed_title_new": ("Yeni config", "New config", "Новый конфиг", "Новий конфіг"),
    "ed_title_edit": ("Config düzenle", "Edit config", "Изменить конфиг", "Змінити конфіг"),
    "ed_name": ("Config adı", "Config name", "Имя конфига", "Ім'я конфігу"),
    "ed_add_label": ("Listeye yeni isim ekle (birden fazlası için virgül)",
                     "Add new name to list (comma for several)",
                     "Добавить имя в список (несколько через запятую)",
                     "Додати ім'я до списку (кілька через кому)"),
    "ed_add": ("Ekle", "Add", "Добавить", "Додати"),
    "ed_remove": ("Seçileni sil", "Remove selected", "Удалить выбранное", "Видалити вибране"),
    "ed_save": ("Kaydet", "Save", "Сохранить", "Зберегти"),
    "ed_cancel": ("İptal", "Cancel", "Отмена", "Скасувати"),
    "ed_copy": ("Mevcut listeden başla", "Start from current list",
                "Начать с текущего списка", "Почати з поточного списку"),
    "ed_names": ("İsimler ({0})", "Names ({0})", "Имена ({0})", "Імена ({0})"),
    "ed_readonly": ("Default config değiştirilemez.\n«Yeni oluştur» ile kendi configini yapabilirsin.",
                    "The Default config cannot be changed.\nUse «Create new» to make your own config.",
                    "Конфиг Default изменить нельзя.\nСоздайте свой через «Создать».",
                    "Конфіг Default змінити не можна.\nСтворіть свій через «Створити»."),
    "err_name_empty": ("Config adı boş olamaz.", "Config name cannot be empty.",
                       "Имя конфига не может быть пустым.", "Ім'я конфігу не може бути порожнім."),
    "err_name_exists": ("Bu isimde bir config zaten var.", "A config with this name already exists.",
                        "Конфиг с таким именем уже существует.", "Конфіг з таким ім'ям уже існує."),
    "del_confirm": ("'{0}' configi silinsin mi?", "Delete config '{0}'?",
                    "Удалить конфиг '{0}'?", "Видалити конфіг '{0}'?"),
    "del_default": ("Default config silinemez.", "The Default config cannot be deleted.",
                    "Конфиг Default удалить нельзя.", "Конфіг Default видалити не можна."),
    "log_cfg_loaded": ("Config yüklendi: {0}", "Config loaded: {0}", "Конфиг загружен: {0}", "Конфіг завантажено: {0}"),
    "log_cfg_saved": ("Config kaydedildi: {0}", "Config saved: {0}", "Конфиг сохранён: {0}", "Конфіг збережено: {0}"),
    "log_cfg_deleted": ("Config silindi: {0}", "Config deleted: {0}", "Конфиг удалён: {0}", "Конфіг видалено: {0}"),
    # ---- data usage
    "d_refresh": ("Yenile", "Refresh", "Обновить", "Оновити"),
    "d_auto": ("Otomatik yenile ({0} sn)", "Auto refresh ({0}s)", "Автообновление ({0} с)", "Автооновлення ({0} с)"),
    "d_only_list": ("Sadece config listesindekiler", "Only names in the config list",
                    "Только имена из списка конфига", "Лише імена зі списку конфігу"),
    "d_search_hint": ("Yaz ve filtrele (virgülle ayır) · boş bırakırsan config listesi kullanılır",
                      "Type to filter (comma separated) · if empty, the config list is used",
                      "Введите для фильтра (через запятую) · если пусто — список конфига",
                      "Введіть для фільтра (через кому) · якщо порожньо — список конфігу"),
    "d_note": (
        "Geçmiş ağ kullanımı: Windows SRUM kayıtları, son 30 gün. Windows bu kayıtları periyodik günceller; canlı hız değildir. Erişim hatasında uygulamayı yönetici olarak aç.",
        "Historical network usage from Windows SRUM for the last 30 days. Windows updates these records periodically; this is not a live rate. Run as administrator if access is denied.",
        "История сетевого трафика Windows SRUM за последние 30 дней. Windows обновляет записи периодически; это не текущая скорость. При отказе в доступе запустите от имени администратора.",
        "Історія мережевого трафіку Windows SRUM за останні 30 днів. Windows оновлює записи періодично; це не поточна швидкість. Якщо доступ заборонено, запустіть від імені адміністратора."),
    "dc_app": ("Uygulama", "App", "Приложение", "Застосунок"),
    "dc_read": ("Alınan", "Received", "Получено", "Отримано"),
    "dc_write": ("Gönderilen", "Sent", "Отправлено", "Надіслано"),
    "dc_total": ("Toplam", "Total", "Всего", "Усього"),
    "dc_last": ("Son kayıt", "Last record", "Последняя запись", "Останній запис"),
    "dc_path": ("Konum", "Location", "Расположение", "Розташування"),
    "d_summary": ("{0} uygulama  ·  toplam {1}", "{0} apps  ·  total {1}",
                  "Приложений: {0}  ·  всего {1}", "Застосунків: {0}  ·  усього {1}"),
    "d_nomatch": ("Eşleşen uygulama yok.", "No matching apps.", "Подходящих приложений нет.", "Відповідних застосунків немає."),
    "d_nowin": ("Bu özellik sadece Windows'ta çalışır.", "This feature only works on Windows.",
                "Эта функция работает только в Windows.", "Ця функція працює лише у Windows."),
    "d_srum_error": (
        "Windows SRUM geçmişi okunamadı: {0}\n'Access denied' ise Slave'i yönetici olarak aç. 'ESE reader is not installed' ise requirements.txt kurulumunu yap.",
        "Could not read Windows SRUM history: {0}\nIf access is denied, run Slave as administrator. If the ESE reader is missing, install requirements.txt.",
        "Не удалось прочитать историю Windows SRUM: {0}\nПри отказе в доступе запустите Slave от имени администратора. Если нет ESE reader, установите requirements.txt.",
        "Не вдалося прочитати історію Windows SRUM: {0}\nЯкщо доступ заборонено, запустіть Slave від імені адміністратора. Якщо немає ESE reader, встановіть requirements.txt."),
    "d_srum_empty": (
        "Son 30 günde okunabilir SRUM ağ kullanım kaydı bulunamadı. SRUM kapalı olabilir veya yönetici izni gerekebilir.",
        "No readable SRUM network usage records were found for the last 30 days. SRUM may be disabled or administrator access may be required.",
        "За последние 30 дней не найдено доступных записей сетевого использования SRUM. SRUM может быть отключён или требуются права администратора.",
        "За останні 30 днів не знайдено доступних записів мережевого використання SRUM. SRUM може бути вимкнено або потрібні права адміністратора."),
    "log_data_start": ("Veri kullanımı okunuyor...", "Reading data usage...",
                       "Чтение данных об использовании...", "Читання даних про використання..."),
    "log_data_done": ("Veri kullanımı okundu: {0} uygulama ({1}s)", "Data usage read: {0} apps ({1}s)",
                      "Данные прочитаны: {0} приложений ({1}с)", "Дані прочитано: {0} застосунків ({1}с)"),
    "log_data_err": ("Veri kullanımı okunamadı: {0}", "Could not read data usage: {0}",
                     "Не удалось прочитать данные: {0}", "Не вдалося прочитати дані: {0}"),
    # ---- browse logs
    "log_stop_req": ("Durdurma istendi.", "Stop requested.", "Запрошена остановка.", "Запитано зупинку."),
    "log_scan_start": ("Tarama başladı. İsimler: {0}", "Scan started. Names: {0}",
                       "Сканирование началось. Имена: {0}", "Сканування розпочато. Імена: {0}"),
    "log_whole": (" (tam kelime)", " (whole word)", " (целое слово)", " (ціле слово)"),
    "log_es": ("es.exe: {0}",) * 4,
    "log_es_none": ("bulunamadı, HTTP sunucusu denenecek", "not found, trying HTTP server",
                    "не найден, пробуем HTTP-сервер", "не знайдено, пробуємо HTTP-сервер"),
    "log_stopped": ("Tarama durduruldu.", "Scan stopped.", "Сканирование остановлено.", "Сканування зупинено."),
    "log_searching": ("Everything'de aranıyor: {0}", "Searching Everything: {0}",
                      "Поиск в Everything: {0}", "Пошук в Everything: {0}"),
    "log_unexpected": ("{0}: beklenmeyen hata {1}", "{0}: unexpected error {1}",
                       "{0}: непредвиденная ошибка {1}", "{0}: непередбачена помилка {1}"),
    "log_found": ("{0}: {1} sonuç ({2}s, {3})", "{0}: {1} results ({2}s, {3})",
                  "{0}: {1} результатов ({2}с, {3})", "{0}: {1} результатів ({2}с, {3})"),
    "log_done": ("Tarama bitti: {0} · toplam {1}", "Scan finished: {0} · total {1}",
                 "Сканирование завершено: {0} · всего {1}", "Сканування завершено: {0} · усього {1}"),
    "log_skip": ("Tarama atlandı: hiçbir isim seçili değil.", "Scan skipped: no names selected.",
                 "Сканирование пропущено: имена не выбраны.", "Сканування пропущено: імена не вибрано."),
    "log_all_on": ("Tüm isimler açıldı.", "All names turned on.", "Все имена включены.", "Усі імена увімкнено."),
    "log_all_off": ("Tüm isimler kapatıldı.", "All names turned off.", "Все имена выключены.", "Усі імена вимкнено."),
    "log_quick": ("Hızlı arama: {0}", "Quick search: {0}", "Быстрый поиск: {0}", "Швидкий пошук: {0}"),
    "log_busy": ("Tarama sürüyor, bitince tekrar dene.", "A scan is running, try again when it finishes.",
                 "Идёт сканирование, повторите после завершения.", "Триває сканування, повторіть після завершення."),
    "log_logs_copied": ("Loglar panoya kopyalandı.", "Logs copied to clipboard.",
                        "Логи скопированы в буфер обмена.", "Логи скопійовано в буфер обміну."),
    "log_path_copied": ("Yol kopyalandı: {0}", "Path copied: {0}", "Путь скопирован: {0}", "Шлях скопійовано: {0}"),
    "log_shown": ("Klasörde gösterildi: {0}", "Shown in folder: {0}", "Показано в папке: {0}", "Показано в папці: {0}"),
    "log_open_err": ("Klasör açılamadı: {0}", "Could not open folder: {0}",
                     "Не удалось открыть папку: {0}", "Не вдалося відкрити папку: {0}"),
    "log_saved": ("Sonuçlar kaydedildi: {0}", "Results saved: {0}", "Результаты сохранены: {0}", "Результати збережено: {0}"),
    "log_save_err": ("Kaydedilemedi: {0}", "Could not save: {0}", "Не удалось сохранить: {0}", "Не вдалося зберегти: {0}"),
    "log_ev_running": ("Everything zaten çalışıyor.", "Everything is already running.",
                       "Everything уже запущен.", "Everything уже запущено."),
    "log_ev_started": ("Everything otomatik başlatıldı.", "Everything was started automatically.",
                       "Everything запущен автоматически.", "Everything запущено автоматично."),
    "log_ev_missing": ("Everything kurulu değil ya da bulunamadı.", "Everything is not installed or could not be found.",
                       "Everything не установлен или не найден.", "Everything не встановлено або не знайдено."),
    "export_title": ("Slave tarama sonuçları - {0}", "Slave scan results - {0}",
                     "Результаты сканирования Slave - {0}", "Результати сканування Slave - {0}"),
    "file_type": ("Metin dosyası", "Text file", "Текстовый файл", "Текстовий файл"),
    "splash_sub": ("PC KONTROL ARACI", "PC CHECK TOOL", "ИНСТРУМЕНТ ПРОВЕРКИ ПК", "ІНСТРУМЕНТ ПЕРЕВІРКИ ПК"),
    "splash_steps": (["çekirdek başlatılıyor", "arama motoru aranıyor", "configler yükleniyor", "hazır"],
                     ["starting core", "locating search engine", "loading configs", "ready"],
                     ["запуск ядра", "поиск движка", "загрузка конфигов", "готово"],
                     ["запуск ядра", "пошук рушія", "завантаження конфігів", "готово"]),
    # ---- appearance
    "ap_title": ("Görünüm", "Appearance", "Оформление", "Оформлення"),
    "ap_theme": ("Renk teması", "Color theme", "Цветовая тема", "Колірна тема"),
    "ap_bg": ("Arka plan görseli", "Background image", "Фоновое изображение", "Фонове зображення"),
    "ap_pick": ("Görsel seç", "Choose image", "Выбрать изображение", "Вибрати зображення"),
    "ap_remove": ("Görseli kaldır", "Remove image", "Убрать изображение", "Прибрати зображення"),
    "ap_blur": ("Bulanıklık", "Blur", "Размытие", "Розмиття"),
    "ap_none": ("Görsel yok · varsayılan: hareketli mavi arka plan", "No image · default: moving blue background",
                "Нет изображения · по умолчанию: движущийся синий фон",
                "Немає зображення · за замовчуванням: рухомий синій фон"),
    "ap_hint": ("Görsel eklenince otomatik bulanıklaştırılır, yazılar rahat okunur.",
                "Images are blurred automatically so the text stays readable.",
                "Изображение автоматически размывается, текст остаётся читаемым.",
                "Зображення автоматично розмивається, текст лишається читабельним."),
    "ap_opacity": ("Arayüz opaklığı", "Interface opacity", "Прозрачность интерфейса", "Прозорість інтерфейсу"),
    "ap_opacity_hint": (
        "Düşürünce paneller cam gibi saydamlaşır, yazılar net kalır. Arkada arka plan görseli (yoksa masaüstü) görünür. 100'ün altına ilk indiğinde kaydırıcıyı bırakınca arayüz bir kez yenilenir.",
        "Lower it for a frosted-glass look: panels turn see-through while the text stays crisp. The background image (or the desktop if none) shows behind. The first time you go below 100 the interface refreshes once when you release the slider.",
        "Уменьшите для эффекта матового стекла: панели становятся прозрачными, текст остаётся чётким. Сзади видно фоновое изображение (или рабочий стол). При первом снижении ниже 100 интерфейс обновится один раз после отпускания ползунка.",
        "Зменште для ефекту матового скла: панелі стають прозорими, текст лишається чітким. Ззаду видно фонове зображення (або робочий стіл). При першому зниженні нижче 100 інтерфейс оновиться один раз після відпускання повзунка."),
    "ap_reco": ("Özel görseller için önerilen ayarlar\nBulanıklık 2 · Opaklık 90",
                "Recommended settings for custom images\nBlur 2 · Interface opacity 90",
                "Рекомендуемые настройки для своих изображений\nРазмытие 2 · Прозрачность 90",
                "Рекомендовані налаштування для власних зображень\nРозмиття 2 · Прозорість 90"),
    "ap_reco_btn": ("Uygula", "Apply", "Применить", "Застосувати"),
    "log_op_noimg": ("Opaklığın etkisi için önce bir arka plan görseli seç.",
                     "Choose a background image first for opacity to have an effect.",
                     "Для прозрачности сначала выберите фоновое изображение.",
                     "Для прозорості спершу виберіть фонове зображення."),
    "th_blue": ("Mavi", "Blue", "Синий", "Синій"),
    "th_red": ("Kırmızı", "Red", "Красный", "Червоний"),
    "th_black": ("Siyah", "Black", "Чёрный", "Чорний"),
    "th_white": ("Beyaz", "White", "Белый", "Білий"),
    "th_purple": ("Mor", "Purple", "Фиолетовый", "Фіолетовий"),
    "th_green": ("Yeşil", "Green", "Зелёный", "Зелений"),
    "img_type": ("Görseller", "Images", "Изображения", "Зображення"),
    "log_look": ("Görünüm güncellendi.", "Appearance updated.", "Оформление обновлено.", "Оформлення оновлено."),
    "ap_need_pil": (
        "Pillow bulunamadı.\n\nUygulama şu Python ile çalışıyor:\n{0}\n\nHata: {1}\n\n(pip, başka bir Python'a yüklemiş olabilir.) Şimdi bu Python'a yüklensin mi?",
        "Pillow was not found.\n\nThe app is running with this Python:\n{0}\n\nError: {1}\n\n(pip may have installed it into a different Python.) Install it into this Python now?",
        "Pillow не найден.\n\nПриложение запущено в этом Python:\n{0}\n\nОшибка: {1}\n\n(pip мог установить его в другой Python.) Установить в этот Python сейчас?",
        "Pillow не знайдено.\n\nЗастосунок запущено в цьому Python:\n{0}\n\nПомилка: {1}\n\n(pip міг встановити його в інший Python.) Встановити в цей Python зараз?"),
    "ap_install": ("Pillow'u yükle", "Install Pillow", "Установить Pillow", "Встановити Pillow"),
    "ap_installing": ("Yükleniyor...", "Installing...", "Установка...", "Встановлення..."),
    "ap_install_ok": ("Pillow yüklendi.", "Pillow installed.", "Pillow установлен.", "Pillow встановлено."),
    "ap_install_fail": ("Yükleme başarısız:\n{0}", "Installation failed:\n{0}",
                        "Не удалось установить:\n{0}", "Не вдалося встановити:\n{0}"),
    # ---- gate
    "gate_pass": ("PASSCODE",) * 4,
    "gate_nick": ("TAKMA AD", "NICKNAME", "НИКНЕЙМ", "НІКНЕЙМ"),
    "gate_nick_empty": ("Takma ad boş olamaz.", "Nickname cannot be empty.",
                        "Никнейм не может быть пустым.", "Нікнейм не може бути порожнім."),
    "gate_enter": ("Giriş", "Enter", "Войти", "Увійти"),
    "gate_wrong": ("Yanlış passcode.", "Wrong passcode.", "Неверный passcode.", "Хибний passcode."),
    "gate_tick": ("Devam etmek için onay kutusunu işaretle.", "Tick the checkbox to continue.",
                  "Поставьте галочку, чтобы продолжить.", "Поставте галочку, щоб продовжити."),
    "gate_consent": (
        "Uygulamanın amacının ne olduğunu ve neleri görebildiğini biliyorum ve yaşanacaklardan ben sorumluyum.",
        "I know what this application is for and what it can see, and I take responsibility for whatever happens.",
        "Я знаю, для чего это приложение и что оно может видеть, и беру на себя ответственность за последствия.",
        "Я знаю, для чого цей застосунок і що він може бачити, і беру на себе відповідальність за наслідки."),
    "gate_discord": (
        "Passcode'un yok mu? Passcode almak için Discord sunucumuza katıl.",
        "You don't have the passcode? Join our Discord server to get the passcode.",
        "Нет passcode? Вступите в наш Discord-сервер, чтобы получить passcode.",
        "Немає passcode? Приєднайтеся до нашого Discord-сервера, щоб отримати passcode."),
    # ---- traces
    "t_scan": ("İzleri tara", "Scan traces", "Скан следов", "Скан слідів"),
    "t_filter_hint": ("Sonuçları filtrele (virgülle ayır) · boşsa config listesindekiler gösterilir",
                      "Filter results (comma separated) · if empty, config-list matches are shown",
                      "Фильтр результатов (через запятую) · если пусто — совпадения из списка конфига",
                      "Фільтр результатів (через кому) · якщо порожньо — збіги зі списку конфігу"),
    "t_note": (
        "Silinse bile iz bırakan kayıtlar: Prefetch, BAM, MUICache, UserAssist, ShimCache, Amcache, USN. Çoğu kayıt için YÖNETİCİ olarak çalıştır.",
        "Records that survive deletion: Prefetch, BAM, MUICache, UserAssist, ShimCache, Amcache, USN. Run as ADMINISTRATOR for most of them.",
        "Записи, переживающие удаление: Prefetch, BAM, MUICache, UserAssist, ShimCache, Amcache, USN. Для большинства запустите от ИМЕНИ АДМИНИСТРАТОРА.",
        "Записи, що переживають видалення: Prefetch, BAM, MUICache, UserAssist, ShimCache, Amcache, USN. Для більшості запустіть від ІМЕНІ АДМІНІСТРАТОРА."),
    "tc_src": ("Kaynak", "Source", "Источник", "Джерело"),
    "tc_name": ("Dosya", "File", "Файл", "Файл"),
    "tc_path": ("Yol / Detay", "Path / Detail", "Путь / Детали", "Шлях / Деталі"),
    "tc_when": ("Zaman", "Time", "Время", "Час"),
    "tc_state": ("Durum", "State", "Состояние", "Стан"),
    "t_deleted": ("SİLİNMİŞ", "DELETED", "УДАЛЁН", "ВИДАЛЕНО"),
    "t_exists": ("var", "exists", "есть", "є"),
    "t_summary": ("{0} kayıt  ·  {1} silinmiş görünüyor", "{0} records  ·  {1} look deleted",
                  "Записей: {0}  ·  удалено: {1}", "Записів: {0}  ·  видалено: {1}"),
    "t_none": ("Eşleşen iz bulunamadı.", "No matching traces found.",
               "Совпадающих следов не найдено.", "Збіжних слідів не знайдено."),
    "log_tr_start": ("Windows izleri taranıyor...", "Scanning Windows traces...",
                     "Сканирование следов Windows...", "Сканування слідів Windows..."),
    "log_tr_src": ("{0}: {1} eşleşme", "{0}: {1} matches", "{0}: совпадений {1}", "{0}: збігів {1}"),
    "log_tr_err": ("{0}: okunamadı ({1})", "{0}: could not read ({1})",
                   "{0}: не удалось прочитать ({1})", "{0}: не вдалося прочитати ({1})"),
    "log_tr_noadmin": ("Yönetici değilsin: bazı kaynaklar okunamayacak.",
                       "Not running as administrator: some sources cannot be read.",
                       "Нет прав администратора: часть источников недоступна.",
                       "Немає прав адміністратора: частина джерел недоступна."),
    "log_tr_done": ("İz taraması bitti: {0} kayıt ({1}s)", "Trace scan finished: {0} records ({1}s)",
                    "Сканирование следов завершено: {0} записей ({1}с)",
                    "Сканування слідів завершено: {0} записів ({1}с)"),
    # ---- DLL / memory (Roblox must be open)
    "p_scan": ("Roblox'u tara", "Scan Roblox", "Скан Roblox", "Скан Roblox"),
    "p_filter_hint": ("Sonuçları filtrele (virgülle ayır)", "Filter results (comma separated)",
                      "Фильтр результатов (через запятую)", "Фільтр результатів (через кому)"),
    "p_note": (
        "Roblox açıkken taranır: (1) Roblox'a yüklenmiş imzasız DLL'ler ve alışılmadık arka plan programları, (2) Roblox belleğine okuma/yazma erişimi olan işlemler (handle), (3) Roblox belleğinin Mapped/Image bölgelerinde isim listesinin stringleri (min. uzunluk 4, ASCII + Unicode). Roblox kapalıysa bu yöntem puana girmez. Roblox koruması bazı okumaları engelleyebilir; bulguları elle incele. YÖNETİCİ olarak ve 64-bit Python ile çalıştır.",
        "Runs while Roblox is open: (1) unsigned DLLs loaded into Roblox and unusual background programs, (2) processes with read/write access to Roblox memory (handles), (3) the config names as strings in Roblox's Mapped/Image memory regions (min length 4, ASCII + Unicode). If Roblox is closed this method is left out of the score. Roblox's protection may block some reads; review findings manually. Run as ADMINISTRATOR with 64-bit Python.",
        "Работает, пока открыт Roblox: (1) неподписанные DLL в Roblox и необычные фоновые программы, (2) процессы с доступом на чтение/запись к памяти Roblox (handle), (3) имена из конфига как строки в Mapped/Image областях памяти Roblox (мин. длина 4, ASCII + Unicode). Если Roblox закрыт, метод не входит в оценку. Защита Roblox может блокировать часть чтений; проверяйте вручную. Запустите от ИМЕНИ АДМИНИСТРАТОРА в 64-битном Python.",
        "Працює, поки відкрито Roblox: (1) непідписані DLL у Roblox і незвичні фонові програми, (2) процеси з доступом на читання/запис до пам'яті Roblox (handle), (3) імена з конфігу як рядки в Mapped/Image областях пам'яті Roblox (мін. довжина 4, ASCII + Unicode). Якщо Roblox закрито, метод не входить в оцінку. Захист Roblox може блокувати частину читань; перевіряйте вручну. Запустіть від ІМЕНІ АДМІНІСТРАТОРА у 64-бітному Python."),
    "pc_kind": ("Tür", "Type", "Тип", "Тип"),
    "pc_name": ("Ad", "Name", "Имя", "Ім'я"),
    "pc_detail": ("Detay", "Detail", "Детали", "Деталі"),
    "pc_flag": ("İşaret", "Flag", "Метка", "Мітка"),
    "pk_mod": ("Roblox modülü (DLL)", "Roblox module (DLL)", "Модуль Roblox (DLL)", "Модуль Roblox (DLL)"),
    "pk_bg": ("Arka plan işlemi", "Background process", "Фоновый процесс", "Фоновий процес"),
    "pk_handle": ("Bellek erişimi (handle)", "Memory access (handle)", "Доступ к памяти (handle)", "Доступ до пам'яті (handle)"),
    "pk_mem": ("Bellek stringi", "Memory string", "Строка в памяти", "Рядок у пам'яті"),
    "pf_name": ("Hile ismi eşleşti", "Cheat name matched", "Совпало имя чита", "Збігся ім'я чита"),
    "pf_inject": ("Roblox'a yüklenmiş imzasız modül", "Unsigned module loaded into Roblox", "Неподписанный модуль в Roblox", "Непідписаний модуль у Roblox"),
    "pf_unsigned": ("İmzasız arka plan programı", "Unsigned background program", "Неподписанная фоновая программа", "Непідписана фонова програма"),
    "pf_net": ("Aktif bağlantısı var", "Has active connections", "Есть активные соединения", "Має активні з'єднання"),
    "pf_handle": ("Roblox belleğini okuyabilen/yazabilen işlem", "Process able to read/write Roblox memory",
                  "Процесс с доступом к памяти Roblox", "Процес з доступом до пам'яті Roblox"),
    "pf_mem": ("Roblox belleğinde hile ismi (string)", "Cheat name string in Roblox memory",
               "Имя чита в памяти Roblox", "Ім'я чита в пам'яті Roblox"),
    "p_rb_open": ("Roblox: açık ({0} işlem)", "Roblox: open ({0} processes)", "Roblox: открыт (процессов: {0})", "Roblox: відкрито (процесів: {0})"),
    "p_rb_closed": ("Roblox not open.",) * 4,
    "p_summary": ("{0} bulgu", "{0} findings", "Находок: {0}", "Знахідок: {0}"),
    "p_history_scan": ("Başlatma geçmişini tara", "Scan launch history", "Сканировать историю запусков", "Сканувати історію запусків"),
    "p_history_idle": ("Roblox başlangıcına yakın uygulama başlatmalarını ve ek dosya izlerini ara.", "Search for app launches near Roblox startup and additional file traces.", "Ищет запуски приложений рядом с Roblox и дополнительные следы файлов.", "Шукає запуски програм поблизу Roblox і додаткові сліди файлів."),
    "p_history_scanning": ("Roblox başlangıç kayıtları ve ek dosya izleri taranıyor…", "Scanning Roblox launch records and additional file traces…", "Сканирование запусков Roblox и дополнительных следов файлов…", "Сканування запусків Roblox і додаткових слідів файлів…"),
    "p_history_done": ("{0} Roblox oturumu · {1} yakın başlatma · {2} ek iz", "{0} Roblox sessions · {1} nearby launches · {2} extra traces", "Сессий Roblox: {0} · запусков рядом: {1} · доп. следов: {2}", "Сесій Roblox: {0} · запусків поруч: {1} · дод. слідів: {2}"),
    "p_history_review": ("{0} kanıt satırı incelenmeli", "{0} evidence rows marked for review", "Требуют проверки строк доказательств: {0}", "Позначено для перевірки рядків доказів: {0}"),
    "p_history_none": ("Prefetch, BAM veya UserAssist içinde tarihli Roblox çalıştırma zamanı bulunamadı.", "No dated Roblox launch was found in Prefetch, BAM, or UserAssist.", "В Prefetch, BAM или UserAssist не найдено датированного запуска Roblox.", "У Prefetch, BAM або UserAssist не знайдено датованого запуску Roblox."),
    "p_history_untimed": ("Roblox izi bulundu ({0}); bu kaynak çalıştırılma zamanını tutmuyor. Tarihli Prefetch/BAM/UserAssist kaydı bulunamadı.", "Roblox traces found ({0}), but these sources do not record launch time. No dated Prefetch/BAM/UserAssist record was available.", "Найдены следы Roblox ({0}), но эти источники не записывают время запуска. Датированной записи Prefetch/BAM/UserAssist нет.", "Знайдено сліди Roblox ({0}), але ці джерела не записують час запуску. Датованого запису Prefetch/BAM/UserAssist немає."),
    "p_history_no_apps": ("Bu açılışın yakınında uygulama çalıştırma kaydı yok.", "No application launch record near this Roblox start.", "Рядом с этим запуском Roblox нет записей о запуске приложений.", "Поблизу цього запуску Roblox немає записів про запуск програм."),
    "p_history_error": ("Windows işlem geçmişi okunamadı.", "Could not read Windows process history.", "Не удалось прочитать историю процессов Windows.", "Не вдалося прочитати історію процесів Windows."),
    "p_history_norange": ("Seçilen aralıkta Roblox açılışı bulunamadı.", "No Roblox launch found in the selected range.", "В выбранном периоде запусков Roblox не найдено.", "У вибраному періоді запусків Roblox не знайдено."),
    "ph_range_today": ("Bugün", "Today", "Сегодня", "Сьогодні"),
    "ph_range_30d": ("Son 30 gün", "Last 30 days", "Последние 30 дней", "Останні 30 днів"),
    "ph_back_10m": ("Öncesi: 10 dk", "Before: 10 min", "До: 10 мин", "До: 10 хв"),
    "ph_back_1h": ("Öncesi: 1 saat", "Before: 1 hour", "До: 1 час", "До: 1 год"),
    "ph_back_6h": ("Öncesi: 6 saat", "Before: 6 hours", "До: 6 часов", "До: 6 год"),
    "ph_back_all": ("Öncesi: tüm aralık", "Before: whole range", "До: весь период", "До: весь період"),
    "p_history_note": ("Prefetch, BAM/UserAssist ve varsa Security 4688/Sysmon 1 kayıtlarını kullanarak Roblox başlangıcına yakın uygulama başlatmalarını gösterir. İmzasız GUI programları Windows/Program Files dışındaysa incelenmeli diye işaretlenir. USN, klasör ve bellek taramaları kendi ayrı sekmelerindedir.", "Shows app launches near Roblox startup using Prefetch, BAM/UserAssist and existing Security 4688/Sysmon 1 records. Unsigned GUI apps outside Windows/Program Files are marked for review. USN, folder and memory scans each have their own tab.", "Показывает запуски приложений рядом со стартом Roblox по данным Prefetch, BAM/UserAssist и имеющимся записям Security 4688/Sysmon 1. Неподписанные GUI-программы вне Windows/Program Files помечаются для проверки. USN, папки и память вынесены в отдельные вкладки.", "Показує запуски програм поблизу старту Roblox за даними Prefetch, BAM/UserAssist та наявними записами Security 4688/Sysmon 1. Непідписані GUI-програми поза Windows/Program Files позначаються для перевірки. USN, теки та пам'ять мають окремі вкладки."),
    "method_scanning": ("Bu yöntem taranıyor…", "Scanning this method…", "Сканирование метода…", "Сканування методу…"),
    "method_error": ("Tarama başarısız: {0}", "Scan failed: {0}", "Ошибка сканирования: {0}", "Помилка сканування: {0}"),
    "method_partial": ("kısmi tarama", "partial scan", "частичное сканирование", "часткове сканування"),
    "usn_note": ("Son 3 gündeki USN oluşturma/silme/yeniden adlandırma kayıtlarını listeler. Günlük yalnızca dosya adını ve sürücüyü verebilir; erişim veya zaman sınırı nedeniyle sonuçlar kısmi olabilir.", "Lists USN create/delete/rename records from the last 3 days. The journal may expose only a filename and drive; permissions or time limits can make results partial.", "Показывает записи USN о создании, удалении и переименовании за последние 3 дня. Журнал может содержать только имя файла и диск; из-за прав или лимита времени результаты могут быть неполными.", "Показує записи USN про створення, видалення та перейменування за останні 3 дні. Журнал може містити лише ім'я файлу та диск; через права або обмеження часу результати можуть бути неповними."),
    "usn_scan": ("USN günlüğünü tara", "Scan USN journal", "Сканировать журнал USN", "Сканувати журнал USN"),
    "usn_done": ("{0} kayıt · sürücüler: {1} · taranan en eski kayıt: {2}", "{0} records · drives: {1} · oldest scanned record: {2}", "Записей: {0} · диски: {1} · самая старая проверенная запись: {2}", "Записів: {0} · диски: {1} · найстаріший перевірений запис: {2}"),
    "newexe_note": ("Downloads, Desktop ve Windows dışındaki ikincil sabit disklerde son 3 günde değiştirilmiş imzasız EXE'leri listeler; tek dosyayı da gösterir. Yapılandırılmış hile ismi eşleşmeleri daha eski dosyalarda da aranır. SHA-256 ve varsa ZoneId gösterilir; bulgu tek başına kanıt değildir.", "Lists unsigned EXEs modified in the last 3 days in Downloads, Desktop and secondary fixed drives outside Windows, including a single file. Configured cheat-name matches are also searched in older files. Shows SHA-256 and ZoneId when available; a finding alone is not proof.", "Показывает неподписанные EXE, изменённые за последние 3 дня в Downloads, Desktop и на дополнительных дисках вне Windows, включая одиночные файлы. Совпадения с именами из списка ищутся и в старых файлах. SHA-256 и ZoneId отображаются, если доступны; это не доказательство чита.", "Показує непідписані EXE, змінені за останні 3 дні у Downloads, Desktop і на додаткових дисках поза Windows, включно з одним файлом. Збіги з налаштованими назвами шукаються і в старіших файлах. SHA-256 та ZoneId показуються, якщо доступні; це не доказ чита."),
    "newexe_scan": ("İmzasız EXE klasörlerini tara", "Scan unsigned EXE folders", "Сканировать папки с неподписанными EXE", "Сканувати теки з непідписаними EXE"),
    "newexe_done": ("{0} kayıt · {1} dosya tarandı · {2} imzasız · {3} isim eşleşmesi · {4} klasör", "{0} records · {1} files scanned · {2} unsigned · {3} name matches · {4} folders", "Записей: {0} · файлов проверено: {1} · неподписанных: {2} · совпадений имён: {3} · папок: {4}", "Записів: {0} · файлів перевірено: {1} · непідписаних: {2} · збігів назв: {3} · тек: {4}"),
    "memory_note": ("Roblox açıkken private çalıştırılabilir bellek bölgelerini ve thread başlangıç adreslerini listeler. JIT ve koruma yazılımları benzer iz bırakabilir; sonuçlar ayrı tutulur ve Risk Score'a eklenmez.", "While Roblox is open, lists private executable memory regions and thread start addresses inside them. JIT and protection software can produce similar traces; results stay separate and do not affect Risk Score.", "При открытом Roblox показывает частные исполняемые области памяти и адреса запуска потоков внутри них. JIT и защитное ПО могут оставлять похожие следы; результаты не влияют на Risk Score.", "Коли Roblox відкритий, показує приватні виконувані області пам'яті та адреси старту потоків у них. JIT і захисне ПЗ можуть залишати схожі сліди; результати не впливають на Risk Score."),
    "memory_scan": ("Roblox özel belleğini tara", "Scan Roblox private memory", "Сканировать частную память Roblox", "Сканувати приватну пам'ять Roblox"),
    "memory_done": ("{0} kayıt · {1} thread başlangıcı · {2} private exec bölgesi", "{0} records · {1} thread starts · {2} private executable regions", "Записей: {0} · стартов потоков: {1} · частных исполняемых областей: {2}", "Записів: {0} · стартів потоків: {1} · приватних виконуваних областей: {2}"),
    "method_idle": ("Henüz taranmadı.", "Not scanned yet.", "Ещё не сканировалось.", "Ще не сканувалося."),
    "method_done": ("{0} kayıt", "{0} records", "Записей: {0}", "Записів: {0}"),
    "method_col_time": ("Zaman", "Time", "Время", "Час"),
    "method_col_name": ("Dosya / işlem", "File / process", "Файл / процесс", "Файл / процес"),
    "method_col_path": ("Yol", "Path", "Путь", "Шлях"),
    "method_col_detail": ("Kayıt / ayrıntı", "Record / detail", "Запись / детали", "Запис / деталі"),
    "p_live_mem_none": ("Private çalıştırılabilir bölgede thread başlangıcı bulunmadı ({0} bölge incelendi). Bu sonuç hile olmadığını kanıtlamaz.", "No thread start was found in private executable memory ({0} regions inspected). This does not prove the system is cheat-free.", "В частной исполняемой памяти не найден старт потока ({0} областей проверено). Это не доказывает отсутствие чита.", "У приватній виконуваній пам'яті не знайдено старт потоку ({0} областей перевірено). Це не доводить відсутність чита."),
    "p_live_mem_partial": ("Tarama kısmi tamamlandı: {0} bölge incelendi; bulgu yok.", "Scan was partial: {0} regions inspected; no thread-start finding.", "Сканирование выполнено частично: проверено областей — {0}; совпадений нет.", "Сканування виконано частково: перевірено областей — {0}; збігів немає."),
    "pw_rb_start": ("Roblox başladı", "Roblox started", "Запуск Roblox", "Запуск Roblox"),
    "pw_app_start": ("Uygulama başlatıldı", "App launched", "Запуск приложения", "Запуск програми"),
    "pw_offset": ("Fark", "Offset", "Разница", "Різниця"),
    "pw_name": ("Uygulama", "Application", "Приложение", "Програма"),
    "pw_source": ("Kayıt", "Record", "Источник", "Джерело"),
    "p_none": ("Şüpheli kayıt bulunamadı.", "No suspicious entries found.", "Подозрительных записей нет.", "Підозрілих записів немає."),
    "log_p_start": ("Roblox taranıyor (DLL / handle / bellek)...", "Scanning Roblox (DLL / handles / memory)...",
                    "Сканирование Roblox (DLL / handle / память)...", "Сканування Roblox (DLL / handle / пам'ять)..."),
    "log_p_src": ("{0}: {1} bulgu / {2} işlem", "{0}: {1} findings / {2} processes",
                  "{0}: находок {1} / процессов {2}", "{0}: знахідок {1} / процесів {2}"),
    "log_p_mem": ("Bellek: {0} bölge tarandı ({1} MB)", "Memory: {0} regions scanned ({1} MB)",
                  "Память: просканировано регионов {0} ({1} МБ)", "Пам'ять: проскановано регіонів {0} ({1} МБ)"),
    "log_p_rb_closed": ("Roblox açık değil. (Roblox yöntemi puana dahil edilmeyecek)",
                        "Roblox is not open. (The Roblox method will be excluded from the score)",
                        "Roblox not open. (метод Roblox не войдёт в оценку)",
                        "Roblox not open. (метод Roblox не ввійде в оцінку)"),
    "log_p_done": ("Roblox taraması bitti: {0} bulgu ({1}s)", "Roblox scan finished: {0} findings ({1}s)",
                   "Сканирование Roblox завершено: {0} ({1}с)", "Сканування Roblox завершено: {0} ({1}с)"),
    # ---- risk
    "r_scan_all": ("Hepsini tara", "Scan all", "Скан всего", "Скан усього"),
    "r_custom": ("Özel hesapla", "Custom calculate", "Выборочный расчёт", "Вибірковий розрахунок"),
    "r_reset": ("Sıfırla", "Reset", "Сброс", "Скидання"),
    "r_methods": ("YÖNTEMLER", "METHODS", "МЕТОДЫ", "МЕТОДИ"),
    "r_state": ("Browse {0} · Data {1} · İzler {2} · Başlatma {3} · USN {4} · EXE {5} · Bellek {6} · Roblox {7} · Adli {8} · Boot {9}",
                "Browse {0} · Data {1} · Traces {2} · Launch {3} · USN {4} · EXE {5} · Memory {6} · Roblox {7} · Forensic {8} · Boot {9}",
                "Browse {0} · Data {1} · Следы {2} · Запуски {3} · USN {4} · EXE {5} · Память {6} · Roblox {7} · Форензика {8} · Boot {9}",
                "Browse {0} · Data {1} · Сліди {2} · Запуски {3} · USN {4} · EXE {5} · Пам'ять {6} · Roblox {7} · Форензика {8} · Boot {9}"),
    "r_ok": ("tarandı", "scanned", "проверено", "перевірено"),
    "r_no": ("taranmadı", "not scanned", "не проверено", "не перевірено"),
    "r_note": (
        "«Hepsini tara» tüm yöntemleri tarar. «Özel hesapla» sadece seçtiklerini tarar; «Sıfırla» sonucu ve seçimi temizler. Canlı Roblox belleği Roblox kapalıysa atlanır. İmzasız dosya, USN kaydı veya özel bellek bölgesi tek başına hile kanıtı değildir; bulguları incele. Bilinen hash'ler slave_hashes.txt dosyasına yazılır.",
        "«Scan all» scans every method. «Custom calculate» scans only selected methods; «Reset» clears the result and selection. Live Roblox memory is skipped when Roblox is closed. An unsigned file, USN record, or private memory region alone is not proof of cheating; review findings manually. Known hashes go in slave_hashes.txt.",
        "«Скан всего» запускает все методы. «Выборочный расчёт» запускает только выбранные; «Сброс» очищает результат и выбор. Проверка памяти пропускается, если Roblox закрыт. Неподписанный файл, запись USN или частная область памяти сами по себе не доказывают чит; проверяйте находки вручную. Известные хеши — в slave_hashes.txt.",
        "«Скан усього» запускає всі методи. «Вибірковий розрахунок» запускає лише вибрані; «Скидання» очищає результат і вибір. Перевірка пам'яті пропускається, якщо Roblox закритий. Непідписаний файл, запис USN чи приватна область пам'яті самі по собі не доводять чит; перевіряйте знахідки вручну. Відомі хеші — у slave_hashes.txt."),
    "r_gauge": ("RİSK PUANI", "RISK SCORE", "ОЦЕНКА РИСКА", "ОЦІНКА РИЗИКУ"),
    "r_cat_hash": ("Bilinen hile karması", "Known cheat hash", "Известный хеш чита", "Відомий хеш чита"),
    "r_cat_process": ("Şüpheli işlem", "Suspicious process", "Подозрительный процесс", "Підозрілий процес"),
    "r_cat_path": ("Tutarsız dosya yolu", "Inconsistent path", "Несоответствие пути", "Невідповідність шляху"),
    "r_cat_name": ("Sadece isim", "Name only", "Только имя", "Лише ім'я"),
    "r_cat_trace": ("Silinse de kalan iz", "Surviving trace", "Уцелевший след", "Вцілілий слід"),
    "r_cat_roblox": ("Roblox (DLL / bellek)", "Roblox (DLL / memory)", "Roblox (DLL / память)", "Roblox (DLL / пам'ять)"),
    "rc_lvl": ("Seviye", "Level", "Уровень", "Рівень"),
    "rc_cat": ("Sinyal", "Signal", "Сигнал", "Сигнал"),
    "rc_find": ("Bulgu", "Finding", "Находка", "Знахідка"),
    "rc_detail": ("Detay", "Detail", "Детали", "Деталі"),
    "r_low": ("DÜŞÜK", "LOW", "НИЗКИЙ", "НИЗЬКИЙ"),
    "r_med": ("ORTA", "MEDIUM", "СРЕДНИЙ", "СЕРЕДНІЙ"),
    "r_high": ("YÜKSEK", "HIGH", "ВЫСОКИЙ", "ВИСОКИЙ"),
    "r_idle": ("Henüz puan yok. «Hepsini tara» ya da yöntem seçip «Özel hesapla».",
               "No score yet. Press «Scan all» or tick methods and press «Custom calculate».",
               "Оценки ещё нет. Нажмите «Скан всего» или выберите методы и «Выборочный расчёт».",
               "Оцінки ще немає. Натисніть «Скан усього» або виберіть методи й «Вибірковий розрахунок»."),
    "r_summary": ("{0} · {1} bulgu · {2} bağımsız sinyal", "{0} · {1} findings · {2} independent signals",
                  "{0} · находок: {1} · независимых сигналов: {2}", "{0} · знахідок: {1} · незалежних сигналів: {2}"),
    "f_hash": ("Bilinen hile karması eşleşti", "Known cheat hash matched", "Совпал известный хеш чита", "Збігся відомий хеш чита"),
    "f_proc": ("Şüpheli işlem çalışıyor", "Suspicious process running", "Запущен подозрительный процесс", "Запущено підозрілий процес"),
    "f_proc_net": ("Şüpheli işlem + aktif bağlantı", "Suspicious process with active connections",
                   "Подозрительный процесс с активными соединениями", "Підозрілий процес з активними з'єднаннями"),
    "f_masq": ("Sistem işlemi adı yanlış konumda", "System process name in the wrong location",
               "Имя системного процесса в неверном месте", "Ім'я системного процесу в хибному місці"),
    "f_path": ("Şüpheli konumda çalıştırılabilir dosya", "Executable in a suspicious location",
               "Исполняемый файл в подозрительном месте", "Виконуваний файл у підозрілому місці"),
    "f_name": ("Dosya adı eşleşmesi", "File name match", "Совпадение имени файла", "Збіг імені файлу"),
    "f_pname": ("İşlem adı eşleşmesi", "Process name match", "Совпадение имени процесса", "Збіг імені процесу"),
    "f_trace_del": ("Çalıştırılmış ama dosya silinmiş", "Was executed/seen but the file is gone",
                    "Запускался/виден, но файл удалён", "Запускався/видно, але файл видалено"),
    "f_trace_run": ("Çalıştırma kaydı bulundu", "Execution record found",
                    "Найдена запись о запуске", "Знайдено запис про запуск"),
    "f_trace_ren": ("Dosya yeniden adlandırılmış (USN)", "File was renamed (USN)",
                    "Файл переименован (USN)", "Файл перейменовано (USN)"),
    "f_trace_seen": ("Sistem kaydında görüldü", "Seen in a system record", "Замечен в системной записи", "Помічений у системному записі"),
    "f_session_app": ("Roblox başlangıcına yakın uygulama", "App launched near Roblox", "Приложение запущено рядом с Roblox", "Програму запущено поблизу Roblox"),
    "f_session_review": ("İmzasız pencere uygulaması incelenmeli", "Unsigned GUI app needs review", "Неподписанное GUI-приложение требует проверки", "Непідписана GUI-програма потребує перевірки"),
    "f_usn_event": ("Yakın tarihli EXE dosya olayı (USN)", "Recent EXE file event (USN)", "Недавнее событие EXE в USN", "Недавня подія EXE в USN"),
    "f_unsigned_exe": ("Yeni imzasız EXE incelenmeli", "Recent unsigned EXE needs review", "Новый неподписанный EXE требует проверки", "Новий непідписаний EXE потребує перевірки"),
    "f_config_match": ("Yapılandırılmış hile adı eşleşmesi", "Configured cheat-name match", "Совпадение с именем из списка", "Збіг із назвою зі списку"),
    "f_exec_region": ("Private çalıştırılabilir bellek bölgesi", "Private executable memory region", "Частная исполняемая область памяти", "Приватна виконувана область пам'яті"),
    "f_exec_thread": ("Thread başlangıcı private bellekte", "Thread start in private executable memory", "Старт потока в частной исполняемой памяти", "Старт потоку в приватній виконуваній пам'яті"),
    "log_risk_start": ("Risk puanı hesaplanıyor...", "Calculating risk score...", "Расчёт оценки риска...", "Розрахунок оцінки ризику..."),
    "log_risk_done": ("Risk puanı: {0}/100 ({1} bulgu)", "Risk score: {0}/100 ({1} findings)",
                      "Оценка риска: {0}/100 (находок: {1})", "Оцінка ризику: {0}/100 (знахідок: {1})"),
    "r_export_html": ("HTML olarak dışa aktar", "Export to HTML", "Экспорт в HTML", "Експорт у HTML"),
    "r_export_title": ("Slave Results", "Slave Results", "Slave Results", "Slave Results"),
    "r_report_subtitle": ("Risk tarama raporu", "Risk scan report", "Отчёт сканирования рисков", "Звіт сканування ризиків"),
    "r_report_generated": ("Oluşturulma", "Generated", "Создан", "Створено"),
    "r_report_score": ("Risk puanı", "Risk score", "Оценка риска", "Оцінка ризику"),
    "r_report_signals": ("Bağımsız sinyal", "Independent signals", "Независимые сигналы", "Незалежні сигнали"),
    "r_report_breakdown": ("Sinyal dağılımı", "Signal breakdown", "Распределение сигналов", "Розподіл сигналів"),
    "r_report_methods": ("Tarama yöntemleri", "Scan methods", "Методы сканирования", "Методи сканування"),
    "r_report_findings": ("Bulgular", "Findings", "Находки", "Знахідки"),
    "r_report_category": ("Sinyal", "Signal", "Сигнал", "Сигнал"),
    "r_report_finding": ("Bulgu", "Finding", "Находка", "Знахідка"),
    "r_report_detail": ("Detay", "Details", "Детали", "Деталі"),
    "r_report_scanned": ("Tarandı", "Scanned", "Проверено", "Перевірено"),
    "r_report_not_scanned": ("Taranmadı", "Not scanned", "Не проверено", "Не перевірено"),
    "r_report_partial": ("Kısmen tamamlandı", "Partially complete", "Частично выполнено", "Виконано частково"),
    "r_report_rb_closed": ("Roblox açık değildi", "Roblox was not open", "Roblox не был запущен", "Roblox не було запущено"),
    "r_report_empty": ("Bu taramada eşleşen bulgu bulunmadı.", "No matching findings in this scan.",
                       "В этом сканировании совпадений не найдено.", "У цьому скануванні збігів не знайдено."),
    "r_report_disclaimer": ("Bu puan inceleme için bir göstergedir, kesin kanıt veya otomatik suçlama değildir. Bulguları bağlamıyla birlikte elle değerlendirin.",
                            "This score is an indicator for review, not proof or an automatic accusation. Review findings in context.",
                            "Эта оценка служит ориентиром для проверки, а не доказательством или автоматическим обвинением. Оценивайте находки с учётом контекста.",
                            "Ця оцінка є орієнтиром для перевірки, а не доказом чи автоматичним звинуваченням. Оцінюйте знахідки з урахуванням контексту."),
    "r_report_print": ("Yazdır / PDF", "Print / PDF", "Печать / PDF", "Друк / PDF"),
    "r_session_title": ("Roblox oturum zaman çizelgesi · bağlam bilgisi", "Roblox session timeline · context only", "Временная шкала сессии Roblox · только контекст", "Часова шкала сесії Roblox · лише контекст"),
    "r_session_note": ("Prefetch, BAM ve UserAssist zamanlarına göre Roblox başlangıcına yakın uygulamalar. Yalnızca zaman yakınlığı zayıf bağlam sinyali verir; açık kalma süresini veya hile olduğunu kanıtlamaz.", "Applications launched near Roblox startup based on Prefetch, BAM, and UserAssist timestamps. Timing alone is only weak context; it does not prove how long an app stayed open or that it was a cheat.", "Приложения, запущенные близко к Roblox по времени Prefetch, BAM и UserAssist. Одно совпадение по времени — лишь слабый контекст; оно не доказывает, как долго приложение оставалось открытым или что это был чит.", "Програми, запущені близько до Roblox за часом Prefetch, BAM і UserAssist. Сам збіг у часі — лише слабкий контекст; він не доводить, як довго програма залишалася відкритою або що це був чит."),
    "r_report_time": ("Zaman", "Time", "Время", "Час"),
    "r_report_path": ("Dosya yolu", "File path", "Путь к файлу", "Шлях до файлу"),
    "r_report_evidence": ("Kayıt / ayrıntı", "Record / details", "Запись / детали", "Запис / деталі"),
    "r_boot_title": ("Önyükleme ortamı · bağlam bilgisi", "Boot environment · context only",
                     "Среда загрузки · только контекст", "Середовище завантаження · лише контекст"),
    "r_boot_note": ("Salt okunur kontrol. Bu bilgiler risk puanına eklenmez; önyükleme girdileri tek başına başka bir işletim sisteminin kurulu olduğunu kanıtlamaz.",
                    "Read-only check. This information does not affect the risk score; boot entries alone do not prove another operating system is installed.",
                    "Проверка только для чтения. Эти сведения не влияют на оценку риска; записи загрузки сами по себе не доказывают установку другой ОС.",
                    "Перевірка лише для читання. Ці відомості не впливають на оцінку ризику; записи завантаження самі по собі не доводять встановлення іншої ОС."),
    "r_boot_type": ("Bilgi", "Information", "Сведения", "Відомості"),
    "r_boot_detail": ("Ayrıntı", "Details", "Детали", "Деталі"),
    "r_boot_current": ("Etkin Windows", "Current Windows", "Текущая Windows", "Поточна Windows"),
    "r_boot_windows": ("Ek Windows kurulum adayı", "Additional Windows installation candidate",
                       "Возможная дополнительная установка Windows", "Можлива додаткова інсталяція Windows"),
    "r_boot_firmware": ("Olası alternatif EFI girdisi", "Possible alternative EFI entry",
                        "Возможная альтернативная запись EFI", "Можливий альтернативний запис EFI"),
    "r_boot_partition": ("Windows dışı bölüm", "Non-Windows partition", "Раздел не Windows", "Розділ не Windows"),
    "r_boot_osloader": ("Ek önyükleme girdisi (BCD)", "Extra boot entry (BCD)", "Доп. запись загрузки (BCD)", "Дод. запис завантаження (BCD)"),
    "r_boot_summary": ("Bağlı yerel sürücülerde ek Windows kurulumu bulunmadı.", "No additional Windows installation found on mounted local drives.",
                       "На подключённых локальных дисках дополнительные установки Windows не найдены.", "На підключених локальних дисках додаткових інсталяцій Windows не знайдено."),
    "r_boot_no_firmware": ("Okunabilen Windows dışı EFI yolu bulunmadı.", "No readable non-Windows EFI path found.",
                           "Читаемые EFI-пути вне Windows не найдены.", "Читабельних EFI-шляхів поза Windows не знайдено."),
    "r_boot_unavailable": ("Firmware girdileri okunamadı; bu bölüm eksik kalmış olabilir.", "Firmware entries could not be read; this section may be incomplete.",
                           "Не удалось прочитать записи firmware; этот раздел может быть неполным.", "Не вдалося прочитати записи firmware; цей розділ може бути неповним."),
    "r_boot_volumes_unavailable": ("Bağlı sürücüler listelenemedi; Windows kurulum kontrolü eksik olabilir.",
                                   "Mounted drives could not be enumerated; the Windows installation check may be incomplete.",
                                   "Не удалось перечислить подключённые диски; проверка установок Windows может быть неполной.",
                                   "Не вдалося перелічити підключені диски; перевірка інсталяцій Windows може бути неповною."),
    "r_boot_checked": ("Kontrol edilen yerel sürücü kökü: {0}", "Mounted local drive roots checked: {0}",
                       "Проверено корней локальных дисков: {0}", "Перевірено коренів локальних дисків: {0}"),
    "r_boot_idle": ("Önyükleme kontrolünü çalıştırmak için bu yöntemi seçin.", "Select this method to scan the boot environment.",
                    "Выберите этот метод для проверки среды загрузки.", "Виберіть цей метод для перевірки середовища завантаження."),
    "r_boot_scanning": ("Önyükleme bilgileri salt okunur biçimde kontrol ediliyor…", "Reading boot context (read-only)…",
                        "Чтение сведений о загрузке (только чтение)…", "Читання відомостей про завантаження (лише читання)…"),
    "r_export_done": ("HTML raporu kaydedildi.", "HTML report saved.", "HTML-отчёт сохранён.", "HTML-звіт збережено."),
    "r_export_fail": ("HTML raporu kaydedilemedi: {0}", "Could not save HTML report: {0}",
                      "Не удалось сохранить HTML-отчёт: {0}", "Не вдалося зберегти HTML-звіт: {0}"),
}


def tx(lang, key, *a):
    v = S.get(key)
    s = v[LANGS.index(lang)] if v else key
    return s.format(*a) if a and isinstance(s, str) else s


def sys_lang():
    try:
        pid = ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0xFF
        return {0x1F: "tr", 0x19: "ru", 0x22: "uk"}.get(pid, "en")
    except Exception:
        return "en"


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def split_names(text):
    return [s.strip() for s in text.replace(";", ",").split(",") if s.strip()]


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ============================== EVERYTHING ==============================
class EverythingError(Exception):
    pass


EVERYTHING_EXES = ("Everything.exe", "Everything64.exe")


def find_es():
    home = os.path.expanduser("~")
    cands = [shutil.which("es"), shutil.which("es.exe"), os.path.join(HERE, "es.exe"),
             r"C:\Program Files\Everything\es.exe", r"C:\Program Files (x86)\Everything\es.exe",
             r"C:\Program Files\Everything 1.5a\es.exe",
             os.path.join(home, "Desktop", "es.exe"), os.path.join(home, "Downloads", "es.exe")]
    return next((c for c in cands if c and os.path.isfile(c)), None)


def everything_running():
    if os.name != "nt":
        return False
    for exe in EVERYTHING_EXES:
        try:
            r = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {exe}", "/NH"],
                               capture_output=True, timeout=15, creationflags=NOWIN)
        except Exception:
            return False
        if exe.lower() in r.stdout.decode("utf-8", "replace").lower():
            return True
    return False


def find_everything():
    cands = []
    for exe in EVERYTHING_EXES:
        cands += [shutil.which(exe), os.path.join(HERE, exe)]
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                     os.environ.get("LOCALAPPDATA")):
            if base:
                cands += [os.path.join(base, "Everything", exe),
                          os.path.join(base, "Everything 1.5a", exe),
                          os.path.join(base, "Programs", "Everything", exe)]
    return next((c for c in cands if c and os.path.isfile(c)), None)


def start_everything():
    if os.name != "nt":
        return "missing"
    if everything_running():
        return "running"
    path = find_everything()
    if not path:
        return "missing"
    try:
        subprocess.Popen([path, "-startup"], cwd=os.path.dirname(path), creationflags=NOWIN)
    except OSError:
        return "missing"
    return "started"


def _decode_lines(raw):
    encs = ["utf-8"]
    try:
        encs += [f"cp{ctypes.windll.kernel32.GetOEMCP()}", f"cp{ctypes.windll.kernel32.GetACP()}"]
    except Exception:
        pass
    best, best_score = None, -1
    for enc in encs:
        try:
            lines = [l.strip() for l in raw.decode(enc).splitlines() if l.strip()]
        except Exception:
            continue
        score = sum(os.path.exists(l) for l in lines[:50])
        if score > best_score:
            best, best_score = lines, score
    if best is None:
        best = [l.strip() for l in raw.decode("utf-8", "replace").splitlines() if l.strip()]
    return best


def everything_term(name):
    n = name.strip()
    return "*" + n.replace(" ", "?") + "*" if " " in n else n


def search_es(es, name, whole):
    cmd = [es, "-n", str(MAX_RESULTS)] + (["-w"] if whole else []) + [everything_term(name)]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60, creationflags=NOWIN)
    except subprocess.TimeoutExpired:
        raise EverythingError("es.exe did not respond within 60 seconds.")
    except OSError as e:
        raise EverythingError(f"could not run es.exe: {e}")
    if r.returncode != 0:
        msg = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
        raise EverythingError(f"es.exe error code {r.returncode}: {msg or 'Everything may not be running.'}")
    return _decode_lines(r.stdout)


def search_http(name, whole):
    q = ("ww:" if whole else "") + everything_term(name)
    params = urllib.parse.urlencode({"search": q, "json": 1, "count": MAX_RESULTS, "path_column": 1})
    try:
        with urllib.request.urlopen(f"{HTTP_URL}/?{params}", timeout=15) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        raise EverythingError(f"HTTP server unreachable ({HTTP_URL}): {e}")
    return [os.path.join(it.get("path", ""), it.get("name", "")) for it in data.get("results", [])]


def search_everything(name, whole):
    errors = []
    es = find_es()
    if es:
        try:
            return search_es(es, name, whole), "es.exe"
        except EverythingError as e:
            errors.append(str(e))
    else:
        errors.append("es.exe not found.")
    try:
        return search_http(name, whole), "HTTP"
    except EverythingError as e:
        errors.append(str(e))
    raise EverythingError("\n".join(errors))


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def file_info(path):
    try:
        st = os.stat(path)
        isdir = os.path.isdir(path)
        return (isdir, "—" if isdir else human(st.st_size),
                datetime.fromtimestamp(st.st_mtime).strftime("%d.%m.%Y %H:%M"))
    except OSError:
        return (False, "—", "—")


# ============================== DATA USAGE ==============================
SRUM_NETWORK_TABLE = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
SRUM_ID_TABLE = "SruDbIdMapTable"
SRUM_LOOKBACK_DAYS = 30


def _srum_parser_class():
    try:
        from dissect.database.ese import ESE
        return ESE
    except ImportError:
        try:
            from dissect.esedb import EseDB
            return EseDB
        except ImportError as e:
            raise RuntimeError("ESE reader is not installed") from e


def _srum_table(db, name):
    getter = getattr(db, "table", None) or getattr(db, "get_table_by_name", None)
    if getter is None:
        raise RuntimeError("ESE reader does not expose table access")
    return getter(name)


def _srum_records(table):
    records = getattr(table, "records", None)
    if callable(records):
        return records()
    if records is not None:
        return records
    records = getattr(table, "get_records", None)
    if callable(records):
        return records()
    raise RuntimeError("ESE reader does not expose table records")


def _srum_value(record, name, default=None):
    try:
        value = record.get(name)
    except (AttributeError, KeyError, TypeError):
        try:
            value = record[name]
        except (AttributeError, KeyError, TypeError):
            return default
    return default if value is None else value


def _srum_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-16-le", "replace")
        except Exception:
            value = value.decode("utf-8", "replace")
    return str(value).replace("\x00", "").lstrip("\ufeff").strip()


def _srum_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except ValueError:
            return None
    if isinstance(value, bytes):
        if len(value) != 8:
            return None
        try:
            ole = struct.unpack("<d", value)[0]
            if 0 < ole < 100000:
                return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=ole)
            value = struct.unpack("<q", value)[0]
        except (OverflowError, ValueError, struct.error):
            return None
    if isinstance(value, (int, float)):
        try:
            if value > 10**16:  # Windows FILETIME
                return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value / 10)
            if value > 10**12:  # Unix milliseconds
                return datetime.fromtimestamp(value / 1000, timezone.utc)
            if value > 10**9:  # Unix seconds
                return datetime.fromtimestamp(value, timezone.utc)
            if value > 0:  # OLE Automation date
                return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=value)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def fetch_srum_usage():
    """Read Windows' per-app network history from SRUM (rather than live disk I/O)."""
    if os.name != "nt":
        raise RuntimeError("Windows only")
    srum_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "sru", "SRUDB.dat")
    try:
        os.stat(srum_path)
    except FileNotFoundError as e:
        raise RuntimeError(f"SRUDB.dat was not found at {srum_path}") from e
    except PermissionError as e:
        raise RuntimeError("SRUDB.dat access denied; run Slave as administrator") from e
    parser_class = _srum_parser_class()
    try:
        with open(srum_path, "rb") as fh:
            db = parser_class(fh)
            id_table = _srum_table(db, SRUM_ID_TABLE)
            network_table = _srum_table(db, SRUM_NETWORK_TABLE)
            id_map = {}
            for record in _srum_records(id_table):
                try:
                    id_type = int(_srum_value(record, "IdType", -1))
                    if id_type == 3:  # User SID, not an application identity.
                        continue
                    app_id = int(_srum_value(record, "IdIndex", -1))
                    app_path = _srum_text(_srum_value(record, "IdBlob"))
                    if app_id >= 0 and app_path:
                        id_map[app_id] = app_path
                except (TypeError, ValueError, OverflowError):
                    continue

            since = datetime.now(timezone.utc) - timedelta(days=SRUM_LOOKBACK_DAYS)
            totals = {}
            for record in _srum_records(network_table):
                try:
                    app_id = int(_srum_value(record, "AppId", -1))
                    if app_id < 0:
                        continue
                    stamp = _srum_datetime(_srum_value(record, "TimeStamp"))
                    if stamp and stamp < since:
                        continue
                    received = max(0, int(_srum_value(record, "BytesRecvd", 0) or 0))
                    sent = max(0, int(_srum_value(record, "BytesSent", 0) or 0))
                    if received + sent <= 0:
                        continue
                    path = id_map.get(app_id) or f"AppId {app_id}"
                    key = path.casefold()
                    name = ntpath.basename(path.replace("/", "\\").rstrip("\\")) or path
                    row = totals.setdefault(key, {
                        "app": name, "inst": 0, "read": 0, "write": 0, "other": 0,
                        "total": 0, "rate": 0.0, "conn": 0, "path": path, "last": None,
                    })
                    row["read"] += received
                    row["write"] += sent
                    row["total"] += received + sent
                    row["inst"] += 1
                    if stamp and (row["last"] is None or stamp > row["last"]):
                        row["last"] = stamp
                except (TypeError, ValueError, OverflowError):
                    continue
    except PermissionError as e:
        raise RuntimeError("SRUDB.dat access denied; run as administrator") from e
    except Exception as e:
        raise RuntimeError(f"could not parse SRUDB.dat: {e}") from e
    return list(totals.values())


PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$paths = @{}
Get-Process | ForEach-Object { $paths[[string]$_.Id] = $_.Path }
$conn = @{}
Get-NetTCPConnection -State Established | Group-Object OwningProcess | ForEach-Object { $conn[[string]$_.Name] = $_.Count }
$rows = Get-CimInstance Win32_PerfRawData_PerfProc_Process |
  Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' } |
  ForEach-Object {
    [pscustomobject]@{
      name  = $_.Name
      pid   = $_.IDProcess
      read  = [double]$_.IOReadBytesPersec
      write = [double]$_.IOWriteBytesPersec
      other = [double]$_.IOOtherBytesPersec
      path  = $paths[[string]$_.IDProcess]
      conns = [int]$conn[[string]$_.IDProcess]
    }
  }
ConvertTo-Json -InputObject @($rows) -Compress
"""


def fetch_live_process_usage():
    if os.name != "nt":
        raise RuntimeError("Windows only")
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + PS_SCRIPT],
            capture_output=True, timeout=90, creationflags=NOWIN)
    except subprocess.TimeoutExpired:
        raise RuntimeError("PowerShell did not respond within 90 seconds.")
    except OSError as e:
        raise RuntimeError(f"could not run PowerShell: {e}")
    out = r.stdout.decode("utf-8", "replace").strip()
    if not out:
        raise RuntimeError(r.stderr.decode("utf-8", "replace").strip() or "empty output")
    try:
        data = json.loads(out)
    except ValueError as e:
        raise RuntimeError(f"unreadable output: {e}")
    if isinstance(data, dict):
        data = [data]
    agg = {}
    for d in data:
        nm = re.sub(r"#\d+$", "", d.get("name") or "")
        if not nm:
            continue
        a = agg.setdefault(nm.lower(), {"app": nm, "inst": 0, "read": 0.0, "write": 0.0,
                                        "other": 0.0, "conn": 0, "path": ""})
        a["inst"] += 1
        a["read"] += d.get("read") or 0
        a["write"] += d.get("write") or 0
        a["other"] += d.get("other") or 0
        a["conn"] += d.get("conns") or 0
        if not a["path"] and d.get("path"):
            a["path"] = d["path"]
    for a in agg.values():
        a["total"] = a["read"] + a["write"]
    return list(agg.values())


# ============================== WINDOWS TRACES ==============================
FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")


def ft_str(ft):
    try:
        if not ft:
            return "—"
        return (FT_EPOCH + timedelta(microseconds=ft // 10)).astimezone().strftime("%d.%m.%Y %H:%M")
    except (OverflowError, OSError, ValueError):
        return "—"


_DEV = {}


def dev_map():
    if _DEV or os.name != "nt":
        return _DEV
    buf = ctypes.create_unicode_buffer(1024)
    for l in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        try:
            if ctypes.windll.kernel32.QueryDosDeviceW(f"{l}:", buf, 1024):
                _DEV[buf.value.lower()] = f"{l}:"
        except Exception:
            break
    return _DEV


def norm_path(p):
    if p.lower().startswith("\\device\\"):
        low = p.lower()
        for dev, drv in dev_map().items():
            if low.startswith(dev + "\\"):
                return drv + p[len(dev):]
    return p


def path_state(path):
    if re.match(r"^[a-zA-Z]:\\", path):
        return os.path.exists(path)
    return None


def mk(path, when="—", reason=""):
    path = norm_path(path)
    return {"path": path, "when": when, "reason": reason, "exists": path_state(path)}


def reg_values(key):
    i = 0
    while True:
        try:
            yield winreg.EnumValue(key, i)
        except OSError:
            return
        i += 1


def reg_subkeys(key):
    i = 0
    while True:
        try:
            yield winreg.EnumKey(key, i)
        except OSError:
            return
        i += 1


def need_win():
    if winreg is None or os.name != "nt":
        raise RuntimeError("Windows only")


def tr_prefetch():
    need_win()
    d = os.path.join(SYSROOT, "Prefetch")
    rows = []
    for fn in os.listdir(d):
        if fn.lower().endswith(".pf") and "-" in fn:
            exe = fn.rsplit("-", 1)[0]
            try:
                when = datetime.fromtimestamp(os.path.getmtime(os.path.join(d, fn))).strftime("%d.%m.%Y %H:%M")
            except OSError:
                when = "—"
            rows.append({"path": exe, "when": when, "reason": "", "exists": None})
    return rows


def tr_bam():
    need_win()
    rows = []
    for root in (r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                 r"SYSTEM\CurrentControlSet\Services\bam\UserSettings"):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root)
        except FileNotFoundError:
            continue
        with k:
            for sid in reg_subkeys(k):
                try:
                    sk = winreg.OpenKey(k, sid)
                except OSError:
                    continue
                with sk:
                    for name, val, typ in reg_values(sk):
                        if typ == winreg.REG_BINARY and len(val) >= 8 and "\\" in name:
                            rows.append(mk(name, ft_str(struct.unpack("<Q", val[:8])[0])))
    return rows


def tr_mui():
    need_win()
    rows = []
    key = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
        for name, _v, _t in reg_values(k):
            if name.endswith(".FriendlyAppName"):
                rows.append(mk(name[:-len(".FriendlyAppName")]))
    return rows


def tr_ua():
    need_win()
    rows = []
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as k:
        for guid in reg_subkeys(k):
            try:
                ck = winreg.OpenKey(k, guid + "\\Count")
            except OSError:
                continue
            with ck:
                for vname, data, _t in reg_values(ck):
                    name = codecs.decode(vname, "rot_13")
                    cnt, ft = 0, 0
                    if isinstance(data, (bytes, bytearray)) and len(data) >= 68:
                        cnt = struct.unpack("<I", data[4:8])[0]
                        ft = struct.unpack("<Q", data[60:68])[0]
                    rows.append(mk(name, ft_str(ft), f"x{cnt}"))
    return rows


def parse_shim(data):
    out = []
    if len(data) < 52:
        return out
    pos = struct.unpack("<I", data[:4])[0]
    if pos not in (0x30, 0x34):
        return out
    while pos + 12 <= len(data) and data[pos:pos + 4] == b"10ts":
        sz = struct.unpack("<I", data[pos + 8:pos + 12])[0]
        entry = data[pos + 12:pos + 12 + sz]
        if len(entry) < sz or sz < 12:
            break
        plen = struct.unpack("<H", entry[:2])[0]
        path = entry[2:2 + plen].decode("utf-16le", "replace")
        ft = struct.unpack("<Q", entry[2 + plen:10 + plen])[0] if len(entry) >= 10 + plen else 0
        out.append((path, ft))
        pos += 12 + sz
    return out


def tr_shim():
    need_win()
    key = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
        data, _t = winreg.QueryValueEx(k, "AppCompatCache")
    return [mk(p, ft_str(ft)) for p, ft in parse_shim(bytes(data))]


def tr_amcache():
    need_win()
    src = os.path.join(SYSROOT, "appcompat", "Programs", "Amcache.hve")
    tmpd = tempfile.mkdtemp(prefix="slave_amc_")
    dst = os.path.join(tmpd, "Amcache.hve")
    loaded, rows = False, []
    try:
        subprocess.run(["esentutl.exe", "/y", src, "/vss", "/d", dst], capture_output=True,
                       timeout=180, creationflags=NOWIN)
        if not os.path.isfile(dst):
            try:
                shutil.copy2(src, dst)
            except OSError:
                raise PermissionError("cannot copy Amcache.hve")
        r = subprocess.run(["reg", "load", r"HKLM\SLAVE_AMC", dst], capture_output=True,
                           timeout=60, creationflags=NOWIN)
        if r.returncode != 0:
            raise PermissionError("reg load failed")
        loaded = True
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SLAVE_AMC\Root\InventoryApplicationFile") as k:
            for sub in reg_subkeys(k):
                try:
                    sk = winreg.OpenKey(k, sub)
                except OSError:
                    continue
                with sk:
                    try:
                        path = winreg.QueryValueEx(sk, "LowerCaseLongPath")[0]
                    except OSError:
                        continue
                    try:
                        sha1 = winreg.QueryValueEx(sk, "FileId")[0][4:]
                    except OSError:
                        sha1 = ""
                    rows.append(mk(path, ft_str(winreg.QueryInfoKey(sk)[2]), f"sha1 {sha1}" if sha1 else ""))
    finally:
        if loaded:
            subprocess.run(["reg", "unload", r"HKLM\SLAVE_AMC"], capture_output=True,
                           timeout=60, creationflags=NOWIN)
        shutil.rmtree(tmpd, ignore_errors=True)
    return rows


def tr_usn(names, seconds=75):
    """Streams the NTFS change journal and keeps only entries whose file name matches."""
    drive = os.environ.get("SystemDrive", "C:")
    p = subprocess.Popen(["fsutil", "usn", "readjournal", drive, "csv"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, creationflags=NOWIN)
    try:
        enc = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:
        enc = "utf-8"
    deadline = time.time() + seconds
    head, seen, rows, total = None, set(), [], 0
    for raw in p.stdout:
        if time.time() > deadline:
            p.kill()
            break
        line = raw.decode(enc, "replace").strip()
        if not line:
            continue
        try:
            cols = next(csv.reader([line]))
        except Exception:
            continue
        total += 1
        if head is None:
            low = [c.strip().lower() for c in cols]
            if "file name" in low:
                head = (low.index("file name"),
                        low.index("reason") if "reason" in low else 2,
                        low.index("time stamp") if "time stamp" in low else 3)
                continue
            head = (1, 2, 3)
        if len(cols) <= max(head[0], head[1]):
            continue
        fname = cols[head[0]].strip()
        m = name_match(fname, names)
        if not m:
            continue
        reason = cols[head[1]].strip()
        key = (fname.lower(), reason.lower())
        if key in seen:
            continue
        seen.add(key)
        when = cols[head[2]].strip() if len(cols) > head[2] else "—"
        rows.append({"path": fname, "when": when or "—", "reason": reason, "exists": None})
        if len(rows) >= 400:
            p.kill()
            break
    p.wait()
    if total == 0:
        err = p.stderr.read().decode(enc, "replace").strip()
        raise PermissionError(err or "no output (administrator required)")
    return rows


def name_match(app, names):
    a = app.lower()
    a = a[:-4] if a.endswith(".exe") else a
    for n in names:
        nl = n.lower().replace(" ", "")
        nl = nl[:-4] if nl.endswith(".exe") else nl
        if len(nl) < 3:
            continue
        if a == nl or (len(nl) >= 5 and nl in a):
            return n
    return None


def trace_match(path, names):
    parts = path.replace("/", "\\").split("\\")
    m = name_match(parts[-1], names)
    if not m and len(parts) > 1:
        m = name_match(parts[-2], names)
    return m


def collect_traces(names, cb):
    """cb(level, key, *args) for logging. Returns list of trace rows."""
    if not is_admin():
        cb("WARN", "log_tr_noadmin")
    rows = []
    sources = (("Prefetch", tr_prefetch), ("BAM", tr_bam), ("MUICache", tr_mui),
               ("UserAssist", tr_ua), ("ShimCache", tr_shim), ("Amcache", tr_amcache),
               ("USN", lambda: tr_usn(names)))
    for label, fn in sources:
        try:
            raw = fn()
        except PermissionError as e:
            cb("WARN", "log_tr_err", label, f"access denied · {e}")
            continue
        except Exception as e:
            cb("WARN", "log_tr_err", label, f"{type(e).__name__}: {e}")
            continue
        hit = 0
        for r in raw:
            m = r.get("m") or trace_match(r["path"], names)
            if m:
                r["m"], r["src"] = m, label
                rows.append(r)
                hit += 1
        cb("OK", "log_tr_src", label, f"{hit}/{len(raw)}")
    uniq, out = set(), []
    for r in rows:
        k = (r["src"], r["path"].lower(), r["reason"].lower())
        if k not in uniq:
            uniq.add(k)
            out.append(r)
    out.sort(key=lambda r: (r["m"].lower(), r["src"], r["path"].lower()))
    return out


# ============================== ROBLOX: DLL / HANDLES / MEMORY ==============================
# Everything in this section only works while Roblox is open.
# Roblox closed -> collect_persist() returns ([], 0) and the method is left out of the risk score.
#
# Crash isolation: the module list (PowerShell) and the handle + memory scan (ctypes) run OUTSIDE the
# GUI process. The ctypes part is this same file started with  --rbscan <job.json> <out.json>.
# If that helper dies for any reason, the GUI only logs a warning and keeps running.
# Bilinen mesru uygulamalar: Roblox'a modul yukleyebilir ya da handle acabilir.
# Sadece ismine guvenmiyoruz: dosya adi bu uygulamayla baslamali VEYA klasor adi bu uygulama olmali,
# ve Temp / Downloads / Desktop / Public altinda olmamali.
SAFE_APPS = ("frosttrap", "bloxstrap", "medalencoder")
SAFE_BAD_DIR_RE = re.compile(r"\\(temp|downloads|desktop|users\\public)\\", re.I)


def is_safe_app(name, path):
    p = (path or "").lower().replace("/", "\\")
    if not p or SAFE_BAD_DIR_RE.search(p):
        return False
    base = os.path.basename(p)
    segs = p.split("\\")[:-1]
    for a in SAFE_APPS:
        if base.startswith(a) or any(s == a or s.startswith(a) for s in segs):
            return True
    return False


PS_RBLX = r"""
$ErrorActionPreference='SilentlyContinue'
$sysre='^[A-Za-z]:\\(Windows|Program Files\\WindowsApps)\\'
$riskre='\\(Temp|Downloads|Desktop|ProgramData|Users\\Public)\\'
$cn=@{}; $cc=@{}
Get-NetTCPConnection -State Established | Group-Object OwningProcess | ForEach-Object {
  $cc[[string]$_.Name]=$_.Count
  $cn[[string]$_.Name]=(@($_.Group | ForEach-Object {$_.RemoteAddress} | Select-Object -Unique -First 3) -join ',') }
$out=@()
$rb=@(Get-Process | Where-Object { $_.Name -match '^(RobloxPlayerBeta|Windows10Universal)$' -and $_.Path -match 'Roblox' })
foreach($p in $rb){
  $out += [pscustomobject]@{kind='proc'; pid=$p.Id; name=$p.Name; path=$p.Path}
  $seen=@{}
  try { foreach($m in $p.Modules){
    $f=$m.FileName
    if(-not $f -or $seen[$f] -or $f -match $sysre -or $f -match '\\Roblox\\'){continue}
    $seen[$f]=1
    if($seen.Count -gt 150){break}
    $sig=(Get-AuthenticodeSignature -LiteralPath $f).Status
    $out += [pscustomobject]@{kind='mod'; pid=$p.Id; name=$m.ModuleName; path=$f; sig=[string]$sig}
  } } catch {}
}
if($rb.Count -gt 0){
  Get-Process | Where-Object { $_.Path -and $_.Path -match $riskre -and $_.Path -notmatch $sysre } | ForEach-Object {
    $sig=(Get-AuthenticodeSignature -LiteralPath $_.Path).Status
    $out += [pscustomobject]@{kind='bg'; pid=$_.Id; name=$_.Name; path=$_.Path; sig=[string]$sig;
                              conns=[int]$cc[[string]$_.Id]; remote=[string]$cn[[string]$_.Id]}
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""

PROC_QUERY, PROC_VM_READ, PROC_LIMITED = 0x0400, 0x0010, 0x1000
MEM_COMMIT, MEM_IMAGE, MEM_MAPPED = 0x1000, 0x1000000, 0x40000
MIN_STR = 4
HANDLE_MASK = 0x0002 | 0x0008 | 0x0010 | 0x0020   # CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE
HANDLE_ENTRY = "<QQQIHHII"                        # SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, 40 bytes on x64
HANDLE_ENTRY_SIZE = struct.calcsize(HANDLE_ENTRY)
ALNUM = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789")   # data is lower-cased before searching
_API = {}


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_uint32), ("PartitionId", ctypes.c_uint16),
                ("RegionSize", ctypes.c_size_t), ("State", ctypes.c_uint32),
                ("Protect", ctypes.c_uint32), ("Type", ctypes.c_uint32)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                ("th32ThreadID", ctypes.c_uint32), ("th32OwnerProcessID", ctypes.c_uint32),
                ("tpBasePri", ctypes.c_int32), ("tpDeltaPri", ctypes.c_int32),
                ("dwFlags", ctypes.c_uint32)]


def api():
    if _API:
        return _API
    if os.name != "nt":
        raise RuntimeError("Windows only")
    if struct.calcsize("P") != 8:
        raise RuntimeError("64-bit Python required")
    c = ctypes
    k = c.WinDLL("kernel32", use_last_error=True)
    ps = c.WinDLL("psapi", use_last_error=True)
    nt = c.WinDLL("ntdll")
    k.OpenProcess.restype = c.c_void_p
    k.OpenProcess.argtypes = [c.c_uint32, c.c_int, c.c_uint32]
    k.CloseHandle.argtypes = [c.c_void_p]
    k.VirtualQueryEx.restype = c.c_size_t
    k.VirtualQueryEx.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p, c.c_size_t]
    k.ReadProcessMemory.restype = c.c_int
    k.ReadProcessMemory.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p]
    k.QueryFullProcessImageNameW.restype = c.c_int
    k.QueryFullProcessImageNameW.argtypes = [c.c_void_p, c.c_uint32, c.c_wchar_p, c.c_void_p]
    k.GetCurrentProcessId.restype = c.c_uint32
    k.OpenThread.restype = c.c_void_p
    k.OpenThread.argtypes = [c.c_uint32, c.c_int, c.c_uint32]
    k.CreateToolhelp32Snapshot.restype = c.c_void_p
    k.CreateToolhelp32Snapshot.argtypes = [c.c_uint32, c.c_uint32]
    k.Thread32First.restype = c.c_int
    k.Thread32First.argtypes = [c.c_void_p, c.POINTER(THREADENTRY32)]
    k.Thread32Next.restype = c.c_int
    k.Thread32Next.argtypes = [c.c_void_p, c.POINTER(THREADENTRY32)]
    ps.GetMappedFileNameW.restype = c.c_uint32
    ps.GetMappedFileNameW.argtypes = [c.c_void_p, c.c_void_p, c.c_wchar_p, c.c_uint32]
    nt.NtQuerySystemInformation.restype = c.c_int32
    nt.NtQuerySystemInformation.argtypes = [c.c_uint32, c.c_void_p, c.c_uint32, c.c_void_p]
    nt.NtQueryInformationThread.restype = c.c_int32
    nt.NtQueryInformationThread.argtypes = [c.c_void_p, c.c_uint32, c.c_void_p, c.c_uint32, c.c_void_p]
    _API.update(k=k, ps=ps, nt=nt)
    return _API


def proc_path(pid):
    k = api()["k"]
    h = k.OpenProcess(PROC_LIMITED, 0, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.c_uint32(1024)
        if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
            return buf.value
    finally:
        k.CloseHandle(h)
    return ""


def sig_map(paths):
    """{path: Authenticode status} with a single PowerShell call."""
    paths = list(dict.fromkeys(p for p in paths if p))
    if not paths:
        return {}
    script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='SilentlyContinue';"
              "$ps=@($env:SLAVE_PATHS | ConvertFrom-Json);$o=@{};"
              "foreach($p in $ps){$o[$p]=[string](Get-AuthenticodeSignature -LiteralPath $p).Status};"
              "ConvertTo-Json -InputObject $o -Compress")
    env = dict(os.environ, SLAVE_PATHS=json.dumps(paths))
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-Command", script], capture_output=True, timeout=120, env=env,
                           creationflags=NOWIN)
        data = json.loads(r.stdout.decode("utf-8", "replace").strip() or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def p_runtime(names):
    """DLL check. Returns (rows, roblox_pids). Empty pid list = Roblox is not open."""
    need_win()
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + PS_RBLX],
                       capture_output=True, timeout=180, creationflags=NOWIN)
    out = r.stdout.decode("utf-8", "replace").strip()
    if not out:
        raise RuntimeError(r.stderr.decode("utf-8", "replace").strip() or "empty output")
    data = json.loads(out)
    if isinstance(data, dict):
        data = [data]
    pids = [int(d["pid"]) for d in data if d.get("kind") == "proc"]
    rows = []
    for d in data:
        kind, path = d.get("kind"), d.get("path") or ""
        if kind not in ("mod", "bg"):
            continue
        name = d.get("name") or os.path.basename(path)
        m = name_match(os.path.basename(path), names) or name_match(name, names)
        if not m and is_safe_app(name, path):
            continue
        unsigned = (d.get("sig") or "") != "Valid"
        conns = d.get("conns") or 0
        flags, w = [], 0.0
        if m:
            flags.append("pf_name")
            w = 0.65
        if unsigned:
            flags.append("pf_inject" if kind == "mod" else "pf_unsigned")
            w = max(w, 0.55 if kind == "mod" else 0.30)
        if not flags:
            continue
        if kind == "bg" and conns:
            flags.append("pf_net")
            w = min(0.7, w + 0.08)
        if m and m.lower() in GENERIC_NAMES and len(flags) == 1:
            w *= 0.4
        detail = path + (f"  ·  {conns} conn → {d.get('remote')}" if conns else "")
        rows.append({"grp": "roblox", "kind": kind, "name": name, "path": path, "detail": detail,
                     "flags": flags, "w": w, "m": m or "", "conn": conns})
    return rows, pids


def p_handles(pids, names, info=None):
    """Handle check: other processes holding a handle to Roblox with read/write/operate rights.
    Runs inside the --rbscan helper process."""
    a = api()
    k, nt = a["k"], a["nt"]
    me = k.GetCurrentProcessId()
    held = {}
    for pid in pids:
        h = k.OpenProcess(PROC_LIMITED, 0, pid)
        if h:
            held[h] = pid
    if not held:
        raise PermissionError("cannot open the Roblox process")
    found = {}
    try:
        size = 1 << 24
        while True:
            buf = ctypes.create_string_buffer(size)
            need = ctypes.c_uint32(0)
            st = nt.NtQuerySystemInformation(64, buf, size, ctypes.byref(need))   # SystemExtendedHandleInformation
            if (st & 0xFFFFFFFF) == 0xC0000004:   # STATUS_INFO_LENGTH_MISMATCH
                size = max(size * 2, need.value + (1 << 20))
                if size > (1 << 30):
                    raise RuntimeError("handle table too large")
                continue
            break
        if st < 0:
            raise RuntimeError(f"NtQuerySystemInformation 0x{st & 0xFFFFFFFF:08x}")
        n = struct.unpack_from("<Q", buf, 0)[0]
        n = min(n, (size - 16) // HANDLE_ENTRY_SIZE)
        raw = ctypes.string_at(buf, 16 + n * HANDLE_ENTRY_SIZE)[16:]
        del buf
        mine = set()
        for obj, pid, hv, _acc, _c, _t, _a, _r in struct.iter_unpack(HANDLE_ENTRY, raw):
            if pid == me and hv in held and obj:
                mine.add(obj)
        skip = set(pids) | {me, os.getppid()}
        if mine:
            for obj, pid, _hv, acc, _c, _t, _a, _r in struct.iter_unpack(HANDLE_ENTRY, raw):
                if obj in mine and pid not in skip and pid > 4 and (acc & HANDLE_MASK):
                    found[pid] = found.get(pid, 0) | acc
    finally:
        for h in held:
            k.CloseHandle(h)
    cand = {}
    for pid, acc in found.items():
        path = proc_path(pid)
        low = path.lower()
        if (not path or SYS_RE.match(path) or "\\roblox\\" in low or "\\windows defender\\" in low
                or is_safe_app(os.path.basename(path), path)):
            continue
        cand[pid] = (path, acc)
    sigs = sig_map([p for p, _ in cand.values()])
    rows = []
    for pid, (path, acc) in cand.items():
        base = os.path.basename(path)
        m = name_match(base, names)
        w = 0.55 if acc & 0x28 else 0.35
        if m:
            w = max(w, 0.65)
        sig = sigs.get(path, "?")
        if sig == "Valid" and not m:
            w *= 0.35
        rights = "+".join(n for bit, n in ((0x10, "read"), (0x20, "write"), (0x08, "operation"),
                                           (0x02, "thread")) if acc & bit)
        rows.append({"grp": "roblox", "kind": "handle", "name": base, "path": path,
                     "detail": f"{path}  ·  PID {pid}  ·  {rights}  ·  sig: {sig}",
                     "flags": ["pf_handle"], "w": w, "m": m or "", "conn": 0})
    return rows


def _find_all(low, pat, wide, limit=40):
    """Offsets of pat in the lower-cased buffer, whole-word only (ASCII or UTF-16LE)."""
    res = []
    n, L = len(low), len(pat)
    i = low.find(pat)
    while i != -1 and len(res) < limit:
        j = i + L
        if wide:
            before = i >= 2 and low[i - 1] == 0 and low[i - 2] in ALNUM
            after = j + 1 < n and low[j + 1] == 0 and low[j] in ALNUM
        else:
            before = i >= 1 and low[i - 1] in ALNUM
            after = j < n and low[j] in ALNUM
        if not before and not after:
            res.append(i)
        i = low.find(pat, i + 1)
    return res


def p_memory(pids, names, info=None):
    """String check: config names (>= 4 chars, ASCII + UTF-16) inside Roblox's Mapped/Image regions.
    Plain bytes.find on a lower-cased copy: no regex, so it stays fast on big regions.
    Runs inside the --rbscan helper process."""
    a = api()
    k, ps = a["k"], a["ps"]
    pats, seen_n = [], set()
    for n in names:
        n = n.strip()
        if len(n) >= MIN_STR and n.isascii() and n.lower() not in seen_n:
            seen_n.add(n.lower())
            pats.append((n, n.lower().encode("ascii"), n.lower().encode("utf-16-le")))
    if not pats:
        return []
    CH, OV = 4 << 20, 256
    deadline = time.time() + 90
    budget = 2 << 30
    rbuf = ctypes.create_string_buffer(CH)
    out, regions, nbytes = {}, 0, 0
    for pid in pids:
        h = k.OpenProcess(PROC_QUERY | PROC_VM_READ, 0, pid)
        if not h:
            raise PermissionError(f"OpenProcess denied (error {ctypes.get_last_error()}): "
                                  "Roblox protection or not running as administrator")
        try:
            addr, mbi = 0, MBI()
            msz = ctypes.sizeof(mbi)
            while addr < 0x7FFFFFFF0000 and time.time() < deadline and nbytes < budget:
                if not k.VirtualQueryEx(h, addr, ctypes.byref(mbi), msz):
                    break
                base, rsz = mbi.BaseAddress or 0, mbi.RegionSize
                if rsz == 0:
                    break
                addr = base + rsz
                if mbi.State != MEM_COMMIT or mbi.Type not in (MEM_IMAGE, MEM_MAPPED):
                    continue
                if mbi.Protect == 0 or (mbi.Protect & 0x101) or rsz > (512 << 20):
                    continue
                fbuf = ctypes.create_unicode_buffer(520)
                got_name = ps.GetMappedFileNameW(h, base, fbuf, 520)
                fn = norm_path(fbuf.value) if got_name else ""
                if fn and (SYS_RE.match(fn) or "\\roblox\\" in fn.lower() or is_safe_app(os.path.basename(fn), fn)):
                    continue
                typ = "mapped" if mbi.Type == MEM_MAPPED else "image"
                where = fn or f"{typ} memory (no file)"
                regions += 1
                off = 0
                while off < rsz and time.time() < deadline:
                    n = min(CH, rsz - off)
                    got = ctypes.c_size_t(0)
                    k.ReadProcessMemory(h, base + off, rbuf, n, ctypes.byref(got))
                    if not got.value:
                        if n < CH:
                            break
                        off += CH - OV
                        continue
                    low = ctypes.string_at(rbuf, got.value).lower()
                    nbytes += got.value
                    for nm, pa, pw in pats:
                        for pat, wide in ((pa, False), (pw, True)):
                            for pos in _find_all(low, pat, wide):
                                ent = out.setdefault((nm, where), {"at": set(), "typ": typ, "file": bool(fn)})
                                ent["at"].add(base + off + pos)
                    if n < CH:
                        break
                    off += CH - OV
        finally:
            k.CloseHandle(h)
    if info is not None:
        info["regions"] = regions
        info["mb"] = nbytes >> 20
    rows = []
    for (nm, where), e in out.items():
        w = 0.55 if not e["file"] else 0.50
        if nm.lower() in GENERIC_NAMES:
            w *= 0.4
        first = min(e["at"])
        rows.append({"grp": "roblox", "kind": "mem", "name": nm, "path": where if e["file"] else "",
                     "detail": f"{where}  ·  {len(e['at'])}x  ·  {e['typ']}  ·  0x{first:x}",
                     "flags": ["pf_mem"], "w": w, "m": nm, "conn": 0})
    rows.sort(key=lambda r: -r["w"])
    return rows[:100]


def p_private_exec_regions(pids, info=None):
    """Reports Roblox threads whose start address sits in a private executable region.
    Read-only; this is an investigation lead (JIT/runtime code can also use private pages)."""
    a = api()
    k, nt = a["k"], a["nt"]
    exec_protect = {0x10, 0x20, 0x40, 0x80}
    snap = k.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    if not snap or snap == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    threads = []
    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        ok = k.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID in pids:
                threads.append((te.th32OwnerProcessID, te.th32ThreadID))
            ok = k.Thread32Next(snap, ctypes.byref(te))
    finally:
        k.CloseHandle(snap)

    findings, scanned_regions, private_exec, opened, thread_denied, thread_matches = [], 0, 0, 0, 0, 0
    deadline = time.time() + 20
    for pid in pids:
        if time.time() >= deadline:
            break
        hp = k.OpenProcess(PROC_QUERY, 0, pid)
        if not hp:
            continue
        opened += 1
        ranges = []
        try:
            addr, mbi = 0, MBI()
            while addr < 0x7FFFFFFF0000 and scanned_regions < 100000 and time.time() < deadline:
                if not k.VirtualQueryEx(hp, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    break
                base, size = mbi.BaseAddress or 0, mbi.RegionSize
                if not size:
                    break
                addr = base + size
                scanned_regions += 1
                protection = mbi.Protect & 0xFF
                if (mbi.State == MEM_COMMIT and mbi.Type == 0x20000 and protection in exec_protect
                        and not (mbi.Protect & (0x01 | 0x100)) and size >= 4096):
                    ranges.append((base, base + size, protection, size))
                    private_exec += 1
                    if len(ranges) >= 500:
                        break
            matched_regions = set()
            for owner, tid in threads:
                if owner != pid:
                    continue
                ht = k.OpenThread(0x0040 | 0x0800, 0, tid)  # QUERY_INFORMATION | QUERY_LIMITED_INFORMATION
                if not ht:
                    thread_denied += 1
                    continue
                try:
                    start = ctypes.c_void_p()
                    status = nt.NtQueryInformationThread(ht, 9, ctypes.byref(start),
                                                         ctypes.sizeof(start), None)
                    if status < 0 or not start.value:
                        continue
                    match = next((r for r in ranges if r[0] <= start.value < r[1]), None)
                    if match:
                        matched_regions.add(match[0])
                        thread_matches += 1
                        findings.append({"pid": pid, "tid": tid, "address": start.value,
                                         "base": match[0], "size": match[3], "protect": match[2],
                                         "region_only": False})
                finally:
                    k.CloseHandle(ht)
            for base, _end, protection, size in ranges:
                if base not in matched_regions and len(findings) < 100:
                    findings.append({"pid": pid, "tid": 0, "address": 0, "base": base,
                                     "size": size, "protect": protection, "region_only": True})
        finally:
            k.CloseHandle(hp)
    denied = max(0, len(pids) - opened)
    if info is not None:
        info["exec_regions"] = private_exec
        info["exec_threads"] = thread_matches
        info["exec_denied"] = denied
        info["exec_thread_denied"] = thread_denied
        info["exec_partial"] = time.time() >= deadline or denied > 0 or thread_denied > 0
    if not opened:
        raise PermissionError("could not query Roblox process memory (try running as administrator)")
    return findings


def rbscan_worker(job_path, out_path):
    """Helper process entry point: python slave.py --rbscan job.json out.json
    Results are written after every stage, so a crash in the memory stage keeps the handle results."""
    res = {"done": [], "errors": {}, "handles": [], "memory": [], "exec": [], "regions": 0, "mb": 0}

    def save():
        tmp = out_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(res, f)
        os.replace(tmp, out_path)

    try:
        faulthandler.enable(open(out_path + ".fault", "w"))
    except Exception:
        pass
    try:
        with open(job_path, "r", encoding="utf-8") as f:
            job = json.load(f)
        pids = [int(x) for x in job["pids"]]
        names = [str(x) for x in job.get("names", [])]
    except Exception as e:
        res["errors"]["Handles"] = res["errors"]["Memory"] = f"{type(e).__name__}: {e}"
        save()
        return 1
    stages = (("Exec memory", "exec", p_private_exec_regions),) if job.get("exec_only") else (
        ("Handles", "handles", p_handles), ("Memory", "memory", p_memory))
    for label, key, fn in stages:
        try:
            res[key] = fn(pids, names, res) if key == "memory" else fn(pids, res) if key == "exec" else fn(pids, names, res)
            res["done"].append(label)
        except PermissionError as e:
            res["errors"][label] = f"access denied · {e}"
        except Exception as e:
            res["errors"][label] = f"{type(e).__name__}: {e}"
        save()
    return 0


def run_isolated_scan(pids, names, cb):
    """Starts the helper process and merges its findings. Never raises, never takes the GUI down."""
    tmpd = tempfile.mkdtemp(prefix="slave_rb_")
    job, out = os.path.join(tmpd, "job.json"), os.path.join(tmpd, "out.json")
    rows = []
    try:
        with open(job, "w", encoding="utf-8") as f:
            json.dump({"pids": list(pids), "names": list(names)}, f)
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--rbscan", job, out]
        else:
            cmd = [sys.executable, os.path.abspath(__file__), "--rbscan", job, out]
        rc, err = None, ""
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=240, creationflags=NOWIN)
            rc = r.returncode
            err = r.stderr.decode("utf-8", "replace").strip()[-200:]
        except subprocess.TimeoutExpired:
            err = "timeout"
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        res = {}
        try:
            with open(out, "r", encoding="utf-8") as f:
                res = json.load(f)
        except Exception:
            pass
        fault = ""
        try:
            with open(out + ".fault", "r", encoding="utf-8", errors="replace") as f:
                fault = f.read().strip()[-300:]
        except OSError:
            pass
        done, errors = set(res.get("done", [])), res.get("errors", {})
        for label, key in (("Handles", "handles"), ("Memory", "memory")):
            if label in errors:
                cb("WARN", "log_tr_err", label, errors[label])
            elif label in done:
                got = res.get(key, [])
                rows += got
                cb("OK", "log_p_src", label, len(got), len(pids))
            else:
                code = f"0x{rc & 0xFFFFFFFF:08X}" if isinstance(rc, int) else "?"
                cb("WARN", "log_tr_err", label,
                   f"helper process stopped early (exit {code}) {err} {fault}".strip())
        if res.get("regions"):
            cb("OK", "log_p_mem", res["regions"], res.get("mb", 0))
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
    return rows


def run_isolated_exec_scan(pids):
    """Runs the private-executable-memory check in the crash-isolated helper."""
    tmpd = tempfile.mkdtemp(prefix="slave_exec_")
    job, out = os.path.join(tmpd, "job.json"), os.path.join(tmpd, "out.json")
    try:
        with open(job, "w", encoding="utf-8") as f:
            json.dump({"pids": list(pids), "names": [], "exec_only": True}, f)
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--rbscan", job, out]
        else:
            cmd = [sys.executable, os.path.abspath(__file__), "--rbscan", job, out]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=120, creationflags=NOWIN)
        except subprocess.TimeoutExpired:
            return [], "memory scan timed out", {}
        with open(out, "r", encoding="utf-8") as f:
            res = json.load(f)
        if res.get("errors", {}).get("Exec memory"):
            return [], res["errors"]["Exec memory"], res
        if proc.returncode and not res.get("done"):
            return [], f"helper exited with code {proc.returncode}", res
        return res.get("exec", []), "", res
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}", {}
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def collect_persist(names, cb):
    """Returns (rows, roblox_process_count). Roblox closed -> ([], 0)."""
    if not is_admin():
        cb("WARN", "log_tr_noadmin")
    try:
        rows, pids = p_runtime(names)
    except Exception as e:
        cb("WARN", "log_tr_err", "Roblox", f"{type(e).__name__}: {e}")
        return [], 0
    if not pids:
        cb("WARN", "log_p_rb_closed")
        return [], 0
    cb("OK", "log_p_src", "Modules/BG", len(rows), len(pids))
    rows = list(rows) + run_isolated_scan(pids, names, cb)
    rows.sort(key=lambda r: -r["w"])
    return rows, len(pids)


# ============================== FORENSIC EVIDENCE COLLECTION ==============================
# Read-only, local machine only. Collects metadata and log entries, never personal file contents.
PS_FOR_PROC = r"""
$ErrorActionPreference='SilentlyContinue'
$o=@(Get-Process | Where-Object { $_.Path } | ForEach-Object {
  [pscustomobject]@{pid=$_.Id; name=$_.Name; path=$_.Path; start=$(try{$_.StartTime.ToString('o')}catch{''})} })
ConvertTo-Json -InputObject @($o) -Compress
"""

PS_FOR_EVT = r"""
$ErrorActionPreference='SilentlyContinue'
$st=(Get-Date).AddDays(-[int]$env:SLAVE_DAYS)
$q=@(
 @{LogName='Application';Id=1000,1001},
 @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117},
 @{LogName='System';Id=7045,104},
 @{LogName='Security';Id=1102}
)
$out=@()
foreach($f in $q){
  $f.StartTime=$st
  Get-WinEvent -FilterHashtable $f -MaxEvents 400 | ForEach-Object {
    $m=[string]$_.Message
    if($m.Length -gt 700){$m=$m.Substring(0,700)}
    $out += [pscustomobject]@{log=$f.LogName; id=$_.Id; time=$_.TimeCreated.ToString('o'); msg=$m}
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def _ps_json(script, env=None, timeout=150):
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script],
                       capture_output=True, timeout=timeout, env=env, creationflags=NOWIN)
    out = r.stdout.decode("utf-8", "replace").strip()
    if not out:
        return []
    data = json.loads(out)
    return [data] if isinstance(data, dict) else data


def fmt_ts(t):
    try:
        return datetime.fromtimestamp(t).strftime("%d.%m.%Y %H:%M")
    except (OSError, OverflowError, ValueError):
        return "—"


def iso_local(s):
    try:
        s = re.sub(r"(\.\d{6})\d+", r"\1", (s or "").replace("Z", "+00:00"))
        return datetime.fromisoformat(s).astimezone().strftime("%d.%m.%Y %H:%M")
    except Exception:
        return (s or "—")[:16] or "—"


def _decompress_prefetch(data):
    if len(data) < 8 or data[:4] != b"MAM\x04":
        return data
    size = struct.unpack_from("<I", data, 4)[0]
    if not size or size > (128 << 20):
        raise ValueError("invalid Prefetch decompressed size")
    fn = ctypes.WinDLL("ntdll").RtlDecompressBufferEx2
    fn.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                   ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    fn.restype = ctypes.c_long
    compressed = ctypes.create_string_buffer(data[8:])
    output = ctypes.create_string_buffer(size)
    actual = ctypes.c_ulong(0)
    status = fn(4, output, size, compressed, len(data) - 8, 4096, ctypes.byref(actual), None)
    if status != 0 or actual.value != size:
        raise ValueError(f"Prefetch decompression failed (0x{status & 0xffffffff:08X})")
    return output.raw[:actual.value]


def prefetch_run_times(path):
    with open(path, "rb") as stream:
        data = _decompress_prefetch(stream.read())
    if len(data) < 152 or data[4:8] != b"SCCA":
        raise ValueError("invalid Prefetch header")
    version = struct.unpack_from("<I", data, 0)[0]
    if version == 17:
        offset, count = 120, 1
    elif version == 23:
        offset, count = 128, 1
    elif version in (26, 30, 31):
        offset, count = 128, 8
    else:
        raise ValueError(f"unsupported Prefetch version {version}")
    result = []
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    for index in range(count):
        raw = struct.unpack_from("<Q", data, offset + index * 8)[0]
        if raw:
            try:
                result.append((epoch + timedelta(microseconds=raw // 10)).astimezone())
            except (OverflowError, ValueError):
                continue
    return sorted(set(result))


def _trace_time(value):
    try:
        return datetime.strptime(value, "%d.%m.%Y %H:%M").astimezone()
    except (TypeError, ValueError):
        return None


def _is_roblox_exe(path):
    name = os.path.basename((path or "").replace("/", "\\")).lower()
    return name in ("robloxplayerbeta.exe", "windows10universal.exe")


def _outside_trusted_install(path):
    if not path:
        return False
    full = os.path.normcase(os.path.abspath(path))
    roots = [os.environ.get("SystemRoot"), os.environ.get("ProgramFiles"),
             os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramW6432")]
    for root in (r for r in roots if r):
        base = os.path.normcase(os.path.abspath(root)).rstrip("\\/")
        if full == base or full.startswith(base + os.sep):
            return False
    return True


def _pe_is_gui(path):
    """True when a readable PE image declares the Windows GUI subsystem."""
    try:
        with open(path, "rb") as stream:
            if stream.read(2) != b"MZ":
                return False
            stream.seek(0x3C)
            off = struct.unpack("<I", stream.read(4))[0]
            if off > (1 << 20):
                return False
            stream.seek(off)
            if stream.read(4) != b"PE\0\0":
                return False
            stream.seek(off + 24)
            magic = struct.unpack("<H", stream.read(2))[0]
            if magic not in (0x10B, 0x20B):
                return False
            stream.seek(off + 24 + 68)
            return struct.unpack("<H", stream.read(2))[0] == 2
    except (OSError, struct.error):
        return False


def _add_review_flags(rows, max_paths=300):
    paths = [row.get("path", "") for row in rows
             if row.get("path") and _outside_trusted_install(row.get("path", ""))][:max_paths]
    signatures = sig_map(paths)
    for row in rows:
        path = row.get("path", "")
        sig = signatures.get(path, "") if path else ""
        review = bool(sig == "NotSigned" and _outside_trusted_install(path) and _pe_is_gui(path))
        row["review"] = review
        if review:
            row["source"] = (row.get("source") or "") + " · REVIEW: unsigned GUI outside trusted dirs"
    return rows


SESSION_NOISE = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "winlogon.exe",
    "conhost.exe", "backgroundtaskhost.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "runtimebroker.exe", "taskhostw.exe", "smartscreen.exe", "wmiprvse.exe", "audiodg.exe",
    "dllhost.exe", "sihost.exe", "compattelrunner.exe", "searchindexer.exe", "ctfmon.exe",
    "taskmgr.exe", "msedgewebview2.exe", "wudfhost.exe", "spoolsv.exe", "dashost.exe",
}


FOOT_SKIP = {"node_modules", "cache", "code cache", "gpucache", "packages", "microsoft", "google",
             "windowsapps", "crashpad", "dawncache", "shadercache"}


def collect_footprints(names, max_depth=3, seconds=25):
    """Files/folders in AppData, ProgramData, Temp, Downloads, Desktop, Documents whose NAME matches
    the list (e.g. Roaming\\dx9ware\\dx9ware2_log.log). Their last-modified time shows when the
    program last wrote there, which usually means when it was last used."""
    home = os.path.expanduser("~")
    roots = [os.environ.get(k) for k in ("APPDATA", "LOCALAPPDATA", "ProgramData", "TEMP")]
    roots += [os.path.join(home, x) for x in ("Downloads", "Desktop", "Documents")]
    deadline, scanned, rows, seen = time.time() + seconds, 0, [], set()
    for root in dict.fromkeys(r for r in roots if r and os.path.isdir(r)):
        base = root.rstrip("\\/").count(os.sep)
        for dp, dns, fns in os.walk(root):
            if time.time() > deadline or scanned > 150000:
                break
            here = list(dns)
            depth = dp.rstrip("\\/").count(os.sep) - base
            dns[:] = [] if depth >= max_depth else [d for d in dns if d.lower() not in FOOT_SKIP]
            for entry in here + fns:
                scanned += 1
                m = name_match(entry, names)
                if not m or m.lower() in GENERIC_NAMES:
                    continue
                full = os.path.join(dp, entry)
                if full.lower() in seen:
                    continue
                seen.add(full.lower())
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                rows.append({"name": entry, "time": datetime.fromtimestamp(st.st_mtime).astimezone(),
                             "path": full, "source": "File footprint (modified)"})
                if len(rows) >= 300:
                    return rows
    return rows


def _fixed_drive_roots():
    roots = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        get_type = ctypes.windll.kernel32.GetDriveTypeW
        get_type.argtypes = [ctypes.c_wchar_p]
        get_type.restype = ctypes.c_uint32
        for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            root = f"{letter}:\\"
            if mask & (1 << i) and get_type(root) == 3:
                roots.append(root)
    except Exception:
        pass
    return roots


def _parse_usn_time(value):
    value = (value or "").strip()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone()
    except ValueError:
        pass
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S",
                "%d.%m.%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).astimezone()
        except ValueError:
            continue
    return None


def _parse_usn_number(value):
    value = (value or "").strip()
    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(value, 16) if re.fullmatch(r"[0-9a-fA-F]{8,}", value) else int(value, 10)
        except ValueError:
            return None


def collect_recent_usn_exes(days=3, max_seconds=45, max_rows=400):
    """Read a bounded tail of each fixed-drive USN journal and keep recent EXE changes."""
    since = datetime.now().astimezone() - timedelta(days=days)
    deadline = time.time() + max_seconds
    rows, partial, errors, drives_seen = [], False, [], []
    oldest_seen, tail_limited = None, False
    for drive in _fixed_drive_roots():
        remaining = deadline - time.time()
        if remaining <= 0:
            partial = True
            break
        start_arg = None
        try:
            query = subprocess.run(["fsutil", "usn", "queryjournal", drive], capture_output=True,
                                   timeout=min(5, max(1, remaining)), creationflags=NOWIN)
            try:
                qtext = (query.stdout + query.stderr).decode(
                    f"cp{ctypes.windll.kernel32.GetOEMCP()}", "replace")
            except Exception:
                qtext = (query.stdout + query.stderr).decode("utf-8", "replace")
            first_m = re.search(r"(?im)^\s*First Usn\s*:\s*(0x[0-9a-f]+|\d+)", qtext)
            next_m = re.search(r"(?im)^\s*Next Usn\s*:\s*(0x[0-9a-f]+|\d+)", qtext)
            if first_m and next_m:
                first_usn = _parse_usn_number(first_m.group(1))
                next_usn = _parse_usn_number(next_m.group(1))
                if first_usn is not None and next_usn is not None:
                    tail_start = max(first_usn, next_usn - (64 << 20))
                    start_arg = f"startusn=0x{tail_start:x}"
                    tail_limited |= tail_start > first_usn
                else:
                    partial = True
                    errors.append(f"{drive} journal bounds could not be parsed")
            else:
                partial = True
                errors.append(f"{drive} journal bounds unavailable; tried from oldest record")
        except (OSError, subprocess.TimeoutExpired) as exc:
            partial = True
            errors.append(f"{drive} journal query failed: {type(exc).__name__}")
        args = ["fsutil", "usn", "readjournal"]
        if start_arg:
            args.append(start_arg)
        args.extend([drive, "csv"])
        try:
            proc = subprocess.Popen(args,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=NOWIN)
        except OSError:
            errors.append(f"{drive} journal could not be opened")
            partial = True
            continue
        drives_seen.append(drive)
        encoding = "utf-8"
        try:
            encoding = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            pass
        header = None
        seen = set()
        try:
            for raw in proc.stdout:
                if time.time() >= deadline:
                    partial = True
                    proc.kill()
                    break
                line = raw.decode(encoding, "replace").strip()
                if not line:
                    continue
                try:
                    cols = next(csv.reader([line]))
                except Exception:
                    continue
                if header is None:
                    low = [c.strip().lower() for c in cols]
                    if "file name" in low:
                        header = (low.index("file name"), low.index("reason") if "reason" in low else 2,
                                  low.index("time stamp") if "time stamp" in low else 3)
                        continue
                    header = (1, 2, 3)
                if len(cols) <= max(header):
                    continue
                filename, reason = cols[header[0]].strip(), cols[header[1]].strip()
                when = _parse_usn_time(cols[header[2]])
                if when and (oldest_seen is None or when < oldest_seen):
                    oldest_seen = when
                low_reason = re.sub(r"[^a-z]", "", reason.lower())
                try:
                    reason_bits = int(reason, 0)
                except ValueError:
                    try:
                        reason_bits = int(reason, 16) if re.fullmatch(r"[0-9a-fA-F]{8,}", reason) else 0
                    except ValueError:
                        reason_bits = 0
                created = "filecreate" in low_reason or bool(reason_bits & 0x00000100)
                deleted = "filedelete" in low_reason or bool(reason_bits & 0x00000200)
                renamed = ("renamenewname" in low_reason or "renameoldname" in low_reason
                           or bool(reason_bits & (0x00001000 | 0x00002000)))
                if not filename.lower().endswith(".exe") or not when or when < since or not (created or deleted or renamed):
                    continue
                kind = "CREATE" if created else "DELETE" if deleted else "RENAME"
                key = (filename.lower(), kind, when.strftime("%Y%m%d%H%M%S"))
                if key in seen:
                    continue
                seen.add(key)
                rows.append({"session_start": None, "start": when, "name": filename, "path": drive,
                             "offset": None, "source": f"USN {kind} · {drive} · full path unavailable",
                             "extra": "usn", "review": False})
                if len(rows) >= max_rows:
                    partial = True
                    proc.kill()
                    break
            if proc.poll() is None:
                proc.wait(timeout=max(1, min(3, int(deadline - time.time()))))
            if proc.returncode not in (0, None):
                partial = True
                errors.append(f"{drive} journal read returned {proc.returncode}")
        except (OSError, subprocess.TimeoutExpired):
            partial = True
            errors.append(f"{drive} journal read timed out")
            try:
                proc.kill()
            except OSError:
                pass
        if len(rows) >= max_rows or time.time() >= deadline:
            break
    if tail_limited and (oldest_seen is None or oldest_seen > since):
        partial = True
        errors.append("journal tail did not reach the full selected time range")
    rows.sort(key=lambda row: row["start"], reverse=True)
    return rows, {"partial": partial, "drives": drives_seen, "oldest": oldest_seen,
                  "tail_limited": tail_limited, "errors": errors}


def collect_new_unsigned_exe_clusters(days=3, names=None, seconds=35, max_candidates=600, max_signatures=250):
    """Find recent unsigned EXEs and configured-name matches in user folders/secondary drives."""
    names = names or []
    since = datetime.now().astimezone() - timedelta(days=days)
    home = os.path.expanduser("~")
    sysdrive = os.path.splitdrive(os.environ.get("SystemDrive", "C:"))[0].lower()
    roots = [os.path.join(home, "Downloads"), os.path.join(home, "Desktop")]
    roots += [root for root in _fixed_drive_roots() if os.path.splitdrive(root)[0].lower() != sysdrive]
    skip_dirs = {"windows", "program files", "program files (x86)", "programdata", "$recycle.bin",
                 "system volume information", "windowsapps", "node_modules", "cache", "code cache",
                 "packages", "crashpad", "shadercache", "temp"}
    deadline, candidates, scanned = time.time() + seconds, [], 0
    for root in dict.fromkeys(r for r in roots if r and os.path.isdir(r)):
        base_depth = root.rstrip("\\/").count(os.sep)
        for folder, dirs, files in os.walk(root):
            if time.time() >= deadline or scanned >= 250000 or len(candidates) >= max_candidates:
                break
            depth = folder.rstrip("\\/").count(os.sep) - base_depth
            dirs[:] = [] if depth >= 5 else [d for d in dirs if d.lower() not in skip_dirs]
            for filename in files:
                scanned += 1
                if not filename.lower().endswith(".exe"):
                    continue
                path = os.path.join(folder, filename)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                created = datetime.fromtimestamp(st.st_ctime).astimezone()
                modified = datetime.fromtimestamp(st.st_mtime).astimezone()
                stamp = created if created >= since else modified
                match = name_match(filename, names)
                if (stamp >= since or match) and _outside_trusted_install(path):
                    candidates.append({"path": path, "time": stamp, "recent": stamp >= since,
                                       "match": match or ""})
                if time.time() >= deadline or len(candidates) >= max_candidates:
                    break
        if time.time() >= deadline or len(candidates) >= max_candidates:
            break
    candidates.sort(key=lambda item: (bool(item.get("match")), item["time"]), reverse=True)
    candidate_limited = len(candidates) >= max_candidates
    signature_limited = len(candidates) > max_signatures
    candidates = candidates[:max_signatures]
    signatures = sig_map([item["path"] for item in candidates])
    unsigned = [item for item in candidates if signatures.get(item["path"]) == "NotSigned"]
    interesting = [item for item in candidates
                   if signatures.get(item["path"]) == "NotSigned" or item.get("match")]
    grouped = {}
    for item in interesting:
        grouped.setdefault(os.path.dirname(item["path"]), []).append(item)
    rows = []
    hash_budget = 256 << 20
    for folder, items in grouped.items():
        count = len(items)
        for item in items:
            try:
                file_size = os.path.getsize(item["path"])
            except OSError:
                file_size = 0
            provenance = _file_provenance(item["path"], max_hash_bytes=min(8 << 20, hash_budget))
            if provenance.get("sha256"):
                hash_budget = max(0, hash_budget - file_size)
            provenance_text = (f" · SHA256 {provenance['sha256'][:16]}…" if provenance.get("sha256") else "")
            if provenance.get("zone_id"):
                provenance_text += f" · ZoneId {provenance['zone_id']}"
            match_text = f" · NAME MATCH {item['match']}" if item.get("match") else ""
            unsigned_text = "UNSIGNED EXE" if signatures.get(item["path"]) == "NotSigned" else "CONFIG NAME MATCH"
            rows.append({"session_start": None, "start": item["time"],
                         "name": os.path.basename(item["path"]), "path": item["path"], "offset": None,
                         "source": f"{unsigned_text} · {count} candidate(s) in folder · {folder}{match_text}{provenance_text}",
                         "extra": "unsigned_folder", "review": True,
                         "unsigned": signatures.get(item["path"]) == "NotSigned",
                         "configured_match": item.get("match", ""), "folder_count": count,
                         "sha256": provenance.get("sha256", ""), "zone_id": provenance.get("zone_id", "")})
    rows.sort(key=lambda row: (row["name"].lower(), row["start"]), reverse=True)
    return rows, {"scanned": scanned,
                  "partial": time.time() >= deadline or candidate_limited or signature_limited,
                  "signature_limited": signature_limited, "signature_count": len(candidates),
                  "unsigned": len(unsigned), "name_matches": sum(bool(x.get("match")) for x in interesting),
                  "folders": len(grouped)}


def _file_provenance(path, max_hash_bytes=256 << 20):
    """Return a bounded SHA-256 and Mark-of-the-Web ZoneId without reading file contents into memory."""
    result = {"sha256": "", "zone_id": ""}
    try:
        if os.path.getsize(path) <= max_hash_bytes:
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            result["sha256"] = digest.hexdigest()
    except OSError:
        pass
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as stream:
            text = stream.read(4096)
        match = re.search(r"(?im)^ZoneId\s*=\s*(\d+)", text)
        if match:
            result["zone_id"] = match.group(1)
    except OSError:
        pass
    return result


def _roblox_log_times():
    """Roblox creates one log file per session; the start time is in the file name
    (0.xxx_20261025T145507Z_Player_xxxx_last.log). Reaches back further than Prefetch's 8 runs."""
    import glob
    bases = [os.path.join(os.environ.get("LOCALAPPDATA", ""), "Roblox", "logs")]
    bases += glob.glob(os.path.join(os.environ.get("LOCALAPPDATA", ""), "Packages",
                                    "ROBLOXCORPORATION.ROBLOX_*", "LocalState", "logs"))
    out = []
    for base in bases:
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for fn in names:
            m = re.search(r"_(\d{8}T\d{6}Z)_", fn)
            if not m or "_Player_" not in fn:
                continue
            try:
                out.append(datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ")
                           .replace(tzinfo=timezone.utc).astimezone())
            except ValueError:
                continue
    return out


def collect_session_history(range_days=1, lookback_minutes=60, after_minutes=2, names=None):
    """For every Roblox launch inside the range (today = since local midnight, or the last N days):
    which apps were launched in the window [Roblox - lookback, Roblox + after]. One row per app and
    session (the launch closest to the Roblox start). lookback_minutes <= 0 means the whole range.
    Sources: Prefetch (last 8 runs per exe), BAM (last activity), UserAssist (last launch);
    Roblox start times: Prefetch + BAM + UserAssist + Roblox log file names."""
    need_win()
    now = datetime.now().astimezone()
    if range_days <= 1:
        since = now.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        since = now - timedelta(days=range_days)
    if lookback_minutes <= 0:
        lookback_minutes = int((now - since).total_seconds() // 60) + 1
    folder = os.path.join(SYSROOT, "Prefetch")
    entries, roblox_times, used_fallback, presence_sources = [], [], False, []
    sources_used = []
    try:
        files = [name for name in os.listdir(folder) if name.lower().endswith(".pf") and "-" in name]
    except OSError:
        files = []

    for filename in files:
        exe = filename.rsplit("-", 1)[0]
        low = exe.lower()
        is_roblox = low in ("robloxplayerbeta.exe", "windows10universal.exe")
        fullpath = os.path.join(folder, filename)
        try:
            times = prefetch_run_times(fullpath)
            quality = "Prefetch run history"
        except Exception:
            # Last-modified is still a useful latest-run fallback when parsing is unavailable.
            try:
                times = [datetime.fromtimestamp(os.path.getmtime(fullpath)).astimezone()]
            except OSError:
                continue
            quality = "Prefetch file time (latest run only)"
            used_fallback = True
        if is_roblox:
            roblox_times.extend(times)
            if "Prefetch" not in sources_used:
                sources_used.append("Prefetch")
        else:
            entries.extend({"name": exe, "time": when, "path": fullpath, "source": quality}
                           for when in times)

    for label, reader in (("BAM (last activity)", tr_bam), ("UserAssist (last launch)", tr_ua)):
        try:
            for item in reader():
                path = norm_path(item.get("path", ""))
                when = _trace_time(item.get("when"))
                if not path or not when:
                    continue
                if _is_roblox_exe(path):
                    roblox_times.append(when)
                    if label.split(" ")[0] not in sources_used:
                        sources_used.append(label.split(" ")[0])
                else:
                    entries.append({"name": os.path.basename(path), "time": when,
                                    "path": path, "source": label})
        except Exception:
            pass
    log_times = _roblox_log_times()
    if log_times:
        roblox_times.extend(log_times)
        sources_used.append("Roblox logs")

    if not roblox_times:
        # MUICache and ShimCache can identify Roblox files, but neither gives a reliable launch time.
        for label, reader in (("MUICache", tr_mui), ("ShimCache", tr_shim)):
            try:
                if any("robloxplayerbeta" in str(item.get("path", "")).lower()
                       or "windows10universal" in str(item.get("path", "")).lower()
                       for item in reader()):
                    presence_sources.append(label)
            except Exception:
                continue
        return {"source": "Prefetch/BAM/UserAssist", "sessions": 0, "rows": [], "rb_times": [],
                "complete": False, "presence": presence_sources}

    # merge launch times that are the same session seen by different sources (within 3 minutes)
    merged = []
    for rb_time in sorted(roblox_times):
        if merged and (rb_time - merged[-1]).total_seconds() <= 180:
            continue
        merged.append(rb_time)
    roblox_times = [x for x in merged if x >= since]
    if not roblox_times:
        return {"source": "range", "sessions": 0, "rows": [], "rb_times": [], "complete": False,
                "empty_range": True}

    result_rows = []
    before, after = timedelta(minutes=lookback_minutes), timedelta(minutes=after_minutes)
    priority = {"Prefetch run history": 0, "Prefetch file time (latest run only)": 1,
                "BAM (last activity)": 2, "UserAssist (last launch)": 3,
                "File footprint (modified)": 4}
    for rb_time in roblox_times:
        groups = {}
        for item in entries:
            low = item["name"].lower()
            if (rb_time - before <= item["time"] <= rb_time + after
                    and low not in SESSION_NOISE and not _is_roblox_exe(item["name"])):
                groups.setdefault(low, []).append(item)
        if not groups:
            result_rows.append({"session_start": rb_time, "start": None, "name": "",
                                "path": "", "offset": None, "source": ""})
            continue
        for items in groups.values():
            best = min(items, key=lambda i: (abs((i["time"] - rb_time).total_seconds()),
                                             priority.get(i["source"], 9)))
            launches = len({i["time"].strftime("%Y%m%d%H%M") for i in items})
            srcs = sorted({i["source"] for i in items}, key=lambda s: priority.get(s, 9))
            src = " + ".join(srcs) + (f" · {launches} launches in window" if launches > 1 else "")
            path = best["path"] if not best["path"].lower().endswith(".pf") else ""
            if not path:
                known_paths = [i for i in items if i.get("path") and not i["path"].lower().endswith(".pf")
                               and os.path.isfile(i["path"])]
                if known_paths:
                    path = min(known_paths, key=lambda i: abs((i["time"] - best["time"]).total_seconds()))["path"]
            result_rows.append({"session_start": rb_time, "start": best["time"],
                                "name": best["name"], "path": path,
                                "offset": int((best["time"] - rb_time).total_seconds()),
                                "source": src})
    _add_review_flags(result_rows)
    scope = "today" if range_days <= 1 else f"last {range_days} days"
    source = f"{scope} · Roblox start: {'+'.join(sources_used)}; app records: Prefetch/BAM/UserAssist"
    if used_fallback:
        source += " · latest-run fallback used"
    return {"source": source, "sessions": len(roblox_times), "rows": result_rows,
            "rb_times": roblox_times, "complete": True}


PS_SESSION_PROC = r"""
$ErrorActionPreference='SilentlyContinue'
$titles=@{}
Get-Process | Where-Object {$_.MainWindowTitle} | ForEach-Object { $titles[[string]$_.Id]=$_.MainWindowTitle }
$vi=@{}
$o=@(Get-CimInstance Win32_Process | ForEach-Object {
  $p=[string]$_.ExecutablePath
  $v=''
  if($p -and $p -notmatch '^[A-Za-z]:\\Windows\\'){
    if(-not $vi.ContainsKey($p)){
      $i=(Get-Item -LiteralPath $p).VersionInfo
      $vi[$p]=(@($i.OriginalFilename,$i.InternalName,$i.ProductName,$i.FileDescription,$i.CompanyName) | Where-Object {$_}) -join ' | '
    }
    $v=$vi[$p]
  }
  [pscustomobject]@{pid=[int]$_.ProcessId; name=[string]$_.Name; path=$p;
    start=$(if($_.CreationDate){([datetime]$_.CreationDate).ToString('o')}else{''});
    title=[string]$titles[[string]$_.ProcessId]; info=$v}
})
ConvertTo-Json -InputObject @($o) -Compress
"""


PS_PROCESS_CREATE_EVENTS = r"""
$ErrorActionPreference='SilentlyContinue'
$st=(Get-Date).AddDays(-[int]$env:SLAVE_DAYS)
$specs=@(
  @{log='Security'; id=4688; source='Security 4688'},
  @{log='Microsoft-Windows-Sysmon/Operational'; id=1; source='Sysmon 1'}
)
$events=@(); $sources=@(); $errors=@(); $partial=$false
foreach($s in $specs){
  try {
    $found=@(Get-WinEvent -FilterHashtable @{LogName=$s.log;Id=$s.id;StartTime=$st} -MaxEvents 5000)
    if($found.Count -ge 5000){$partial=$true}
    if($found.Count -gt 0){$sources += $s.source}
    foreach($e in $found){
      $x=[xml]$e.ToXml(); $d=@{}
      foreach($item in $x.Event.EventData.Data){$key=[string]$item.Name; $d[$key]=[string]$item.InnerText}
      $image=[string]$d['NewProcessName']; $parent=[string]$d['ParentProcessName']
      if(-not $parent){$parent=[string]$d['CreatorProcessName']}
      if(-not $image){$image=[string]$d['Image']; $parent=[string]$d['ParentImage']}
      $events += [pscustomobject]@{time=$e.TimeCreated.ToString('o'); image=$image; parent=$parent; source=$s.source}
    }
  } catch {$errors += ($s.source + ': unavailable')}
}
ConvertTo-Json -InputObject @{events=@($events);sources=@($sources);errors=@($errors);partial=$partial} -Depth 4 -Compress
"""


def collect_process_creation_events(range_days, rb_times, lookback_minutes, after_minutes=2):
    """Read already-recorded Security 4688 / Sysmon 1 events; never enables auditing."""
    env = dict(os.environ, SLAVE_DAYS=str(max(1, int(range_days))))
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                               "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + PS_PROCESS_CREATE_EVENTS],
                              capture_output=True, timeout=90, env=env, creationflags=NOWIN)
        raw = json.loads(proc.stdout.decode("utf-8", "replace").strip() or "{}")
    except Exception as exc:
        return [], {"sources": [], "errors": [f"event log query failed: {type(exc).__name__}"], "partial": True}
    raw = raw if isinstance(raw, dict) else {}
    events = raw.get("events", [])
    if isinstance(events, dict):
        events = [events]
    starts = list(rb_times or [])
    parsed = []
    for item in events:
        when = iso_dt(item.get("time"))
        path = (item.get("image") or "").strip()
        if when and path:
            entry = {"time": when, "path": path, "parent": (item.get("parent") or "").strip(),
                     "source": item.get("source") or "Process creation log"}
            parsed.append(entry)
            if _is_roblox_exe(path):
                starts.append(when)
    starts.sort()
    rb_sessions = []
    for when in starts:
        if not rb_sessions or (when - rb_sessions[-1]).total_seconds() > 180:
            rb_sessions.append(when)
    if not rb_sessions:
        sources = raw.get("sources", [])
        errors = raw.get("errors", [])
        return [], {"sources": [sources] if isinstance(sources, str) else sources,
                    "errors": [errors] if isinstance(errors, str) else errors,
                    "partial": bool(raw.get("partial")), "sessions": 0, "rb_times": []}
    before, after = timedelta(minutes=lookback_minutes), timedelta(minutes=after_minutes)
    rows, dedup = [], {}
    for item in parsed:
        if _is_roblox_exe(item["path"]):
            continue
        name = os.path.basename(item["path"])
        if not name or name.lower() in SESSION_NOISE or (item["path"] and SYS_RE.match(item["path"])):
            continue
        rb_start = min(rb_sessions, key=lambda t: abs((item["time"] - t).total_seconds()))
        offset = (item["time"] - rb_start).total_seconds()
        if not -before.total_seconds() <= offset <= after.total_seconds():
            continue
        key = (os.path.normcase(item["path"]).lower(), round(item["time"].timestamp()), round(rb_start.timestamp()))
        source = item["source"] + (f" · parent: {item['parent']}" if item["parent"] else "")
        if key in dedup:
            rows[dedup[key]]["source"] += " + " + item["source"]
            continue
        dedup[key] = len(rows)
        rows.append({"session_start": rb_start, "start": item["time"], "name": name,
                     "path": item["path"], "offset": int(offset), "source": source,
                     "extra": "process_event", "review": False})
    sources = raw.get("sources", [])
    errors = raw.get("errors", [])
    rows.sort(key=lambda row: row["start"], reverse=True)
    row_cap = len(rows) > 300
    rows = rows[:300]
    return rows, {"sources": [sources] if isinstance(sources, str) else sources,
                  "errors": [errors] if isinstance(errors, str) else errors,
                  "partial": bool(raw.get("partial") or row_cap), "sessions": len(rb_sessions),
                  "rb_times": rb_sessions}


def mark_session_hits(rows, names):
    """Flags rows whose app name matches the config list and moves them to the top."""
    for r in rows:
        base = os.path.basename((r.get("path") or "").replace("/", "\\"))
        m = name_match(r.get("name") or "", names) or name_match(base, names)
        r["hit"] = bool(r.get("hit") or m)
        if m:
            r["hit_name"] = m
        r.setdefault("review", False)
        if m:
            marker = f"NAME MATCH: {m}"
            if marker not in (r.get("source") or ""):
                r["source"] = (r.get("source") or "") + f" · {marker}"
    rows.sort(key=lambda r: (-(r["session_start"].timestamp() if r.get("session_start") else 0),
                             not r.get("review"), not r.get("hit"),
                             -(r["start"].timestamp() if r.get("start") else 0)))
    return rows


def iso_dt(s):
    try:
        s = re.sub(r"(\.\d{6})\d+", r"\1", (s or "").replace("Z", "+00:00"))
        return datetime.fromisoformat(s).astimezone()
    except Exception:
        return None


def fmt_offset(delta):
    if delta is None:
        return "—"
    sign = "+" if delta >= 0 else "−"
    m = abs(int(delta)) // 60
    return f"{sign}{m // 60}h {m % 60}m" if m >= 60 else f"{sign}{m}m"


def collect_running_context(names, lookback_minutes=60, after_minutes=2):
    """Roblox is open now: report only running apps launched in the selected launch window.
    Uses WMI (works for elevated processes too, Path may be empty without admin), also matches the
    window title and file version info (OriginalFilename / ProductName ...) so a renamed exe is caught.
    Instances of the same program are merged. Returns None when Roblox is not running."""
    need_win()
    procs = _ps_json(PS_SESSION_PROC, timeout=180)
    rb_names = ("robloxplayerbeta.exe", "windows10universal.exe")
    rb = []
    for p in procs:
        nm, pth = (p.get("name") or "").lower(), (p.get("path") or "").lower()
        if nm in rb_names and (not pth or "roblox" in pth):
            started = iso_dt(p.get("start"))
            if started:
                rb.append(started)
    if not rb:
        return None
    rb_start = min(rb)
    before = timedelta(minutes=lookback_minutes)
    after = timedelta(minutes=after_minutes)
    groups = {}
    for p in procs:
        path, name = p.get("path") or "", p.get("name") or ""
        started = iso_dt(p.get("start"))
        low = name.lower()
        if (not started or started < rb_start - before or started > rb_start + after
                or not name or low in rb_names or low.startswith("roblox")
                or low in SESSION_NOISE or (path and SYS_RE.match(path))):
            continue
        key = (low, path.lower())
        g = groups.get(key)
        if g is None:
            groups[key] = {"name": name, "path": path, "start": started, "n": 1,
                           "title": p.get("title") or "", "info": p.get("info") or ""}
        else:
            g["n"] += 1
            g["start"] = min(g["start"], started)
            g["title"] = g["title"] or p.get("title") or ""
    sigs = sig_map([g["path"] for g in groups.values()])
    rows = []
    for g in groups.values():
        name, path = g["name"], g["path"]
        sig = sigs.get(path, "?") if path else "no path (run as administrator)"
        review = bool(path and sig == "NotSigned" and _outside_trusted_install(path)
                      and _pe_is_gui(path))
        meta = f'{g["title"]} {g["info"]}'.lower()
        m = (name_match(name, names) or name_match(os.path.basename(path), names)
             or next(iter(names_in(meta, names)), None))
        src = f"Running now" + (f" ×{g['n']}" if g["n"] > 1 else "") + f" · sig: {sig}"
        if review:
            src += " · REVIEW: unsigned GUI outside trusted dirs"
        if m:
            src += f" · NAME MATCH: {m}"
            extra = " | ".join(x for x in (g["title"], g["info"]) if x)
            if extra:
                src += f" · {extra[:120]}"
        rows.append({"session_start": rb_start, "start": g["start"], "name": name, "path": path,
                     "offset": int((g["start"] - rb_start).total_seconds()), "source": src,
                     "hit": bool(m), "review": review})
    rows.sort(key=lambda r: (not r["hit"], r["start"]))
    if not rows:
        return [{"session_start": rb_start, "start": None, "name": "", "path": "", "offset": None,
                 "source": "Running process snapshot · no app launch within selected window",
                 "hit": False, "review": False}]
    return rows


def names_in(low, names, minlen=5):
    hit = []
    for n in names:
        nl = n.lower().strip()
        if len(nl) >= minlen and re.search(r"(?<![a-z0-9])" + re.escape(nl) + r"(?![a-z0-9])", low):
            hit.append(n)
    return hit


def gw(m, w):
    return w * 0.4 if m and m.lower() in GENERIC_NAMES else w


def frow(kind, name, path, detail, when, key, w, m=""):
    return {"kind": kind, "name": name, "path": path, "detail": detail, "when": when,
            "key": key, "w": w, "m": m}


def f_processes(names):
    """Process + file metadata: path, start time, file times, size, SHA-256, signature."""
    need_win()
    cand = []
    for d in _ps_json(PS_FOR_PROC):
        path, name = d.get("path") or "", d.get("name") or ""
        if not path or SYS_RE.match(path) or is_safe_app(name, path):
            continue
        m = name_match(name, names) or name_match(os.path.basename(path), names)
        risky = bool(RISKY_DIR_RE.search(path))
        if m or risky:
            cand.append((d, path, m))
    cand = cand[:80]
    sigs = sig_map([c[1] for c in cand])
    rows = []
    for d, path, m in cand:
        sig = sigs.get(path, "?")
        if not m and sig == "Valid":
            continue
        try:
            st = os.stat(path)
            times = (f"created {fmt_ts(st.st_ctime)} · modified {fmt_ts(st.st_mtime)} · "
                     f"accessed {fmt_ts(st.st_atime)} · {human(st.st_size)}")
            sha = sha256_file(path)[:16] + "…" if st.st_size <= (300 << 20) else "-"
        except OSError:
            times, sha = "file not readable", "-"
        started = iso_local(d.get("start"))
        if m:
            w = gw(m, 0.25 if sig == "Valid" else 0.55)
        else:
            w = 0.30
        rows.append(frow("meta", d.get("name") or os.path.basename(path), path,
                         f"{path}  ·  PID {d.get('pid')}  ·  started {started}  ·  {times}  ·  "
                         f"sha256 {sha}  ·  sig: {sig}", started,
                         "ff_proc_name" if m else "ff_proc_path", w, m or ""))
    return rows


def f_artifacts(names):
    """File timestamps / execution artifacts: Prefetch (first + last run) and Recent items."""
    need_win()
    rows = []
    pf = os.path.join(SYSROOT, "Prefetch")
    try:
        files = os.listdir(pf)
    except OSError:
        files = []
    for fn in files:
        if not fn.lower().endswith(".pf") or "-" not in fn:
            continue
        exe = fn.rsplit("-", 1)[0]
        m = name_match(exe, names)
        if not m:
            continue
        try:
            st = os.stat(os.path.join(pf, fn))
        except OSError:
            continue
        rows.append(frow("time", exe, "",
                         f"Prefetch  ·  first run ≈ {fmt_ts(st.st_ctime)}  ·  last run {fmt_ts(st.st_mtime)}",
                         fmt_ts(st.st_mtime), "ff_pf", gw(m, 0.28), m))
    rec = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent")
    try:
        lnks = os.listdir(rec)
    except OSError:
        lnks = []
    for fn in lnks:
        if not fn.lower().endswith(".lnk"):
            continue
        base = fn[:-4]
        m = name_match(base, names)
        if not m:
            continue
        try:
            st = os.stat(os.path.join(rec, fn))
        except OSError:
            continue
        rows.append(frow("time", base, "",
                         f"Recent item  ·  last used {fmt_ts(st.st_mtime)}  ·  created {fmt_ts(st.st_ctime)}",
                         fmt_ts(st.st_mtime), "ff_lnk", gw(m, 0.12), m))
    return rows


def f_events(names, days=14):
    """Application crashes, Defender detections, service installs, cleared event logs."""
    need_win()
    env = dict(os.environ, SLAVE_DAYS=str(days))
    rows = []
    for d in _ps_json(PS_FOR_EVT, env=env, timeout=200):
        log, eid = d.get("log") or "", int(d.get("id") or 0)
        msg = re.sub(r"\s+", " ", d.get("msg") or "")
        low = msg.lower()
        when = iso_local(d.get("time"))
        hit = names_in(low, names)
        m = hit[0] if hit else ""
        short = msg[:260]
        if eid in (1000, 1001):
            if not m and "robloxplayerbeta" not in low:
                continue
            rows.append(frow("crash", f"Application {eid}", "", short, when, "ff_crash",
                             gw(m, 0.30) if m else 0.10, m))
        elif eid in (1116, 1117):
            rows.append(frow("crash", f"Defender {eid}", "", short, when, "ff_def",
                             gw(m, 0.40) if m else 0.30, m))
        elif eid == 7045:
            risky = bool(RISKY_DIR_RE.search(msg))
            if not m and not risky:
                continue
            rows.append(frow("crash", f"Service {eid}", "", short, when, "ff_svc",
                             gw(m, 0.40) if m else 0.25, m))
        elif eid in (1102, 104):
            rows.append(frow("hist", f"{log} {eid}", "", short, when, "ff_clear", 0.45))
    rows.sort(key=lambda r: -r["w"])
    return rows[:150]


def _mt(p):
    try:
        return os.path.getmtime(p)
    except OSError:
        return 0


def f_roblox_logs(names):
    """Newest Roblox log files: lines that mention a name from the list (max 2 per file/name)."""
    base = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Roblox", "logs")
    try:
        files = [os.path.join(base, f) for f in os.listdir(base) if f.lower().endswith(".log")]
    except OSError:
        return []
    files = sorted(files, key=_mt, reverse=True)[:5]
    lowered = [n.lower().strip() for n in names if len(n.strip()) >= 5]
    rows, count = [], {}
    for fp in files:
        try:
            with open(fp, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - (4 << 20)))
                text = f.read().decode("utf-8", "replace")
        except OSError:
            continue
        for line in text.splitlines():
            low = line.lower()
            if not any(n in low for n in lowered):
                continue
            hit = names_in(low, names)
            if not hit:
                continue
            key = (fp, hit[0])
            if count.get(key, 0) >= 2:
                continue
            count[key] = count.get(key, 0) + 1
            rows.append(frow("crash", os.path.basename(fp), fp, line.strip()[:260],
                             fmt_ts(_mt(fp)), "ff_rblog", gw(hit[0], 0.30), hit[0]))
        if len(rows) >= 60:
            break
    return rows


def f_recycle(names):
    """Recycle Bin $I records: original path + deletion time of deleted files whose name matches."""
    rows = []
    for L in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{L}:\\$Recycle.Bin"
        if not os.path.isdir(root):
            continue
        try:
            sids = os.listdir(root)
        except OSError:
            continue
        for sid in sids:
            d = os.path.join(root, sid)
            try:
                items = os.listdir(d)
            except OSError:
                continue
            for fn in items:
                if not fn.startswith("$I"):
                    continue
                try:
                    with open(os.path.join(d, fn), "rb") as f:
                        b = f.read(1200)
                    ver = struct.unpack("<Q", b[:8])[0]
                    ft = struct.unpack("<Q", b[16:24])[0]
                    if ver == 2:
                        n = struct.unpack("<I", b[24:28])[0]
                        orig = b[28:28 + n * 2].decode("utf-16le", "replace")
                    else:
                        orig = b[24:544].decode("utf-16le", "replace")
                    orig = orig.split("\x00")[0]
                except Exception:
                    continue
                m = name_match(os.path.basename(orig.replace("/", "\\")), names)
                if not m:
                    continue
                rows.append(frow("hist", os.path.basename(orig.replace("/", "\\")), orig,
                                 f"Recycle Bin  ·  deleted {ft_str(ft)}  ·  {orig}", ft_str(ft),
                                 "ff_recycle", gw(m, 0.40), m))
    return rows


def collect_forensic(names, cb):
    """cb(level, key, *args) for logging. Returns list of evidence rows."""
    if not is_admin():
        cb("WARN", "log_tr_noadmin")
    rows = []
    sources = (("Processes", f_processes), ("Artifacts", f_artifacts), ("Events", f_events),
               ("RobloxLogs", f_roblox_logs), ("RecycleBin", f_recycle))
    for label, fn in sources:
        try:
            got = fn(names)
        except PermissionError as e:
            cb("WARN", "log_tr_err", label, f"access denied · {e}")
            continue
        except Exception as e:
            cb("WARN", "log_tr_err", label, f"{type(e).__name__}: {e}")
            continue
        rows += got
        cb("OK", "log_tr_src", label, str(len(got)))
    seen, out = set(), []
    for r in rows:
        k = (r["kind"], r["name"].lower(), r["detail"][:120].lower())
        if k not in seen:
            seen.add(k)
            out.append(r)
    out.sort(key=lambda r: -r["w"])
    return out


# ============================== RISK ENGINE ==============================
RISK_CATS = ("hash", "process", "path", "name", "trace", "roblox", "forensic")
EXEC_EXT = {".exe", ".dll", ".zip", ".rar", ".7z", ".bat", ".cmd", ".ps1", ".scr", ".msi", ".jar"}
RISKY_DIR_RE = re.compile(r"\\(temp|downloads|desktop|appdata|programdata|users\\public)\\", re.I)
GENERIC_NAMES = {"real", "wave", "volt", "delta", "severe", "lumen", "velocity", "loader",
                 "loader.exe", "loader.zip", "updater", "updater.exe", "bootstrapper", "mapper",
                 "matrix", "imgui", "drift"}
SYS_PROC = {"svchost", "csrss", "lsass", "explorer", "winlogon", "services", "smss",
            "wininit", "taskhostw", "dwm", "conhost", "runtimebroker"}
RAN_SRC = {"Prefetch", "BAM", "UserAssist", "MUICache"}


def load_known_hashes():
    s = set()
    try:
        with open(HASH_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip().lower()
                if re.fullmatch(r"[0-9a-f]{64}", line):
                    s.add(line)
    except OSError:
        pass
    return s


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_hits(paths, known):
    hits = set()
    for p in list(dict.fromkeys(paths))[:500]:
        try:
            if p and os.path.isfile(p) and os.path.getsize(p) <= 300 * 1024 * 1024 and sha256_file(p) in known:
                hits.add(p)
        except OSError:
            continue
    return hits


BOOT_DETAIL_KEYS = {"windows_none": "r_boot_summary", "firmware_none": "r_boot_no_firmware",
                    "unavailable": "r_boot_unavailable",
                    "volumes_unavailable": "r_boot_volumes_unavailable"}

PS_BOOT_PARTS = r"""
$ErrorActionPreference='SilentlyContinue'
$o=@(Get-Partition | ForEach-Object { [pscustomobject]@{disk=$_.DiskNumber; part=$_.PartitionNumber;
  gpt=[string]$_.GptType; mbr=[int]$_.MbrType; size=[int64]$_.Size} })
ConvertTo-Json -InputObject @($o) -Compress
"""
FOREIGN_GPT = {
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6f-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709": "Linux root (x86-64)",
    "bc13c2ff-59e6-4262-a352-b275fd6f7172": "Linux /boot",
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "Linux /home",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
}
FOREIGN_MBR = {130: "Linux swap (MBR)", 131: "Linux (MBR)", 142: "Linux LVM (MBR)"}
FW_GENERIC_RE = re.compile(r"(?i)\b(windows|pxe|ipv4|ipv6|network|usb|cd|dvd|diskette|removable|uefi)\b")


def _bcd_descriptions(args):
    bcdedit = os.path.join(SYSROOT, "System32", "bcdedit.exe")
    r = subprocess.run([bcdedit] + args, capture_output=True, timeout=12, creationflags=NOWIN)
    text_out = "\n".join(_decode_lines(r.stdout))
    return [d.strip() for d in re.findall(r"(?im)^description\s+(.+)$", text_out)]


def boot_extra_rows():
    """Non-Windows partitions (Linux/Apple, found by GPT/MBR type, so no drive letter is needed),
    extra BCD OS entries and non-generic firmware boot entries."""
    rows = []
    try:
        for d in _ps_json(PS_BOOT_PARTS):
            gpt = (d.get("gpt") or "").strip("{}").lower()
            label = FOREIGN_GPT.get(gpt) or FOREIGN_MBR.get(d.get("mbr"))
            if label:
                rows.append({"kind": "partition",
                             "detail": f"Disk {d.get('disk')} · Partition {d.get('part')} · {label} · "
                                       f"{human(d.get('size') or 0)}"})
    except Exception:
        pass
    try:
        descs = _bcd_descriptions(["/enum", "osloader"])
        if len(descs) > 1:
            rows.extend({"kind": "osloader", "detail": x} for x in descs)
    except Exception:
        pass
    try:
        for x in dict.fromkeys(_bcd_descriptions(["/enum", "firmware"])):
            if not FW_GENERIC_RE.search(x):
                rows.append({"kind": "firmware", "detail": x})
    except Exception:
        pass
    return rows


def collect_boot_context():
    rows = _collect_boot_base()
    if os.name == "nt":
        rows.extend(boot_extra_rows())
        # a real firmware entry makes the "no firmware path" placeholder wrong
        if any(r["kind"] == "firmware" for r in rows):
            rows = [r for r in rows if r["kind"] != "firmware_none"]
    return rows


def _collect_boot_base():
    """Read-only boot context: current Windows, mounted Windows candidates, and non-Microsoft EFI paths."""
    rows = []
    if os.name != "nt":
        return [{"kind": "unavailable", "detail": "windows_only"}]

    current_path = os.path.normpath(os.environ.get("SystemRoot", r"C:\Windows"))
    current = os.path.normcase(current_path)
    version = sys.getwindowsversion()
    current_label = (f"Windows {'11' if version.build >= 22000 else version.major} "
                     f"(build {version.build}) · {current_path}")
    rows.append({"kind": "current", "detail": current_label})

    roots_checked = 0
    candidates = []
    try:
        mask = int(ctypes.windll.kernel32.GetLogicalDrives())
        for i in range(26):
            if not mask & (1 << i):
                continue
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) not in (2, 3):
                continue
            roots_checked += 1
            win_dir = os.path.join(root, "Windows")
            if not any(os.path.isfile(os.path.join(win_dir, "System32", loader))
                       for loader in ("winload.exe", "winload.efi")):
                continue
            normalized = os.path.normcase(os.path.normpath(win_dir))
            if normalized != current:
                candidates.append(normalized)
    except Exception:
        rows.append({"kind": "volumes_unavailable", "detail": ""})

    if candidates:
        rows.extend({"kind": "windows", "detail": path} for path in sorted(set(candidates)))
    else:
        rows.append({"kind": "windows_none", "detail": ""})
    rows.append({"kind": "checked", "detail": str(roots_checked)})

    bcdedit = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "bcdedit.exe")
    if not os.path.isfile(bcdedit):
        bcdedit = shutil.which("bcdedit.exe") or shutil.which("bcdedit")
    if not bcdedit:
        rows.append({"kind": "unavailable", "detail": "bcdedit_missing"})
        return rows

    try:
        result = subprocess.run([bcdedit, "/enum", "firmware", "/v"],
                                capture_output=True, timeout=12, creationflags=NOWIN)
    except (OSError, subprocess.TimeoutExpired):
        rows.append({"kind": "unavailable", "detail": "bcd_query_failed"})
        return rows
    if result.returncode != 0:
        rows.append({"kind": "unavailable", "detail": "bcd_query_failed"})
        return rows

    text_out = "\n".join(_decode_lines(result.stdout + b"\n" + result.stderr))
    efi_paths = set(re.findall(r"(?i)(?:[A-Z]:)?\\EFI\\[^\s]*?\.efi", text_out))
    other_paths = sorted(path for path in efi_paths
                         if "\\microsoft\\boot\\" not in path.lower()
                         and not path.lower().endswith("\\bootmgfw.efi"))
    if other_paths:
        rows.extend({"kind": "firmware", "detail": path} for path in other_paths)
    else:
        rows.append({"kind": "firmware_none", "detail": ""})
    return rows


def risk_level(score):
    return "r_low" if score < 25 else ("r_med" if score < 60 else "r_high")


def risk_engine(files, procs, traces, names, pers=(), fors=(), session=(), usn=(), unsigned=(), execmem=()):
    """Returns {score, catw, findings, signals}; findings = (cat, weight, text_key, detail)."""
    known = load_known_hashes()
    cand = []
    for items in files.values():
        for path, isdir, *_ in items:
            if not isdir and not SYS_RE.match(path) and os.path.splitext(path)[1].lower() in EXEC_EXT:
                cand.append(path)
    for r in procs:
        if r.get("path") and name_match(r["app"], names):
            cand.append(r["path"])
    for tr in traces:
        if tr["exists"]:
            cand.append(tr["path"])
    for r in pers:
        if r["path"]:
            cand.append(r["path"])
    for r in fors:
        if r["path"]:
            cand.append(r["path"])
    for r in session:
        path = r.get("path") or ""
        app = r.get("name") or ""
        if (path and os.path.isfile(path)
                and (r.get("hit") or r.get("review") or name_match(app, names))):
            cand.append(path)
    hits = hash_hits(cand, known) if known else set()
    if known:
        for r in unsigned:
            digest, path = (r.get("sha256") or "").lower(), r.get("path") or ""
            if digest and digest in known and path:
                hits.add(path)

    F, seen = [], set()
    for name, items in files.items():
        generic = name.lower() in GENERIC_NAMES
        for path, isdir, *_ in items:
            if path in seen or isdir or SYS_RE.match(path):
                continue
            seen.add(path)
            ext = os.path.splitext(path)[1].lower()
            if path in hits:
                F.append(("hash", 0.60, "f_hash", path))
            elif ext in EXEC_EXT and RISKY_DIR_RE.search(path):
                F.append(("path", 0.28, "f_path", path))
            else:
                F.append(("name", 0.05 if generic else 0.12, "f_name", path))

    for r in procs:
        app, path = r["app"], r.get("path") or ""
        detail = f"{app}  —  {path}" if path else app
        if app.lower() in SYS_PROC and path and not SYS_RE.match(path):
            F.append(("path", 0.40, "f_masq", detail))
        m = name_match(app, names)
        if not m:
            continue
        if path in hits:
            F.append(("hash", 0.60, "f_hash", detail))
        risky = bool(path) and bool(RISKY_DIR_RE.search(path))
        if m.lower() in GENERIC_NAMES:
            F.append(("process", 0.30, "f_proc", detail) if risky else ("name", 0.05, "f_pname", detail))
        else:
            net = r.get("conn", 0) > 0
            F.append(("process", 0.40 if net else 0.32, "f_proc_net" if net else "f_proc", detail))

    for tr in traces:
        src = tr["src"]
        detail = f"[{src}] {tr['path']}" + (f"  ·  {tr['when']}" if tr["when"] not in ("", "—") else "") \
            + (f"  ·  {tr['reason']}" if tr["reason"] else "")
        if tr["path"] in hits:
            F.append(("hash", 0.60, "f_hash", detail))
            continue
        gone = tr["exists"] is False
        if src == "USN":
            rs = tr["reason"].lower()
            if "rename" in rs:
                w, key = 0.35, "f_trace_ren"
            elif "delete" in rs:
                w, key = 0.35, "f_trace_del"
            else:
                w, key = 0.12, "f_trace_seen"
        elif gone:
            w, key = (0.50 if src in RAN_SRC else 0.35), "f_trace_del"
        elif src in RAN_SRC:
            w, key = 0.28, "f_trace_run"
        else:
            w, key = 0.15, "f_trace_seen"
        if tr["m"].lower() in GENERIC_NAMES:
            w *= 0.4
        F.append(("trace", w, key, detail))

    for r in pers:
        detail = f"[{r['kind']}] {r['path']}" + (f"  ·  {r['detail']}" if r["detail"] != r["path"] else "")
        if r["path"] and r["path"] in hits:
            F.append(("hash", 0.60, "f_hash", detail))
        else:
            F.append(("roblox", r["w"], r["flags"][0], detail))

    for r in fors:
        detail = f"[{r['kind']}] {r['detail']}"
        if r["path"] and r["path"] in hits:
            F.append(("hash", 0.60, "f_hash", detail))
        else:
            F.append(("forensic", r["w"], r["key"], detail))

    seen_session = set()
    for r in session:
        app = (r.get("name") or "").strip()
        start = r.get("start")
        session_start = r.get("session_start")
        if not app or not start or not session_start:
            continue
        identity = (app.lower(), r.get("path") or "", start, session_start)
        if identity in seen_session:
            continue
        seen_session.add(identity)
        path = r.get("path") or ""
        detail = f"{app} · {start:%Y-%m-%d %H:%M:%S} · Roblox {session_start:%Y-%m-%d %H:%M:%S}"
        if path:
            detail += f" · {path}"
        if r.get("source"):
            detail += f" · {r['source']}"
        delta = r.get("offset")
        if delta is None:
            try:
                delta = int((start - session_start).total_seconds())
            except (TypeError, ValueError):
                delta = 0
        distance = abs(int(delta))
        match = name_match(app, names) or r.get("hit_name")
        if path and path in hits:
            F.append(("hash", 0.60, "f_hash", detail))
        elif r.get("hit") or match:
            generic = bool(match and str(match).lower() in GENERIC_NAMES)
            weight = (0.08 if generic else 0.32) if distance <= 10 * 60 else (0.04 if generic else 0.12)
            if distance <= 60 * 60:
                F.append(("name" if generic else "process", weight,
                          "f_pname" if generic else "f_config_match", detail))
        elif r.get("review"):
            if distance <= 10 * 60:
                F.append(("process", 0.22, "f_session_review", detail))
            elif distance <= 60 * 60:
                F.append(("process", 0.10, "f_session_review", detail))
        else:
            # Ordinary launches are only weak context; keep them visible without treating
            # a nearby launch record as evidence of cheating by itself.
            if distance <= 15 * 60:
                F.append(("trace", 0.04, "f_session_app", detail))
            elif distance <= 60 * 60:
                F.append(("trace", 0.02, "f_session_app", detail))

    for r in usn:
        name = r.get("name") or "Unknown.exe"
        path = r.get("path") or ""
        source = r.get("source") or "USN"
        when = r.get("start")
        kind_match = re.search(r"\b(CREATE|DELETE|RENAME)\b", source, re.I)
        kind = kind_match.group(1).upper() if kind_match else "CHANGE"
        detail = f"{name} · {when:%Y-%m-%d %H:%M:%S}" if when else name
        detail += f" · {source}"
        match = name_match(name, names)
        if match:
            generic = match.lower() in GENERIC_NAMES
            F.append(("name" if generic else "process", 0.08 if generic else 0.26,
                      "f_name" if generic else "f_config_match", detail))
        else:
            weight = {"DELETE": 0.10, "RENAME": 0.08, "CREATE": 0.05}.get(kind, 0.05)
            F.append(("trace", weight, "f_usn_event", detail))

    for r in unsigned:
        name, path = r.get("name") or "Unknown.exe", r.get("path") or ""
        when, source = r.get("start"), r.get("source") or "Recent executable scan"
        detail = f"{name} · {path}"
        if when:
            detail += f" · {when:%Y-%m-%d %H:%M:%S}"
        detail += f" · {source}"
        if path and path in hits:
            F.append(("hash", 0.60, "f_hash", detail))
            continue
        match = r.get("configured_match") or name_match(name, names)
        if match:
            generic = str(match).lower() in GENERIC_NAMES
            F.append(("name" if generic else "process", 0.08 if generic else 0.32,
                      "f_name" if generic else "f_config_match", detail))
        elif r.get("unsigned"):
            weight = 0.16 if int(r.get("folder_count") or 0) >= 2 else 0.10
            F.append(("process", weight, "f_unsigned_exe", detail))

    for r in execmem:
        detail = r.get("source") or r.get("detail") or "Roblox private executable memory"
        if r.get("region_only"):
            F.append(("roblox", 0.06, "f_exec_region", detail))
        else:
            F.append(("roblox", 0.24, "f_exec_thread", detail))

    best, cnt = {}, {}
    context_only = {"f_session_app", "f_session_review", "f_usn_event", "f_unsigned_exe",
                    "f_config_match", "f_exec_region", "f_exec_thread"}
    for cat, w, key, _d in F:
        best[cat] = max(best.get(cat, 0.0), w)
        if key not in context_only:
            cnt[cat] = cnt.get(cat, 0) + 1
    catw = {}
    for c in RISK_CATS:
        b = best.get(c, 0.0)
        catw[c] = b + (1 - b) * min(0.10, 0.005 * (cnt.get(c, 1) - 1)) if b else 0.0
    p = 1.0
    for w in catw.values():
        p *= 1 - w
    total = 1 - p
    signals = sum(1 for w in catw.values() if w >= 0.10)
    if signals >= 3:
        total = min(1.0, total + 0.08)
    F.sort(key=lambda x: -x[1])
    return {"score": int(round(total * 100)), "catw": catw, "findings": F, "signals": signals}


# ============================== THEME / DRAWING ==============================
GREEN, AMBER, RED = "#3fb950", "#e3a008", "#f85149"


def _hex(c):
    return tuple(int(c[i:i + 2], 16) for i in (1, 3, 5))


def lerp(c1, c2, t):
    t = max(0.0, min(1.0, t))
    a, b = _hex(c1), _hex(c2)
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


THEMES = {
    "blue":   dict(BG="#11151b", PANEL="#171c23", CARD="#202731", LINE="#303946", FG="#e7ebf0",
                   MUTED="#9aa5b2", ACCENT="#5b91d1", ACCENT2="#7897bd", ONACC="#08111c"),
    "red":    dict(BG="#100a0b", PANEL="#181012", CARD="#221619", LINE="#3d2429", FG="#f3e8e9",
                   MUTED="#8a6b70", ACCENT="#ff4d5a", ACCENT2="#ff9a5c", ONACC="#1a0003"),
    "black":  dict(BG="#050505", PANEL="#0d0d0d", CARD="#161616", LINE="#2b2b2b", FG="#f2f2f2",
                   MUTED="#7d7d7d", ACCENT="#e8e8e8", ACCENT2="#8c8c8c", ONACC="#050505"),
    "white":  dict(BG="#e9edf3", PANEL="#ffffff", CARD="#f1f4f9", LINE="#cdd5e0", FG="#1a2230",
                   MUTED="#6b7787", ACCENT="#1a73e8", ACCENT2="#7c5cff", ONACC="#ffffff"),
    "purple": dict(BG="#0c0a14", PANEL="#141022", CARD="#1d1730", LINE="#322a4d", FG="#ece8f6",
                   MUTED="#7d7396", ACCENT="#a78bfa", ACCENT2="#f472b6", ONACC="#120a24"),
    "green":  dict(BG="#08110d", PANEL="#0e1a14", CARD="#14251c", LINE="#244134", FG="#e4f2ea",
                   MUTED="#6b8778", ACCENT="#34d399", ACCENT2="#2fb8ff", ONACC="#00180e"),
}
THEME_ORDER = ["blue", "red", "black", "white", "purple", "green"]


GLASS = False
GLASS_KEY = "#010203"   # panel rengi bu olur ve pencerede 'saydam renk' olarak isaretlenir


def set_theme(key):
    global BG, PANEL, CARD, LINE, FG, MUTED, ACCENT, ACCENT2, ONACC
    global HOVER, HOVER2, ROW_ALT, SEL, DANGER, DANGER_H, LIGHT
    th = THEMES.get(key, THEMES["blue"])
    BG, PANEL, CARD, LINE = th["BG"], th["PANEL"], th["CARD"], th["LINE"]
    if GLASS:
        BG = PANEL = CARD = GLASS_KEY
    FG, MUTED, ACCENT, ACCENT2, ONACC = th["FG"], th["MUTED"], th["ACCENT"], th["ACCENT2"], th["ONACC"]
    LIGHT = sum(_hex(th["BG"])) > 450
    HOVER = lerp(ACCENT, "#ffffff", 0.3) if not LIGHT else lerp(ACCENT, "#000000", 0.15)
    HOVER2 = lerp(ACCENT2, "#ffffff", 0.3) if not LIGHT else lerp(ACCENT2, "#000000", 0.15)
    ROW_ALT = CARD if GLASS else lerp(CARD, FG, 0.04)
    SEL = lerp(CARD, ACCENT, 0.3)
    DANGER = lerp(CARD, RED, 0.25)
    DANGER_H = lerp(CARD, RED, 0.42)


set_theme("blue")


def glass(c):
    # Keep controls flat and legible; only a quiet border separates them from the surface.
    return lerp(c, FG, 0.10), c, c


def set_alpha(win, a):
    try:
        win.attributes("-alpha", a)
    except tk.TclError:
        pass


def rounded_rect(cv, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return cv.create_polygon(pts, smooth=True, **kw)


def flow_layout(frame, items, cell_w, padx=0):
    state = {"cols": 0}

    def regrid(_e=None):
        width = frame.winfo_width()
        cols = max(1, width // cell_w) if width > 1 else PER_ROW
        if cols == state["cols"]:
            return
        state["cols"] = cols
        for i, wd in enumerate(items):
            r, c = divmod(i, cols)
            wd.grid(row=r, column=c, sticky="w", pady=1, padx=(0, padx))

    frame.bind("<Configure>", regrid)
    regrid()


class RoundButton(tk.Canvas):
    def __init__(self, parent, text, command, bg, fg, hover, width=100, height=34,
                 font=("Segoe UI", 10, "bold"), parent_bg=None):
        super().__init__(parent, width=width, height=height, bg=parent_bg or PANEL,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.command, self.bg_c, self.fg_c, self.hover_c = command, bg, fg, hover
        self.enabled = True
        r = 6
        self.r_border = rounded_rect(self, 1, 1, width - 1, height - 1, r, fill="", outline="")
        self.r_base = rounded_rect(self, 2, 2, width - 2, height - 2, max(2, r - 1), fill="", outline="")
        self.r_gloss = rounded_rect(self, 5, 3, width - 5, 6, 2, fill="", outline="")
        self.label = self.create_text(width / 2, height / 2, text=text, fill=fg, font=font)
        self._paint(bg)
        self.bind("<Enter>", lambda e: self.enabled and self._paint(self.hover_c))
        self.bind("<Leave>", lambda e: self._paint(self.bg_c if self.enabled else LINE))
        self.bind("<Button-1>", lambda e: self.enabled and self.command())

    def _paint(self, color):
        border, base, gloss = glass(color)
        self.itemconfig(self.r_border, fill=border)
        self.itemconfig(self.r_base, fill=base)
        self.itemconfig(self.r_gloss, fill=base)

    def set_enabled(self, enabled):
        self.enabled = enabled
        self._paint(self.bg_c if enabled else LINE)
        self.itemconfig(self.label, fill=self.fg_c if enabled else MUTED)
        self.config(cursor="hand2" if enabled else "arrow")

    def set_text(self, text, fg=None):
        self.itemconfig(self.label, text=text)
        if fg:
            self.fg_c = fg
            self.itemconfig(self.label, fill=fg)

    def set_colors(self, bg, fg, hover):
        self.bg_c, self.fg_c, self.hover_c = bg, fg, hover
        self._paint(bg)
        self.itemconfig(self.label, fill=fg)


# ============================== BOOT SOUND / SPLASH ==============================
def boot_sound_file():
    path = os.path.join(tempfile.gettempdir(), "slave_boot_v2_release.wav")
    if os.path.isfile(path):
        return path
    rate, total = 22050, 1.65
    count = int(rate * total)
    samples = [0.0] * count
    tau = 2 * math.pi

    # A quiet, rounded three-note motif; the second partial adds warmth without a harsh beep.
    for start, frequency, length, volume in ((0.06, 523.25, 0.52, 0.28),
                                              (0.31, 659.25, 0.58, 0.24),
                                              (0.62, 783.99, 0.88, 0.22)):
        first = int(start * rate)
        for i in range(int(length * rate)):
            at = first + i
            if at >= count:
                break
            elapsed = i / rate
            attack = min(1.0, elapsed / 0.035)
            decay = math.exp(-elapsed * 3.4)
            fundamental = math.sin(tau * frequency * elapsed)
            overtone = 0.18 * math.sin(tau * frequency * 2 * elapsed)
            samples[at] += volume * attack * decay * (fundamental + overtone)
    peak = max(1e-6, max(abs(value) for value in samples))
    gain = 0.16 * 32767 / peak
    pcm = struct.pack("<%dh" % count, *(int(value * gain) for value in samples))
    temp_path = path + ".tmp"
    with wave.open(temp_path, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(rate)
        output.writeframes(pcm)
    os.replace(temp_path, path)
    return path


def play_boot_sound():
    if winsound is None:
        return
    try:
        winsound.PlaySound(boot_sound_file(), winsound.SND_FILENAME | winsound.SND_ASYNC)
    except Exception:
        pass


def draw_slave_mark(canvas, center_x, center_y, radius=54, base_bg=None):
    """Draw the original Slave mark from its concentric rings, arcs, and center dot."""
    bg = base_bg or BG
    scale = radius / 54.0
    glow = [canvas.create_oval(center_x-r*scale, center_y-r*scale,
                               center_x+r*scale, center_y+r*scale,
                               outline="", fill=bg) for r in (72, 58, 46)]
    arcs = [canvas.create_arc(center_x-r*scale, center_y-r*scale,
                              center_x+r*scale, center_y+r*scale,
                              start=0, extent=extent, style="arc", outline=color,
                              width=max(1, round(width*scale)))
            for r, width, color, extent in ((54, 4, ACCENT, 110),
                                             (42, 3, ACCENT2, 80),
                                             (30, 2, LINE, 140))]
    core_r = 8 * scale
    core = canvas.create_oval(center_x-core_r, center_y-core_r,
                              center_x+core_r, center_y+core_r,
                              fill=ACCENT, outline="")
    return {"glow": glow, "arcs": arcs, "core": core, "bg": bg}


def animate_slave_mark(canvas, mark, state, elapsed):
    """Animate the original hand-drawn mark, with the app state shown by its color."""
    if state == "splash":
        colors = (ACCENT, ACCENT2, LINE)
        multiplier = 1.0
        pulse = 0.5 + 0.5 * math.sin(elapsed * 4.0)
        core_color = lerp(ACCENT, "#ffffff", 0.3 * pulse)
        glow_bases = (0.04, 0.07, 0.11)
    else:
        color = {"ready": GREEN, "error": RED, "progress": AMBER}.get(state, ACCENT)
        colors = (color, lerp(color, mark["bg"], 0.30), lerp(color, mark["bg"], 0.55))
        multiplier = 2.6 if state == "progress" else 1.0
        pulse = 0.5 + 0.5 * math.sin(elapsed * (5.0 if state == "progress" else 1.6))
        core_color = lerp(color, "#ffffff", 0.3 * pulse)
        glow_bases = (0.08, 0.07, 0.06)
    for arc, speed, color in zip(mark["arcs"], (200, -140, 90), colors):
        canvas.itemconfig(arc, start=(elapsed * speed * multiplier) % 360, outline=color)
    for oval, base in zip(mark["glow"], glow_bases):
        canvas.itemconfig(oval, fill=lerp(mark["bg"], colors[0], base * (0.6 + 0.8 * pulse)))
    canvas.itemconfig(mark["core"], fill=core_color)


class Splash:
    W, H = 560, 360
    TOTAL = 2.35

    def __init__(self, root, on_done, lang="en"):
        self.on_done = on_done
        self.steps = tx(lang, "splash_steps")
        width, height = self.W, self.H
        self.win = tk.Toplevel(root)
        self.win.overrideredirect(True)
        try:
            self.win.attributes("-topmost", True)
        except tk.TclError:
            pass
        x = (root.winfo_screenwidth() - width) // 2
        y = (root.winfo_screenheight() - height) // 2
        self.win.geometry(f"{width}x{height}+{x}+{y}")
        self.win.configure(bg=BG)
        set_alpha(self.win, 0.0)
        canvas = self.cv = tk.Canvas(self.win, width=width, height=height, bg=BG,
                                     highlightthickness=0, bd=0)
        canvas.pack()
        canvas.create_rectangle(1, 1, width - 2, height - 2, outline=LINE, width=1)

        center_x, center_y = width // 2, 105
        self.logo = draw_slave_mark(canvas, center_x, center_y, 54)
        self.logo_angle = 0.0
        self.title = canvas.create_text(center_x, 181, text="SLAVE", fill=BG,
                                        font=("Segoe UI", 27, "bold"))
        self.version = canvas.create_text(center_x, 209, text="VERSION 2.0", fill=BG,
                                          font=("Segoe UI", 9, "bold"))
        self.credit = canvas.create_text(center_x, 238, text=CREDIT, fill=BG,
                                         font=("Segoe UI", 9))
        self.status_line = canvas.create_text(center_x, 282, text="", fill=MUTED,
                                              font=("Segoe UI", 9))
        self.track = (96, width - 96, 316)
        canvas.create_line(self.track[0], self.track[2], self.track[1], self.track[2],
                           fill=LINE, width=2, capstyle="round")
        self.fill = canvas.create_line(self.track[0], self.track[2], self.track[0], self.track[2],
                                       fill=ACCENT, width=2, capstyle="round")
        self.t0 = time.time()
        threading.Thread(target=play_boot_sound, daemon=True).start()
        self._tick()

    @staticmethod
    def _ease(value):
        value = max(0.0, min(1.0, value))
        return value * value * (3.0 - 2.0 * value)

    def _tick(self):
        elapsed = time.time() - self.t0
        if elapsed < 0.28:
            set_alpha(self.win, self._ease(elapsed / 0.28))
        elif elapsed > self.TOTAL:
            set_alpha(self.win, 1.0 - self._ease((elapsed - self.TOTAL) / 0.28))
        else:
            set_alpha(self.win, 1.0)
        if elapsed > self.TOTAL + 0.28:
            self.win.destroy()
            self.on_done()
            return

        progress = self._ease((elapsed - 0.16) / (self.TOTAL - 0.20))
        animate_slave_mark(self.cv, self.logo, "splash", elapsed)
        for item, delay in ((self.title, 0.22), (self.version, 0.48), (self.credit, 0.66)):
            amount = self._ease((elapsed - delay) / 0.28)
            self.cv.itemconfig(item, fill=lerp(BG, FG if item == self.title else MUTED, amount))
        status_index = min(3, int(progress * 4))
        self.cv.itemconfig(self.status_line, text=self.steps[status_index])
        left, right, y = self.track
        self.cv.coords(self.fill, left, y, left + (right - left) * progress, y)
        self.win.after(33, self._tick)


# ============================== CONFIG SYSTEM ==============================
class ConfigEditor:
    def __init__(self, app, tool, name, names, is_new, readonly, on_save):
        self.app, self.tool, self.on_save = app, tool, on_save
        self.is_new, self.readonly = is_new, readonly
        self.names = list(names)
        t = app.t
        w = self.win = tk.Toplevel(app.root)
        w.title(t("ed_title_new" if is_new else "ed_title_edit"))
        w.configure(bg=BG)
        w.geometry("470x560")
        w.minsize(400, 480)
        w.transient(app.root)
        w.grab_set()
        lab = dict(bg=BG, fg=MUTED, font=("Segoe UI", 8, "bold"))
        ent = dict(bg=CARD, fg=FG, insertbackground=FG, relief="flat", font=("Segoe UI", 10),
                   highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT,
                   readonlybackground=CARD, disabledbackground=CARD, disabledforeground=MUTED)

        tk.Label(w, text=t("ed_name").upper(), **lab).pack(anchor="w", padx=16, pady=(16, 3))
        self.name_var = tk.StringVar(value=name)
        self.name_e = tk.Entry(w, textvariable=self.name_var, **ent)
        self.name_e.pack(fill="x", padx=16, ipady=6)
        if not is_new:
            self.name_e.config(state="readonly")

        if is_new:
            self.copy_var = tk.BooleanVar(value=False)
            tk.Checkbutton(w, text=t("ed_copy"), variable=self.copy_var, command=self._copy_current,
                           bg=BG, fg=MUTED, selectcolor=CARD, activebackground=BG, activeforeground=FG,
                           font=("Segoe UI", 9), highlightthickness=0, bd=0,
                           cursor="hand2").pack(anchor="w", padx=14, pady=(8, 0))

        if readonly:
            tk.Label(w, text=t("ed_readonly"), bg=BG, fg=AMBER, font=("Segoe UI", 9),
                     justify="left").pack(anchor="w", padx=16, pady=(10, 0))
        else:
            tk.Label(w, text=t("ed_add_label").upper(), **lab).pack(anchor="w", padx=16, pady=(14, 3))
            row = tk.Frame(w, bg=BG)
            row.pack(fill="x", padx=16)
            self.add_e = tk.Entry(row, **ent)
            self.add_e.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
            self.add_e.bind("<Return>", lambda e: self.add())
            self.add_e.focus_set()
            RoundButton(row, t("ed_add"), self.add, ACCENT2, "#ffffff", HOVER2,
                        width=90, height=32, parent_bg=BG).pack(side="left")

        self.count_lbl = tk.Label(w, **lab)
        self.count_lbl.pack(anchor="w", padx=16, pady=(14, 3))
        lf = tk.Frame(w, bg=BG)
        lf.pack(fill="both", expand=True, padx=16)
        self.lb = tk.Listbox(lf, bg=CARD, fg=FG, selectbackground=SEL, selectforeground=FG,
                             relief="flat", font=("Segoe UI", 10), highlightthickness=1,
                             highlightbackground=LINE, activestyle="none", selectmode="extended")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.lb.yview)
        self.lb.configure(yscrollcommand=sb.set)
        self.lb.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.lb.bind("<Delete>", lambda e: self.remove())

        bot = tk.Frame(w, bg=BG)
        bot.pack(fill="x", padx=16, pady=14)
        if not readonly:
            RoundButton(bot, t("ed_remove"), self.remove, CARD, FG, LINE, width=130, height=34,
                        parent_bg=BG).pack(side="left")
            RoundButton(bot, t("ed_save"), self.save, ACCENT, ONACC, HOVER, width=100, height=34,
                        parent_bg=BG).pack(side="right")
            RoundButton(bot, t("ed_cancel"), w.destroy, CARD, FG, LINE, width=90, height=34,
                        parent_bg=BG).pack(side="right", padx=8)
        else:
            RoundButton(bot, t("close"), w.destroy, CARD, FG, LINE, width=90, height=34,
                        parent_bg=BG).pack(side="right")
        self._fill()

    def _fill(self):
        self.lb.delete(0, "end")
        for n in self.names:
            self.lb.insert("end", n)
        self.count_lbl.config(text=self.app.t("ed_names", len(self.names)).upper())

    def _add_names(self, items):
        for s in items:
            if not any(s.lower() == n.lower() for n in self.names):
                self.names.append(s)

    def _copy_current(self):
        if self.copy_var.get():
            self._add_names(self.tool.names)
            self._fill()

    def add(self):
        self._add_names(split_names(self.add_e.get()))
        self.add_e.delete(0, "end")
        self._fill()
        self.lb.see("end")

    def remove(self):
        for i in sorted(self.lb.curselection(), reverse=True):
            del self.names[i]
        self._fill()

    def save(self):
        t = self.app.t
        nm = self.name_var.get().strip()
        if self.is_new:
            if not nm:
                messagebox.showerror("Slave", t("err_name_empty"), parent=self.win)
                return
            if nm.lower() in [c.lower() for c in self.tool.cfgs]:
                messagebox.showerror("Slave", t("err_name_exists"), parent=self.win)
                return
        self.win.destroy()
        self.on_save(nm, list(self.names))


class ToolCfg:
    """One independent config set (Browse / Data usage / Traces / DLL-Memory each own one)."""

    def __init__(self, app, key, default_names, data):
        self.app, self.key, self.default_names = app, key, list(default_names)
        data = data if isinstance(data, dict) else {}
        cfgs = data.get("configs") if isinstance(data.get("configs"), dict) else {}
        old_def = cfgs.get(DEFAULT_CFG) if isinstance(cfgs.get(DEFAULT_CFG), dict) else {}
        cfgs[DEFAULT_CFG] = {"names": None,
                             "disabled": [n for n in old_def.get("disabled", []) if n in self.default_names]}
        for k, v in list(cfgs.items()):
            if k != DEFAULT_CFG:
                if not isinstance(v, dict) or not isinstance(v.get("names"), list):
                    del cfgs[k]
                else:
                    v.setdefault("disabled", [])
        self.cfgs = cfgs
        self.active = data.get("active") if data.get("active") in cfgs else DEFAULT_CFG
        self.names, self.enabled = [], {}
        self.combo = self.sel_fr = None
        self.on_load = lambda: None
        self.on_toggle = lambda: None
        self.apply()

    def apply(self):
        c = self.cfgs[self.active]
        self.names = list(self.default_names) if c.get("names") is None else list(c["names"])
        dis = set(c.get("disabled", []))
        self.enabled = {n: tk.BooleanVar(value=n not in dis) for n in self.names}

    def store_disabled(self):
        if self.active in self.cfgs:
            self.cfgs[self.active]["disabled"] = [n for n in self.names if not self.enabled[n].get()]

    def data_out(self):
        self.store_disabled()
        return {"active": self.active, "configs": self.cfgs}

    def active_names(self):
        return [n for n in self.names if self.enabled[n].get()]

    def busy(self):
        return {"browse": self.app.scanning, "trace": self.app.trace_busy,
                "persist": self.app.persist_busy,
                "forensic": self.app.forensic_busy}.get(self.key, False)

    def build_ui(self, card):
        app = self.app
        bar = tk.Frame(card, bg=PANEL)
        bar.pack(fill="x", padx=12, pady=(10, 0))
        lc = tk.Label(bar, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold"))
        lc.pack(side="left", padx=(0, 8))
        app.reg(lambda: lc.config(text=app.t("cfg_label")))
        self.combo = ttk.Combobox(bar, state="readonly", width=26, style="Dark.TCombobox", font=("Segoe UI", 10))
        self.combo.pack(side="left", ipady=3, padx=(0, 10))
        self.combo.bind("<<ComboboxSelected>>", self._picked)
        for key, cmd, bg, fg, hov, w in (
                ("cfg_new", self.new, ACCENT2, "#ffffff", HOVER2, 120),
                ("cfg_edit", self.edit, CARD, FG, LINE, 130),
                ("cfg_del", self.delete, DANGER, RED, DANGER_H, 80)):
            b = RoundButton(bar, "", cmd, bg, fg, hov, width=w, height=32, parent_bg=PANEL)
            b.pack(side="left", padx=(0, 8))
            app.reg(lambda b=b, k=key: b.set_text(app.t(k)))

        head = tk.Frame(card, bg=PANEL)
        head.pack(fill="x", padx=12, pady=(12, 0))
        l1 = tk.Label(head, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold"))
        l1.pack(side="left")
        l2 = tk.Label(head, bg=PANEL, fg=MUTED, font=("Segoe UI", 8))
        l2.pack(side="left", padx=8)
        app.reg(lambda: l1.config(text=app.t("names_head")))
        app.reg(lambda: l2.config(text=app.t("names_hint")))
        for key, val in (("all_off", False), ("all_on", True)):
            b = RoundButton(head, "", lambda v=val: self.set_all(v), CARD, FG, LINE,
                            width=120, height=26, font=("Segoe UI", 8, "bold"), parent_bg=PANEL)
            b.pack(side="right", padx=(6, 0))
            app.reg(lambda b=b, k=key: b.set_text(app.t(k)))
        self.sel_fr = tk.Frame(card, bg=PANEL)
        self.sel_fr.pack(fill="x", padx=12, pady=(2, 10))
        self.refresh_combo()
        self.build_checks()

    def refresh_combo(self):
        order = [DEFAULT_CFG] + sorted((k for k in self.cfgs if k != DEFAULT_CFG), key=str.lower)
        self.combo.config(values=order)
        self.combo.set(self.active)

    def build_checks(self):
        for w in self.sel_fr.winfo_children():
            w.destroy()
        items = [tk.Checkbutton(self.sel_fr, text=name, variable=self.enabled[name], command=self.toggled,
                                width=14, anchor="w", **self.app.ck(PANEL)) for name in self.names]
        flow_layout(self.sel_fr, items, 142)

    def toggled(self):
        self.app.save_config()
        self.on_toggle()

    def set_all(self, value):
        for v in self.enabled.values():
            v.set(value)
        self.app.save_config()
        self.on_toggle()
        self.app.dlog("INFO", "log_all_on" if value else "log_all_off")

    def _picked(self, _e=None):
        name = self.combo.get()
        if name == self.active:
            return
        if self.busy():
            self.combo.set(self.active)
            self.app.dlog("WARN", "log_busy")
            return
        self.load(name)

    def load(self, name, log="log_cfg_loaded"):
        if name not in self.cfgs:
            return
        self.store_disabled()
        self.active = name
        self.apply()
        self.refresh_combo()
        self.build_checks()
        self.on_load()
        self.app.save_config()
        self.app.dlog("OK", log, name)

    def new(self):
        if self.busy():
            self.app.dlog("WARN", "log_busy")
            return
        ConfigEditor(self.app, self, "", [], True, False, self.saved)

    def edit(self):
        if self.busy():
            self.app.dlog("WARN", "log_busy")
            return
        ConfigEditor(self.app, self, self.active, self.names, False, self.active == DEFAULT_CFG, self.saved)

    def saved(self, name, names):
        old = self.cfgs.get(name, {})
        self.cfgs[name] = {"names": names, "disabled": [d for d in old.get("disabled", []) if d in names]}
        if name == self.active:
            self.active = None
        self.load(name, "log_cfg_saved")

    def delete(self):
        if self.active == DEFAULT_CFG:
            messagebox.showinfo("Slave", self.app.t("del_default"))
            return
        if self.busy():
            self.app.dlog("WARN", "log_busy")
            return
        name = self.active
        if messagebox.askyesno(self.app.t("cfg_del"), self.app.t("del_confirm", name)):
            del self.cfgs[name]
            self.active = None
            self.load(DEFAULT_CFG)
            self.app.dlog("INFO", "log_cfg_deleted", name)


# ============================== APPEARANCE ==============================
class AppearanceDialog:
    def __init__(self, app, geo=None):
        self.app = app
        t = app.t
        w = self.win = tk.Toplevel(app.root)
        w.title(t("ap_title"))
        w.configure(bg=BG)
        w.geometry(geo or "460x800")
        w.resizable(False, False)
        w.transient(app.root)
        lab = dict(bg=BG, fg=MUTED, font=("Segoe UI", 8, "bold"))

        tk.Label(w, text=t("ap_theme").upper(), **lab).pack(anchor="w", padx=18, pady=(18, 8))
        grid = tk.Frame(w, bg=BG)
        grid.pack(anchor="w", padx=18)
        for i, key in enumerate(THEME_ORDER):
            r, c = divmod(i, 3)
            cell = tk.Frame(grid, bg=BG)
            cell.grid(row=r, column=c, padx=(0, 12), pady=(0, 8))
            th = THEMES[key]
            sel = key == app.theme
            cv = tk.Canvas(cell, width=124, height=66, bg=BG, highlightthickness=0, cursor="hand2")
            rounded_rect(cv, 2, 2, 122, 64, 14, fill=ACCENT if sel else th["LINE"], outline="")
            rounded_rect(cv, 4, 4, 120, 62, 12, fill=th["BG"], outline="")
            rounded_rect(cv, 14, 13, 110, 25, 5, fill=th["CARD"], outline="")
            rounded_rect(cv, 14, 36, 70, 54, 9, fill=th["ACCENT"], outline="")
            rounded_rect(cv, 17, 38, 67, 44, 3, fill=lerp(th["ACCENT"], "#ffffff", 0.3), outline="")
            cv.create_oval(84, 36, 102, 54, fill=th["ACCENT2"], outline="")
            cv.pack()
            cv.bind("<Button-1>", lambda e, k=key: app.apply_look(theme=k))
            tk.Label(cell, text=t("th_" + key), bg=BG, fg=FG if sel else MUTED,
                     font=("Segoe UI", 9, "bold" if sel else "normal")).pack(pady=(3, 0))

        tk.Label(w, text=t("ap_bg").upper(), **lab).pack(anchor="w", padx=18, pady=(14, 6))
        name = os.path.basename(app.bg_image) if app.bg_image else t("ap_none")
        tk.Label(w, text=name, bg=BG, fg=FG if app.bg_image else MUTED, font=("Segoe UI", 9),
                 anchor="w", wraplength=420, justify="left").pack(anchor="w", padx=18)
        row = tk.Frame(w, bg=BG)
        row.pack(anchor="w", padx=18, pady=8)
        RoundButton(row, t("ap_pick"), self.pick, ACCENT, ONACC, HOVER, width=150, height=34,
                    parent_bg=BG).pack(side="left", padx=(0, 8))
        RoundButton(row, t("ap_remove"), lambda: app.apply_look(image=""), CARD, FG, LINE,
                    width=150, height=34, parent_bg=BG).pack(side="left")

        sc_kw = dict(orient="horizontal", length=410, bg=BG, fg=FG, troughcolor=CARD,
                     highlightthickness=0, bd=0, activebackground=ACCENT, font=("Segoe UI", 9))
        tk.Label(w, text=t("ap_blur").upper(), **lab).pack(anchor="w", padx=18, pady=(10, 0))
        self.sc = tk.Scale(w, from_=0, to=30, **sc_kw)
        self.sc.set(app.bg_blur)
        self.sc.pack(anchor="w", padx=18)
        self.sc.bind("<ButtonRelease-1>", lambda e: app.apply_look(blur=int(self.sc.get())))

        tk.Label(w, text=t("ap_opacity").upper(), **lab).pack(anchor="w", padx=18, pady=(10, 0))
        self.op = tk.Scale(w, from_=40, to=100, **sc_kw)
        self.op.set(app.ui_opacity)
        self.op.config(command=lambda v: app.set_opacity(int(float(v)), save=False))
        self.op.pack(anchor="w", padx=18)
        self.op.bind("<ButtonRelease-1>", lambda e: app.set_opacity(int(self.op.get())))
        tk.Label(w, text=t("ap_hint") + "\n" + t("ap_opacity_hint"), bg=BG, fg=MUTED,
                 font=("Segoe UI", 8), wraplength=420, justify="left").pack(anchor="w", padx=18, pady=(4, 0))
        rec = tk.Frame(w, bg=BG)
        rec.pack(anchor="w", padx=18, pady=(12, 0))
        tk.Label(rec, text=t("ap_reco"), bg=BG, fg=ACCENT, font=("Segoe UI", 9, "bold"),
                 justify="left").pack(side="left", padx=(0, 12))
        RoundButton(rec, t("ap_reco_btn"), self.apply_reco, CARD, FG, LINE, width=100, height=28,
                    font=("Segoe UI", 8, "bold"), parent_bg=BG).pack(side="left")
        if not PIL_OK:
            tk.Label(w, text=f"Pillow: {PIL_ERR}\nPython: {sys.executable}", bg=BG, fg=AMBER,
                     font=("Segoe UI", 8), wraplength=420, justify="left").pack(anchor="w", padx=18, pady=(8, 4))
            self.inst_btn = RoundButton(w, t("ap_install"), self.install_pil, ACCENT2, "#ffffff",
                                        HOVER2, width=170, height=34, parent_bg=BG)
            self.inst_btn.pack(anchor="w", padx=18)
        bot = tk.Frame(w, bg=BG)
        bot.pack(fill="x", side="bottom", padx=18, pady=14)
        RoundButton(bot, t("close"), w.destroy, CARD, FG, LINE, width=90, height=34,
                    parent_bg=BG).pack(side="right")

    def _alive(self):
        try:
            return self.win.winfo_exists()
        except tk.TclError:
            return False

    def install_pil(self):
        app = self.app
        t = app.t
        self.inst_btn.set_text(t("ap_installing"))
        self.inst_btn.set_enabled(False)

        def done(ok, out):
            parent = self.win if self._alive() else app.root
            if ok and try_import_pil():
                messagebox.showinfo("Slave", t("ap_install_ok"), parent=parent)
                app.apply_look()
            else:
                if self._alive():
                    self.inst_btn.set_text(t("ap_install"))
                    self.inst_btn.set_enabled(True)
                messagebox.showerror("Slave", t("ap_install_fail", out or PIL_ERR), parent=parent)

        def work():
            try:
                r = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pillow"],
                                   capture_output=True, text=True, timeout=300, creationflags=NOWIN)
                ok, out = r.returncode == 0, (r.stdout + r.stderr).strip()[-600:]
            except Exception as e:
                ok, out = False, str(e)
            app.root.after(0, done, ok, out)

        threading.Thread(target=work, daemon=True).start()

    def apply_reco(self):
        app = self.app
        app.ui_opacity = 90
        app._init_glass()
        app.apply_look(blur=2)      # saves and rebuilds the interface

    def pick(self):
        t = self.app.t
        if not PIL_OK:
            if messagebox.askyesno("Slave", t("ap_need_pil", sys.executable, PIL_ERR), parent=self.win):
                self.install_pil()
            return
        fn = filedialog.askopenfilename(
            parent=self.win, filetypes=[(t("img_type"), "*.png *.jpg *.jpeg *.bmp *.gif *.webp"), ("*", "*.*")])
        if fn:
            self.app.apply_look(image=fn)


# ---- Win32 helpers for the opacity veil (explicit argtypes: 64-bit safe) ----
_U32 = {}


def _user32():
    """user32 with proper prototypes. Without argtypes a 64-bit HWND is truncated to 32 bits."""
    if _U32:
        return _U32["u"]
    u = ctypes.WinDLL("user32", use_last_error=True)
    u.GetParent.restype = ctypes.c_void_p
    u.GetParent.argtypes = [ctypes.c_void_p]
    u.GetAncestor.restype = ctypes.c_void_p
    u.GetAncestor.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    u.GetWindowLongW.restype = ctypes.c_long
    u.GetWindowLongW.argtypes = [ctypes.c_void_p, ctypes.c_int]
    u.SetWindowLongW.restype = ctypes.c_long
    u.SetWindowLongW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long]
    u.SetWindowPos.restype = ctypes.c_int
    u.SetWindowPos.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    u.SetLayeredWindowAttributes.restype = ctypes.c_int
    u.SetLayeredWindowAttributes.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_ubyte, ctypes.c_uint32]
    _U32["u"] = u
    return u


class Veil:
    """Click-through translucent window that lays the (brighter, blurred) background image over
    the UI. Image over UI at alpha a == UI at opacity (1-a) over the image.
    The alpha and the click-through style are applied with the Win32 API directly (not only
    through Tk's -alpha), and the veil also works while the main window is maximized."""
    MAX_ALPHA = 0.72

    def __init__(self, app):
        self.app = app
        self.win = self.label = self.photo = None
        self._err_logged = False

    def _fail(self, e):
        if not self._err_logged:
            self._err_logged = True
            try:
                self.app.dlog_raw("ERROR", f"veil: {type(e).__name__}: {e}")
            except Exception:
                pass

    def _create(self):
        w = tk.Toplevel(self.app.root)
        w.withdraw()
        w.overrideredirect(True)
        w.transient(self.app.root)
        w.configure(bg=BG)
        self.label = tk.Label(w, bd=0, highlightthickness=0, bg=BG, anchor="nw")
        self.label.pack(fill="both", expand=True)
        w.geometry("1x1+0+0")
        w.update_idletasks()
        self.win = w

    def _hwnd(self):
        u = _user32()
        child = self.win.winfo_id()
        top = u.GetAncestor(child, 2)          # GA_ROOT: the real top-level (Tk wrapper) window
        return top or u.GetParent(child) or child

    def _native(self, alpha):
        """Layered + click-through + no-activate, then the alpha, straight through Win32."""
        if os.name != "nt" or self.win is None:
            return
        u = _user32()
        hwnd = self._hwnd()
        st = u.GetWindowLongW(hwnd, -20)       # GWL_EXSTYLE
        want = st | 0x80000 | 0x20 | 0x80 | 0x8000000   # layered, transparent (click-through), toolwindow, noactivate
        if want != st:
            u.SetWindowLongW(hwnd, -20, want)
            # SWP_NOSIZE | NOMOVE | NOZORDER | NOACTIVATE | FRAMECHANGED
            u.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020)
        u.SetLayeredWindowAttributes(hwnd, 0, max(1, min(255, int(alpha * 255))), 0x2)   # LWA_ALPHA

    def hide(self):
        if self.win is not None:
            try:
                self.win.withdraw()
            except tk.TclError:
                pass

    def sync(self):
        app = self.app
        try:
            try:
                state = app.root.state()
            except tk.TclError:
                return
            show = (app.bg_on and app.ui_opacity < 100 and app._veil_photo is not None
                    and state in ("normal", "zoomed"))
            if not show:
                self.hide()
                return
            main = app.main
            W, H = main.winfo_width(), main.winfo_height()
            if W < 20 or H < 20:
                self.hide()
                return
            if self.win is None:
                self._create()
            if self.photo is not app._veil_photo:
                self.photo = app._veil_photo
                self.label.config(image=self.photo)
            alpha = min(self.MAX_ALPHA, self.MAX_ALPHA * (100 - app.ui_opacity) / 60.0)
            self.win.geometry(f"{W}x{H}+{main.winfo_rootx()}+{main.winfo_rooty()}")
            set_alpha(self.win, alpha)
            if self.win.state() == "withdrawn":
                self.win.deiconify()
            self.win.update_idletasks()
            self._native(alpha)
        except tk.TclError:
            pass
        except Exception as e:
            self._fail(e)


class Glass:
    # Frosted-glass backdrop. In glass mode every panel/card colour of the UI is the colour key
    # GLASS_KEY, which Windows renders fully transparent. This borderless window sits directly
    # BEHIND the main window and shows through those transparent parts:
    #   - with a background image: the blurred image, tinted toward the panel colour
    #   - without an image: a solid panel-coloured sheet whose own alpha lets the desktop through
    # Text, buttons and lines are drawn by the main window and stay 100% opaque.
    def __init__(self, app):
        self.app = app
        self.win = self.label = self.photo = None
        self._base = self._base_key = self._pkey = self._geo = self._job = None
        self._last = 0.0
        self._err = False

    def _fail(self, e):
        if self._err:
            return
        self._err = True
        try:
            self.app.dlog_raw("ERROR", f"glass: {type(e).__name__}: {e}")
        except Exception:
            pass
        try:
            self.app.root.attributes("-transparentcolor", "")
        except tk.TclError:
            pass
        self.hide()

    def _hwnd(self):
        u = _user32()
        child = self.win.winfo_id()
        return u.GetAncestor(child, 2) or u.GetParent(child) or child

    def _create(self):
        w = tk.Toplevel(self.app.root)
        w.withdraw()
        w.overrideredirect(True)
        self.label = tk.Label(w, bd=0, highlightthickness=0, anchor="nw")
        self.label.pack(fill="both", expand=True)
        w.geometry("1x1+0+0")
        w.update_idletasks()
        self.win = w
        u = _user32()
        h = self._hwnd()
        st = u.GetWindowLongW(h, -20)                      # GWL_EXSTYLE
        u.SetWindowLongW(h, -20, st | 0x08000000 | 0x80)   # NOACTIVATE | TOOLWINDOW (no taskbar button)
        u.SetWindowPos(h, None, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020)

    def hide(self):
        if self.win is not None:
            try:
                self.win.withdraw()
            except tk.TclError:
                pass

    def zsync(self):
        # keep this window directly below the main window in the z-order
        if self.win is None or self._err:
            return
        try:
            if self.win.state() == "withdrawn":
                return
            u = _user32()
            root_h = u.GetAncestor(self.app.root.winfo_id(), 2)
            if root_h:
                u.SetWindowPos(self._hwnd(), root_h, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0010)
        except tk.TclError:
            pass
        except Exception as e:
            self._fail(e)

    def _make_base(self, W, H):
        app = self.app
        img = app._src
        iw, ih = img.size
        s = max(W / iw, H / ih)
        img = img.resize((max(W, int(iw * s) + 1), max(H, int(ih * s) + 1)),
                         getattr(Image, "Resampling", Image).LANCZOS)
        l, tp = (img.width - W) // 2, (img.height - H) // 2
        img = img.crop((l, tp, l + W, tp + H))
        if app.bg_blur > 0:
            img = img.filter(ImageFilter.GaussianBlur(app.bg_blur))
        return img

    def _later(self):
        if self._job is None:
            self._job = self.app.root.after(260, self._run_job)

    def _run_job(self):
        self._job = None
        self.sync()

    def _paint(self, W, H):
        app = self.app
        tint = THEMES.get(app.theme, THEMES["blue"])["PANEL"]
        use_img = bool(PIL_OK and app.bg_on and app._src is not None)
        if not use_img:
            self.photo = self._pkey = None
            self.label.config(image="", bg=tint)
            set_alpha(self.win, max(0.15, app.ui_opacity / 100.0))
            return
        set_alpha(self.win, 1.0)
        bkey = (app._src_path, app.bg_blur, W, H)
        if bkey != self._base_key:
            now = time.time()
            if self._base is not None and now - self._last < 0.25:
                self._later()
                return
            self._base, self._base_key, self._last = self._make_base(W, H), bkey, now
        t = max(0.0, min(1.0, (app.ui_opacity - 40) / 60.0))
        p = round(0.2 + 0.8 * t, 2)
        pkey = (bkey, p, tint)
        if pkey != self._pkey:
            img = Image.blend(self._base, Image.new("RGB", self._base.size, tint), p)
            self.photo = ImageTk.PhotoImage(img)
            self.label.config(image=self.photo, bg=tint)
            self._pkey = pkey

    def sync(self):
        app = self.app
        if self._err:
            return
        try:
            if not app.glass or os.name != "nt":
                self.hide()
                return
            try:
                state = app.root.state()
            except tk.TclError:
                return
            if state not in ("normal", "zoomed"):
                self.hide()
                return
            root = app.root
            W, H = root.winfo_width(), root.winfo_height()
            if W < 50 or H < 50:
                self.hide()
                return
            if self.win is None:
                self._create()
            geo = f"{W}x{H}+{root.winfo_rootx()}+{root.winfo_rooty()}"
            if geo != self._geo:
                self._geo = geo
                self.win.geometry(geo)
            self._paint(W, H)
            if self.win.state() == "withdrawn":
                had_focus = root.focus_displayof() is not None
                self.win.deiconify()
                self.win.update_idletasks()
                self.zsync()
                if had_focus:
                    root.focus_force()
            else:
                self.zsync()
        except tk.TclError:
            pass
        except Exception as e:
            self._fail(e)


# ============================== MAIN APP ==============================
KW_X = dict(fill="x", padx=12, pady=(10, 0))
KW_EXP = dict(fill="both", expand=True, padx=12, pady=(10, 0))
KW_BAR = dict(fill="x", padx=12, pady=10)
BLOB_SPECS = [
    (0.20, 0.30, 0.10, 0.08, 0.21, 0.17, 0.0, 260),
    (0.75, 0.25, 0.08, 0.12, 0.15, 0.23, 1.7, 300),
    (0.55, 0.75, 0.12, 0.08, 0.19, 0.13, 3.1, 280),
    (0.90, 0.80, 0.07, 0.10, 0.25, 0.20, 4.4, 220),
    (0.35, 0.90, 0.09, 0.07, 0.17, 0.27, 5.2, 200),
]
BLOB_RINGS = 8
RISK_METHODS = ("browse", "data", "trace", "session", "usn", "newexe", "memory",
                "roblox", "forensic", "boot")
# status logo (small version of the splash logo): radius, line width, extent, speed (deg/s)
ORB_ARCS = ((14, 2, 110, 200), (10, 2, 80, -140), (6, 1, 140, 90))


class SlaveApp:
    PW = 400
    guns_proc = None

    def __init__(self, root, nick=""):
        self.root = root
        root.title("Slave v" + VERSION)
        height = max(640, min(900, root.winfo_screenheight() - 90))
        root.geometry(f"1200x{height}")
        root.minsize(900, 620)

        cfg = load_config()
        self.nick = (nick or cfg.get("nick") or "user").strip()[:NICK_MAX] or "user"
        self.lang = cfg.get("lang") if cfg.get("lang") in LANGS else sys_lang()
        self.theme = cfg.get("theme") if cfg.get("theme") in THEMES else "blue"
        set_theme(self.theme)
        root.configure(bg=BG)
        self.bg_image = ""  # her açılışta sıfırlanır: görsel yok
        try:
            self.bg_blur = 0  # her açılışta sıfırlanır: blur 0
        except (TypeError, ValueError):
            self.bg_blur = 0  # (hata durumunda da 0)
        try:
            self.ui_opacity = 100  # her açılışta sıfırlanır: opaklık 100
        except (TypeError, ValueError):
            self.ui_opacity = 100
        self._init_glass()
        self._tr = []

        tools = cfg.get("tools") if isinstance(cfg.get("tools"), dict) else {}
        self.bcfg = ToolCfg(self, "browse", DEFAULT_NAMES, tools.get("browse"))
        self.dcfg = ToolCfg(self, "data", DEFAULT_NAMES, tools.get("data"))
        self.tcfg = ToolCfg(self, "trace", DEFAULT_NAMES, tools.get("trace"))
        self.pcfg = ToolCfg(self, "persist", DEFAULT_NAMES, tools.get("persist"))
        self.fcfg = ToolCfg(self, "forensic", DEFAULT_NAMES, tools.get("forensic"))
        self.bcfg.on_load = self._b_loaded
        self.dcfg.on_load = self.dcfg.on_toggle = self._d_render
        self.tcfg.on_load = self.tcfg.on_toggle = self._t_render
        self.pcfg.on_load = self.pcfg.on_toggle = self._p_render
        self.fcfg.on_load = self.fcfg.on_toggle = self._f_render
        self.temp = []

        self.results, self.row_path, self.chips = {}, {}, {}
        self.filter = None
        self.scanning = self.stop = False
        self.status = ("status_ready",)
        self.engine = "—"
        self.log_lines = []
        self.logs_open = False
        self._log_w = 0
        self._slide_id = 0
        self._t0 = time.time()
        self._orb_last = time.time()
        self._orb_ang = [0.0, 0.0, 0.0]
        self.notice_state = self.d_notice_state = self.t_notice_state = self.p_notice_state = None
        self.f_notice_state = None
        self.page = "browse"
        self.data_rows, self.data_live_rows, self.data_busy = [], [], False
        self.trace_rows, self.trace_busy = [], False
        self.persist_rows, self.persist_busy, self.roblox_n = [], False, None
        self.session_state, self.session_rows = "idle", []
        self.session_count, self.session_source = 0, ""
        self.session_presence = []
        self.method_data = {
            key: {"rows": [], "status": "", "busy": False, "error": ""}
            for key in ("usn", "newexe", "memory")
        }
        self.forensic_rows, self.forensic_busy = [], False
        self.boot_rows, self.boot_busy = [], False
        self.dsort = ("total", True)
        self.var_whole = tk.BooleanVar(value=bool(cfg.get("whole", False)))
        self.var_sys = tk.BooleanVar(value=bool(cfg.get("hide_sys", True)))
        self.var_dauto = tk.BooleanVar(value=False)
        self.var_donly = tk.BooleanVar(value=bool(cfg.get("data_only_list", False)))

        self.ap_dialog = None
        self._bg_job = self._bg_key = self._bg_photo = self._src_path = self._src = None
        self._veil_photo = None
        self.bg_on = False
        self.veil = Glass(self)

        # risk engine state
        self.r_result, self.r_shown = None, 0.0
        self.r_busy = self.r_wait = False
        self.r_generation = 0
        self.r_sel = []
        self.r_have = {k: False for k in RISK_METHODS}
        self.rm = {k: tk.BooleanVar(value=True) for k in RISK_METHODS}

        self._build_ui()
        root.bind("<Configure>", self._root_cfg, add="+")
        root.bind("<Unmap>", lambda e: e.widget is root and self.veil.hide(), add="+")
        root.bind("<Map>", lambda e: e.widget is root and root.after(60, self.veil.sync), add="+")
        root.bind("<FocusIn>", lambda e: e.widget is root and self.veil.zsync(), add="+")
        self._animate()
        self.root.after(AUTO_SECONDS * 1000, self._d_auto_tick)

    # ---------- basics ----------
    @property
    def names(self):
        return self.bcfg.names

    @property
    def enabled(self):
        return self.bcfg.enabled

    def ck(self, bg):
        return dict(bg=bg, fg=MUTED, selectcolor=CARD, activebackground=bg, activeforeground=FG,
                    font=("Segoe UI", 9), highlightthickness=0, bd=0, cursor="hand2")

    def t(self, key, *a):
        return tx(self.lang, key, *a)

    def reg(self, fn):
        self._tr.append(fn)
        fn()

    def apply_lang(self):
        for fn in self._tr:
            fn()
        self._refresh_scan_btn()
        for code, b in self.btn_lang.items():
            if code == self.lang:
                b.set_colors(ACCENT2, "#ffffff", HOVER2)
            else:
                b.set_colors(CARD, MUTED, LINE)
        for state, lbl in ((self.notice_state, "notice"), (self.d_notice_state, "dnotice"),
                           (self.t_notice_state, "tnotice"), (self.p_notice_state, "pnotice"),
                           (self.f_notice_state, "fnotice")):
            if state:
                getattr(self, lbl).config(text=self.t(state[0]), fg=state[1])
        self._render()
        self._d_render()
        self._t_render()
        self._p_render()
        self._f_render()
        self._r_render()

    def set_lang(self, code):
        self.lang = code
        self.apply_lang()
        self.save_config()

    def _refresh_scan_btn(self):
        if self.scanning:
            self.btn_scan.set_text(self.t("stop"))
            self.btn_scan.set_colors(DANGER, RED, DANGER_H)
        else:
            self.btn_scan.set_text(self.t("scan"))
            self.btn_scan.set_colors(ACCENT, ONACC, HOVER)

    def save_config(self):
        data = {
            "lang": self.lang, "theme": self.theme,  # (görsel kaydedilmez)
            "nick": self.nick,  # (blur / opaklık kaydedilmez)
            "tools": {"browse": self.bcfg.data_out(), "data": self.dcfg.data_out(),
                      "trace": self.tcfg.data_out(), "persist": self.pcfg.data_out(),
                      "forensic": self.fcfg.data_out()},
            "whole": self.var_whole.get(), "hide_sys": self.var_sys.get(),
            "data_only_list": self.var_donly.get(),
        }
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ---------- build / look ----------
    def _build_ui(self):
        self._tr = []
        self.chips = {}
        self.page_cards = {}
        self.bg_on = False
        self._bg_key = None
        self.root.configure(bg=BG)
        self._build_style()
        self._build_logpanel()
        self._build_bgitems()
        self._build_header()
        self._build_tabs()
        self._build_browse()
        self._build_data()
        self._build_trace()
        self._build_persist()
        self._build_session()
        self._build_method_page("usn")
        self._build_method_page("newexe")
        self._build_method_page("memory")
        self._build_forensic()
        self._build_risk()
        self._build_credits()
        self.apply_lang()
        self.show_page(self.page)
        if self.notice_state:
            self._show_notice(*self.notice_state)
        if self.d_notice_state:
            self._d_show_notice(*self.d_notice_state)
        if self.t_notice_state:
            self._t_show_notice(*self.t_notice_state)
        if self.p_notice_state:
            self._p_show_notice(*self.p_notice_state)
        if self.f_notice_state:
            self._f_show_notice(*self.f_notice_state)
        if self.logs_open:
            self.btn_logs.set_text("Logs", FG)
        self.main.bind("<Configure>", self._on_main_cfg)
        self.root.after(60, self._load_bg)

    def rebuild(self):
        self.logpanel.destroy()
        self.main.destroy()
        self._build_ui()

    def apply_look(self, theme=None, image=None, blur=None):
        if theme is not None:
            self.theme = theme
            set_theme(theme)
        if image is not None:
            self.bg_image = image
        if blur is not None:
            self.bg_blur = blur
        self.save_config()
        geo = None
        if self.ap_dialog and self.ap_dialog.win.winfo_exists():
            geo = self.ap_dialog.win.geometry()
            self.ap_dialog.win.destroy()
        self.rebuild()
        self.dlog("INFO", "log_look")
        if geo:
            self.open_appearance(geo)

    def _init_glass(self):
        # glass mode = interface opacity below 100 (Windows only)
        global GLASS
        GLASS = os.name == "nt" and self.ui_opacity < 100
        self.glass = GLASS
        set_theme(self.theme)
        try:
            self.root.configure(bg=BG)
            self.root.attributes("-transparentcolor", GLASS_KEY if GLASS else "")
        except tk.TclError:
            pass

    def set_opacity(self, value, save=True):
        self.ui_opacity = max(40, min(100, int(value)))
        if save:
            self.save_config()
            if (self.ui_opacity < 100) != self.glass:
                self._init_glass()
                self.apply_look()      # rebuild the UI with / without the glass colours
                return
        self.veil.sync()

    def _apply_win_alpha(self):
        set_alpha(self.root, 1.0)

    def _glass_items(self):
        # in glass mode the backdrop window shows the picture, so the canvas draws nothing itself
        if self.glass:
            self.main.itemconfig(self.bg_item, state="hidden")
            for ids in self.blobs:
                for oid in ids:
                    self.main.itemconfig(oid, state="hidden")

    def open_appearance(self, geo=None):
        if self.ap_dialog and self.ap_dialog.win.winfo_exists():
            self.ap_dialog.win.lift()
            return
        self.ap_dialog = AppearanceDialog(self, geo if isinstance(geo, str) else None)

    def _build_style(self):
        st = ttk.Style(self.root)
        st.theme_use("clam")
        st.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=FG,
                     rowheight=28, borderwidth=0, font=("Segoe UI", 10))
        st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        st.configure("Treeview.Heading", background=PANEL, foreground=MUTED, relief="flat",
                     font=("Segoe UI", 9, "bold"), borderwidth=0, padding=(8, 6))
        st.map("Treeview", background=[("selected", SEL)], foreground=[("selected", FG)])
        st.map("Treeview.Heading", background=[("active", PANEL)])
        st.configure("Vertical.TScrollbar", background=LINE, troughcolor=PANEL, bordercolor=PANEL,
                     arrowcolor=MUTED, lightcolor=LINE, darkcolor=LINE)
        st.configure("Dark.TCombobox", fieldbackground=CARD, background=LINE, foreground=FG,
                     arrowcolor=MUTED, bordercolor=LINE, lightcolor=CARD, darkcolor=CARD,
                     selectbackground=CARD, selectforeground=FG)
        st.map("Dark.TCombobox", fieldbackground=[("readonly", CARD)], foreground=[("readonly", FG)],
               selectbackground=[("readonly", CARD)], selectforeground=[("readonly", FG)])
        self.root.option_add("*TCombobox*Listbox.background", CARD)
        self.root.option_add("*TCombobox*Listbox.foreground", FG)
        self.root.option_add("*TCombobox*Listbox.selectBackground", SEL)
        self.root.option_add("*TCombobox*Listbox.selectForeground", FG)

    def _build_bgitems(self):
        cv = self.main
        self.bg_item = cv.create_image(0, 0, anchor="nw")
        self.blobs = []

    def _root_cfg(self, e):
        if e.widget is self.root:
            self.root.after_idle(self.veil.sync)

    def _on_main_cfg(self, e):
        if e.widget is not self.main:
            return
        if self._bg_job:
            try:
                self.root.after_cancel(self._bg_job)
            except Exception:
                pass
        self._bg_job = self.root.after(130, self._load_bg)

    def _load_bg(self):
        self._bg_job = None
        cv = self.main
        W, H = cv.winfo_width(), cv.winfo_height()
        if W < 20 or H < 20:
            return
        path = self.bg_image
        use = bool(path) and PIL_OK and os.path.isfile(path)
        if use:
            key = (path, self.bg_blur, W, H, BG)
            if key != self._bg_key:
                try:
                    self._bg_photo = self._make_bg(path, W, H)
                    self._bg_key = key
                except Exception as e:
                    self.dlog_raw("ERROR", f"background: {e}")
                    use = False
        self.bg_on = use
        if use:
            cv.itemconfig(self.bg_item, image=self._bg_photo, state="normal")
        else:
            cv.itemconfig(self.bg_item, state="hidden")
        for ids in self.blobs:
            for oid in ids:
                cv.itemconfig(oid, state="hidden" if use else "normal")
        self._apply_win_alpha()
        self._glass_items()
        self.veil.sync()

    def _make_bg(self, path, W, H):
        if self._src_path != path:
            img = Image.open(path).convert("RGB")
            img.thumbnail((2400, 2400))
            self._src, self._src_path = img, path
        img = self._src
        iw, ih = img.size
        s = max(W / iw, H / ih)
        img = img.resize((max(W, int(iw * s) + 1), max(H, int(ih * s) + 1)),
                         getattr(Image, "Resampling", Image).LANCZOS)
        l, tp = (img.width - W) // 2, (img.height - H) // 2
        img = img.crop((l, tp, l + W, tp + H))
        if self.bg_blur > 0:
            img = img.filter(ImageFilter.GaussianBlur(self.bg_blur))
        # brighter copy used by the opacity veil (lighter tint so it shows clearly through the UI)
        self._veil_photo = ImageTk.PhotoImage(Image.blend(img, Image.new("RGB", (W, H), BG), 0.15))
        img = Image.blend(img, Image.new("RGB", (W, H), BG), 0.35)
        return ImageTk.PhotoImage(img)

    def _build_header(self):
        self.hdr = tk.Canvas(self.main, height=64, bg=PANEL, highlightthickness=0)
        self.hdr.pack(fill="x", padx=12, pady=(12, 0))
        # Original compact status mark: layered rings, three rotating arcs, and a pulsing center.
        ox, oy = 34, 32
        self.orb_glow = self.hdr.create_oval(0, 0, 0, 0, fill=PANEL, outline="")
        self.orb_arcs = [self.hdr.create_arc(ox-r, oy-r, ox+r, oy+r, start=0, extent=extent,
                                             style="arc", outline=GREEN, width=width)
                         for r, width, extent, _speed in ORB_ARCS]
        self.orb = self.hdr.create_oval(ox-2.5, oy-2.5, ox+2.5, oy+2.5, fill=GREEN, outline="")
        self.hdr.create_text(62, 24, text="SLAVE", anchor="w", fill=FG,
                             font=("Segoe UI", 14, "bold"))
        self.hdr.create_text(125, 27, text="VERSION 2.0", anchor="w", fill=MUTED,
                             font=("Segoe UI", 8, "bold"))
        self.sub_txt = self.hdr.create_text(62, 46, text="", anchor="w", fill=MUTED, font=("Segoe UI", 9))
        self.user_txt = self.hdr.create_text(0, 8, anchor="e", text=f'User: "{self.nick}"',
                                             fill=ACCENT, font=("Segoe UI", 8, "bold"))
        self.btn_scan = RoundButton(self.hdr, "", self.toggle_scan, ACCENT, ONACC, HOVER, width=92, height=32)
        self.btn_logs = RoundButton(self.hdr, "Logs", self.toggle_logs, CARD, FG, LINE, width=76, height=32)
        self.btn_look = RoundButton(self.hdr, "Style", self.open_appearance, CARD, FG, LINE,
                                    width=64, height=30, font=("Segoe UI", 9, "bold"))
        self.w_scan = self.hdr.create_window(0, 36, window=self.btn_scan, anchor="e")
        self.w_logs = self.hdr.create_window(0, 36, window=self.btn_logs, anchor="e")
        self.w_look = self.hdr.create_window(0, 36, window=self.btn_look, anchor="e")
        self.btn_lang, self.w_lang = {}, {}
        for code in LANGS:
            b = RoundButton(self.hdr, code.upper(), lambda c=code: self.set_lang(c), CARD, MUTED,
                            LINE, width=44, height=30, font=("Segoe UI", 9, "bold"))
            self.btn_lang[code] = b
            self.w_lang[code] = self.hdr.create_window(0, 36, window=b, anchor="e")
        self.hdr.bind("<Configure>", self._layout_header)

    def _layout_header(self, e):
        x = e.width - 16
        self.hdr.coords(self.user_txt, x, 9)
        self.hdr.coords(self.w_scan, x, 36)
        x -= 92 + 10
        self.hdr.coords(self.w_logs, x, 36)
        x -= 76 + 8
        self.hdr.coords(self.w_look, x, 36)
        x -= 64 + 16
        for i, code in enumerate(LANGS):
            self.hdr.coords(self.w_lang[code], x - (len(LANGS) - 1 - i) * 50, 36)

    def _build_tabs(self):
        tabs = tk.Frame(self.main, bg=PANEL)
        tabs.pack(fill="x", padx=16, pady=(8, 0))
        self.tab_btn = {}
        items = (("browse", 116), ("data", 140), ("trace", 96), ("persist", 116),
                 ("session", 136), ("usn", 116), ("newexe", 168), ("memory", 120),
                 ("forensic", 110), ("risk", 116), ("credits", 96))
        for i, (key, width) in enumerate(items):
            button = RoundButton(tabs, "", lambda k=key: self.show_page(k), CARD, MUTED, LINE,
                                 width=width, height=32, font=("Segoe UI", 9), parent_bg=PANEL)
            button.grid(row=i // 8, column=i % 8, padx=6, pady=5, sticky="w")
            self.tab_btn[key] = button
            self.reg(lambda b=button, k=key: b.set_text(self.t("tab_" + k)))

    def show_page(self, key):
        self.page = key
        if key != "credits":
            self.close_guns()
        for pages in self.page_cards.values():
            for widget, _ in pages:
                widget.pack_forget()
        for widget, options in self.page_cards[key]:
            widget.pack(**options)
        for name, button in self.tab_btn.items():
            button.set_colors(ACCENT if name == key else CARD,
                              ONACC if name == key else MUTED,
                              HOVER if name == key else LINE)
        if key == "data" and not self.data_rows and not self.data_busy:
            self.d_refresh()

    # ---------- Browse page ----------
    def _build_browse(self):
        cA = tk.Frame(self.main, bg=PANEL)
        self.bcfg.build_ui(cA)

        cB = tk.Frame(self.main, bg=PANEL)
        self.chips_fr = tk.Frame(cB, bg=PANEL)
        self.chips_fr.pack(fill="x", padx=12, pady=(10, 4))
        row = tk.Frame(cB, bg=PANEL)
        row.pack(fill="x", padx=12, pady=(6, 2))
        self.entry = tk.Entry(row, bg=CARD, fg=FG, insertbackground=FG, relief="flat",
                              font=("Segoe UI", 10), highlightthickness=1,
                              highlightbackground=LINE, highlightcolor=ACCENT)
        self.entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.entry.bind("<Return>", lambda e: self.quick_search())
        b = RoundButton(row, "", self.quick_search, ACCENT, ONACC, HOVER, width=100, height=32, parent_bg=PANEL)
        b.pack(side="left")
        self.reg(lambda: b.set_text(self.t("search")))
        hint = tk.Label(cB, bg=PANEL, fg=MUTED, font=("Segoe UI", 8), anchor="w", justify="left", wraplength=950)
        hint.pack(fill="x", padx=14)
        self.reg(lambda: hint.config(text=self.t("entry_hint")))
        opts = tk.Frame(cB, bg=PANEL)
        opts.pack(fill="x", padx=12, pady=(6, 10))
        c1 = tk.Checkbutton(opts, variable=self.var_sys, command=self._sys_changed, **self.ck(PANEL))
        c1.pack(side="left")
        c2 = tk.Checkbutton(opts, variable=self.var_whole, command=self._whole_changed, **self.ck(PANEL))
        c2.pack(side="left", padx=16)
        self.reg(lambda: c1.config(text=self.t("ck_sys")))
        self.reg(lambda: c2.config(text=self.t("ck_whole")))

        self.tree_fr = tk.Frame(self.main, bg=PANEL)
        inner = tk.Frame(self.tree_fr, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=8, pady=8)
        cols = ("kw", "name", "path", "size", "date")
        self.tree = ttk.Treeview(inner, columns=cols, show="headings", selectmode="browse")
        for c, w, anchor in (("kw", 80, "w"), ("name", 210, "w"), ("path", 400, "w"),
                             ("size", 80, "e"), ("date", 130, "w")):
            self.tree.heading(c, text=c, anchor=anchor)
            self.tree.column(c, width=w, anchor=anchor, stretch=(c == "path"))
        self.reg(lambda: [self.tree.heading(c, text=self.t("col_" + c)) for c in cols])
        self.tree.tag_configure("odd", background=ROW_ALT)
        self.tree.tag_configure("even", background=CARD)
        sb = ttk.Scrollbar(inner, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.show_in_folder())
        self.notice = tk.Label(self.tree_fr, bg=CARD, fg=MUTED, font=("Segoe UI", 11), justify="center")

        bar = tk.Frame(self.main, bg=PANEL, height=64)
        bar.pack_propagate(False)
        for key, cmd, w in (("show", self.show_in_folder, 158), ("copy_path", self.copy_path, 150),
                            ("export", self.export_txt, 132)):
            b = RoundButton(bar, "", cmd, CARD, FG, LINE, width=w, height=36)
            b.pack(side="left", padx=(14, 0))
            self.reg(lambda b=b, k=key: b.set_text(self.t(k)))
        self.summary = tk.Label(bar, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10))
        self.summary.pack(side="right", padx=16)

        self.page_cards["browse"] = [(cA, KW_X), (cB, KW_X), (self.tree_fr, KW_EXP), (bar, KW_BAR)]
        self._build_chips()

    def _b_loaded(self):
        self.temp, self.results, self.filter = [], {}, None
        self.r_have["browse"] = False
        self._hide_notice()
        self._build_chips()
        self._render()

    def _build_chips(self):
        for w in self.chips_fr.winfo_children():
            w.destroy()
        self.chips = {}
        items = []
        for name in self.names + self.temp:
            b = RoundButton(self.chips_fr, name, lambda n=name: self.set_filter(n), CARD, MUTED, LINE,
                            width=136, height=28, font=("Segoe UI", 9, "bold"), parent_bg=PANEL)
            self.chips[name] = b
            items.append(b)
        flow_layout(self.chips_fr, items, 144, padx=8)
        self._render()

    def quick_search(self):
        terms = []
        for s in split_names(self.entry.get()):
            s = next((n for n in self.names if n.lower() == s.lower()), s)
            if not any(s.lower() == o.lower() for o in terms):
                terms.append(s)
        if not terms:
            return
        if self.scanning:
            self.dlog("WARN", "log_busy")
            return
        self.temp = [x for x in terms if x not in self.names]
        self.entry.delete(0, "end")
        self.filter = None
        self._build_chips()
        self.dlog("INFO", "log_quick", ", ".join(terms))
        self.start_scan(names=terms)

    def _whole_changed(self):
        self.save_config()
        if not self.scanning:
            self.start_scan()

    def _sys_changed(self):
        self.save_config()
        self._render()

    def start_scan(self, names=None):
        if self.scanning:
            return
        if names is None:
            if self.temp:
                self.temp = []
                self._build_chips()
            names = self.bcfg.active_names()
        if not names:
            self.results = {}
            self._render()
            self._show_notice("notice_none", AMBER)
            self.dlog("WARN", "log_skip")
            return
        self.scanning, self.stop = True, False
        self.r_have["browse"] = False
        self.results = {}
        self.filter = None
        self._hide_notice()
        self._render()
        self._refresh_scan_btn()
        threading.Thread(target=self._scan_worker, args=(self.var_whole.get(), names), daemon=True).start()

    def _scan_worker(self, whole, names):
        es = find_es()
        self.dlog_raw("INFO", self.t("log_scan_start", ", ".join(names)) + (self.t("log_whole") if whole else ""))
        self.dlog("INFO", "log_es", es or self.t("log_es_none"))
        failed = False
        for i, name in enumerate(names, 1):
            if self.stop:
                self.dlog("WARN", "log_stopped")
                break
            self.status = ("status_scanning", name, i, len(names))
            self.dlog("TOOL", "log_searching", name)
            t0 = time.time()
            try:
                paths, engine = search_everything(name, whole)
            except EverythingError as e:
                self.dlog_raw("ERROR", f"{name}: {e}")
                if i == 1:
                    failed = True
                    self.root.after(0, self._show_notice, "notice_setup", AMBER)
                    break
                continue
            except Exception as e:
                self.dlog("ERROR", "log_unexpected", name, repr(e))
                continue
            infos = [(p, *file_info(p)) for p in paths]
            self.dlog("OK", "log_found", name, len(paths), f"{time.time() - t0:.1f}", engine)
            self.root.after(0, self._set_results, name, infos, engine)
        self.root.after(0, self._scan_done, failed)

    def _set_results(self, name, infos, engine):
        self.results[name] = infos
        self.engine = engine
        self._render()

    def _scan_done(self, failed):
        self.scanning = False
        self.status = ("status_error",) if failed else ("status_ready",)
        self._refresh_scan_btn()
        if failed:
            return
        self.r_have["browse"] = True
        counts = {n: len(self._visible(n)) for n in self.names + self.temp if n in self.results}
        total = sum(counts.values())
        self.dlog("OK", "log_done", ", ".join(f"{n}={c}" for n, c in counts.items()), total)
        if total == 0 and counts:
            self._show_notice("notice_nomatch", GREEN)

    def _visible(self, name):
        hide = self.var_sys.get()
        return [x for x in self.results.get(name, []) if not (hide and SYS_RE.match(x[0]))]

    def set_filter(self, name):
        self.filter = None if self.filter == name else name
        self._render()

    def _render(self):
        t = self.tree
        t.delete(*t.get_children())
        self.row_path.clear()
        shown = total = 0
        for name in self.names + self.temp:
            items = self._visible(name)
            total += len(items)
            chip = self.chips.get(name)
            active = self.filter == name
            if chip:
                if name in self.results:
                    chip.set_text(f"{name}  {len(items)}",
                                  fg=(ONACC if active else (AMBER if items else MUTED)))
                else:
                    chip.set_text(name, fg=(ONACC if active else MUTED))
                if active:
                    chip.set_colors(ACCENT, ONACC, HOVER)
                else:
                    chip.set_colors(CARD, chip.fg_c, LINE)
            if self.filter and self.filter != name:
                continue
            for path, isdir, size, date in sorted(items, key=lambda x: x[0].lower()):
                folder, base = os.path.split(path)
                iid = t.insert("", "end", tags=("odd" if shown % 2 else "even",),
                               values=(name, ("📁 " if isdir else "") + base, folder, size, date))
                self.row_path[iid] = path
                shown += 1
        self.summary.config(text=self.t("summary", shown, total))
        if shown:
            self._hide_notice()

    def _show_notice(self, key, color=MUTED):
        self.notice_state = (key, color)
        self.notice.config(text=self.t(key), fg=color)
        self.notice.place(relx=0.5, rely=0.45, anchor="center")
        self.notice.lift()

    def _hide_notice(self):
        self.notice_state = None
        self.notice.place_forget()

    def _selected(self):
        sel = self.tree.selection()
        return self.row_path.get(sel[0]) if sel else None

    def show_in_folder(self):
        path = self._selected()
        if not path:
            return
        try:
            if os.name == "nt":
                subprocess.Popen(["explorer", f"/select,{path}"])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path)])
            self.dlog("INFO", "log_shown", path)
        except Exception as e:
            self.dlog("ERROR", "log_open_err", e)

    def copy_path(self):
        path = self._selected()
        if path:
            self.root.clipboard_clear()
            self.root.clipboard_append(path)
            self.dlog("INFO", "log_path_copied", path)

    def export_txt(self):
        if not any(self.results.values()):
            return
        fn = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="slave_results.txt",
                                          filetypes=[(self.t("file_type"), "*.txt")])
        if not fn:
            return
        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write(self.t("export_title", f"{datetime.now():%d.%m.%Y %H:%M}") + "\n\n")
                for name in self.names + self.temp:
                    if name not in self.results:
                        continue
                    items = self._visible(name)
                    f.write(f"[{name}] ({len(items)})\n")
                    for path, *_ in sorted(items, key=lambda x: x[0].lower()):
                        f.write(f"  {path}\n")
                    f.write("\n")
            self.dlog("OK", "log_saved", fn)
        except OSError as e:
            self.dlog("ERROR", "log_save_err", e)

    # ---------- Data usage page ----------
    def _build_data(self):
        cA = tk.Frame(self.main, bg=PANEL)
        self.dcfg.build_ui(cA)

        cB = tk.Frame(self.main, bg=PANEL)
        row = tk.Frame(cB, bg=PANEL)
        row.pack(fill="x", padx=12, pady=(10, 2))
        self.dentry = tk.Entry(row, bg=CARD, fg=FG, insertbackground=FG, relief="flat",
                               font=("Segoe UI", 10), highlightthickness=1,
                               highlightbackground=LINE, highlightcolor=ACCENT)
        self.dentry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.dentry.bind("<KeyRelease>", lambda e: self._d_render())
        b = RoundButton(row, "", self.d_refresh, ACCENT, ONACC, HOVER, width=100, height=32, parent_bg=PANEL)
        b.pack(side="left")
        self.reg(lambda: b.set_text(self.t("d_refresh")))
        hint = tk.Label(cB, bg=PANEL, fg=MUTED, font=("Segoe UI", 8), anchor="w")
        hint.pack(fill="x", padx=14)
        self.reg(lambda: hint.config(text=self.t("d_search_hint")))
        opts = tk.Frame(cB, bg=PANEL)
        opts.pack(fill="x", padx=12, pady=(6, 10))
        c1 = tk.Checkbutton(opts, variable=self.var_donly, command=self._d_only_changed, **self.ck(PANEL))
        c1.pack(side="left")
        c2 = tk.Checkbutton(opts, variable=self.var_dauto, **self.ck(PANEL))
        c2.pack(side="left", padx=16)
        self.reg(lambda: c1.config(text=self.t("d_only_list")))
        self.reg(lambda: c2.config(text=self.t("d_auto", AUTO_SECONDS)))

        fr = tk.Frame(self.main, bg=PANEL)
        inner = tk.Frame(fr, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=8, pady=8)
        self.dcols = ("app", "read", "write", "total", "last", "path")
        self.dtree = ttk.Treeview(inner, columns=self.dcols, show="headings", selectmode="browse")
        for c, w, anchor in (("app", 160, "w"), ("read", 95, "e"), ("write", 95, "e"),
                             ("total", 95, "e"), ("last", 140, "w"), ("path", 320, "w")):
            self.dtree.column(c, width=w, anchor=anchor, stretch=(c == "path"))
        self.reg(lambda: [self.dtree.heading(c, text=self.t("dc_" + c), command=lambda c=c: self.d_sort(c))
                          for c in self.dcols])
        self.dtree.tag_configure("odd", background=ROW_ALT)
        self.dtree.tag_configure("even", background=CARD)
        sb = ttk.Scrollbar(inner, orient="vertical", command=self.dtree.yview)
        self.dtree.configure(yscrollcommand=sb.set)
        self.dtree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.dnotice = tk.Label(fr, bg=CARD, fg=MUTED, font=("Segoe UI", 11), justify="center", wraplength=900)

        bar = tk.Frame(self.main, bg=PANEL, height=64)
        bar.pack_propagate(False)
        note = tk.Label(bar, bg=PANEL, fg=MUTED, font=("Segoe UI", 8), justify="left", anchor="w", wraplength=620)
        note.pack(side="left", padx=16)
        self.reg(lambda: note.config(text=self.t("d_note")))
        self.dsummary = tk.Label(bar, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10))
        self.dsummary.pack(side="right", padx=16)
        self.page_cards["data"] = [(cA, KW_X), (cB, KW_X), (fr, KW_EXP), (bar, KW_BAR)]

    def _d_only_changed(self):
        self.save_config()
        self._d_render()

    def d_sort(self, col):
        asc_first = col in ("app", "path")
        if self.dsort[0] == col:
            self.dsort = (col, not self.dsort[1])
        else:
            self.dsort = (col, not asc_first)
        self._d_render()

    def d_refresh(self):
        if self.data_busy:
            return
        if os.name != "nt":
            self._d_show_notice("d_nowin", AMBER)
            return
        self.data_busy = True
        self.r_have["data"] = False
        self.dlog("TOOL", "log_data_start")
        threading.Thread(target=self._d_worker, daemon=True).start()

    def _d_worker(self):
        t0 = time.time()
        try:
            rows = fetch_srum_usage()
        except Exception as e:
            self.dlog("ERROR", "log_data_err", e)
            self.root.after(0, self._d_done, None, None, str(e))
            return
        try:
            live_rows = fetch_live_process_usage()
        except Exception as e:
            self.dlog_raw("WARN", f"live process counters unavailable: {e}")
            live_rows = []
        self.dlog("OK", "log_data_done", len(rows), f"{time.time() - t0:.1f}")
        self.root.after(0, self._d_done, rows, live_rows, "")

    def _d_done(self, rows, live_rows, error):
        self.data_busy = False
        if rows is None:
            self.status = ("status_error",)
            self.data_rows = []
            self.data_live_rows = []
            self.r_have["data"] = False
            self._d_show_notice("d_srum_error", AMBER, error)
            self._d_render()
            return
        if not (self.scanning or self.trace_busy or self.persist_busy):
            self.status = ("status_ready",)
        self.data_rows = rows
        self.data_live_rows = live_rows or []
        self.r_have["data"] = True
        self._d_render()
        if not rows:
            self._d_show_notice("d_srum_empty", AMBER)

    def _d_terms(self):
        typed = split_names(self.dentry.get())
        if typed:
            return typed
        if self.var_donly.get():
            return self.dcfg.active_names()
        return None

    def _d_render(self):
        t = self.dtree
        t.delete(*t.get_children())
        terms = self._d_terms()
        rows = self.data_rows
        if terms is not None:
            low = [x.lower() for x in terms]
            rows = [r for r in rows if any(x in r["app"].lower() or x in r["path"].lower() for x in low)]
        key, desc = self.dsort
        if key in ("app", "path"):
            keyf = lambda r: r[key].lower()
        elif key == "last":
            keyf = lambda r: r[key] or datetime.min.replace(tzinfo=timezone.utc)
        else:
            keyf = lambda r: r[key]
        rows = sorted(rows, key=keyf, reverse=desc)
        for i, r in enumerate(rows):
            t.insert("", "end", tags=("odd" if i % 2 else "even",),
                     values=(r["app"], human(r["read"]), human(r["write"]), human(r["total"]),
                             r["last"].astimezone().strftime("%d.%m.%Y %H:%M") if r["last"] else "—", r["path"]))
        self.dsummary.config(text=self.t("d_summary", len(rows), human(sum(r["total"] for r in rows))))
        if rows:
            self._d_hide_notice()
        elif self.data_rows:
            self._d_show_notice("d_nomatch", GREEN)

    def _d_show_notice(self, key, color=MUTED, *args):
        self.d_notice_state = (key, color, *args)
        self.dnotice.config(text=self.t(key, *args), fg=color)
        self.dnotice.place(relx=0.5, rely=0.45, anchor="center")
        self.dnotice.lift()

    def _d_hide_notice(self):
        self.d_notice_state = None
        self.dnotice.place_forget()

    def _d_auto_tick(self):
        if self.var_dauto.get() and self.page == "data":
            self.d_refresh()
        self.root.after(AUTO_SECONDS * 1000, self._d_auto_tick)

    # ---------- Traces page ----------
    def _build_trace(self):
        cA = tk.Frame(self.main, bg=PANEL)
        self.tcfg.build_ui(cA)

        cB = tk.Frame(self.main, bg=PANEL)
        row = tk.Frame(cB, bg=PANEL)
        row.pack(fill="x", padx=12, pady=(10, 2))
        self.tentry = tk.Entry(row, bg=CARD, fg=FG, insertbackground=FG, relief="flat",
                               font=("Segoe UI", 10), highlightthickness=1,
                               highlightbackground=LINE, highlightcolor=ACCENT)
        self.tentry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.tentry.bind("<KeyRelease>", lambda e: self._t_render())
        b = RoundButton(row, "", self.t_scan, ACCENT, ONACC, HOVER, width=140, height=32, parent_bg=PANEL)
        b.pack(side="left")
        self.reg(lambda: b.set_text(self.t("t_scan")))
        hint = tk.Label(cB, bg=PANEL, fg=MUTED, font=("Segoe UI", 8), anchor="w")
        hint.pack(fill="x", padx=14)
        self.reg(lambda: hint.config(text=self.t("t_filter_hint")))
        note = tk.Label(cB, bg=PANEL, fg=AMBER, font=("Segoe UI", 8), anchor="w", justify="left", wraplength=950)
        note.pack(fill="x", padx=14, pady=(2, 10))
        self.reg(lambda: note.config(text=self.t("t_note")))

        fr = tk.Frame(self.main, bg=PANEL)
        inner = tk.Frame(fr, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=8, pady=8)
        self.tcols = ("src", "name", "path", "when", "state")
        self.ttree = ttk.Treeview(inner, columns=self.tcols, show="headings", selectmode="browse")
        for c, w, anchor in (("src", 100, "w"), ("name", 170, "w"), ("path", 420, "w"),
                             ("when", 130, "w"), ("state", 100, "w")):
            self.ttree.column(c, width=w, anchor=anchor, stretch=(c == "path"))
        self.reg(lambda: [self.ttree.heading(c, text=self.t("tc_" + c)) for c in self.tcols])
        self.ttree.tag_configure("odd", background=ROW_ALT)
        self.ttree.tag_configure("even", background=CARD)
        self.ttree.tag_configure("gone", foreground=RED)
        sb = ttk.Scrollbar(inner, orient="vertical", command=self.ttree.yview)
        self.ttree.configure(yscrollcommand=sb.set)
        self.ttree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tnotice = tk.Label(fr, bg=CARD, fg=MUTED, font=("Segoe UI", 11), justify="center")

        bar = tk.Frame(self.main, bg=PANEL, height=56)
        bar.pack_propagate(False)
        self.tsummary = tk.Label(bar, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10))
        self.tsummary.pack(side="right", padx=16)
        self.page_cards["trace"] = [(cA, KW_X), (cB, KW_X), (fr, KW_EXP), (bar, KW_BAR)]

    def t_scan(self):
        if self.trace_busy:
            return
        if os.name != "nt":
            self._t_show_notice("d_nowin", AMBER)
            return
        names = self.tcfg.active_names()
        if not names:
            self._t_show_notice("notice_none", AMBER)
            self.dlog("WARN", "log_skip")
            return
        self.trace_busy = True
        self.r_have["trace"] = False
        self.trace_rows = []
        self._t_hide_notice()
        self._t_render()
        self.status = ("status_scanning", self.t("tab_trace"), 1, 1)
        self.dlog("TOOL", "log_tr_start")
        threading.Thread(target=self._t_worker, args=(names,), daemon=True).start()

    def _t_worker(self, names):
        t0 = time.time()
        try:
            rows = collect_traces(names, lambda lvl, key, *a: self.dlog(lvl, key, *a))
        except Exception as e:
            self.dlog_raw("ERROR", f"traces: {e!r}")
            rows = None
        self.dlog("OK", "log_tr_done", len(rows or []), f"{time.time() - t0:.1f}")
        self.root.after(0, self._t_done, rows)

    def _t_done(self, rows):
        self.trace_busy = False
        self.status = ("status_ready",)
        if rows is None:
            self.status = ("status_error",)
            return
        self.trace_rows = rows
        self.r_have["trace"] = True
        self._t_render()
        if not rows:
            self._t_show_notice("t_none", GREEN)

    def _t_render(self):
        try:
            t = self.ttree
            t.delete(*t.get_children())
            typed = [x.lower() for x in split_names(self.tentry.get())]
            on = {n.lower() for n in self.tcfg.active_names()}
            rows = []
            for r in self.trace_rows:
                if typed:
                    if not any(x in r["path"].lower() or x in r["m"].lower() for x in typed):
                        continue
                elif r["m"].lower() not in on:
                    continue
                rows.append(r)
            gone = 0
            for i, r in enumerate(rows):
                dele = r["exists"] is False
                gone += dele
                base = os.path.basename(r["path"].replace("/", "\\").rstrip("\\")) or r["path"]
                state = self.t("t_deleted") if dele else (self.t("t_exists") if r["exists"] else "—")
                detail = r["path"] + (f"   ({r['reason']})" if r["reason"] else "")
                tags = ("odd" if i % 2 else "even",) + (("gone",) if dele else ())
                t.insert("", "end", tags=tags, values=(r["src"], base, detail, r["when"], state))
            self.tsummary.config(text=self.t("t_summary", len(rows), gone))
            if rows:
                self._t_hide_notice()
        except tk.TclError:
            pass

    def _t_show_notice(self, key, color=MUTED):
        self.t_notice_state = (key, color)
        self.tnotice.config(text=self.t(key), fg=color)
        self.tnotice.place(relx=0.5, rely=0.45, anchor="center")
        self.tnotice.lift()

    def _t_hide_notice(self):
        self.t_notice_state = None
        self.tnotice.place_forget()

    # ---------- DLL / Memory page (Roblox must be open) ----------
    def _build_persist(self):
        cA = tk.Frame(self.main, bg=PANEL)
        self.pcfg.build_ui(cA)

        cB = tk.Frame(self.main, bg=PANEL)
        row = tk.Frame(cB, bg=PANEL)
        row.pack(fill="x", padx=12, pady=(10, 2))
        self.pentry = tk.Entry(row, bg=CARD, fg=FG, insertbackground=FG, relief="flat",
                               font=("Segoe UI", 10), highlightthickness=1,
                               highlightbackground=LINE, highlightcolor=ACCENT)
        self.pentry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.pentry.bind("<KeyRelease>", lambda e: self._p_render())
        b = RoundButton(row, "", self.p_scan, ACCENT, ONACC, HOVER, width=160, height=32, parent_bg=PANEL)
        b.pack(side="left")
        self.reg(lambda: b.set_text(self.t("p_scan")))
        hint = tk.Label(cB, bg=PANEL, fg=MUTED, font=("Segoe UI", 8), anchor="w")
        hint.pack(fill="x", padx=14)
        self.reg(lambda: hint.config(text=self.t("p_filter_hint")))
        self.p_rb = tk.Label(cB, bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold"), anchor="w")
        self.p_rb.pack(fill="x", padx=14, pady=(4, 0))
        note = tk.Label(cB, bg=PANEL, fg=AMBER, font=("Segoe UI", 8), anchor="w", justify="left", wraplength=950)
        note.pack(fill="x", padx=14, pady=(2, 10))
        self.reg(lambda: note.config(text=self.t("p_note")))

        fr = tk.Frame(self.main, bg=PANEL)
        inner = tk.Frame(fr, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=8, pady=8)
        self.pcols = ("kind", "name", "detail", "flag")
        self.ptree = ttk.Treeview(inner, columns=self.pcols, show="headings", selectmode="browse")
        for c, w, anchor in (("kind", 170, "w"), ("name", 170, "w"), ("detail", 420, "w"), ("flag", 260, "w")):
            self.ptree.column(c, width=w, anchor=anchor, stretch=(c == "detail"))
        self.reg(lambda: [self.ptree.heading(c, text=self.t("pc_" + c)) for c in self.pcols])
        self.ptree.tag_configure("low", foreground=GREEN)
        self.ptree.tag_configure("med", foreground=AMBER)
        self.ptree.tag_configure("high", foreground=RED)
        sb = ttk.Scrollbar(inner, orient="vertical", command=self.ptree.yview)
        self.ptree.configure(yscrollcommand=sb.set)
        self.ptree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.pnotice = tk.Label(fr, bg=CARD, fg=MUTED, font=("Segoe UI", 11), justify="center")

        bar = tk.Frame(self.main, bg=PANEL, height=56)
        bar.pack_propagate(False)
        self.psummary = tk.Label(bar, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10))
        self.psummary.pack(side="right", padx=16)
        self.page_cards["persist"] = [(cA, KW_X), (cB, KW_X), (fr, KW_EXP), (bar, KW_BAR)]

    def _build_session(self):
        """Dedicated UI for Roblox launch history and the new file-trace methods."""
        panel = tk.Frame(self.main, bg=PANEL)
        heading = tk.Frame(panel, bg=PANEL)
        heading.pack(fill="x", padx=14, pady=(12, 5))
        title = tk.Label(heading, bg=PANEL, fg=FG, font=("Segoe UI", 12, "bold"), anchor="w")
        title.pack(side="left", fill="x", expand=True)
        self.reg(lambda: title.config(text=self.t("tab_session")))

        self.p_history_note = tk.Label(panel, bg=PANEL, fg=MUTED, font=("Segoe UI", 9),
                                       anchor="w", justify="left", wraplength=1080)
        self.p_history_note.pack(fill="x", padx=14, pady=(0, 10))
        self.reg(lambda: self.p_history_note.config(text=self.t("p_history_note")))

        history_row = tk.Frame(panel, bg=PANEL)
        history_row.pack(fill="x", padx=14, pady=(0, 7))
        self.p_history_btn = RoundButton(history_row, "", self.p_history_scan, ACCENT, ONACC, HOVER,
                                         width=245, height=32, parent_bg=PANEL)
        self.p_history_btn.pack(side="left", padx=(0, 8))
        self.reg(lambda: self.p_history_btn.set_text(self.t("p_history_scan")))
        self.ph_range = ttk.Combobox(history_row, state="readonly", width=13, style="Dark.TCombobox",
                                     font=("Segoe UI", 9))
        self.ph_range.pack(side="left", ipady=2, padx=(0, 6))
        self.ph_back = ttk.Combobox(history_row, state="readonly", width=20, style="Dark.TCombobox",
                                    font=("Segoe UI", 9))
        self.ph_back.pack(side="left", ipady=2, padx=(0, 8))

        def _ph_combo_labels():
            ri, bi = self.ph_range.current(), self.ph_back.current()
            self.ph_range.config(values=[self.t("ph_range_today"), self.t("ph_range_30d")])
            self.ph_back.config(values=[self.t(k) for k in ("ph_back_10m", "ph_back_1h", "ph_back_6h", "ph_back_all")])
            self.ph_range.current(0 if ri < 0 else ri)
            self.ph_back.current(1 if bi < 0 else bi)
        self.reg(_ph_combo_labels)
        self.p_history_status = tk.Label(history_row, bg=PANEL, fg=MUTED,
                                         font=("Segoe UI", 9), anchor="w")
        self.p_history_status.pack(side="left", fill="x", expand=True, padx=(8, 0))

        table = tk.Frame(panel, bg=PANEL)
        table.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.phcols = ("rb_start", "app_start", "name", "offset", "source")
        self.ph_tree = ttk.Treeview(table, columns=self.phcols, show="headings", height=16, selectmode="browse")
        for col, width in (("rb_start", 155), ("app_start", 155), ("name", 210), ("offset", 90), ("source", 470)):
            self.ph_tree.heading(col, text=self.t("pw_" + col))
            self.ph_tree.column(col, width=width, anchor="w", stretch=(col == "source"))
        self.reg(lambda: [self.ph_tree.heading(col, text=self.t("pw_" + col)) for col in self.phcols])
        self.ph_tree.tag_configure("hit", foreground=RED)
        self.ph_tree.tag_configure("review", foreground=AMBER)
        yscroll = ttk.Scrollbar(table, orient="vertical", command=self.ph_tree.yview)
        xscroll = ttk.Scrollbar(table, orient="horizontal", command=self.ph_tree.xview)
        self.ph_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.ph_tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)
        self.reg(self._p_history_render)
        self.page_cards["session"] = [(panel, KW_EXP)]

    def _build_method_page(self, key):
        """Build one independent page/table for one evidence method."""
        panel = tk.Frame(self.main, bg=PANEL)
        header = tk.Frame(panel, bg=PANEL)
        header.pack(fill="x", padx=14, pady=(12, 5))
        title = tk.Label(header, bg=PANEL, fg=FG, font=("Segoe UI", 12, "bold"), anchor="w")
        title.pack(side="left", fill="x", expand=True)
        self.reg(lambda title=title, key=key: title.config(text=self.t("tab_" + key)))

        row = tk.Frame(panel, bg=PANEL)
        row.pack(fill="x", padx=14, pady=(0, 7))
        button = RoundButton(row, "", lambda k=key: self._scan_method_page(k),
                             ACCENT, ONACC, HOVER, width=210, height=32, parent_bg=PANEL)
        button.pack(side="left", padx=(0, 10))
        self.reg(lambda button=button, key=key: button.set_text(self.t(key + "_scan")))
        status = tk.Label(row, bg=PANEL, fg=MUTED, font=("Segoe UI", 9), anchor="w")
        status.pack(side="left", fill="x", expand=True)

        note = tk.Label(panel, bg=PANEL, fg=MUTED, font=("Segoe UI", 9), anchor="w",
                        justify="left", wraplength=1080)
        note.pack(fill="x", padx=14, pady=(0, 10))
        self.reg(lambda note=note, key=key: note.config(text=self.t(key + "_note")))

        table = tk.Frame(panel, bg=PANEL)
        table.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        cols = ("time", "name", "path", "detail")
        tree = ttk.Treeview(table, columns=cols, show="headings", height=16, selectmode="browse")
        for col, width in (("time", 155), ("name", 220), ("path", 390), ("detail", 520)):
            tree.heading(col, text=self.t("method_col_" + col))
            tree.column(col, width=width, anchor="w", stretch=(col == "detail"))
        self.reg(lambda tree=tree, cols=cols: [tree.heading(c, text=self.t("method_col_" + c)) for c in cols])
        tree.tag_configure("review", foreground=AMBER)
        yscroll = ttk.Scrollbar(table, orient="vertical", command=tree.yview)
        xscroll = ttk.Scrollbar(table, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)

        data = self.method_data.setdefault(key, {"rows": [], "status": "", "busy": False, "error": ""})
        data.update({"panel": panel, "button": button, "status_label": status, "tree": tree})
        self.page_cards[key] = [(panel, KW_EXP)]
        self.reg(lambda data=data: self._render_method_page(data))

    def _render_method_page(self, data):
        try:
            data["status_label"].config(text=data.get("status") or self.t("method_idle"))
            data["button"].set_enabled(not data.get("busy"))
            tree = data["tree"]
            tree.delete(*tree.get_children())
            for item in data.get("rows", []):
                when = item.get("start")
                stamp = when.strftime("%d.%m.%Y %H:%M:%S") if when else "—"
                tree.insert("", "end", tags=(("review",) if item.get("review") else ()),
                            values=(stamp, item.get("name", ""), item.get("path", ""), item.get("source", "")))
        except (tk.TclError, AttributeError):
            pass

    def _scan_method_page(self, key):
        data = self.method_data[key]
        if data.get("busy"):
            return
        data["busy"] = True
        data["rows"] = []
        data["error"] = ""
        data["status"] = self.t("method_scanning")
        self.r_have[key] = False
        self._r_state_text()
        self._render_method_page(data)

        def work():
            rows, meta, error = [], {}, ""
            try:
                if key == "usn":
                    rows, meta = collect_recent_usn_exes(days=3)
                elif key == "newexe":
                    rows, meta = collect_new_unsigned_exe_clusters(days=3, names=self.pcfg.active_names())
                elif key == "memory":
                    _, pids = p_runtime(self.pcfg.active_names())
                    if not pids:
                        raise RuntimeError("Roblox is not running")
                    found, error, meta = run_isolated_exec_scan(pids)
                    for r in found:
                        region_only = r.get("region_only")
                        kind = "PRIVATE EXEC REGION" if region_only else "PRIVATE EXEC THREAD START"
                        name = "Private executable region" if region_only else f"Roblox thread {r.get('tid')}"
                        detail = (f"{kind} · PID {r.get('pid')} · base 0x{r.get('base', 0):x} · "
                                  f"{r.get('size', 0):,} bytes · protect 0x{r.get('protect', 0):x}")
                        if not region_only:
                            detail += f" · TID {r.get('tid')} start 0x{r.get('address', 0):x}"
                        else:
                            detail += " · no thread start matched this region"
                        rows.append({"start": datetime.now().astimezone(), "name": name,
                                     "path": "", "source": detail, "review": True,
                                     "region_only": bool(region_only), "pid": r.get("pid"),
                                     "tid": r.get("tid"), "base": r.get("base"),
                                     "size": r.get("size"), "protect": r.get("protect"),
                                     "address": r.get("address")})
                else:
                    raise ValueError("unknown scan method")
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
            self.root.after(0, self._method_page_done, key, rows, meta, error)
        threading.Thread(target=work, daemon=True).start()

    def _method_page_done(self, key, rows, meta, error):
        data = self.method_data[key]
        data["busy"] = False
        data["rows"] = rows
        data["error"] = error or ""
        self.r_have[key] = not bool(error)
        if error:
            data["status"] = self.t("method_error", error[:120])
        elif key == "usn":
            oldest = meta.get("oldest")
            oldest_text = oldest.strftime("%d.%m.%Y %H:%M:%S") if oldest else "—"
            data["status"] = self.t("usn_done", len(rows), ", ".join(meta.get("drives", [])) or "—", oldest_text)
            if meta.get("errors"):
                data["status"] += " · " + "; ".join(meta["errors"][:2])
            if meta.get("partial"):
                data["status"] += " · " + self.t("method_partial")
        elif key == "newexe":
            data["status"] = self.t("newexe_done", len(rows), meta.get("scanned", 0),
                                    meta.get("unsigned", 0), meta.get("name_matches", 0),
                                    meta.get("folders", 0))
            if meta.get("partial"):
                data["status"] += " · " + self.t("method_partial")
        elif key == "memory" and not rows and meta.get("exec_partial"):
            data["status"] = self.t("p_live_mem_partial", meta.get("exec_regions", 0))
        elif key == "memory" and not rows:
            data["status"] = self.t("p_live_mem_none", meta.get("exec_regions", 0))
        elif key == "memory":
            data["status"] = self.t("memory_done", len(rows), meta.get("exec_threads", 0),
                                    meta.get("exec_regions", 0))
            if meta.get("exec_partial"):
                data["status"] += " · " + self.t("method_partial")
        else:
            data["status"] = self.t("method_done", len(rows))
            if meta.get("partial") or meta.get("exec_partial"):
                data["status"] += " · " + self.t("method_partial")
        self._r_state_text()
        self._render_method_page(data)

    def p_history_scan(self):
        if self.session_state == "scanning":
            return
        if os.name != "nt":
            self.session_state = "error"
            self.r_have["session"] = False
            self._p_history_render()
            self._r_state_text()
            return
        self.r_have["session"] = False
        self.session_state, self.session_rows = "scanning", []
        self.session_count, self.session_source = 0, ""
        self.session_presence = []
        self._p_history_render()
        self._r_state_text()

        names = self.pcfg.active_names()
        ri = max(self.ph_range.current(), 0)
        bi = self.ph_back.current()
        bi = 1 if bi < 0 else bi
        range_days = 1 if ri == 0 else 30
        lookback = (10, 60, 360, 0)[bi]

        def work():
            result, error = None, None
            try:
                result = collect_session_history(range_days, lookback, names=names)
            except Exception as exc:
                error = str(exc)
            live_err = ""
            try:
                live = collect_running_context(names, lookback, 2)
                if live is None:
                    live_err = "Roblox process not found"
            except Exception as exc:
                live, live_err = None, f"{type(exc).__name__}: {exc}"
            if live_err:
                self.dlog_raw("WARN", f"session live list: {live_err}")
            if live:
                if result is None:
                    result = {"source": "", "sessions": 0, "rows": [], "rb_times": [], "complete": False}
                    error = None
                result.pop("empty_range", None)
                rb_live = live[0]["session_start"]
                same = any(abs((x - rb_live).total_seconds()) <= 180 for x in result.get("rb_times", []))
                live_names = {r["name"].lower() for r in live}
                kept = []
                for r in result["rows"]:
                    st = r.get("session_start")
                    if st and abs((st - rb_live).total_seconds()) <= 180:
                        r["session_start"] = rb_live
                        if r.get("start"):
                            r["offset"] = int((r["start"] - rb_live).total_seconds())
                        # this session is covered by the live list: live wins, history keeps the rest
                        if not r.get("name") or r["name"].lower() in live_names:
                            continue
                    kept.append(r)
                result["rows"] = live + kept
                if not same:
                    result["sessions"] += 1
                result["complete"] = True
                result["source"] = (result["source"] + " · " if result["source"] else "") + "live process list"
            if live_err and result is not None:
                result["source"] = (result["source"] + " · " if result["source"] else "") + f"live list: {live_err[:90]}"

            # The launch-history page includes only process-launch evidence; file journals
            # and private-memory findings are rendered on their own dedicated pages.
            rb_times = list((result or {}).get("rb_times", []))
            if live:
                rb_times.append(live[0]["session_start"])
            process_rows, process_meta = [], {"sources": [], "errors": [], "partial": False}
            try:
                event_lookback = lookback if lookback > 0 else (range_days * 24 * 60)
                process_rows, process_meta = collect_process_creation_events(
                    range_days, rb_times, event_lookback, 2)
                _add_review_flags(process_rows)
            except Exception as exc:
                process_meta["errors"].append(f"process event scan: {type(exc).__name__}")
                process_meta["partial"] = True
            scan_notes = []
            if process_meta.get("sources"):
                scan_notes.append("process logs: " + "+".join(process_meta["sources"]))
            else:
                scan_notes.append("no readable Security 4688 / Sysmon 1 process records")
            if process_meta.get("partial"):
                scan_notes.append("process log scan partial")
            if process_meta.get("errors"):
                scan_notes.extend(str(x) for x in process_meta["errors"][:2])

            extra_rows = process_rows
            if result is None:
                result = {"source": "", "sessions": 0, "rows": [], "rb_times": [],
                          "complete": False, "presence": []}
            result.setdefault("rows", [])
            result["rows"].extend(extra_rows)
            if extra_rows:
                result["complete"] = True
                result.pop("empty_range", None)
                if error:
                    scan_notes.append(f"session history unavailable: {error[:90]}")
                    error = None
            if scan_notes:
                result["source"] = (result.get("source", "") + " · " if result.get("source") else "") + "; ".join(scan_notes)
            for rb_start in process_meta.get("rb_times", []):
                if rb_start and not any(abs((old - rb_start).total_seconds()) <= 180
                                        for old in result.get("rb_times", [])):
                    result.setdefault("rb_times", []).append(rb_start)
                    result["sessions"] = result.get("sessions", 0) + 1
            if process_meta.get("rb_times"):
                result["complete"] = True
            result["extra_partial"] = bool(process_meta.get("partial"))
            result["extra_counts"] = {"process": len(process_rows)}
            if result:
                mark_session_hits(result["rows"], names)
            self.root.after(0, self._p_history_done, result, error)
        threading.Thread(target=work, daemon=True).start()

    def _p_history_done(self, result, error):
        if error:
            self.session_state = "error"
        elif result and result.get("empty_range") and not result.get("complete"):
            self.session_state = "norange"
            self.session_rows = []
        elif not result or not result.get("complete"):
            self.session_state = "untimed" if result and result.get("presence") else "none"
            self.session_presence = (result or {}).get("presence", [])
            self.session_rows = []
        else:
            self.session_state = "done"
            self.session_rows = result["rows"]
            self.session_count = result["sessions"]
            self.session_source = result["source"]
            self.session_extra_counts = result.get("extra_counts", {})
            self.session_extra_partial = result.get("extra_partial", False)
        self.r_have["session"] = self.session_state not in ("error", "scanning")
        self.status = ("status_ready",)
        self._p_history_render()
        self._r_state_text()

    def _p_history_render(self):
        try:
            if self.session_state == "scanning":
                status = self.t("p_history_scanning")
            elif self.session_state == "done":
                apps = sum(bool(row.get("name")) and not row.get("extra") for row in self.session_rows)
                extras = sum(bool(row.get("extra")) for row in self.session_rows)
                reviews = sum(bool(row.get("review")) for row in self.session_rows)
                status = self.t("p_history_done", self.session_count, apps, extras) + " · " + self.session_source
                if reviews:
                    status += " · " + self.t("p_history_review", reviews)
                hits = sum(bool(row.get("hit")) for row in self.session_rows)
                if hits:
                    status += f"  ·  ⚠ {hits} name match"
            elif self.session_state == "norange":
                status = self.t("p_history_norange")
            elif self.session_state == "none":
                status = self.t("p_history_none")
            elif self.session_state == "untimed":
                status = self.t("p_history_untimed", ", ".join(self.session_presence))
            elif self.session_state == "error":
                status = self.t("p_history_error")
            else:
                status = self.t("p_history_idle")
            self.p_history_status.config(text=status)
            self.p_history_btn.set_enabled(self.session_state != "scanning")
            self.ph_tree.delete(*self.ph_tree.get_children())
            for row in self.session_rows:
                fmt = lambda val: val.strftime("%d.%m.%Y %H:%M:%S") if val else "—"
                delta = row.get("offset")
                offset = fmt_offset(delta)
                tags = tuple(tag for tag, enabled in (("hit", row.get("hit")),
                                                       ("review", row.get("review"))) if enabled)
                self.ph_tree.insert("", "end", tags=tags,
                                    values=(fmt(row.get("session_start")), fmt(row.get("start")),
                                                          row.get("name") or self.t("p_history_no_apps"), offset,
                                                          row.get("source") or "—"))
        except (tk.TclError, AttributeError):
            pass

    def p_scan(self):
        if self.persist_busy:
            return
        if os.name != "nt":
            self._p_show_notice("d_nowin", AMBER)
            return
        names = self.pcfg.active_names()
        if not names:
            self._p_show_notice("notice_none", AMBER)
            self.dlog("WARN", "log_skip")
            return
        self.persist_busy = True
        self.r_have["roblox"] = False
        self.persist_rows, self.roblox_n = [], None
        self._p_hide_notice()
        self._p_render()
        self.status = ("status_scanning", self.t("tab_persist"), 1, 1)
        self.dlog("TOOL", "log_p_start")
        threading.Thread(target=self._p_worker, args=(names,), daemon=True).start()

    def _p_worker(self, names):
        t0 = time.time()
        try:
            rows, nrb = collect_persist(names, lambda lvl, key, *a: self.dlog(lvl, key, *a))
        except Exception as e:
            self.dlog_raw("ERROR", f"roblox scan: {e!r}")
            rows, nrb = None, 0
        self.dlog("OK", "log_p_done", len(rows or []), f"{time.time() - t0:.1f}")
        self.root.after(0, self._p_done, rows, nrb)

    def _p_done(self, rows, nrb):
        self.persist_busy = False
        self.status = ("status_ready",)
        if rows is None:
            self.status = ("status_error",)
            return
        self.persist_rows, self.roblox_n = rows, nrb
        self.r_have["roblox"] = nrb > 0      # Roblox closed -> method is invalid for the score
        self._p_render()
        if not rows:
            self._p_show_notice("p_none" if nrb else "p_rb_closed", GREEN if nrb else AMBER)

    def _p_render(self):
        try:
            t = self.ptree
            t.delete(*t.get_children())
            if self.roblox_n is None:
                self.p_rb.config(text="")
            elif self.roblox_n == 0:
                self.p_rb.config(text=self.t("p_rb_closed"), fg=AMBER)
            else:
                self.p_rb.config(text=self.t("p_rb_open", self.roblox_n), fg=GREEN)
            typed = [x.lower() for x in split_names(self.pentry.get())]
            on = {n.lower() for n in self.pcfg.active_names()}
            rows = []
            for r in self.persist_rows:
                if typed:
                    if not any(x in r["path"].lower() or x in r["name"].lower() or x in r["m"].lower()
                               for x in typed):
                        continue
                elif r["m"] and r["m"].lower() not in on:
                    continue
                rows.append(r)
            for r in rows:
                lv = "low" if r["w"] < 0.25 else ("med" if r["w"] < 0.5 else "high")
                flags = " + ".join(self.t(f) for f in r["flags"])
                t.insert("", "end", tags=(lv,),
                         values=(self.t("pk_" + r["kind"]), r["name"], r["detail"], flags))
            self.psummary.config(text=self.t("p_summary", len(rows)))
            if rows:
                self._p_hide_notice()
        except tk.TclError:
            pass

    def _p_show_notice(self, key, color=MUTED):
        self.p_notice_state = (key, color)
        self.pnotice.config(text=self.t(key), fg=color)
        self.pnotice.place(relx=0.5, rely=0.45, anchor="center")
        self.pnotice.lift()

    def _p_hide_notice(self):
        self.p_notice_state = None
        self.pnotice.place_forget()

    # ---------- Forensic page ----------
    def _build_forensic(self):
        cA = tk.Frame(self.main, bg=PANEL)
        self.fcfg.build_ui(cA)

        cB = tk.Frame(self.main, bg=PANEL)
        row = tk.Frame(cB, bg=PANEL)
        row.pack(fill="x", padx=12, pady=(10, 2))
        self.fentry = tk.Entry(row, bg=CARD, fg=FG, insertbackground=FG, relief="flat",
                               font=("Segoe UI", 10), highlightthickness=1,
                               highlightbackground=LINE, highlightcolor=ACCENT)
        self.fentry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.fentry.bind("<KeyRelease>", lambda e: self._f_render())
        b = RoundButton(row, "", self.f_scan, ACCENT, ONACC, HOVER, width=160, height=32, parent_bg=PANEL)
        b.pack(side="left")
        self.reg(lambda: b.set_text(self.t("fe_scan")))
        hint = tk.Label(cB, bg=PANEL, fg=MUTED, font=("Segoe UI", 8), anchor="w", justify="left", wraplength=950)
        hint.pack(fill="x", padx=14)
        self.reg(lambda: hint.config(text=self.t("fe_filter_hint")))
        note = tk.Label(cB, bg=PANEL, fg=AMBER, font=("Segoe UI", 8), anchor="w", justify="left", wraplength=950)
        note.pack(fill="x", padx=14, pady=(2, 10))
        self.reg(lambda: note.config(text=self.t("fe_note")))

        fr = tk.Frame(self.main, bg=PANEL)
        inner = tk.Frame(fr, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=8, pady=8)
        self.fcols = ("kind", "name", "detail", "when", "flag")
        self.ftree = ttk.Treeview(inner, columns=self.fcols, show="headings", selectmode="browse")
        for c, w, anchor in (("kind", 170, "w"), ("name", 140, "w"), ("detail", 420, "w"),
                             ("when", 120, "w"), ("flag", 240, "w")):
            self.ftree.column(c, width=w, anchor=anchor, stretch=(c == "detail"))
        self.reg(lambda: [self.ftree.heading(c, text=self.t("fc_" + c)) for c in self.fcols])
        self.ftree.tag_configure("low", foreground=GREEN)
        self.ftree.tag_configure("med", foreground=AMBER)
        self.ftree.tag_configure("high", foreground=RED)
        sb = ttk.Scrollbar(inner, orient="vertical", command=self.ftree.yview)
        self.ftree.configure(yscrollcommand=sb.set)
        self.ftree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.fnotice = tk.Label(fr, bg=CARD, fg=MUTED, font=("Segoe UI", 11), justify="center")

        bar = tk.Frame(self.main, bg=PANEL, height=56)
        bar.pack_propagate(False)
        self.fsummary = tk.Label(bar, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10))
        self.fsummary.pack(side="right", padx=16)
        self.page_cards["forensic"] = [(cA, KW_X), (cB, KW_X), (fr, KW_EXP), (bar, KW_BAR)]

    def f_scan(self):
        if self.forensic_busy:
            return
        if os.name != "nt":
            self._f_show_notice("d_nowin", AMBER)
            return
        names = self.fcfg.active_names()
        if not names:
            self._f_show_notice("notice_none", AMBER)
            self.dlog("WARN", "log_skip")
            return
        self.forensic_busy = True
        self.r_have["forensic"] = False
        self.forensic_rows = []
        self._f_hide_notice()
        self._f_render()
        self.status = ("status_scanning", self.t("tab_forensic"), 1, 1)
        self.dlog("TOOL", "log_fe_start")
        threading.Thread(target=self._f_worker, args=(names,), daemon=True).start()

    def _f_worker(self, names):
        t0 = time.time()
        try:
            rows = collect_forensic(names, lambda lvl, key, *a: self.dlog(lvl, key, *a))
        except Exception as e:
            self.dlog_raw("ERROR", f"forensic: {e!r}")
            rows = None
        self.dlog("OK", "log_fe_done", len(rows or []), f"{time.time() - t0:.1f}")
        self.root.after(0, self._f_done, rows)

    def _f_done(self, rows):
        self.forensic_busy = False
        self.status = ("status_ready",)
        if rows is None:
            self.status = ("status_error",)
            return
        self.forensic_rows = rows
        self.r_have["forensic"] = True
        self._f_render()
        if not rows:
            self._f_show_notice("fe_none", GREEN)

    def _f_render(self):
        try:
            t = self.ftree
            t.delete(*t.get_children())
            typed = [x.lower() for x in split_names(self.fentry.get())]
            on = {n.lower() for n in self.fcfg.active_names()}
            rows = []
            for r in self.forensic_rows:
                if typed:
                    if not any(x in r["path"].lower() or x in r["name"].lower() or x in r["m"].lower()
                               or x in r["detail"].lower() for x in typed):
                        continue
                elif r["m"] and r["m"].lower() not in on:
                    continue
                rows.append(r)
            for r in rows:
                lv = "low" if r["w"] < 0.25 else ("med" if r["w"] < 0.5 else "high")
                t.insert("", "end", tags=(lv,),
                         values=(self.t("fk_" + r["kind"]), r["name"], r["detail"], r["when"], self.t(r["key"])))
            self.fsummary.config(text=self.t("fe_summary", len(rows)))
            if rows:
                self._f_hide_notice()
        except tk.TclError:
            pass

    def _f_show_notice(self, key, color=MUTED):
        self.f_notice_state = (key, color)
        self.fnotice.config(text=self.t(key), fg=color)
        self.fnotice.place(relx=0.5, rely=0.45, anchor="center")
        self.fnotice.lift()

    def _f_hide_notice(self):
        self.f_notice_state = None
        self.fnotice.place_forget()

    # ---------- Risk page ----------
    def _build_risk(self):
        cA = tk.Frame(self.main, bg=PANEL)
        mrow = tk.Frame(cA, bg=PANEL)
        mrow.pack(fill="x", padx=12, pady=(10, 0))
        ml = tk.Label(mrow, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold"))
        ml.pack(fill="x", anchor="w", pady=(0, 2))
        self.reg(lambda: ml.config(text=self.t("r_methods")))
        method_options = tk.Frame(mrow, bg=PANEL)
        method_options.pack(fill="x")
        method_checks = []
        for key in RISK_METHODS:
            c = tk.Checkbutton(method_options, variable=self.rm[key], **self.ck(PANEL))
            self.reg(lambda c=c, k=key: c.config(text=self.t("tab_" + k)))
            method_checks.append(c)
        flow_layout(method_options, method_checks, 170, padx=8)
        row = tk.Frame(cA, bg=PANEL)
        row.pack(fill="x", padx=12, pady=(8, 4))
        for key, cmd, bg, fg, hov, w in (
                ("r_scan_all", self.r_all, ACCENT, ONACC, HOVER, 140),
                ("r_custom", self.r_custom, ACCENT2, "#ffffff", HOVER2, 170),
                ("r_reset", self.r_reset, DANGER, RED, DANGER_H, 110),
                ("r_export_html", self.r_export_html, "#26374a", "#dce9f7", "#344a63", 170)):
            b = RoundButton(row, "", cmd, bg, fg, hov, width=w, height=34, parent_bg=PANEL)
            b.pack(side="left", padx=(0, 8))
            self.reg(lambda b=b, k=key: b.set_text(self.t(k)))
            if key == "r_export_html":
                self.r_export_btn = b
                b.set_enabled(False)
        self.r_state_lbl = tk.Label(cA, bg=PANEL, fg=MUTED, font=("Segoe UI", 9), anchor="w",
                                    justify="left", wraplength=1100)
        self.r_state_lbl.pack(fill="x", padx=14)
        self.reg(self._r_state_text)
        note = tk.Label(cA, bg=PANEL, fg=MUTED, font=("Segoe UI", 8), anchor="w", justify="left", wraplength=950)
        note.pack(fill="x", padx=14, pady=(2, 10))
        self.reg(lambda: note.config(text=self.t("r_note")))

        cBoot = tk.Frame(self.main, bg=PANEL)
        boot_title = tk.Label(cBoot, bg=PANEL, fg=FG, font=("Segoe UI", 10, "bold"), anchor="w")
        boot_title.pack(fill="x", padx=12, pady=(10, 2))
        self.reg(lambda: boot_title.config(text=self.t("r_boot_title")))
        boot_note = tk.Label(cBoot, bg=PANEL, fg=MUTED, font=("Segoe UI", 8), anchor="w",
                             justify="left", wraplength=1050)
        boot_note.pack(fill="x", padx=12, pady=(0, 6))
        self.reg(lambda: boot_note.config(text=self.t("r_boot_note")))
        boot_inner = tk.Frame(cBoot, bg=PANEL)
        boot_inner.pack(fill="x", padx=8, pady=(0, 8))
        self.r_boot_tree = ttk.Treeview(boot_inner, columns=("type", "detail"), show="headings", height=4)
        self.r_boot_tree.column("type", width=260, anchor="w", stretch=False)
        self.r_boot_tree.column("detail", width=800, anchor="w", stretch=True)
        self.reg(lambda: [self.r_boot_tree.heading(c, text=self.t("r_boot_" + c))
                          for c in ("type", "detail")])
        boot_sb = ttk.Scrollbar(boot_inner, orient="vertical", command=self.r_boot_tree.yview)
        self.r_boot_tree.configure(yscrollcommand=boot_sb.set)
        self.r_boot_tree.pack(side="left", fill="x", expand=True)
        boot_sb.pack(side="right", fill="y")
        self.reg(self._r_boot_render)

        cC = tk.Frame(self.main, bg=PANEL)
        self.r_cv = tk.Canvas(cC, height=310, bg=PANEL, highlightthickness=0)
        self.r_cv.pack(fill="x", padx=12, pady=8)
        self.r_cv.bind("<Configure>", lambda e: self._r_draw())

        fr = tk.Frame(self.main, bg=PANEL)
        inner = tk.Frame(fr, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=8, pady=8)
        self.rcols = ("lvl", "cat", "find", "detail")
        self.rtree = ttk.Treeview(inner, columns=self.rcols, show="headings", selectmode="browse")
        for c, w, anchor in (("lvl", 90, "w"), ("cat", 160, "w"), ("find", 280, "w"), ("detail", 500, "w")):
            self.rtree.column(c, width=w, anchor=anchor, stretch=(c == "detail"))
        self.reg(lambda: [self.rtree.heading(c, text=self.t("rc_" + c)) for c in self.rcols])
        self.rtree.tag_configure("low", foreground=GREEN)
        self.rtree.tag_configure("med", foreground=AMBER)
        self.rtree.tag_configure("high", foreground=RED)
        sb = ttk.Scrollbar(inner, orient="vertical", command=self.rtree.yview)
        self.rtree.configure(yscrollcommand=sb.set)
        self.rtree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        bar = tk.Frame(self.main, bg=PANEL, height=56)
        bar.pack_propagate(False)
        self.r_verdict = tk.Label(bar, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 11, "bold"))
        self.r_verdict.pack(side="left", padx=16)
        self.page_cards["risk"] = [(cA, KW_X), (cC, KW_X), (cBoot, KW_X), (fr, KW_EXP), (bar, KW_BAR)]

    def _r_state_text(self):
        ok, no = self.t("r_ok"), self.t("r_no")
        h = self.r_have
        values = []
        for key in RISK_METHODS:
            memory_closed = (key == "memory"
                             and "not running" in self.method_data.get("memory", {}).get("error", "").lower())
            if ((key == "roblox" and not h[key] and self.roblox_n == 0) or memory_closed):
                values.append(self.t("r_report_rb_closed"))
            else:
                values.append(ok if h[key] else no)
        self.r_state_lbl.config(text=self.t("r_state", *values))

    def _r_boot_render(self):
        tree = self.r_boot_tree
        tree.delete(*tree.get_children())
        if not self.boot_rows:
            detail = self.t("r_boot_scanning" if self.boot_busy else "r_boot_idle")
            tree.insert("", "end", values=(self.t("tab_boot"), detail))
            return
        labels = {
            "current": "r_boot_current", "windows": "r_boot_windows", "firmware": "r_boot_firmware",
            "windows_none": "r_boot_type", "firmware_none": "r_boot_firmware",
            "unavailable": "r_boot_type", "volumes_unavailable": "r_boot_type",
            "checked": "r_boot_type", "partition": "r_boot_partition", "osloader": "r_boot_osloader",
        }
        for row in self.boot_rows:
            kind = row.get("kind", "unavailable")
            detail = row.get("detail", "")
            if kind == "checked":
                detail = self.t("r_boot_checked", detail)
            elif kind in ("windows_none", "firmware_none", "unavailable", "volumes_unavailable"):
                detail = self.t(BOOT_DETAIL_KEYS[kind])
            tree.insert("", "end", values=(self.t(labels.get(kind, "r_boot_unavailable")), detail))

    def _r_boot_scan(self):
        self.boot_busy = True
        self.r_have["boot"] = False
        self._r_boot_render()
        self._r_state_text()

        def work():
            try:
                rows = collect_boot_context()
            except Exception:
                rows = [{"kind": "unavailable", "detail": "scan_failed"}]
            self.root.after(0, self._r_boot_done, rows)
        threading.Thread(target=work, daemon=True).start()

    def _r_boot_done(self, rows):
        self.boot_busy = False
        self.boot_rows = rows
        self.r_have["boot"] = True
        self._r_boot_render()
        self._r_state_text()

    @staticmethod
    def _r_color(s):
        return GREEN if s < 25 else (AMBER if s < 60 else RED)

    def r_all(self):
        for v in self.rm.values():
            v.set(True)
        self.r_run(list(self.rm))

    def r_custom(self):
        sel = [k for k, v in self.rm.items() if v.get()]
        if not sel:
            self.r_result = None
            self.r_sel = []
            self._r_render()
            return
        self.r_run(sel)

    def r_reset(self):
        self.r_generation += 1
        self.r_busy = False
        for v in self.rm.values():
            v.set(False)
        self.r_result, self.r_shown, self.r_wait, self.r_sel = None, 0.0, False, []
        self._r_state_text()
        self._r_render()

    def r_run(self, sel):
        if self.r_busy or self.r_wait:
            return
        self.r_sel, self.r_wait = list(sel), True
        self.r_result, self.r_shown = None, 0.0
        self._r_state_text()
        self._r_render()
        if "browse" in sel and not self.scanning:
            self.start_scan()
        if "data" in sel and not self.data_busy:
            self.d_refresh()
        if "trace" in sel and not self.trace_busy:
            self.t_scan()
        if "session" in sel and self.session_state != "scanning":
            self.p_history_scan()
        for key in ("usn", "newexe", "memory"):
            if key in sel and not self.method_data[key].get("busy"):
                self._scan_method_page(key)
        if "roblox" in sel and not self.persist_busy:
            self.p_scan()
        if "forensic" in sel and not self.forensic_busy:
            self.f_scan()
        if "boot" in sel and not self.boot_busy:
            self._r_boot_scan()
        self.root.after(600, self._r_poll)

    def _r_poll(self):
        if not self.r_wait:
            return
        methods_busy = any(self.method_data[k].get("busy") for k in self.method_data)
        if (self.scanning or self.data_busy or self.trace_busy or self.persist_busy or self.forensic_busy
                or self.boot_busy or self.session_state == "scanning" or methods_busy):
            self.root.after(400, self._r_poll)
            return
        self.r_wait = False
        self.r_calc()

    def r_calc(self):
        if self.r_busy:
            return
        self._r_state_text()
        use = [k for k in self.r_sel if self.r_have.get(k)]   # Roblox closed -> 'roblox' is dropped here
        if not use:
            self.r_result = None
            self._r_render()
            return
        self.r_busy = True
        self.dlog("TOOL", "log_risk_start")
        files = dict(self.results) if "browse" in use else {}
        procs = list(self.data_live_rows) if "data" in use else []
        traces = list(self.trace_rows) if "trace" in use else []
        pers = list(self.persist_rows) if "roblox" in use else []
        fors = list(self.forensic_rows) if "forensic" in use else []
        session = list(self.session_rows) if "session" in use else []
        usn = list(self.method_data["usn"].get("rows", [])) if "usn" in use else []
        unsigned = list(self.method_data["newexe"].get("rows", [])) if "newexe" in use else []
        execmem = list(self.method_data["memory"].get("rows", [])) if "memory" in use else []
        generation = self.r_generation
        names = []
        for cfg, k in ((self.bcfg, "browse"), (self.dcfg, "data"), (self.tcfg, "trace"), (self.pcfg, "roblox"),
                         (self.fcfg, "forensic"), (self.pcfg, "session"), (self.pcfg, "newexe"),
                         (self.pcfg, "memory")):
            if k in use:
                names += [n for n in cfg.active_names() if n not in names]

        def work():
            try:
                res = risk_engine(files, procs, traces, names, pers, fors,
                                  session=session, usn=usn, unsigned=unsigned, execmem=execmem)
            except Exception as e:
                self.dlog_raw("ERROR", f"risk: {e!r}")
                res = None
            self.root.after(0, self._r_done, res, generation)
        threading.Thread(target=work, daemon=True).start()

    def _r_done(self, res, generation):
        if generation != self.r_generation:
            return
        self.r_busy = False
        if res is None:
            return
        self.r_result = res
        self.dlog("OK", "log_risk_done", res["score"], len(res["findings"]))
        self._r_render()
        self._r_anim()

    def r_export_html(self):
        res = self.r_result
        if not res:
            return

        esc = lambda value: html.escape(str(value), quote=True)
        score = max(0, min(100, int(res.get("score", 0))))
        level = self.t(risk_level(score))
        color = "#f2f2f2"
        now = datetime.now().astimezone()
        stamp = now.strftime("%Y-%m-%d %H:%M:%S %Z").strip()

        cat_rows = []
        for category in RISK_CATS:
            pct = max(0, min(100, int(round(res.get("catw", {}).get(category, 0) * 100))))
            bar_color = "#e8e8e8"
            cat_rows.append(
                '<div class="signal"><div class="signal-head"><span>'
                + esc(self.t("r_cat_" + category))
                + f'</span><b>{pct}<small>/100</small></b></div>'
                + f'<div class="track"><i style="width:{pct}%;background:{bar_color}"></i></div></div>'
            )

        method_rows = []
        for method in RISK_METHODS:
            requested = method in self.r_sel
            method_error = self.method_data.get(method, {}).get("error", "")
            if requested and ((method == "roblox" and self.roblox_n == 0)
                              or (method == "memory" and "not running" in method_error.lower())):
                status, status_class = self.t("r_report_rb_closed"), "skip"
            elif requested and method == "boot" and any(
                    r.get("kind") in ("unavailable", "volumes_unavailable") for r in self.boot_rows):
                status, status_class = self.t("r_report_partial"), "skip"
            elif requested and self.r_have.get(method):
                status, status_class = self.t("r_report_scanned"), "done"
            else:
                status, status_class = self.t("r_report_not_scanned"), "muted"
            method_rows.append(
                '<div class="method"><span>' + esc(self.t("tab_" + method))
                + f'</span><b class="{status_class}">{esc(status)}</b></div>'
            )

        boot_section = ""
        if "boot" in self.r_sel and self.r_have.get("boot"):
            boot_labels = {
                "current": "r_boot_current", "windows": "r_boot_windows", "firmware": "r_boot_firmware",
                "windows_none": "r_boot_type", "firmware_none": "r_boot_firmware",
                "unavailable": "r_boot_type", "volumes_unavailable": "r_boot_type",
                "checked": "r_boot_type", "partition": "r_boot_partition", "osloader": "r_boot_osloader",
            }
            boot_report_rows = []
            for row in self.boot_rows:
                kind = row.get("kind", "unavailable")
                detail = row.get("detail", "")
                if kind == "checked":
                    detail = self.t("r_boot_checked", detail)
                elif kind in ("windows_none", "firmware_none", "unavailable", "volumes_unavailable"):
                    detail = self.t(BOOT_DETAIL_KEYS[kind])
                boot_report_rows.append(
                    f'<tr><td>{esc(self.t(boot_labels.get(kind, "r_boot_unavailable")))}</td>'
                    f'<td class="detail">{esc(detail)}</td></tr>'
                )
            boot_section = (
                '<section class="card findings"><h2>' + esc(self.t("r_boot_title"))
                + '</h2><p class="subtitle">' + esc(self.t("r_boot_note"))
                + '</p><div class="table-wrap"><table><thead><tr><th>'
                + esc(self.t("r_boot_type")) + '</th><th>' + esc(self.t("r_boot_detail"))
                + '</th></tr></thead><tbody>' + "".join(boot_report_rows) + '</tbody></table></div></section>'
            )

        session_section = ""
        if "session" in self.r_sel and self.r_have.get("session"):
            session_rows_html = []
            for row in self.session_rows:
                fmt_hist = lambda value: value.strftime("%d.%m.%Y %H:%M:%S") if value else "—"
                delta = row.get("offset")
                offset = fmt_offset(delta)
                session_rows_html.append(
                    '<tr><td>' + esc(fmt_hist(row.get("session_start"))) + '</td><td>'
                    + esc(fmt_hist(row.get("start"))) + '</td><td>' + esc(row.get("name") or self.t("p_history_no_apps"))
                    + '</td><td>' + esc(offset) + '</td><td class="detail">' + esc(row.get("source", "")) + '</td></tr>'
                )
            if not session_rows_html:
                session_rows_html.append('<tr><td colspan="5" class="empty">'
                                         + esc(self.t("r_report_empty")) + '</td></tr>')
            session_section = (
                '<section class="card findings"><h2>' + esc(self.t("r_session_title"))
                + '</h2><p class="subtitle">' + esc(self.t("r_session_note"))
                + '</p><div class="table-wrap"><table><thead><tr><th>'
                + esc(self.t("pw_rb_start")) + '</th><th>' + esc(self.t("pw_app_start"))
                + '</th><th>' + esc(self.t("pw_name")) + '</th><th>' + esc(self.t("pw_offset"))
                + '</th><th>' + esc(self.t("pw_source"))
                + '</th></tr></thead><tbody>' + "".join(session_rows_html) + '</tbody></table></div></section>'
            )

        method_evidence_sections = []
        for method in ("usn", "newexe", "memory"):
            if method not in self.r_sel or not self.r_have.get(method):
                continue
            rows = self.method_data.get(method, {}).get("rows", [])
            evidence_rows = []
            for row in rows[:300]:
                when = row.get("start")
                when_text = when.strftime("%d.%m.%Y %H:%M:%S") if when else "—"
                evidence_rows.append(
                    '<tr><td>' + esc(when_text) + '</td><td>' + esc(row.get("name", ""))
                    + '</td><td class="detail">' + esc(row.get("path", "") or "—")
                    + '</td><td class="detail">' + esc(row.get("source", "")) + '</td></tr>'
                )
            if not evidence_rows:
                evidence_rows.append('<tr><td colspan="4" class="empty">'
                                     + esc(self.t("r_report_empty")) + '</td></tr>')
            method_evidence_sections.append(
                '<section class="card findings"><h2>' + esc(self.t("tab_" + method)) + '</h2>'
                + '<p class="subtitle">' + esc(self.method_data[method].get("status", ""))
                + '</p><div class="table-wrap"><table><thead><tr><th>'
                + esc(self.t("r_report_time")) + '</th><th>' + esc(self.t("pw_name"))
                + '</th><th>' + esc(self.t("r_report_path")) + '</th><th>'
                + esc(self.t("r_report_evidence")) + '</th></tr></thead><tbody>'
                + "".join(evidence_rows) + '</tbody></table></div></section>'
            )

        finding_rows = []
        for category, weight, key, detail in res.get("findings", []):
            row_level = "low" if weight < 0.25 else ("med" if weight < 0.5 else "high")
            finding_rows.append(
                f'<tr><td><span class="pill {row_level}">{esc(self.t("r_" + row_level))}</span></td>'
                f'<td>{esc(self.t("r_cat_" + category))}</td>'
                f'<td>{esc(self.t(key))}</td><td class="detail">{esc(detail)}</td></tr>'
            )
        if not finding_rows:
            finding_rows.append(
                '<tr><td colspan="4" class="empty">' + esc(self.t("r_report_empty")) + '</td></tr>'
            )

        doc = '''<!doctype html>
<html lang="%%LANG%%"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%%TITLE%%</title><style>
:root{color-scheme:dark;--bg:#060606;--fg:#e8e8e8;--mut:#8b8b8b;--ac:#fff;--bd:#2a2a2a;--card:#0c0c0c}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 14% 0%,#ffffff0b,transparent 42%),radial-gradient(ellipse at 92% 20%,#ffffff07,transparent 38%),var(--bg);color:var(--fg);font:15px/1.55 Inter,"Segoe UI",Arial,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:46px 26px 60px}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:13px}.brand-logo{width:48px;height:48px;filter:drop-shadow(0 0 16px #ffffff18)}.brand-logo g{transform-box:view-box;transform-origin:100px 100px}.r1{animation:spin 9s linear infinite}.r2{animation:spin 14s linear infinite reverse}@keyframes spin{to{transform:rotate(360deg)}}.brand-name{font-size:15px;font-weight:800;letter-spacing:.18em}.brand-sub,.generated{color:var(--mut);font-size:12px}.generated{text-align:right}.hero,.card{border:1px solid var(--bd);border-radius:18px;background:linear-gradient(145deg,#111,#0a0a0a);box-shadow:0 18px 60px #0009}.hero{padding:30px;display:grid;grid-template-columns:250px 1fr;gap:34px;align-items:center}.score-ring{width:210px;height:210px;border-radius:50%;padding:12px;margin:auto;background:conic-gradient(from -90deg,%%COLOR%% %%SCORE%%%,#303030 %%SCORE%%%)}.score-inner{height:100%;border:1px solid #333;border-radius:50%;background:#080808;display:flex;flex-direction:column;align-items:center;justify-content:center}.score-num{font-size:58px;line-height:1;font-weight:800;letter-spacing:-.06em;color:%%COLOR%%}.score-label{margin-top:8px;color:var(--mut);font-size:11px;font-weight:800;letter-spacing:.14em}.level{display:inline-flex;margin-top:13px;padding:5px 12px;border-radius:99px;color:%%COLOR%%;background:#ffffff0d;border:1px solid #ffffff30;font-size:11px;font-weight:800;letter-spacing:.08em}.hero h1{font-size:30px;line-height:1.15;margin:0 0 8px}.subtitle{margin:0;color:var(--mut)}.stats{display:flex;gap:12px;flex-wrap:wrap;margin-top:24px}.stat{min-width:160px;padding:13px 16px;border:1px solid var(--bd);border-radius:12px;background:#080808}.stat b{display:block;font-size:22px}.stat span{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}.card{padding:22px}.card h2{margin:0 0 18px;font-size:15px;letter-spacing:.04em}.signal{margin:15px 0}.signal-head{display:flex;justify-content:space-between;gap:16px;font-size:13px}.signal-head b{font-variant-numeric:tabular-nums}.signal-head small{color:var(--mut);font-weight:500}.track{height:7px;background:#292929;border-radius:99px;overflow:hidden;margin-top:8px}.track i{height:100%;display:block;border-radius:inherit}.method{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:11px 0;border-bottom:1px solid #252525}.method:last-child{border-bottom:0}.method b{font-size:11px}.done{color:#dedede}.skip{color:#aaa}.muted{color:var(--mut)}.findings{margin-top:18px}.table-wrap{overflow:auto;border:1px solid var(--bd);border-radius:12px}table{width:100%;border-collapse:collapse;min-width:760px}th{padding:12px 14px;text-align:left;background:#151515;color:#bcbcbc;font-size:10px;text-transform:uppercase;letter-spacing:.1em}td{padding:12px 14px;border-top:1px solid #252525;vertical-align:top;font-size:12px}tbody tr:hover{background:#ffffff06}.detail{max-width:480px;word-break:break-word;color:#c8c8c8}.pill{display:inline-block;padding:3px 8px;border-radius:99px;font-size:10px;font-weight:800}.pill.low{background:#222;color:#aaa}.pill.med{background:#444;color:#eee}.pill.high{background:#eee;color:#080808}.empty{text-align:center;padding:28px;color:var(--mut)}.note{margin-top:18px;padding:15px 17px;border:1px solid #303030;border-radius:12px;background:#101010;color:#bcbcbc;font-size:12px}.footer{display:flex;justify-content:space-between;gap:16px;margin-top:20px;color:#777;font-size:11px}.print{color:var(--ac);text-decoration:none}.print:hover{text-decoration:underline}@media(max-width:760px){.wrap{padding:24px 14px 36px}.hero{grid-template-columns:1fr;padding:22px}.score-ring{width:180px;height:180px}.grid{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.generated{text-align:left}.hero h1{font-size:25px}}@media(prefers-reduced-motion:reduce){.r1,.r2{animation:none}}@media print{body{background:#fff;color:#181818;print-color-adjust:exact;-webkit-print-color-adjust:exact}.wrap{max-width:none;padding:0}.hero,.card{box-shadow:none;break-inside:avoid}.findings{break-before:auto}.print{display:none}}
@media print{body{background:#fff;color:#111}.hero,.card{background:#fff;border-color:#ccc;color:#111}.score-inner,.stat,.note{background:#fff;border-color:#ccc;color:#111}.score-num{color:#111}.brand-sub,.generated,.subtitle,.stat span,.footer,.detail,.signal-head small{color:#555}.track{background:#ddd}th{background:#eee;color:#111}td{border-color:#ddd}.pill.low{background:#eee;color:#444}.pill.med{background:#bbb;color:#111}.pill.high{background:#111;color:#fff}.findings{break-inside:auto}tr{break-inside:avoid}}
:root{--muted:var(--mut)}
</style></head><body><main class="wrap">
<header class="top"><div class="brand"><svg class="brand-logo" viewBox="0 0 200 200" role="img" aria-label="Slave"><circle cx="100" cy="100" r="98" fill="#080808"/><circle cx="100" cy="100" r="82" fill="#0e0e0e"/><circle cx="100" cy="100" r="62" fill="#151515"/><g class="r1"><circle cx="100" cy="100" r="70" fill="none" stroke="#fff" stroke-width="5" stroke-dasharray="120 320"/></g><g class="r2"><circle cx="100" cy="100" r="48" fill="none" stroke="#777" stroke-width="4" stroke-dasharray="55 247"/></g><circle cx="100" cy="100" r="11" fill="#fff"/></svg><div><div class="brand-name">SLAVE</div><div class="brand-sub">%%SUBTITLE%%</div></div></div><div class="generated">%%GENERATED_LABEL%%<br><b>%%GENERATED%%</b></div></header>
<section class="hero"><div class="score-ring"><div class="score-inner"><div class="score-num">%%SCORE%%</div><div class="score-label">%%SCORE_LABEL%%</div><div class="level">%%LEVEL%%</div></div></div><div><h1>%%TITLE%%</h1><p class="subtitle">%%SUBTITLE%%</p><div class="stats"><div class="stat"><b>%%FINDING_COUNT%%</b><span>%%FINDINGS_LABEL%%</span></div><div class="stat"><b>%%SIGNALS%%</b><span>%%SIGNALS_LABEL%%</span></div></div></div></section>
<div class="grid"><section class="card"><h2>%%BREAKDOWN_LABEL%%</h2>%%CATEGORIES%%</section><section class="card"><h2>%%METHODS_LABEL%%</h2>%%METHODS%%</section></div>
 %%BOOT_SECTION%%
 %%SESSION_SECTION%%
 %%METHOD_EVIDENCE_SECTIONS%%
 <section class="card findings"><h2>%%FINDINGS_LABEL%% <span style="color:var(--muted);font-weight:500">· %%FINDING_COUNT%%</span></h2><div class="table-wrap"><table><thead><tr><th>%%LEVEL_LABEL%%</th><th>%%CATEGORY_LABEL%%</th><th>%%FINDING_LABEL%%</th><th>%%DETAIL_LABEL%%</th></tr></thead><tbody>%%FINDINGS%%</tbody></table></div></section>
<div class="note">%%DISCLAIMER%%</div><footer class="footer"><span>Slave v%%VERSION%% · %%TITLE%%</span><a class="print" href="#" onclick="window.print();return false">%%PRINT_LABEL%%</a></footer>
</main></body></html>'''
        values = {
            "LANG": esc(self.lang), "TITLE": esc(self.t("r_export_title")),
            "SUBTITLE": esc(self.t("r_report_subtitle")),
            "GENERATED_LABEL": esc(self.t("r_report_generated")), "GENERATED": esc(stamp),
            "SCORE_LABEL": esc(self.t("r_report_score")), "SCORE": str(score),
            "COLOR": color, "LEVEL": esc(level), "FINDING_COUNT": str(len(res.get("findings", []))),
            "FINDINGS_LABEL": esc(self.t("r_report_findings")),
            "SIGNALS": str(int(res.get("signals", 0))),
            "SIGNALS_LABEL": esc(self.t("r_report_signals")),
            "BREAKDOWN_LABEL": esc(self.t("r_report_breakdown")),
            "METHODS_LABEL": esc(self.t("r_report_methods")),
            "CATEGORIES": "".join(cat_rows), "METHODS": "".join(method_rows),
            "BOOT_SECTION": boot_section,
            "SESSION_SECTION": session_section,
            "METHOD_EVIDENCE_SECTIONS": "".join(method_evidence_sections),
            "FINDINGS": "".join(finding_rows), "LEVEL_LABEL": esc(self.t("rc_lvl")),
            "CATEGORY_LABEL": esc(self.t("r_report_category")),
            "FINDING_LABEL": esc(self.t("r_report_finding")),
            "DETAIL_LABEL": esc(self.t("r_report_detail")),
            "DISCLAIMER": esc(self.t("r_report_disclaimer")),
            "PRINT_LABEL": esc(self.t("r_report_print")), "VERSION": esc(VERSION),
        }
        doc = re.sub(r"%%([A-Z_]+)%%", lambda match: values.get(match.group(1), match.group(0)), doc)

        initial = f"slave_results_{now:%Y%m%d_%H%M%S}.html"
        filename = filedialog.asksaveasfilename(
            defaultextension=".html", initialfile=initial,
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")],
        )
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(doc)
            self.dlog("OK", "log_saved", filename)
            messagebox.showinfo("Slave", self.t("r_export_done"), parent=self.root)
        except OSError as e:
            messagebox.showerror("Slave", self.t("r_export_fail", e), parent=self.root)

    def _r_render(self):
        try:
            t = self.rtree
            t.delete(*t.get_children())
            res = self.r_result
            if not res:
                self.r_shown = 0.0
                self.r_export_btn.set_enabled(False)
                self.r_verdict.config(text=self.t("r_idle"), fg=MUTED)
                self._r_draw()
                return
            self.r_export_btn.set_enabled(True)
            lvl_key = {"low": "r_low", "med": "r_med", "high": "r_high"}
            for cat, w, key, detail in res["findings"][:300]:
                lv = "low" if w < 0.25 else ("med" if w < 0.5 else "high")
                t.insert("", "end", tags=(lv,),
                         values=(self.t(lvl_key[lv]), self.t("r_cat_" + cat), self.t(key), detail))
            self.r_verdict.config(
                text=self.t("r_summary", self.t(risk_level(res["score"])), len(res["findings"]), res["signals"]),
                fg=self._r_color(res["score"]))
            self._r_draw()
        except tk.TclError:
            pass

    def _r_anim(self):
        if not self.r_result:
            return
        target = self.r_result["score"]
        diff = target - self.r_shown
        if abs(diff) < 0.6:
            self.r_shown = float(target)
            self._r_draw()
            return
        self.r_shown += diff * 0.14 + (0.5 if diff > 0 else -0.5)
        self._r_draw()
        self.root.after(30, self._r_anim)

    def _r_draw(self):
        cv = self.r_cv
        try:
            cv.delete("all")
            W = max(cv.winfo_width(), 640)
            s = self.r_shown
            cx, cy, r = 170, 150, 115
            box = (cx - r, cy - r, cx + r, cy + r)
            for a, b, col in ((0, 25, GREEN), (25, 60, AMBER), (60, 100, RED)):
                cv.create_arc(*box, start=180 - b * 1.8, extent=(b - a) * 1.8, style="arc",
                              width=18, outline=lerp(PANEL, col, 0.75))
            ang = math.radians(180 - s * 1.8)
            cv.create_line(cx, cy, cx + (r - 26) * math.cos(ang), cy - (r - 26) * math.sin(ang),
                           fill=FG, width=3, capstyle="round")
            cv.create_oval(cx - 7, cy - 7, cx + 7, cy + 7, fill=FG, outline="")
            cv.create_text(cx, cy + 36, text=str(int(round(s))), fill=self._r_color(s), font=("Segoe UI", 26, "bold"))
            cv.create_text(cx, cy + 64, text=self.t("r_gauge"), fill=MUTED, font=("Segoe UI", 9, "bold"))
            cv.create_text(cx - r, cy + 12, text="0", fill=MUTED, font=("Segoe UI", 8))
            cv.create_text(cx + r, cy + 12, text="100", fill=MUTED, font=("Segoe UI", 8))
            x0, x1 = 400, W - 70
            for i, c in enumerate(RISK_CATS):
                y = 14 + i * 42
                w = self.r_result["catw"][c] if self.r_result else 0.0
                cv.create_text(x0, y, text=self.t("r_cat_" + c), anchor="w", fill=FG, font=("Segoe UI", 10, "bold"))
                rounded_rect(cv, x0, y + 12, x1, y + 22, 5, fill=LINE, outline="")
                if w > 0:
                    rounded_rect(cv, x0, y + 12, max(x0 + 10, x0 + (x1 - x0) * w), y + 22, 5,
                                 fill=self._r_color(w * 100), outline="")
                cv.create_text(W - 20, y + 17, text=str(int(round(w * 100))), anchor="e",
                               fill=MUTED, font=("Segoe UI", 9))
        except tk.TclError:
            pass

    # ---------- guns.lol page inside the app ----------
    def open_guns(self):
        if self.guns_proc and self.guns_proc.poll() is None:
            return
        try:
            importlib.import_module("webview")
        except Exception:
            if messagebox.askyesno("Slave", self.t("gw_need")):
                self._guns_install()
            else:
                webbrowser.open(GUNS_URL)
            return
        self._guns_launch()

    def _guns_install(self):
        self.dlog("INFO", "ap_installing")

        def done(ok, out):
            importlib.invalidate_caches()
            if ok:
                self._guns_launch()
            else:
                messagebox.showerror("Slave", self.t("ap_install_fail", out))
                webbrowser.open(GUNS_URL)

        def work():
            try:
                r = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pywebview"],
                                   capture_output=True, text=True, timeout=600, creationflags=NOWIN)
                ok, out = r.returncode == 0, (r.stdout + r.stderr).strip()[-600:]
            except Exception as e:
                ok, out = False, str(e)
            self.root.after(0, done, ok, out)

        threading.Thread(target=work, daemon=True).start()

    def _guns_launch(self):
        import atexit
        import base64
        cv = self.cr_cv
        try:
            sc = max(1.0, self.root.winfo_fpixels("1i") / 96.0)
        except tk.TclError:
            sc = 1.0
        x, y = int(cv.winfo_rootx()), int(cv.winfo_rooty())
        w, h = int(cv.winfo_width() / sc), int(cv.winfo_height() / sc)
        labels = json.dumps({"copy": self.t("gw_copy"), "copied": self.t("gw_copied"),
                             "close": self.t("close")}, ensure_ascii=False)
        lab = base64.b64encode(labels.encode("utf-8")).decode("ascii")
        args = ["--guns", GUNS_URL, str(x), str(y), str(max(300, w)), str(max(300, h)), lab]
        if getattr(sys, "frozen", False):
            cmd = [sys.executable] + args
        else:
            cmd = [sys.executable, os.path.abspath(__file__)] + args
        try:
            self.guns_proc = subprocess.Popen(cmd, creationflags=NOWIN)
        except Exception as e:
            self.dlog_raw("ERROR", f"guns window: {e!r}")
            webbrowser.open(GUNS_URL)
            return
        proc = self.guns_proc
        atexit.register(lambda: proc.poll() is None and proc.terminate())
        self.root.after(3000, self._guns_check, proc)

    def _guns_check(self, proc):
        rc = proc.poll()
        if rc not in (None, 0):
            self.dlog_raw("WARN", f"guns window stopped (exit {rc}), opening browser instead")
            webbrowser.open(GUNS_URL)

    def close_guns(self):
        p = self.guns_proc
        if p and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass

    # ---------- Credits page ----------
    def _build_credits(self):
        fr = tk.Frame(self.main, bg=PANEL)
        cv = self.cr_cv = tk.Canvas(fr, bg=PANEL, highlightthickness=0)
        cv.pack(fill="both", expand=True, padx=8, pady=8)
        self.cr_avatar = None
        try:
            self.cr_avatar = tk.PhotoImage(data=AVATAR_B64)
        except tk.TclError:
            pass
        self.cr_guns = GunsLink(cv, PANEL)
        self.cr_guns.command = self.open_guns
        self.cr_guns_win = cv.create_window(0, 0, window=self.cr_guns, anchor="nw")
        cv.bind("<Configure>", lambda e: self._cr_draw())
        self.reg(self._cr_draw)
        self.page_cards["credits"] = [(fr, KW_EXP)]

    def _cr_draw(self):
        cv = self.cr_cv
        try:
            cv.delete("cr")
            W, H = cv.winfo_width(), cv.winfo_height()
            if W < 300 or H < 250:
                return
            av = self.cr_avatar
            aw, ah = (av.width(), av.height()) if av else (230, 300)
            pad = 26
            pw_, ph_ = aw + pad * 2, ah + pad * 2
            px2 = W - 60
            px1 = px2 - pw_
            py1 = H / 2 - ph_ / 2
            py2 = py1 + ph_
            if av:
                cv.create_image((px1 + px2) / 2, (py1 + py2) / 2, image=av, tags="cr")
            else:
                cv.create_text((px1 + px2) / 2, (py1 + py2) / 2, text="KE", fill=FG,
                               font=("Segoe UI", 48, "bold"), tags="cr")

            x0 = 60
            maxw = max(200, int(px1 - 40 - x0))
            y = H / 2 - 120
            cv.create_text(x0, y, text=self.t("cr_title"), anchor="w", fill=MUTED,
                           font=("Segoe UI", 10, "bold"), tags="cr")
            y += 52
            for dx, dy in ((-2, 0), (2, 0), (0, -2), (0, 2), (-2, -2), (2, 2), (-2, 2), (2, -2)):
                cv.create_text(x0 + dx, y + dy, text="KillerEmperor", anchor="w",
                               fill=lerp(PANEL, ACCENT, 0.25), font=("Segoe UI", 38, "bold"), tags="cr")
            name = cv.create_text(x0, y, text="KillerEmperor", anchor="w", fill=ACCENT,
                                  font=("Segoe UI", 38, "bold"), tags="cr")
            bb = cv.bbox(name)
            bw, bh = 104, 30
            if bb[2] + 18 + bw < px1 - 30:
                bx, by = bb[2] + 18, y - bh / 2 + 3
                y += 34
            else:
                bx, by = x0, y + 30
                y += 34 + bh + 10
            rounded_rect(cv, bx - 4, by - 4, bx + bw + 4, by + bh + 4, bh // 2 + 4,
                         fill=lerp(PANEL, ACCENT2, 0.35), outline="", tags="cr")
            rounded_rect(cv, bx, by, bx + bw, by + bh, bh // 2, fill=ACCENT2, outline="", tags="cr")
            rounded_rect(cv, bx + 4, by + 2, bx + bw - 4, by + bh * 0.5, 6,
                         fill=lerp(ACCENT2, "#ffffff", 0.3), outline="", tags="cr")
            cv.create_text(bx + bw / 2, by + bh / 2, text="★ OWNER", fill="#ffffff",
                           font=("Segoe UI", 11, "bold"), tags="cr")

            y += 36
            cv.create_text(x0, y, text=self.t("cr_solo"), anchor="nw", fill=FG,
                           font=("Segoe UI", 13, "bold"), width=maxw, tags="cr")
            y += 34
            cv.create_text(x0, y, text=self.t("cr_socials"), anchor="nw", fill=MUTED,
                           font=("Segoe UI", 11), width=maxw, tags="cr")
            y += 52
            cv.coords(self.cr_guns_win, x0 - 4, y)
        except tk.TclError:
            pass

    # ---------- logs ----------
    def _build_logpanel(self):
        PW = self.PW
        self.logpanel = tk.Frame(self.root, bg=PANEL, width=int(self._log_w))
        self.logpanel.pack(side="right", fill="y")
        self.logpanel.pack_propagate(False)
        self.main = tk.Canvas(self.root, bg=BG, highlightthickness=0, bd=0)
        self.main.pack(side="left", fill="both", expand=True)
        self.main.pack_propagate(False)

        inner = tk.Frame(self.logpanel, bg=PANEL, width=PW)
        inner.pack(side="left", fill="y")
        inner.pack_propagate(False)
        tk.Frame(inner, bg=LINE, width=1).pack(side="left", fill="y")
        body = tk.Frame(inner, bg=PANEL)
        body.pack(side="left", fill="both", expand=True)

        top = tk.Frame(body, bg=PANEL, height=64)
        top.pack(fill="x")
        top.pack_propagate(False)
        title = tk.Label(top, bg=PANEL, fg=FG, font=("Segoe UI", 12, "bold"))
        title.pack(side="left", padx=(14, 0))
        self.reg(lambda: title.config(text=self.t("logs_title")))
        small = ("Segoe UI", 9, "bold")
        for key, cmd, w, padx in (("close", self.toggle_logs, 76, (4, 12)), ("copy", self.copy_logs, 98, 4),
                                  ("clear", self.clear_logs, 84, 4)):
            b = RoundButton(top, "", cmd, CARD, FG, LINE, width=w, height=28, font=small)
            b.pack(side="right", padx=padx)
            self.reg(lambda b=b, k=key: b.set_text(self.t(k)))

        self.logbox = tk.Text(body, bg=BG, fg=FG, font=("Consolas", 9), wrap="word", relief="flat",
                              padx=10, pady=8, state="disabled", borderwidth=0, highlightthickness=0,
                              cursor="arrow", insertwidth=0, spacing1=2)
        self.logbox.pack(fill="both", expand=True)
        colors = {"INFO": MUTED, "TOOL": ACCENT, "OK": GREEN, "WARN": AMBER, "ERROR": RED}
        self.logbox.tag_config("ts", foreground=MUTED)
        for lvl, col in colors.items():
            self.logbox.tag_config(lvl, foreground=col)
            self.logbox.tag_config("b_" + lvl, foreground=col, font=("Consolas", 9, "bold"))
        for ts, level, text in self.log_lines:
            self._log_insert(ts, level, text)

    def toggle_logs(self):
        self.logs_open = not self.logs_open
        if self.logs_open:
            self.btn_logs.set_text("Logs", FG)
            self.logbox.see("end")
        self._slide_id += 1
        self._slide(self._slide_id, self.PW if self.logs_open else 0)

    def _slide(self, sid, target):
        if sid != self._slide_id:
            return
        diff = target - self._log_w
        cur = target if abs(diff) <= 3 else self._log_w + diff * 0.25 + (3 if diff > 0 else -3)
        cur = max(0, min(self.PW, cur))
        self._log_w = cur
        self.logpanel.config(width=int(cur))
        if cur != target:
            self.root.after(14, self._slide, sid, target)

    def dlog(self, level, key, *args):
        self.dlog_raw(level, self.t(key, *args))

    def dlog_raw(self, level, text):
        ts = datetime.now().strftime("%H:%M:%S")
        self.root.after(0, self._dlog_ui, ts, level, str(text))

    def _log_insert(self, ts, level, text):
        t = self.logbox
        t.config(state="normal")
        t.insert("end", ts + " ", "ts")
        t.insert("end", f"{level:<5} ", "b_" + level)
        t.insert("end", text + "\n", level)
        if int(t.index("end-1c").split(".")[0]) > 1500:
            t.delete("1.0", "400.0")
        t.see("end")
        t.config(state="disabled")

    def _dlog_ui(self, ts, level, text):
        self.log_lines.append((ts, level, text))
        if len(self.log_lines) > 1500:
            del self.log_lines[:400]
        self._log_insert(ts, level, text)
        if level == "ERROR" and not self.logs_open:
            self.btn_logs.set_text("Logs ●", RED)

    def clear_logs(self):
        self.log_lines = []
        self.logbox.config(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.config(state="disabled")

    def copy_logs(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.logbox.get("1.0", "end"))
        self.dlog("INFO", "log_logs_copied")

    # ---------- animation / lifecycle ----------
    def _animate(self):
        try:
            self._tick()
        except tk.TclError:
            pass
        self.root.after(50, self._animate)

    def _tick(self):
        now = time.time()
        self._zn = getattr(self, "_zn", 0) + 1
        if self._zn % 5 == 0:
            self.veil.zsync()
        t = now - self._t0
        method_busy = any(value.get("busy") for value in self.method_data.values())
        busy = (self.scanning or self.data_busy or self.trace_busy or self.persist_busy
                or self.forensic_busy or self.r_busy or self.session_state == "scanning"
                or self.boot_busy or method_busy)
        err = bool(self.status) and self.status[0] == "status_error"
        color = AMBER if busy else (RED if err else GREEN)
        pulse = 0.5 + 0.5 * math.sin(t * (5.0 if busy else 1.6))
        dt = max(0.0, min(0.2, now - self._orb_last))
        self._orb_last = now
        speed = 2.6 if busy else 1.0
        shades = (color, lerp(color, PANEL, 0.30), lerp(color, PANEL, 0.55))
        for i, (arc, spec) in enumerate(zip(self.orb_arcs, ORB_ARCS)):
            self._orb_ang[i] = (self._orb_ang[i] + spec[3] * speed * dt) % 360
            self.hdr.itemconfig(arc, start=self._orb_ang[i], outline=shades[i])
        radius = 17 + 3 * pulse
        self.hdr.coords(self.orb_glow, 34-radius, 32-radius, 34+radius, 32+radius)
        self.hdr.itemconfig(self.orb_glow, fill=lerp(PANEL, color, 0.08 + 0.10 * pulse))
        self.hdr.itemconfig(self.orb, fill=lerp(color, "#ffffff", 0.3 * pulse))

        dots = "." * (int(t * 3) % 4) if busy else ""
        cur = {"data": self.dcfg, "trace": self.tcfg, "persist": self.pcfg,
               "forensic": self.fcfg}.get(self.page, self.bcfg)
        eng = f"  ·  Everything: {self.engine}" if self.page == "browse" else ""
        cfg_txt = f"  ·  Config: {cur.active}" if self.page not in ("risk", "credits") else ""
        self.hdr.itemconfig(self.sub_txt, text=f"{self.t(*self.status)}{dots}{eng}{cfg_txt}")
        # Keep the content canvas still; animation is reserved for the startup sequence.

    def reveal(self):
        set_alpha(self.root, 0.0)
        self.root.deiconify()
        self.root.lift()

        def fade(a=0.0):
            a += 0.07
            set_alpha(self.root, min(a, 1.0))
            if a < 1.0:
                self.root.after(16, fade, a)
            else:
                self._apply_win_alpha()
                self.veil.sync()
        fade()
        threading.Thread(target=self._boot, daemon=True).start()

    def _boot(self):
        state = start_everything()
        self.dlog("WARN" if state == "missing" else "OK", "log_ev_" + state)
        time.sleep(3.0 if state == "started" else 0.7)
        self.root.after(0, self.start_scan)

    def toggle_scan(self):
        if self.page == "data":
            self.d_refresh()
        elif self.page == "trace":
            self.t_scan()
        elif self.page == "persist":
            self.p_scan()
        elif self.page == "session":
            self.p_history_scan()
        elif self.page in ("usn", "newexe", "memory"):
            self._scan_method_page(self.page)
        elif self.page == "forensic":
            self.f_scan()
        elif self.page == "risk":
            self.r_all()
        elif self.page == "credits":
            pass
        elif self.scanning:
            self.stop = True
            self.dlog("WARN", "log_stop_req")
        else:
            self.start_scan()


# ============================== PASSCODE GATE ==============================
# The passcode is never stored in plain text: only a salted PBKDF2 hash lives here.
_PC_SALT = bytes.fromhex("29d59536557384f2735b38d8e44f6404")
_PC_HASH = "224f90047786c462c0295e7cb0991688f2f3a77b0548f5604609a22182c06b43"
_PC_ITER = 200000

_DISCORD_PTS = [
    (20.32, 4.37), (15.45, 2.85), (14.82, 4.10), (13.5, 3.88), (12, 3.84), (10.5, 3.88),
    (9.33, 4.10), (8.71, 2.85), (3.83, 4.37), (1.6, 7.6), (0.4, 12.0), (0.10, 18.06),
    (2.2, 20.0), (6.09, 21.17), (7.31, 19.18), (5.43, 18.18), (5.30, 17.05), (6.3, 16.6),
    (9.0, 17.5), (12, 17.9), (15.0, 17.5), (18.3, 16.6), (19.25, 17.05), (19.1, 18.18),
    (17.3, 19.18), (18.5, 21.17), (21.8, 20.0), (23.9, 18.06), (23.6, 12.0), (22.4, 7.6),
]


def check_passcode(text):
    d = hashlib.pbkdf2_hmac("sha256", text.encode("utf-8"), _PC_SALT, _PC_ITER)
    return hmac.compare_digest(d.hex(), _PC_HASH)


GUNS_GRAY_B64 = (
    "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")
GUNS_PURPLE_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAEUAAABQCAYAAABPlrgBAAALHUlEQVR42t2cfbAVdRnHP7vngKiElJNNZaWTpEgTA74AgghkiJRRFlOYDVlpjPQiMxkp5pAvSL6QkWQ0DBWMSOhMVloNkYABUmY2AxmZvWjptSwISy+Xe89uf+z3F89dd/fsHnbvvafz1+Xcc/fs7/v7Ps/zfb7Pb/HWz+6kjV8+EABjgTuAccA/gK8BX9RnLgDmAiOA/cAm4MvAvwEPCOMXrbcxIG5BQ4HVwGigARwHLAb2AZ3A1wWee50NnAW8G+jRe2Ec6XZmSSgwRosxNb0XAl8BvqHPNfReICDOAy43f8P/Cyhud/8GdBmQPMMi95ma3vP1cwO4TmD2xIFpZ1DcLv8BWGPes+HlpYSdB7wCWAUcY8Bse1BqAiEEftNC6DWA05V0A73ntSsonlnUEOAq4EaBUysIag9wCXCFrue3Iyg1kzDfAWwFlgBHp4RKXrYtVVVqAL7fRuxwCXI4cCewETjDVJZWrwtwhCrVse3CFMeOBjAN2AHM0w4HprIcTmlvAKcAnwcCv03YcaTC5MfASBP/fkqpDmKVKK/mmQecOlAVrW/YMRZYAYyPleK0Mu0b5oQ5WeTpb4cCF/oDNFzcLl+lZDre5I40djTM73YCv2ghrALgOH+AscPT4k5VIl2i3Wtk5I6GCbUHgXOACQJyYYKoy1LIPvC0P8DYEQLzge3AudIRWfrDgbUP+CQwHXjIMOZ2KV4/A5jQSP2ngXX9nVM8w44TgOVq9d2C6xkLcWD9TEDuijEuAA4CB5qEi6/v+SvwIeBZv5/Z4SrFXLHjApM7stjhVO3twAwBUo+p3SPlsYxMyUUN89nbZCdsA/x6P7HD3czxwJeAi2LhQEYyrQN7Jc3XxsLPUyiMUcWakFCBXLmuAx3ApcAD1rTy+4kdDeCD2pmLYkIsix11k0zXxpKvu8Y8YIsA6UkAxIXL94DJAqRu847fh+xwQuy1csruBt6UQ4g59hyUxTgD2G0AdqCdCGxQCzAsISe5EPo9cBnwHuBJ0xgGfWlHOjAawCzgVuAkcxPNhFgNeBi4UnnHbqa7xkeAG4DXmzCqJVzrPuCjqlY2yfeZ8+bo3gBepaR3nwDJww5f7LhOPc92LdQ37DhBjPumAGnEFG3cpfuWABlskvzLXvWK2dEjui9TFWjGDhcqNanSzxp21GI7Oxe4SeHYSGBH0uZ3prGjSlBsZRkOfAFYYG4kq7K4RHsAuEXGUZfuMTDi7kSB8YEcFcv2PweBv9Pbu60cFJe9XYu/HBgVW3Cz3LFTIO5M0DKoUt0CvC4ld6SBAvAv4JnYe5m0KqOyBHLAlqpvGWVo6meEi68wuwmYKkDiueMNwDrgLgGSljuyyvl24HnTgVfGFFtZzpbCHJuzxXd//zv1LZti+cZ95v1E5vLxOXJHUsIeBDyl/JSb8mUYQIuBzQIkq8VHrHCVZ7VE1qYEdhxLNN27xwBSy3nPodn0nfJz/2h6Ispmis0d44CvyivNww5Xpv8MfE4LTsodUwTIyfQeaJETEBdWtynZdzbplFsGxVaWwRJTi8SUPPZgzWiFq9V3+DHQhgDX6tr1HJUljSEvEY0uNsQ2kjJBsfbgGFWWSTlKoq0su2QM/zDGDgfaGEn0cTlY12zzOoGfxowrysopXqwDvVL+xaScLb6vXVsEnClA/JhMD4HPyBwalyMnJQEfmvt1+eiSguZ1LlAsO94m5G9W2c2yB23H+4g60SUSZbayNIA3A/erag2l2MgibFKapxewInOBUjPUXyDzeEoBdvhERyGmAY8mtPg+0VGI7cA7zW7nZYctzY8QnTwgdo23ijF5Hf1UUHx6D4fuV98yvAA7ngNmywT6j8kdjtqj5GGsAF5TUIjZ79mrcJ4M/CRW4QL1RONbkR5+Qu4IJKa2AecXZMd3ZOvdG1uou+4CXXdGjuumhYoPrAcmyoY4IGshqQrNyiPrk6qPZ770FMn0WTkri2dc8KslwzHl1LFjhPLGzJxNXFrn/ARwjdE3g4FuohmP1TJuM07TvfSQcr4tK5kOUZjsFCBBTnZ4wErR9C6zk7bUfljsmNkiO5zrdrNYeI/5nm597gkpVrtZAG8B3hgDKhcog7SgBUSnerJi3N7oHuBd8kQ7EnLHMKJJ/hqiw3mNApXFsnCTGsWFwD9jYe4AfkFNqFW0bgx6ViugzAEupPngyd7oKjWAD5iFWr90oszjS3OwLgl4Xwl7vvqWHSbU04TYjtjiXSkuDEpdZk3YpAK4378gRq2OlW5n/taI5r+LFJI9BVsJV643S3w9ZTavp8m9PaakOyRWhkeYzcoNyrACJs37NGKomy9xY8fTZABNNQss2nC679ovQAbFnfYUxd0t5dwTU7dIq9RM4g/zhM9jTT7swuZHAuQIszsNxe1CyfSpLcj0JIlwjsyk7hxFolv+7yrdC/Q+MtpVVNX6atFfzOgkHeInCfEuYyydq8qyFDiqYDJN2/kAeCXRycU04eV826MUqj/XhsTVqyfNFNJ7TtQUlMfVkHkpQseBdYbK72SBsVxKcnTBUps3hD6WcD+eyS+ni7k3EJ2JtaXYbc6T6ry9Imzx1s/udPG2SF9Q1MMIKHd+5HZ7n1qCjgQL4DLlr2EJEsL+e47Ub61IovVN9bhRVSXrAkFMr4SUP1CzITTDaClnCawVY4fFwtVqqEB90XqT+wrllNDs9nx1nbUUusV7JY9qXi5kPq776JKXuwW4OEH72K55D9GRjlsz1pHLeXOUPUA0a92mOA0rXHizKUEoY+pTqnjXS4PY8LZW54tqVZZJPhRmSJId6S6+m2i6v6yF/FJ2GNWV0EmwKK3VuUXg7Y6NXlp6+Qk5oyaDaPPhXrykV5CQv1wy7dIGnseh4xne4d6znxDLofFU9hctZxW8fLNYazLtkuW4WF20fdiJMkGxbHlc3kWzMaPL+j0Vgxcay+BO6aWHYoCVtgtZxs4K4PsZYWQ753rMS6kixzxHdEDnciXTWlnsSEu0pITSFSqHr1afYeWy+3kj8CzR2HR0rKKVkVN84JdED0N2xCYNlcRr1s3UgD9pZ9yw2jf24MOS/DNUys+Uaf18EfuvQJfeoY2sio3/k/l5Ve8klb3RRAdx75ar1m1i3XkeE4meuDi6qMHThLWTtBGVVsV6Tvp6EnTbjBFMTBPYAfp2tQyfLknrONZOFiiVCkq/wE7VDBu8FE1gRxErZfz4JVDdgTCXQw8weP0NCjE2hBlZ32mJPSrrZeQWF8IjjW9SGwigkOK3ZC3itwX+Jm9e+URRz7UvQCly3Y0VXHOmqlxlbKkKFLeLP1ClaqmFT/FZPCKnvywG9hkoTpLvVwdLSTLcJdc5ROf6gyoSbtXH0AG+XSLVXdN3DPDeqtZQJSiOGQ8Cvy65aQuJjpLWqKAJrRKU0Nz0vSXmAMe4CUQDuNJ94qqf9wlNCO2lwOwlZ5M4raQ2ok9BcTf/DNGpKEqm+8ntVH3iCdcTW8qcEQXtVpKTNMtmNZSH66HakczWdgUF0xSuO8wc4BrBQcB3ZV+U7iH3FSjupjcAf2lhIXb610U0zbyYyLAuXdn2FSiuPO8jOkFZpHO2078tRCeTrpEt4VWRV/ryuWTn2a7h0OnrMCc7OolOX04HfsXLj5S1LSiuT9nFoacrgiafrRG5eFOInhzrpsT5zkAAxSbY9SkJ1x0Vcw7ftcDbic7Jlj7fGSigOAZsJTpQ487CBvR+dP9RqdXrOfS//VXKjv4ExfUpLxEdlYDeY5MDREfFJhM9QtNn7LCv/vhfMRwjVqoazSY6fNxBdJjPPmDZL8P9/wIJ1qCHcXuZtAAAAABJRU5ErkJggg==")


class GunsLink(tk.Canvas):
    """guns.lol logo: grey normally, purple on hover, click opens the profile."""

    def __init__(self, parent, bg):
        super().__init__(parent, width=77, height=88, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        self.img_g = tk.PhotoImage(data=GUNS_GRAY_B64)
        self.img_p = tk.PhotoImage(data=GUNS_PURPLE_B64)
        self.item = self.create_image(4, 4, anchor="nw", image=self.img_g)
        self.bind("<Enter>", lambda e: self.itemconfig(self.item, image=self.img_p))
        self.bind("<Leave>", lambda e: self.itemconfig(self.item, image=self.img_g))
        self.bind("<Button-1>", lambda e: (getattr(self, "command", None)
                                           or (lambda: webbrowser.open(GUNS_URL)))())


AVATAR_B64 = (
    "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"
)


class DiscordIcon(tk.Canvas):
    SIZE = 40

    def __init__(self, parent, bg):
        S_ = self.SIZE
        super().__init__(parent, width=S_, height=S_, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        k = S_ / 26.0
        off = (S_ - 24 * k) / 2
        pts = []
        for x, y in _DISCORD_PTS:
            pts += [off + x * k, off + y * k]
        self.shape = self.create_polygon(pts, fill=MUTED, outline=MUTED, width=2, joinstyle="round")
        for cx in (8.02, 15.99):
            self.create_oval(off + (cx - 2.0) * k, off + (12.91 - 2.3) * k,
                             off + (cx + 2.0) * k, off + (12.91 + 2.3) * k, fill=bg, outline=bg)
        self.bind("<Enter>", lambda e: self.itemconfig(self.shape, fill="#5865F2", outline="#5865F2"))
        self.bind("<Leave>", lambda e: self.itemconfig(self.shape, fill=MUTED, outline=MUTED))
        self.bind("<Button-1>", lambda e: webbrowser.open(DISCORD_URL))


class PasscodeGate:
    def __init__(self, root, lang, on_ok):
        self.root, self.lang, self.on_ok = root, lang, on_ok
        self.items = []
        w = self.win = tk.Toplevel(root)
        w.title("Slave")
        w.configure(bg=BG)
        W, H = 480, 700
        w.geometry(f"{W}x{H}+{(w.winfo_screenwidth() - W) // 2}+{max(0, (w.winfo_screenheight() - H) // 3)}")
        w.resizable(False, False)
        w.protocol("WM_DELETE_WINDOW", root.destroy)

        langbar = tk.Frame(w, bg=BG)
        langbar.pack(fill="x", padx=14, pady=(12, 0))
        self.lbtn = {}
        for code in reversed(LANGS):
            b = RoundButton(langbar, code.upper(), lambda c=code: self.set_lang(c), CARD, MUTED, LINE,
                            width=44, height=28, font=("Segoe UI", 9, "bold"), parent_bg=BG)
            b.pack(side="right", padx=(6, 0))
            self.lbtn[code] = b

        logo_canvas = tk.Canvas(w, width=126, height=126, bg=BG, highlightthickness=0, bd=0)
        logo_canvas.pack(pady=(6, 0))
        self.login_logo = draw_slave_mark(logo_canvas, 63, 63, 40, BG)
        self.login_logo_canvas = logo_canvas
        self.login_logo_started = time.time()
        tk.Label(w, text="SLAVE  ·  VERSION 2.0", bg=BG, fg=FG,
                 font=("Segoe UI", 12, "bold")).pack(pady=(0, 2))
        tk.Label(w, text=CREDIT, bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack()
        self._label("splash_sub", dict(fg=MUTED, font=("Segoe UI", 9)), pady=(2, 10))

        ent_kw = dict(bg=CARD, fg=FG, insertbackground=FG, relief="flat", font=("Segoe UI", 13),
                      highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT)

        # nickname
        self._label("gate_nick", dict(fg=MUTED, font=("Segoe UI", 8, "bold")), anchor="w", padx=40, pady=(0, 4))
        self.nick_var = tk.StringVar(value=str(load_config().get("nick") or "")[:NICK_MAX])
        self.nick_entry = tk.Entry(w, textvariable=self.nick_var, **ent_kw)
        self.nick_entry.pack(fill="x", padx=40, ipady=8)
        self.nick_entry.bind("<Return>", lambda e: self.entry.focus_set())
        self.nick_var.trace_add("write", lambda *_: self._clip_nick())

        # passcode
        self._label("gate_pass", dict(fg=MUTED, font=("Segoe UI", 8, "bold")), anchor="w", padx=40, pady=(14, 4))
        self.var = tk.StringVar()
        self.entry = tk.Entry(w, textvariable=self.var, show="•", **ent_kw)
        self.entry.pack(fill="x", padx=40, ipady=8)
        self.entry.bind("<Return>", lambda e: self.submit())
        (self.entry if self.nick_var.get().strip() else self.nick_entry).focus_set()
        self.err = tk.Label(w, text="", bg=BG, fg=RED, font=("Segoe UI", 9))
        self.err.pack(anchor="w", padx=40, pady=(6, 0))

        self._label("gate_discord", dict(fg=MUTED, font=("Segoe UI", 9), wraplength=400, justify="center"),
                    pady=(8, 4))
        DiscordIcon(w, BG).pack()

        self.ok = tk.BooleanVar(value=False)
        row = tk.Frame(w, bg=BG)
        row.pack(fill="x", padx=36, pady=(22, 0))
        self.chk = tk.Checkbutton(row, variable=self.ok, command=self._tick_changed, bg=BG, fg=MUTED,
                                  selectcolor=CARD, activebackground=BG, activeforeground=FG,
                                  highlightthickness=0, bd=0, cursor="hand2", font=("Segoe UI", 9),
                                  justify="left", anchor="w", wraplength=380)
        self.chk.pack(anchor="w")
        self.items.append((self.chk, "gate_consent"))

        self.btn = RoundButton(w, "", self.submit, ACCENT, ONACC, HOVER, width=160, height=38, parent_bg=BG)
        self.btn.pack(pady=22)
        self.btn.set_enabled(False)
        self.apply_lang()
        self._animate_login_logo()

    def _animate_login_logo(self):
        try:
            elapsed = time.time() - self.login_logo_started
            state = "error" if self.err.cget("text") == self.t("gate_wrong") else "splash"
            animate_slave_mark(self.login_logo_canvas, self.login_logo, state, elapsed)
            self.login_logo_canvas.after(50, self._animate_login_logo)
        except tk.TclError:
            pass

    def _clip_nick(self):
        s = self.nick_var.get()
        if len(s) > NICK_MAX:
            self.nick_var.set(s[:NICK_MAX])
        if self.err.cget("text") == self.t("gate_nick_empty") and s.strip():
            self.err.config(text="")

    def _label(self, key, kw, anchor="center", padx=0, pady=0):
        lb = tk.Label(self.win, bg=BG, **kw)
        if anchor == "center":
            lb.pack(padx=padx, pady=pady)
        else:
            lb.pack(anchor=anchor, padx=padx, pady=pady)
        self.items.append((lb, key))
        return lb

    def t(self, key):
        return tx(self.lang, key)

    def apply_lang(self):
        for wd, key in self.items:
            wd.config(text=self.t(key))
        self.btn.set_text(self.t("gate_enter"))
        for code, b in self.lbtn.items():
            if code == self.lang:
                b.set_colors(ACCENT2, "#ffffff", HOVER2)
            else:
                b.set_colors(CARD, MUTED, LINE)

    def set_lang(self, code):
        self.lang = code
        cfg = load_config()
        cfg["lang"] = code
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
        self.apply_lang()

    def _tick_changed(self):
        self.btn.set_enabled(self.ok.get())
        if self.ok.get():
            self.err.config(text="")

    def submit(self):
        nick = self.nick_var.get().strip()[:NICK_MAX]
        if not nick:
            self.err.config(text=self.t("gate_nick_empty"))
            self.nick_entry.focus_set()
            return
        if not self.ok.get():
            self.err.config(text=self.t("gate_tick"))
            return
        if check_passcode(self.var.get()):
            cfg = load_config()
            cfg["nick"] = nick
            try:
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, ensure_ascii=False, indent=2)
            except OSError:
                pass
            self.win.destroy()
            self.on_ok(nick)
        else:
            self.err.config(text=self.t("gate_wrong"))
            animate_slave_mark(self.login_logo_canvas, self.login_logo, "error", time.time() - self.login_logo_started)
            self.var.set("")
            self.entry.focus_set()


GUNS_JS = '''
(function () {
  if (document.getElementById("slave-bar")) return;
  var L = __LABELS__;
  var bar = document.createElement("div");
  bar.id = "slave-bar";
  bar.style.cssText = "position:fixed;top:10px;right:10px;z-index:2147483647;display:flex;gap:8px;font-family:Segoe UI,Arial,sans-serif";
  function mk(text, fn, bg) {
    var b = document.createElement("button");
    b.textContent = text;
    b.style.cssText = "padding:8px 16px;border:0;border-radius:18px;cursor:pointer;font-weight:700;font-size:13px;color:#fff;box-shadow:0 2px 12px rgba(0,0,0,.55);background:" + bg;
    b.onclick = fn;
    return b;
  }
  var copy = mk(L.copy, function () {
    var u = location.href;
    function done() { copy.textContent = L.copied; setTimeout(function () { copy.textContent = L.copy; }, 1500); }
    function fallback() {
      var t = document.createElement("textarea");
      t.value = u; document.body.appendChild(t); t.select();
      try { document.execCommand("copy"); done(); } catch (e) {}
      document.body.removeChild(t);
    }
    try { navigator.clipboard.writeText(u).then(done, fallback); } catch (e) { fallback(); }
  }, "#a855f7");
  var close = mk(L.close, function () {
    if (window.pywebview && window.pywebview.api) window.pywebview.api.close();
  }, "#3a3f4b");
  bar.appendChild(copy);
  bar.appendChild(close);
  document.body.appendChild(bar);
})();
'''


def guns_window(url, x, y, w, h, labels_b64):
    # helper process: python slave.py --guns url x y w h labels   (frameless pywebview window)
    import base64
    try:
        import webview
    except Exception:
        return 2
    labels = base64.b64decode(labels_b64).decode("utf-8")
    holder = {}

    class Api:
        def close(self):
            holder["win"].destroy()

    win = webview.create_window("guns.lol", url, js_api=Api(), x=x, y=y, width=w, height=h,
                                frameless=True)
    holder["win"] = win
    js = GUNS_JS.replace("__LABELS__", labels)

    def on_loaded():
        try:
            win.evaluate_js(js)
        except Exception:
            pass

    win.events.loaded += on_loaded
    webview.start()
    return 0


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    root.withdraw()
    cfg = load_config()
    lang = cfg.get("lang") if cfg.get("lang") in LANGS else sys_lang()
    set_theme(cfg.get("theme") if cfg.get("theme") in THEMES else "blue")

    def start(nick):
        app = SlaveApp(root, nick)
        Splash(root, app.reveal, app.lang)

    PasscodeGate(root, lang, start)
    root.mainloop()


if __name__ == "__main__":
    if len(sys.argv) >= 8 and sys.argv[1] == "--guns":
        sys.exit(guns_window(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                             int(sys.argv[5]), int(sys.argv[6]), sys.argv[7]))
    # helper process for the Roblox handle + memory scan (started by run_isolated_scan)
    if len(sys.argv) >= 4 and sys.argv[1] == "--rbscan":
        sys.exit(rbscan_worker(sys.argv[2], sys.argv[3]))
    main()



