"""Формирование фида индикаторов компрометации в формате JSONL.

Источники: MalwareBazaar (последние 100 образцов), VirusTotal (вердикты
антивирусов), APT ETDA (типы инструментов и связанные APT-группы).

Результат: output/malware_feed.jsonl. Повторный запуск использует кэш
в data/raw и не обращается к сети.

Ключи читаются из secrets.env (VT_API_KEY, MB_AUTH_KEY, HTTPS_PROXY).
"""
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent
DATA = ROOT / "data"
RAW_MB = DATA / "raw" / "mb"
RAW_VT = DATA / "raw" / "vt"
RAW_ETDA = DATA / "raw" / "etda"
OUT = ROOT / "output"

MB_URL = "https://mb-api.abuse.ch/api/v1/"
VT_URL = "https://www.virustotal.com/api/v3/files/"
ETDA_TOOLS_URL = "https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=t"
ETDA_ACTORS_URL = "https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=g"

SAMPLE_COUNT = 100


#### Общее: ключи, настройки, HTTP

def read_secrets() -> dict:
    """Читает secrets.env в формате KEY=VALUE."""
    path = ROOT / "secrets.env"
    values = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


SECRETS = read_secrets()


def setting(name: str, default: str = "") -> str:
    """Возвращает значение: сначала из окружения, затем из secrets.env."""
    import os
    return os.environ.get(name) or SECRETS.get(name) or default


PROXY = setting("HTTPS_PROXY") or setting("https_proxy")
CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE
OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": PROXY, "https": PROXY} if PROXY else {}),
    urllib.request.HTTPSHandler(context=CONTEXT),
)


def http(url: str, data: dict | None = None, headers: dict | None = None) -> bytes:
    """Выполняет HTTP-запрос с тремя попытками; при наличии data используется POST."""
    body = urllib.parse.urlencode(data).encode() if data else None
    request = urllib.request.Request(url, data=body, headers={"User-Agent": "ti-feed", **(headers or {})})
    for attempt in range(3):
        try:
            with OPENER.open(request, timeout=90) as response:
                return response.read()
        except urllib.error.HTTPError:
            raise
        except Exception:
            if attempt == 2:
                raise
            time.sleep(3)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


#### Модуль 1. Импорт данных

def import_malwarebazaar() -> list[dict]:
    """Загружает последние 100 образцов; селектор get_recent фиксирован."""
    cache = RAW_MB / "recent_100.json"
    if cache.exists():
        return load_json(cache)["data"]

    body = http(MB_URL, {"query": "get_recent", "selector": "100"},
                {"Auth-Key": setting("MB_AUTH_KEY")})
    payload = json.loads(body)
    if payload.get("query_status") != "ok":
        raise RuntimeError("MalwareBazaar ответил: " + str(payload.get("query_status")))
    save_json(cache, payload)
    return payload["data"]


def import_virustotal(sha256: str) -> dict | None:
    """Возвращает отчёт VirusTotal по хэшу; ответы кэшируются из-за лимита 4 запроса в минуту."""
    cache = RAW_VT / (sha256 + ".json")
    if cache.exists():
        payload = load_json(cache)
        return None if "error" in payload else payload

    try:
        body = http(VT_URL + sha256, headers={"x-apikey": setting("VT_API_KEY")})
        payload = json.loads(body)
    except urllib.error.HTTPError as error:
        # 404 означает отсутствие файла в VirusTotal; кэшируем, чтобы не повторять запрос
        payload = {"error": error.code}
    save_json(cache, payload)
    time.sleep(16)  # ограничение бесплатного тарифа: 4 запроса в минуту
    return None if "error" in payload else payload


def parse_virustotal(sha256: str, payload: dict | None) -> dict:
    """Извлекает из отчёта поля, необходимые для фида."""
    result = {"sha256": sha256, "found": False, "detects": [], "categories": [], "names": []}
    if not payload:
        return result

    attributes = payload.get("data", {}).get("attributes", {})
    results = attributes.get("last_analysis_results", {})
    useless = {"detected", "malicious", "malware", "unsafe", "virus", "trojan", "suspicious", "generic"}
    detects = []
    for engine in results.values():
        if engine.get("category") != "malicious":
            continue
        name = (engine.get("result") or "").strip()
        if name and name.lower() not in useless and name not in detects:
            detects.append(name)

    popular = attributes.get("popular_threat_classification", {})
    result.update(
        found=True,
        detects=detects[:40],
        categories=[item["value"] for item in popular.get("popular_threat_category", [])],
        names=[item["value"] for item in popular.get("popular_threat_name", [])],
    )
    return result


def import_etda() -> tuple[dict, dict]:
    """Загружает две базы ETDA: инструменты (tools) и группы (actors)."""
    tools_cache = RAW_ETDA / "tools.json"
    actors_cache = RAW_ETDA / "actors.json"
    if tools_cache.exists() and actors_cache.exists():
        return load_json(actors_cache), load_json(tools_cache)

    actors = json.loads(http(ETDA_ACTORS_URL))
    tools = json.loads(http(ETDA_TOOLS_URL))
    save_json(actors_cache, actors)
    save_json(tools_cache, tools)
    return actors, tools


#### Модуль 2. Совмещение данных

# Соответствие типов ETDA классам берем из справочника.
# Отсутствующие в справочнике типы приведены к ближайшим по смыслу:
# Wiper и Miner — Trojan, POS и ATM — Trojan-Banker.
TYPE_TO_CLASS = {
    "backdoor": "Backdoor",
    "remote command": "Backdoor",
    "botnet": "Backdoor",
    "control panel": "Backdoor",
    "info stealer": "Trojan-PSW",
    "credential stealer": "Trojan-PSW",
    "keylogger": "Trojan-Spy",
    "exfiltration": "Trojan-Spy",
    "banking trojan": "Trojan-Banker",
    "pos malware": "Trojan-Banker",
    "atm malware": "Trojan-Banker",
    "swift malware": "Trojan-Banker",
    "ransomware": "Trojan-Ransom",
    "big game hunting": "Trojan-Ransom",
    "downloader": "Trojan-Downloader",
    "loader": "Trojan-Dropper",
    "dropper": "Trojan-Dropper",
    "tunneling": "Trojan-Proxy",
    "ddos": "Trojan-DDoS",
    "worm": "Worm",
    "rootkit": "Rootkit",
    "reconnaissance": "HackTool",
    "vulnerability scanner": "HackTool",
    "poisoning": "HackTool",
    "0-day": "Exploit",
    "wiper": "Trojan",
    "ics malware": "Trojan",
    "miner": "Trojan",
    # те же значения в качестве категорий VirusTotal
    "trojan": "Trojan",
    "spyware": "Trojan-Spy",
    "stealer": "Trojan-PSW",
    "rat": "Backdoor",
    "hacktool": "HackTool",
    "virus": "Virus",
    "adware": "Adware",
    "pua": "Adware",
    "keylogger ": "Trojan-Spy",
}

# Если семейства нет в ETDA, тип часто определяется по суффиксу названия:
# RustyStealer, PureRAT, ScoobyLoader, RAHIDLOCKER.
SUFFIX_TO_CLASS = {
    "stealer": "Trojan-PSW",
    "grabber": "Trojan-PSW",
    "clipper": "Trojan-PSW",
    "rat": "Backdoor",
    "botnet": "Backdoor",
    "keylogger": "Trojan-Spy",
    "logger": "Trojan-Spy",
    "downloader": "Trojan-Downloader",
    "loader": "Trojan-Dropper",
    "dropper": "Trojan-Dropper",
    "locker": "Trojan-Ransom",
    "ransom": "Trojan-Ransom",
    "crypt": "Trojan-Ransom",
    "worm": "Worm",
    "miner": "Trojan",
}


def normalize(name: str) -> str:
    """Приводит название к нижнему регистру и оставляет только буквы и цифры."""
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def name_variants(name: str) -> list[str]:
    """Возвращает варианты названия: полное, без разделителей, без суффикса.
    Пример: «Downloader.Upatre» — downloaderupatre, upatre.
    """
    forms = [normalize(name)]
    if "." in name:
        forms.append(normalize(name.split(".")[-1]))
    for form in list(forms):
        for suffix in ("stealer", "rat", "loader", "dropper", "downloader", "bot", "logger", "locker", "clipper"):
            if form.endswith(suffix) and len(form) - len(suffix) >= 4:
                forms.append(form[: -len(suffix)])
    return list(dict.fromkeys(forms))


def build_etda_index(actors: dict, tools: dict) -> dict:
    """Строит индекс: нормализованное название или синоним -> типы и APT-группы."""
    group_names = {actor["uuid"]: actor["value"] for actor in actors.get("values", [])}
    index = {}
    for tool in tools.get("values", []):
        types = [str(item).lower() for item in tool.get("meta", {}).get("type", [])]
        groups = []
        for link in tool.get("related", []):
            if link.get("type") == "used-by" and link.get("dest-uuid") in group_names:
                groups.append(group_names[link["dest-uuid"]])
        entry = {"name": tool["value"], "types": types, "groups": sorted(set(groups))}
        names = [tool["value"]] + list(tool.get("meta", {}).get("synonyms", []))
        for name in names:
            for variant in name_variants(name):
                if len(variant) >= 5:  # короткие фрагменты («pure») дают ложные совпадения
                    index.setdefault(variant, entry)
    return index


def classes_from_virustotal(vt: dict) -> list[str]:
    """Переводит категории VirusTotal в классы справочника."""
    classes = []
    for category in vt.get("categories", []):
        mapped = TYPE_TO_CLASS.get(category.lower())
        if mapped and mapped not in classes:
            classes.append(mapped)
    return classes


def order_classes(classes: list[str]) -> list[str]:
    """Сортирует классы по убыванию опасности: HIGH, MEDIUM, остальные."""
    def rank(name: str) -> int:
        if name in HIGH_CLASSES:
            return 0
        if name in MEDIUM_CLASSES:
            return 1
        return 2
    return sorted(classes, key=rank)


def classify(sample: dict, vt: dict, etda: dict) -> tuple[list[str], list[str], list[str], str]:
    """Определяет классы ВПО, семейства и APT-группы образца.

    Источники в порядке приоритета: ETDA, суффикс названия, категории
    VirusTotal. Дополнительно возвращает источник класса.
    """
    signature = (sample.get("signature") or "").strip()
    families = [signature] if signature else []
    classes, groups, source = [], [], "none"

    # 1. Поиск семейства в ETDA и перевод его типов в классы.
    if signature:
        for variant in name_variants(signature):
            entry = etda.get(variant)
            if not entry:
                continue
            groups = entry["groups"]
            for item in entry["types"]:
                mapped = TYPE_TO_CLASS.get(item)
                if mapped and mapped not in classes:
                    classes.append(mapped)
            if classes:
                source = "etda"
            break

        # 2. ETDA не содержит семейство — проверка суффикса названия.
        if not classes:
            normalized = normalize(signature)
            for suffix, mapped in SUFFIX_TO_CLASS.items():
                if normalized.endswith(suffix) and mapped not in classes:
                    classes.append(mapped)
                    source = "heuristic"
                    break

    # 3. Резервный вариант — категории VirusTotal.
    if not classes and vt.get("found"):
        classes = classes_from_virustotal(vt)
        if classes:
            source = "vt"
        if not families:
            families = [name for name in vt.get("names", []) if len(name) >= 5][:3]

    return order_classes(classes)[:3], families[:3], groups, source


#### Модуль 3. Аналитика

# Классы разделены на три группы согласно справочнику.
# HIGH — контроль над устройством, уничтожение данных, кража учётных
# данных и доступа к финансовым системам.
HIGH_CLASSES = {
    "Backdoor", "Rootkit", "Bootkit", "Trojan-Ransom", "Trojan-Banker",
    "Trojan-PSW", "Trojan-Spy", "Trojan-IM", "Trojan-GameThief",
}
# MEDIUM — доставка нагрузки, распространение, помехи, инструменты атакующего.
MEDIUM_CLASSES = {
    "Trojan", "Trojan-Dropper", "Trojan-Downloader", "Trojan-Proxy", "Trojan-DDoS",
    "Trojan-SMS", "Trojan-Mailfinder", "Trojan-FakeAV", "Trojan-ArcBomb",
    "Trojan-Notifier", "Trojan-Clicker", "Virus", "Worm", "Net-Worm", "Email-Worm",
    "IM-Worm", "IRC-Worm", "P2P-Worm", "Exploit", "DoS", "Flooder", "Phishing",
    "HackTool", "VirTool", "Constructor",
}
# LOW — остальные классы справочника: прямо не отнесены к вредоносным ПО
# (RiskTool, RemoteAdmin, Server-*, Adware) либо относятся к рекламе и спаму.

LEVELS = ["LOW", "MEDIUM", "HIGH"]


def threat_level(classes: list[str], groups: list[str], detects: int) -> str:
    """Вычисляет уровень угрозы по классам ВПО.

    Уровень определяется наиболее опасной группой, к которой относится
    хотя бы один класс. Принадлежность семейства к APT-группе в ETDA
    повышает уровень на одну ступень: аналогичное ПО в целевой атаке
    опаснее массового.

    Если класс определить не удалось, но антивирусы фиксируют детекты,
    уровень — MEDIUM: LOW в фиде означал бы, что образец можно игнорировать.
    При отсутствии детектов уровень LOW.
    """
    level = 0  # 0=LOW, 1=MEDIUM, 2=HIGH
    for item in classes:
        if item in HIGH_CLASSES:
            level = max(level, 2)
        elif item in MEDIUM_CLASSES:
            level = max(level, 1)

    if not classes and detects:
        level = max(level, 1)

    if groups and level < 2:
        level += 1

    return LEVELS[level]


#### Модуль 4. Экспорт

def build_feed() -> tuple[list[dict], list[str]]:
    samples = import_malwarebazaar()[:SAMPLE_COUNT]
    actors, tools = import_etda()
    etda = build_etda_index(actors, tools)
    print("образцов: %d, инструментов в ETDA: %d" % (len(samples), len(tools.get("values", []))))

    feed, sources = [], []
    for number, sample in enumerate(samples, 1):
        sha256 = sample["sha256_hash"]
        report = parse_virustotal(sha256, import_virustotal(sha256))
        classes, families, groups, source = classify(sample, report, etda)

        sources.append(source)
        feed.append({
            "md5": sample["md5_hash"],
            "sha256": sha256,
            "malware_class": classes,
            "malware_family": families,
            "av_detects": report["detects"],
            "threat_level": threat_level(classes, groups, len(report["detects"])),
        })
        if number % 20 == 0:
            print("  обработано %d/%d" % (number, len(samples)))
    return feed, sources


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    feed, sources = build_feed()

    path = OUT / "malware_feed.jsonl"
    with path.open("w", encoding="utf-8") as file:
        for record in feed:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")

    levels = {level: sum(1 for record in feed if record["threat_level"] == level) for level in LEVELS}
    with_classes = sum(1 for record in feed if record["malware_class"])
    print("\nзаписей: %d, с классом: %d" % (len(feed), with_classes))
    print("уровни: LOW %(LOW)d, MEDIUM %(MEDIUM)d, HIGH %(HIGH)d" % levels)
    print("класс взят из ETDA: %(etda)d, по названию: %(heuristic)d, "
          "из вердикта VT: %(vt)d, не определён: %(none)d" % {
              key: sources.count(key) for key in ("etda", "heuristic", "vt", "none")})
    print("файл: %s" % path)


if __name__ == "__main__":
    main()