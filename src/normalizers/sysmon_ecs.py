#!/usr/bin/env python3
"""
sysmon_to_ecs_jsonl.py

Конвертирует Sysmon XML <Event> в JSONL в стиле ECS.

Использование:
    python sysmon_to_ecs_jsonl.py input.xml > out.jsonl
    cat input.xml | python sysmon_to_ecs_jsonl.py > out.jsonl

Поддерживает:
 - Парсинг namespace'ов в XML
 - System (Provider, EventID, TimeCreated, Computer, Execution, Security и т.д.)
 - EventData -> Data Name="..." -> маппинг в ECS (process.*, process.parent.*, user.*, ...)
 - Разбор строки Hashes вида "MD5=...,SHA256=...,IMPHASH=..."
 - Формирование process.args (попытка разбить command line)
 - Безопасное поведение при отсутствии полей
"""

import sys
import xml.etree.ElementTree as ET
import json
import os
import shlex
from datetime import datetime, timezone

# Простая карта событий Sysmon -> текстовое действие (расширяйте по необходимости)
EVENT_ACTION_MAP = {
    "1": "process_created",
    "2": "file_time_changed",
    "3": "network_connection",
    "4": "sysmon_service_state_change",
    "5": "process_terminated",
    "6": "driver_loaded",
    "7": "image_loaded",
    "8": "create_remote_thread",
    "9": "raw_access_read",
    "10": "process_access",
    "11": "file_created",
    "12": "registry_event",
    "13": "registry_event",
    "255": "custom"
}

def strip_ns(tag: str) -> str:
    """Убирает namespace из тега {ns}Tag -> Tag"""
    if tag is None:
        return tag
    return tag.split('}', 1)[-1] if '}' in tag else tag

def parse_hashes(hashes_field: str):
    """Парсит строку типа 'MD5=...,SHA256=...,IMPHASH=...' -> dict"""
    if not hashes_field:
        return {}
    parts = [p.strip() for p in hashes_field.split(',') if p.strip()]
    out = {}
    for p in parts:
        if '=' in p:
            k, v = p.split('=', 1)
            k = k.strip().lower()
            v = v.strip()
            # маппим стандартно: md5 -> process.hash.md5, sha256 -> process.hash.sha256, imphash -> process.hash.imphash
            out[k] = v
    return out

def split_command_line(cmd: str):
    """Попытка разбить command line на args. Возвращает list или []"""
    if not cmd:
        return []
    # попробуем shlex с posix=False (Windows-like)
    try:
        return shlex.split(cmd, posix=False)
    except Exception:
        # fallback: простая разбивка по пробелам
        return [p for p in cmd.split() if p]

def parse_event(elem: ET.Element):
    """Парсит один <Event> элемент (ElementTree.Element) -> dict (ECS-like)"""
    # Поиск child System и EventData
    system = None
    eventdata = None
    for child in elem:
        t = strip_ns(child.tag)
        if t == "System":
            system = child
        elif t == "EventData":
            eventdata = child

    # Соберём все Data элементы в словарь Name->text
    data = {}
    if eventdata is not None:
        for d in eventdata:
            if strip_ns(d.tag).lower() in ("data", "d"):
                name = d.attrib.get("Name") or d.attrib.get("name")
                # иногда значение хранится внутри <Data>text</Data>
                val = d.text if d.text is not None else ""
                if name:
                    data[name] = val

    # system fields
    sys_fields = {}
    if system is not None:
        for c in system:
            tag = strip_ns(c.tag)
            # многие интересные поля — это атрибуты внутри вложенных элементов
            if tag == "Provider":
                sys_fields["provider_name"] = c.attrib.get("Name")
                sys_fields["provider_guid"] = c.attrib.get("Guid")
            elif tag == "EventID":
                sys_fields["event_id"] = (c.text or "").strip()
            elif tag == "TimeCreated":
                sys_fields["timecreated"] = c.attrib.get("SystemTime") or (c.text or "").strip()
            elif tag == "EventRecordID":
                sys_fields["event_record_id"] = (c.text or "").strip()
            elif tag == "Execution":
                sys_fields["exec_process_id"] = c.attrib.get("ProcessID")
                sys_fields["exec_thread_id"] = c.attrib.get("ThreadID")
            elif tag == "Computer":
                sys_fields["computer"] = (c.text or "").strip()
            elif tag == "Security":
                sys_fields["security_userid"] = c.attrib.get("UserID") or (c.text or "").strip()
            else:
                # сохраняем небольшую резервную копию прочих системных полей, если нужно
                if tag and (c.text is not None):
                    sys_fields[tag.lower()] = c.text.strip()

    # Выбираем временную метку: предпочтение Data["UtcTime"], иначе System TimeCreated
    ts = None
    if data.get("UtcTime"):
        # формат "2025-11-26 15:36:46.357" -- предположим UTC, добавим Z
        try:
            # пробуем с микросекундами
            dt = datetime.strptime(data["UtcTime"].strip(), "%Y-%m-%d %H:%M:%S.%f")
            dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.isoformat()
        except Exception:
            try:
                dt = datetime.strptime(data["UtcTime"].strip(), "%Y-%m-%d %H:%M:%S")
                dt = dt.replace(tzinfo=timezone.utc)
                ts = dt.isoformat()
            except Exception:
                ts = data["UtcTime"].strip()
    elif sys_fields.get("timecreated"):
        # пример "2025-11-26 15:36:46.359453+00:00"
        raw = sys_fields["timecreated"]
        try:
            # попробуем распарсить ISO с timezone
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.isoformat()
        except Exception:
            ts = raw

    # Build ECS event
    ecs = {}
    if ts:
        ecs["@timestamp"] = ts

    # host
    host = {}
    if sys_fields.get("computer"):
        host["hostname"] = sys_fields["computer"]
    ecs["host"] = host

    # winlog / raw sysmon metadata
    winlog = {}
    # Provider, EventID, Channel, EventRecordID, Execution attrs
    if sys_fields.get("provider_name"):
        winlog["provider_name"] = sys_fields["provider_name"]
    if sys_fields.get("event_id"):
        winlog["event_id"] = sys_fields["event_id"]
    if sys_fields.get("event_record_id"):
        winlog["record_id"] = sys_fields["event_record_id"]
    if sys_fields.get("exec_process_id"):
        winlog["execution_process_id"] = sys_fields["exec_process_id"]
    if sys_fields.get("exec_thread_id"):
        winlog["execution_thread_id"] = sys_fields["exec_thread_id"]
    # raw EventData dictionary as fallback
    if data:
        winlog["event_data"] = data
    ecs["winlog"] = winlog

    # event
    event = {}
    if sys_fields.get("event_id"):
        eid = sys_fields["event_id"]
        event["id"] = eid
        event["action"] = EVENT_ACTION_MAP.get(eid, f"sysmon_event_{eid}")
        event["dataset"] = f"sysmon.eventid_{eid}"
    ecs["event"] = event

    # user
    user = {}
    # prefer Data["User"] which often содержит DOMAIN\user
    user_value = data.get("User") or data.get("UserName") or None
    if user_value:
        # разбиваем DOMAIN\user
        if "\\" in user_value:
            domain, username = user_value.split("\\", 1)
            user["domain"] = domain
            user["name"] = username
        else:
            user["name"] = user_value
    # добавить SID из Security UserID если есть
    if sys_fields.get("security_userid"):
        user["id"] = sys_fields["security_userid"]
    ecs["user"] = user

    # process
    process = {}
    # process.id
    pid = data.get("ProcessId") or data.get("ProcessId".lower()) or data.get("ProcessId".upper()) or None
    if not pid:
        pid = data.get("ProcessId")
    if pid:
        try:
            process["pid"] = int(pid, 0)  # допускает 0x.. hex
        except Exception:
            try:
                process["pid"] = int(pid)
            except Exception:
                process["pid"] = pid

    # process.entity_id (Guid)
    if data.get("ProcessGuid"):
        process["entity_id"] = data.get("ProcessGuid")

    # process.executable and name
    image = data.get("Image") or data.get("ImagePath") or data.get("ProcessImage")
    if image:
        process["executable"] = image
        process["name"] = os.path.basename(image).strip('"')

    # command line & args
    cmd = data.get("CommandLine") or data.get("Command")
    if cmd:
        process["command_line"] = cmd
        args = split_command_line(cmd)
        if args:
            process["args"] = args

    # integrity level
    if data.get("IntegrityLevel"):
        process["integrity_level"] = data.get("IntegrityLevel")

    # logon id
    if data.get("LogonId"):
        process.setdefault("token", {})["logon_id"] = data.get("LogonId")

    # hashes
    hashes_raw = data.get("Hashes") or data.get("Hash")
    if hashes_raw:
        parsed_hashes = parse_hashes(hashes_raw)
        if parsed_hashes:
            # поместим в process.hash.{md5,sha256,imphash,...}
            process_hash = {}
            for k, v in parsed_hashes.items():
                if k in ("md5", "sha256", "sha1", "sha512", "imphash"):
                    process_hash[k] = v
                else:
                    process_hash[k] = v
            process["hash"] = process_hash

    # PE / file metadata (FileVersion, Description, Product, Company, OriginalFileName)
    pe = {}
    if data.get("FileVersion"):
        pe["file_version"] = data.get("FileVersion")
    if data.get("Description"):
        pe["description"] = data.get("Description")
    if data.get("Product"):
        pe["product"] = data.get("Product")
    if data.get("Company"):
        pe["company"] = data.get("Company")
    if data.get("OriginalFileName"):
        pe["original_file_name"] = data.get("OriginalFileName")
    if pe:
        process["pe"] = pe

    ecs["process"] = process

    # parent process
    parent = {}
    parent_pid = data.get("ParentProcessId")
    if parent_pid:
        try:
            parent["pid"] = int(parent_pid, 0)
        except Exception:
            parent["pid"] = parent_pid
    parent_image = data.get("ParentImage")
    if parent_image:
        parent["executable"] = parent_image
        parent["name"] = os.path.basename(parent_image).strip('"')
    parent_cmd = data.get("ParentCommandLine")
    if parent_cmd:
        parent["command_line"] = parent_cmd
    if parent:
        ecs["process"].setdefault("parent", {}).update(parent)

    # network connection fields (простейший пример)
    if sys_fields.get("event_id") == "3" or data.get("DestinationIp") or data.get("SourceIp"):
        net = {}
        if data.get("SourceIp"):
            net.setdefault("source", {})["ip"] = data.get("SourceIp")
        if data.get("SourcePort"):
            try:
                net.setdefault("source", {})["port"] = int(data.get("SourcePort"))
            except Exception:
                net.setdefault("source", {})["port"] = data.get("SourcePort")
        if data.get("DestinationIp"):
            net.setdefault("destination", {})["ip"] = data.get("DestinationIp")
        if data.get("DestinationPort"):
            try:
                net.setdefault("destination", {})["port"] = int(data.get("DestinationPort"))
            except Exception:
                net.setdefault("destination", {})["port"] = data.get("DestinationPort")
        if net:
            ecs["network"] = net

    # message: краткое читаемое сообщение
    try:
        parts = []
        if ecs["process"].get("name"):
            parts.append(f"{ecs['process'].get('name')}")
        if ecs["process"].get("pid"):
            parts.append(f"(pid={ecs['process'].get('pid')})")
        if ecs["process"].get("command_line"):
            parts.append(f"cmd={ecs['process'].get('command_line')}")
        ecs["message"] = " ".join(parts) if parts else None
    except Exception:
        ecs["message"] = None

    # Добавим raw XML (в winlog.raw_event) — это может быть полезно для forensic/дедупа
    try:
        ecs.setdefault("winlog", {})["raw_event"] = ET.tostring(elem, encoding="unicode")
    except Exception:
        pass

    # Удаляем пустые dict'ы для компактности
    def prune(d):
        if isinstance(d, dict):
            return {k: prune(v) for k, v in d.items() if v not in (None, {}, [], "")}
        return d
    ecs = prune(ecs)
    return ecs

def iter_events_from_tree(tree_root):
    """Итератор: находит все Event элементы в дереве (универсально к namespace)"""
    for elem in tree_root.iter():
        if strip_ns(elem.tag) == "Event":
            yield elem

def main(path, output_file=None):
    # читаем вход: файл или stdin
    if os.path.exists(path):
        with open(path, "rb") as f:
            xml_bytes = f.read()
    else:
        print(f"File {path} not found, reading from stdin", file=sys.stderr)



    # Пытаемся парсить. Sysmon XML часто содержит несколько <Event> подряд или один <Events> корень.
    try:
        root = ET.fromstring(xml_bytes)
        # Если корень — не Event, ищем все Event внутри
        events = list(iter_events_from_tree(root))
    except ET.ParseError:
        # Иногда файл содержит несколько подряд сериализованных <Event> без общего корня.
        # Тогда оборачиваем в искусственный корень.
        try:
            fixed = b"<Events>" + xml_bytes + b"</Events>"
            root = ET.fromstring(fixed)
            events = list(iter_events_from_tree(root))
        except ET.ParseError as e:
            print(f"Failed to parse XML: {e}", file=sys.stderr)
            sys.exit(2)

    out_count = 0
    for ev in events:
        ecs_event = parse_event(ev)
        with (open(output_file, "a", encoding="utf-8") if output_file else sys.stdout) as out_fh:
            out_fh.write(json.dumps(ecs_event, ensure_ascii=False) + "\n")
            
        out_count += 1

    # stderr — краткий отчёт
    print(f"# Converted {out_count} events", file=sys.stderr)

if __name__ == "__main__":
    main(sys.argv[1])
