#!/usr/bin/env python3
"""
auditd_to_ecs_fixed.py

Исправленная версия нормализатора auditd -> JSONL (ECS-like fields).
... (текст сокращён для примера)
"""

from __future__ import annotations
import re
import json
import argparse
import sys
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
import binascii

try:
    import pwd
except Exception:
    pwd = None

# Регексы
RE_MSG = re.compile(r'\bmsg=audit\((?P<ts>[\d\.]+):(?P<id>\d+)\)')
RE_TYPE = re.compile(r'\btype=(?P<type>\w+)')
RE_KV = re.compile(r'(?P<k>[a-zA-Z0-9_]+)=(?:"(?P<q>[^"]*)"|(?P<u>[^ ]+))')
RE_HEX = re.compile(r'^[0-9a-fA-F]+$')
RE_CONTROL = re.compile(r'[\x00-\x1f\x7f]+')

SYSCALL_NUM_TO_NAME = {
    59: 'execve',
    57: 'fork',
    56: 'clone',
    2: 'open',
    257: 'openat',
}

AU_UNSET = 4294967295

def parse_kv_pairs(s: str) -> Dict[str, str]:
    res = {}
    for m in RE_KV.finditer(s):
        k = m.group('k')
        v = m.group('q') if m.group('q') is not None else m.group('u')
        res[k] = v
    return res

def parse_msg_header(s: str) -> Optional[Tuple[float, str]]:
    m = RE_MSG.search(s)
    if not m:
        return None
    ts = float(m.group('ts'))
    id_ = m.group('id')
    return ts, id_

def decode_proctitle(hex_or_escaped: str) -> str:
    v = hex_or_escaped
    if '\\0' in v:
        try:
            return v.replace('\\0', ' ').strip()
        except Exception:
            return v
    if RE_HEX.match(v):
        try:
            b = binascii.unhexlify(v)
            s = b.split(b'\x00')[0].decode('utf-8', errors='replace')
            return s
        except Exception:
            return v
    return v

def iso_from_timestamp(ts: float, tz: str = 'utc') -> str:
    if tz == 'local':
        dt = datetime.fromtimestamp(ts)
        return dt.isoformat()
    else:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.isoformat().replace('+00:00', 'Z')

def try_resolve_username(uid_str: Optional[str]) -> Optional[str]:
    if uid_str is None:
        return None
    if pwd is None:
        return None
    try:
        uid = int(uid_str)
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return None

def sanitize_key(raw: str) -> str:
    if raw is None:
        return None
    s = RE_CONTROL.sub(' ', raw)
    s = s.replace('\\x1d', ' ')
    s = s.strip()
    s = re.sub(r'^\(null\)\s*', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\b[A-Z_]+=[-A-Za-z0-9_./]+\b', '', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s or None

def map_syscall_num(maybe_num: str) -> Tuple[Optional[str], Optional[int]]:
    if maybe_num is None:
        return None, None
    try:
        n = int(maybe_num)
    except Exception:
        return maybe_num, None
    name = SYSCALL_NUM_TO_NAME.get(n)
    if name:
        return name, n
    return f'syscall_{n}', n

def merge_dict(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k, v in src.items():
        if k not in dst:
            dst[k] = v
        else:
            if isinstance(dst[k], list) and isinstance(v, list):
                dst[k].extend(v)
            elif isinstance(dst[k], dict) and isinstance(v, dict):
                merge_dict(dst[k], v)
            else:
                pass

def build_ecs_event(group: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
    ts = group['ts']
    out: Dict[str, Any] = {}
    out['@timestamp'] = iso_from_timestamp(ts, tz=options.get('timezone', 'utc'))
    out['event'] = {
        'dataset': 'auditd.log',
        'module': 'auditd',
        'kind': 'event',
    }

    audit_meta: Dict[str, Any] = {}
    try:
        audit_meta['record_id'] = int(group.get('id'))
    except Exception:
        audit_meta['record_id'] = group.get('id')
    audit_meta['sequence'] = group.get('id')
    out['audit'] = audit_meta

    process: Dict[str, Any] = {}
    user: Dict[str, Any] = {}
    file: List[Dict[str, Any]] = []

    exec_args: List[str] = []
    command_line_from_proctitle: Optional[str] = None
    rule_name: Optional[str] = None
    syscall_name: Optional[str] = None
    syscall_code: Optional[int] = None
    outcome: Optional[str] = None

    for entry in group.get('entries', []):
        t = entry.get('type')
        kv = entry.get('kv', {})

        if 'key' in kv:
            rule_name = sanitize_key(kv.get('key'))

        if t == 'SYSCALL':
            syscall_name_val = None
            if 'SYSCALL' in kv and kv.get('SYSCALL'):
                syscall_name_val = kv.get('SYSCALL')
            elif 'syscall' in kv and kv.get('syscall'):
                syscall_name_val = kv.get('syscall')

            if syscall_name_val:
                if re.fullmatch(r'\d+', str(syscall_name_val)):
                    mapped, code = map_syscall_num(syscall_name_val)
                    syscall_name = mapped or syscall_name
                    syscall_code = code or syscall_code
                else:
                    syscall_name = str(syscall_name_val).lower()
                    if 'syscall' in kv and re.fullmatch(r'\d+', str(kv.get('syscall'))):
                        try:
                            syscall_code = int(kv.get('syscall'))
                        except Exception:
                            pass

            if 'success' in kv:
                outcome = 'success' if kv.get('success') in ('yes', 'true', 'ok') else 'failure'
            if 'pid' in kv:
                try:
                    process['pid'] = int(kv['pid'])
                except Exception:
                    process['pid'] = kv['pid']
            if 'ppid' in kv:
                try:
                    process.setdefault('parent', {})['pid'] = int(kv['ppid'])
                except Exception:
                    process.setdefault('parent', {})['pid'] = kv.get('ppid')
            if 'auid' in kv:
                auid_raw = kv.get('auid')
                try:
                    auid_int = int(auid_raw)
                    if auid_int == AU_UNSET:
                        user.setdefault('audit', {})['id'] = None
                        user.setdefault('audit', {})['raw'] = auid_raw
                    else:
                        user.setdefault('audit', {})['id'] = auid_int
                except Exception:
                    user.setdefault('audit', {})['id'] = auid_raw
            if 'uid' in kv:
                try:
                    user['id'] = int(kv.get('uid'))
                except Exception:
                    user['id'] = kv.get('uid')
            if 'euid' in kv:
                try:
                    user.setdefault('effective', {})['id'] = int(kv.get('euid'))
                except Exception:
                    user.setdefault('effective', {})['id'] = kv.get('euid')
            if 'comm' in kv:
                process['name'] = kv.get('comm')
            if 'exe' in kv:
                process['executable'] = kv.get('exe')
            if 'proctitle' in kv:
                command_line_from_proctitle = decode_proctitle(kv.get('proctitle'))

        elif t == 'EXECVE':
            numeric_keys = sorted([k for k in kv.keys() if re.fullmatch(r'a\d+', k)],
                                  key=lambda x: int(x[1:]))
            args = [kv[k] for k in numeric_keys]
            if args:
                exec_args = args
            if 'exe' in kv and 'executable' not in process:
                process['executable'] = kv.get('exe')
            if 'comm' in kv and 'name' not in process:
                process['name'] = kv.get('comm')
            if 'proctitle' in kv and not exec_args:
                command_line_from_proctitle = decode_proctitle(kv.get('proctitle'))

        elif t == 'CWD':
            if 'cwd' in kv:
                process['working_directory'] = kv.get('cwd')

        elif t == 'PATH':
            f = {}
            if 'name' in kv:
                f['path'] = kv.get('name')
            if 'inode' in kv:
                try:
                    f['inode'] = int(kv.get('inode'))
                except Exception:
                    f['inode'] = kv.get('inode')
            if 'mode' in kv:
                f['mode'] = kv.get('mode')
            if 'ouid' in kv:
                f.setdefault('owner', {})['id'] = kv.get('ouid')
                if options.get('resolve-users'):
                    name = try_resolve_username(kv.get('ouid'))
                    if name:
                        f['owner']['name'] = name
            if 'ogid' in kv:
                f.setdefault('owner', {})['gid'] = kv.get('ogid')
            if 'item' in kv:
                try:
                    f['item'] = int(kv.get('item'))
                except Exception:
                    f['item'] = kv.get('item')
            file.append(f)

        elif t and t.startswith('NET'):
            addr = {}
            for k in ('saddr', 'daddr', 'sport', 'dport', 'family'):
                if k in kv:
                    addr[k] = kv[k]
            if addr:
                out.setdefault('network', {}).update(addr)

        elif t and t.startswith('USER'):
            if 'auid' in kv:
                user.setdefault('audit', {})['id'] = kv.get('auid')
            if 'uid' in kv:
                user['id'] = kv.get('uid')
            if 'acct' in kv:
                user['name'] = kv.get('acct')

        else:
            if 'comm' in kv and 'name' not in process:
                process['name'] = kv.get('comm')
            if 'exe' in kv and 'executable' not in process:
                process['executable'] = kv.get('exe')
            if 'proctitle' in kv and not command_line_from_proctitle:
                command_line_from_proctitle = decode_proctitle(kv.get('proctitle'))

    if exec_args:
        process['args'] = exec_args
        process['command_line'] = ' '.join(exec_args)
    elif command_line_from_proctitle:
        process['command_line'] = command_line_from_proctitle
        process['args'] = command_line_from_proctitle.split(' ')

    # ====== Изменено: если один путь — положим объект, если несколько — список ======
    if file:
        file_sorted = sorted(file, key=lambda x: x.get('item', 0))
        if len(file_sorted) == 1:
            out['file'] = file_sorted[0]
        else:
            out['file'] = file_sorted
    # ========================================================================

    if syscall_name:
        out['event']['action'] = syscall_name
    if syscall_code is not None:
        out['event']['code'] = syscall_code

    if outcome:
        out['event']['outcome'] = outcome

    if options.get('resolve-users') and 'id' in user and 'name' not in user:
        name = try_resolve_username(user.get('id'))
        if name:
            user['name'] = name

    if user:
        out['user'] = user
    if process:
        out['process'] = process
    if rule_name:
        out.setdefault('rule', {})['name'] = rule_name

    if options.get('keep-raw'):
        out.setdefault('message', {})['original'] = '\n'.join(group.get('raw', []))

    return out

def read_audit_stream(f):
    groups: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    for raw_line in f:
        line = raw_line.rstrip('\n')
        hdr = parse_msg_header(line)
        if not hdr:
            if order:
                last_id = order[-1]
                groups[last_id]['raw'].append(line)
                typ_m = RE_TYPE.search(line)
                typ = typ_m.group('type') if typ_m else None
                kv = parse_kv_pairs(line)
                groups[last_id]['entries'].append({'type': typ, 'kv': kv, 'raw': line})
            continue

        ts, id_ = hdr
        if id_ not in groups:
            groups[id_] = {'id': id_, 'ts': ts, 'raw': [], 'entries': []}
            order.append(id_)
        groups[id_]['raw'].append(line)
        typ_m = RE_TYPE.search(line)
        typ = typ_m.group('type') if typ_m else None
        kv = parse_kv_pairs(line)
        groups[id_]['entries'].append({'type': typ, 'kv': kv, 'raw': line})

    for id_ in order:
        yield groups[id_]


def normalize_auditd(input_path, output_path) -> None:
    with open(input_path, 'r', encoding='utf-8', errors='replace') as inp, \
         open(output_path, 'w', encoding='utf-8') as out:
        for group in read_audit_stream(inp):
            ecs = build_ecs_event(group, options={
                'resolve-users': False,
                'timezone': 'utc',
                'keep-raw': False,
            })
            out.write(json.dumps(ecs, ensure_ascii=False) + '\n')
            



def main():
    p = argparse.ArgumentParser(description="Normalize auditd logs to JSONL (ECS-like fields) - fixed")
    p.add_argument('-i', '--input', default='-', help='Input auditd log file (default stdin)')
    p.add_argument('-o', '--output', default='-', help='Output JSONL file (default stdout)')
    p.add_argument('--resolve-users', action='store_true', help='Try to resolve numeric UIDs to usernames (uses pwd)')
    p.add_argument('--timezone', choices=['utc', 'local'], default='utc', help='Timestamp timezone for @timestamp')
    p.add_argument('--keep-raw', action='store_true', help='Keep original raw audit lines in message.original')
    p.add_argument('--debug', action='store_true', help='Print debug information to stderr')
    args = p.parse_args()

    inp = sys.stdin if args.input == '-' else open(args.input, 'r', encoding='utf-8', errors='replace')
    out = sys.stdout if args.output == '-' else open(args.output, 'w', encoding='utf-8')

    options = {
        'resolve-users': args.resolve_users,
        'timezone': args.timezone,
        'keep-raw': args.keep_raw,
    }

    try:
        count = 0
        for group in read_audit_stream(inp):
            ecs = build_ecs_event(group, options)
            out.write(json.dumps(ecs, ensure_ascii=False) + '\n')
            count += 1
            if args.debug and count % 100 == 0:
                print(f"[debug] processed {count} events", file=sys.stderr)
        if args.debug:
            print(f"[debug] done. total events: {count}", file=sys.stderr)
    finally:
        if inp is not sys.stdin:
            inp.close()
        if out is not sys.stdout:
            out.close()

if __name__ == '__main__':
    main()
