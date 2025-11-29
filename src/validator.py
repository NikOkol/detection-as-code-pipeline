#!/usr/bin/env python3
"""
sigma_validator.py

Validate Sigma-like rule (YAML) against ECS-normalized auditd logs (JSON lines).
Usage:
    python sigma_validator.py --rule rule.yaml --logs logs.jsonl
Or import functions from this file in your code.

Notes:
 - Requires PyYAML (pip install pyyaml). If PyYAML is absent, the script will error with instructions.
 - This implementation evaluates all selections against the same single event.
 - Timeframe / multi-event correlation is NOT implemented here (see notes at the end).
"""

import argparse
import ast
import json
import re
from typing import Any, Dict, List
from datetime import datetime, timedelta

try:
    import yaml
except Exception as e:
    raise RuntimeError(
        "PyYAML is required. Install with: pip install pyyaml\nOriginal error: " + str(e)
    )

# ---------------------------
# Utilities to read nested fields
# ---------------------------
def get_field_value(event: Dict[str, Any], dotted_field: str):
    """
    Get value from nested dict by dotted field name, e.g. "process.command_line".
    Returns None if not present.
    If the final value is list, returns a joined string of elements (space-separated) for matching.
    """
    parts = dotted_field.split(".")
    cur = event
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    # If list, join into string for text matching
    if isinstance(cur, list):
        # flatten if list of dicts? try to stringify
        try:
            return " ".join(str(x) for x in cur)
        except Exception:
            return str(cur)
    return cur

# ---------------------------
# Matching helpers
# ---------------------------
def looks_like_regex(s: str) -> bool:
    # treat patterns that include regex chars or explicit '.*' or '|' as regex
    regex_chars = set(".*+?^$[](){}|\\")
    return any(ch in s for ch in regex_chars)

def match_value(value: Any, operator: str, patterns: List[str]) -> bool:
    """
    value: string or other scalar
    operator: 'contains' or 'endswith'
    patterns: list of pattern strings from Sigma
    Matching is case-insensitive.
    """
    if value is None:
        return False
    # stringify
    v = str(value)
    v_lower = v.lower()

    # split patterns into positive and negative (negated patterns start with '!')
    pos_patterns = []
    neg_patterns = []
    for pat in patterns:
        if pat is None:
            continue
        s = str(pat)
        if s.startswith("!"):
            neg_patterns.append(s[1:])
        else:
            pos_patterns.append(s)

    def pattern_matches(pat_str: str, use_regex_fallback=True) -> bool:
        # Prefer regex when pattern looks like regex or operator explicitly asks for regex
        if looks_like_regex(pat_str):
            try:
                return re.search(pat_str, v, flags=re.IGNORECASE) is not None
            except re.error:
                # invalid regex, fallback to substring
                return pat_str.lower() in v_lower
        else:
            return pat_str.lower() in v_lower

    # Check negated patterns first: if any negated pattern matches, the whole condition fails
    for np in neg_patterns:
        if pattern_matches(np):
            return False

    # If operator is contains (default), any positive pattern match suffices
    # EXISTENCE operator: True if field present (patterns ignored)
    if operator in ("exists", "exists\n"):
        return True  # we already returned False earlier if value is None

    if operator in ("contains", "default"):
        if not pos_patterns:
            # no positive patterns -> true as long as negatives didn't match
            return True
        for pat in pos_patterns:
            if pattern_matches(pat):
                return True
        return False
    elif operator in ("re", "regex"):
        # treat all pos_patterns as regexes; if none provided -> False unless negation filtering
        if not pos_patterns and neg_patterns:
            # only negative patterns provided -> True if none match
            for np in neg_patterns:
                if pattern_matches(np):
                    return False
            return True
        for pat in pos_patterns:
            try:
                if re.search(pat, v):
                    # check negative patterns: if any negated regex matches, fail
                    neg_fail = False
                    for np in neg_patterns:
                        try:
                            if re.search(np, v):
                                neg_fail = True
                                break
                        except re.error:
                            if np.lower() in v_lower:
                                neg_fail = True
                                break
                    if not neg_fail:
                        return True
            except re.error:
                # invalid regex, fallback to substring
                if pat.lower() in v_lower:
                    return True
        return False
    elif operator == "lowercase":
        # compare lowercased value against patterns (substring by default)
        if not pos_patterns:
            return True
        for pat in pos_patterns:
            if pat.lower() in v_lower:
                return True
        return False
    elif operator == "endswith":
        for pat in pos_patterns:
            if v_lower.endswith(pat.lower()):
                return True
        return False
    elif operator == "equals":
        for pat in pos_patterns:
            if v_lower == pat.lower():
                return True
        return False
    elif operator == "startswith":
        for pat in pos_patterns:
            if v_lower.startswith(pat.lower()):
                return True
        return False
    else:
        raise ValueError(f"Unsupported operator: {operator}")

# ---------------------------
# Parse Sigma-like YAML into internal representation
# ---------------------------
def parse_sigma_rule(yaml_text: str) -> Dict[str, Any]:
    """
    Parse YAML text of Sigma rule into dict with:
      - selections: dict of selection_name -> list of conditions (each cond is dict with field, operator, values)
      - detection_condition: the raw string
      - timeframe: optional string
      - fields: optional list
    """
    # Preprocess YAML: when a mapping key contains '|re:' the following regex value
    # often contains characters that need quoting in YAML. Detect lines like
    # '  file.path|re: (?i).*regex...'
    # and wrap the RHS regex into quotes so PyYAML can parse it.
    def _prequote_re_values(s: str) -> str:
        lines = s.splitlines()
        out_lines = []
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            m = re.match(r"^(\s*)([^:\n]+\|re:)(\s*)(.*)$", line)
            if m:
                indent = m.group(1)
                key = m.group(2)
                rest = m.group(4).rstrip()
                # collect following indented lines that are continuation of the regex
                j = i + 1
                parts = [rest] if rest else []
                while j < n:
                    next_line = lines[j]
                    # consider a continuation only if it's more indented than current key
                    if re.match(r"^\s+$", next_line):
                        # blank/whitespace line -> stop
                        break
                    if next_line.startswith(indent + "  ") or next_line.startswith(indent + "\t"):
                        parts.append(next_line.strip())
                        j += 1
                        continue
                    break
                combined = " ".join(p for p in parts if p)
                combined = combined.strip()
                # escape backslashes so YAML double-quoted scalar stays valid
                combined = combined.replace('\\', '\\\\')
                combined = combined.replace('"', '\\"')
                out_lines.append(f"{indent}{key} \"{combined}\"")
                i = j
            else:
                out_lines.append(line)
                i += 1
        return "\n".join(out_lines)

    pre = _prequote_re_values(yaml_text)
    try:
        doc = yaml.safe_load(pre)
    except Exception:
        # Fallback: manual parsing of detection block to be tolerant to unquoted regex keys.
        doc = {}
        lines = yaml_text.splitlines()
        # find detection: start
        det_idx = None
        for i, L in enumerate(lines):
            if re.match(r"^\s*detection:\s*$", L):
                det_idx = i
                break
        detection = {}
        if det_idx is not None:
            i = det_idx + 1
            current_sel = None
            sel_indent = None
            while i < len(lines):
                L = lines[i]
                # stop when we reach non-indented (top-level) or end
                if re.match(r"^\S", L):
                    break
                # selection header: e.g. '  browser_artifact_paths:'
                msel = re.match(r"^(\s*)([a-zA-Z0-9_]+):\s*$", L)
                if msel:
                    current_sel = msel.group(2)
                    sel_indent = len(msel.group(1))
                    detection[current_sel] = {}
                    i += 1
                    continue
                # inside a selection
                if current_sel is not None:
                    # item with possible operator in key: '    file.path|re: (?i)...' or '    process.name|lowercase:'
                    mkey_re = re.match(r"^\s*([^:\n]+)\|\s*re:\s*(.+)$", L)
                    if mkey_re:
                        field = mkey_re.group(1).strip()
                        pattern = mkey_re.group(2).strip()
                        # set as a mapping with key 'field|re' -> pattern
                        detection[current_sel][f"{field}|re"] = pattern
                        i += 1
                        continue
                    mkey_op = re.match(r"^\s*([^:\n]+)\|\s*([^:\n]+):\s*(.*)$", L)
                    if mkey_op:
                        field = mkey_op.group(1).strip()
                        op = mkey_op.group(2).strip()
                        rest = mkey_op.group(3).strip()
                        if rest:
                            # inline value
                            # try to parse as list item string
                            if rest.startswith("-"):
                                detection[current_sel][f"{field}|{op}"] = [rest[1:].strip()]
                            else:
                                detection[current_sel][f"{field}|{op}"] = rest
                        else:
                            # value likely on following indented lines (list)
                            j = i + 1
                            vals = []
                            while j < len(lines):
                                ln = lines[j]
                                if re.match(r"^\s*[-]\s*(.+)$", ln):
                                    vals.append(re.match(r"^\s*[-]\s*(.+)$", ln).group(1).strip())
                                    j += 1
                                    continue
                                break
                            detection[current_sel][f"{field}|{op}"] = vals
                            i = j
                            continue
                    # plain list entries under selection (unlikely for this rule), try to parse '- val'
                    mlist = re.match(r"^\s*[-]\s*(.+)$", L)
                    if mlist:
                        # store under a synthetic key
                        detection[current_sel].setdefault("__items__", []).append(mlist.group(1).strip())
                        i += 1
                        continue
                i += 1
        doc["detection"] = detection
        # try to extract timeframe and fields with simple regex
        tf_m = re.search(r"^\s*timeframe:\s*(\S+)", yaml_text, flags=re.M)
        if tf_m:
            doc["timeframe"] = tf_m.group(1).strip()
        f_m = re.search(r"^\s*fields:\s*$", yaml_text, flags=re.M)
        if f_m:
            # collect following '- field' lines
            lines_l = yaml_text.splitlines()
            idx = f_m.start()
            # naive: collect all '- ' entries
            doc["fields"] = re.findall(r"^-\s*(\S+)$", yaml_text, flags=re.M)
        else:
            doc["fields"] = []
    selections = {}
    detection = doc.get("detection", {}) or {}
    # collect selections: keys except detection_condition, timeframe, etc.
    for key, value in detection.items():
        if key in ("detection_condition", "condition", "timeframe"):
            continue
        # value is likely a mapping of 'field|operator': [values]
        if isinstance(value, dict):
            conds = []
            for field_with_op, vals in value.items():
                # field_with_op like "process.command_line|contains" or "file.path|re: (?i).*foo"
                field = field_with_op
                op = "contains"
                # support operators with optional ':' and extra spec (e.g. 'file.path|re: (?i)...')
                if "|" in field_with_op:
                    parts = field_with_op.split("|", 1)
                    field = parts[0]
                    op_part = parts[1]
                    # op_part may be like 're: (?i)...' or 'lowercase' or 'exists'
                    if ":" in op_part:
                        op_name, rest = op_part.split(":", 1)
                        op = op_name.strip()
                        rest = rest.lstrip()
                        # If YAML value is empty/null and the operator had inline pattern, use it
                        if (vals is None or (isinstance(vals, list) and len(vals) == 0) or vals == "") and rest:
                            # assign the inline pattern as the single pattern
                            patterns = [rest]
                            # append cond and continue to next
                            conds.append({"field": field, "op": op, "patterns": patterns})
                            continue
                    else:
                        op = op_part.strip()
                # vals can be list or single value
                if isinstance(vals, list):
                    patterns = vals
                else:
                    patterns = [vals]
                # clean patterns: strip surrounding quotes and whitespace
                def _clean_pat(x):
                    if x is None:
                        return x
                    s = str(x).strip()
                    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
                        s = s[1:-1]
                    # Undo doubled backslashes introduced when pre-quoting regex values
                    # (prequote replaces "\\" for YAML double-quoted scalars). If
                    # a pattern contains "\\\\" it likely represents a single
                    # backslash escape (e.g. "\\." -> "\.") that should be
                    # passed to the regex engine. Collapse double backslashes to a
                    # single backslash to restore the intended regex.
                    s = s.replace('\\\\', '\\')
                    return s.strip()
                patterns = [_clean_pat(p) for p in patterns]
                conds.append({"field": field, "op": op, "patterns": patterns})
            selections[key] = conds
        else:
            # selection might be a plain mapping deeper; try to handle shallow dicts
            selections[key] = []  # nothing understood
    # Sigma rules sometimes use 'detection_condition' or 'condition'
    detection_condition = detection.get("detection_condition", "") or detection.get("condition", "")
    timeframe = detection.get("timeframe", doc.get("timeframe", None))
    fields = doc.get("fields", [])
    return {
        "selections": selections,
        "detection_condition": str(detection_condition),
        "timeframe": timeframe,
        "fields": fields,
        "raw": doc,
    }


def parse_timeframe_to_seconds(tf: str) -> int:
    """
    Parse timeframe strings like '1m', '30s', '2h' into seconds. Return 0 for None/empty.
    """
    if not tf:
        return 0
    s = str(tf).strip()
    m = re.match(r"^(\d+)([smh]?)$", s, flags=re.IGNORECASE)
    if not m:
        return 0
    val = int(m.group(1))
    unit = m.group(2).lower()
    if unit == 's' or unit == '':
        return val
    if unit == 'm':
        return val * 60
    if unit == 'h':
        return val * 3600
    return val

# ---------------------------
# Evaluate a selection against a single event
# ---------------------------
def eval_selection(selection_conds: List[Dict[str, Any]], event: Dict[str, Any]) -> bool:
    """
    A selection typically contains one or more field conditions; selection is TRUE when
    ALL of its field conditions are satisfied (logical AND within selection).
    For each field condition, we treat it as (field op any_of(patterns)).
    """
    if not selection_conds:
        return False
    for cond in selection_conds:
        field = cond["field"]
        op = cond["op"]
        patterns = cond["patterns"]
        val = get_field_value(event, field)
        if not match_value(val, op, patterns):
            # this field condition fails -> selection false
            return False
    # all field conditions passed
    return True

# ---------------------------
# Safe boolean expression evaluator for detection_condition
# ---------------------------
class SafeEval(ast.NodeVisitor):
    """
    Evaluate a boolean expression AST composed of Names (selection keys), BoolOp (and/or),
    UnaryOp (not), and parentheses. Names are resolved from mapping provided.
    """

    def __init__(self, names: Dict[str, bool]):
        self.names = names

    def visit(self, node):
        if isinstance(node, ast.Expression):
            return self.visit(node.body)
        return super().visit(node)

    def visit_BoolOp(self, node: ast.BoolOp):
        if isinstance(node.op, ast.And):
            for v in node.values:
                if not self.visit(v):
                    return False
            return True
        elif isinstance(node.op, ast.Or):
            for v in node.values:
                if self.visit(v):
                    return True
            return False
        else:
            raise ValueError("Unsupported BoolOp")

    def visit_UnaryOp(self, node: ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return not self.visit(node.operand)
        raise ValueError("Unsupported UnaryOp")

    def visit_Name(self, node: ast.Name):
        if node.id in self.names:
            return bool(self.names[node.id])
        raise ValueError(f"Unknown name in detection_condition: {node.id}")

    def visit_Paren(self, node):
        return self.visit(node.value)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, bool):
            return node.value
        raise ValueError("Only boolean constants allowed")

    def generic_visit(self, node):
        raise ValueError(f"Unsupported expression element: {type(node).__name__}")

def eval_detection_condition(condition: str, selection_results: Dict[str, bool]) -> bool:
    """
    Given detection_condition string (uses selection names and 'and/or/not'), evaluate safely.
    Transform selection names (YAML keys) into valid Python names: they are often simple.
    We'll parse the condition with ast and evaluate using SafeEval.
    """
    if not condition or not condition.strip():
        return False
    # Normalize logical operators to lowercase python operators
    cond = condition.strip()
    # Replace common uppercase operators (AND/OR/NOT) and variants with python keywords
    cond = re.sub(r"\bAND\b", "and", cond, flags=re.IGNORECASE)
    cond = re.sub(r"\bOR\b", "or", cond, flags=re.IGNORECASE)
    cond = re.sub(r"\bNOT\b", "not", cond, flags=re.IGNORECASE)
    # Remove excessive whitespace/newlines
    cond = " ".join(cond.split())

    # Selection names in YAML may contain characters not valid in Python identifiers.
    # Map selection names to safe python identifiers by replacing non-word chars with '_'.
    name_map = {}
    for name in selection_results.keys():
        safe = re.sub(r"[^0-9a-zA-Z_]", "_", name)
        # ensure does not start with digit
        if re.match(r"^[0-9]", safe):
            safe = "s_" + safe
        name_map[name] = safe

    # Replace occurrences of original names in condition with safe names using word boundaries
    cond_safe = cond
    # Sort by length desc to avoid partial replacements
    for orig in sorted(name_map.keys(), key=lambda x: -len(x)):
        safe = name_map[orig]
        cond_safe = re.sub(rf"\b{re.escape(orig)}\b", safe, cond_safe)

    # Build safe selection_results mapping with safe names
    safe_selection_results = {name_map[k]: v for k, v in selection_results.items()}

    # Parse with ast
    try:
        tree = ast.parse(cond_safe, mode="eval")
    except SyntaxError:
        # fallback: try compacted string
        try:
            tree = ast.parse(cond_safe, mode="eval")
        except SyntaxError as e:
            raise
    evaluator = SafeEval(safe_selection_results)
    return evaluator.visit(tree)

# ---------------------------
# High-level matching function
# ---------------------------
def match_events_from_rule(rule_yaml_text: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Returns list of events that match the detection_condition of the rule.
    Each event is returned as a tuple/dict with original event and evaluation details.
    """
    rule = parse_sigma_rule(rule_yaml_text)
    # DEBUG: show parsed rule selections/detection_condition when investigating regex parsing
    # (temporary)
    # print("DEBUG PARSED RULE:", json.dumps({"selections": list(rule.get('selections', {}).keys()), "detection_condition": rule.get('detection_condition'), "timeframe": rule.get('timeframe')}, indent=2))
    selections = rule["selections"]
    tf = rule.get("timeframe")
    tf_seconds = parse_timeframe_to_seconds(tf) if tf else 0
    matched = []

    # Pre-parse timestamps to datetime for efficient windowing
    def parse_ts(e):
        ts = e.get("@timestamp") or e.get("timestamp")
        if not ts:
            return None
        try:
            # assume ISO format
            return datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except Exception:
            return None

    events_with_ts = [(e, parse_ts(e)) for e in events]

    # If timeframe is specified, only consider windows anchored at events that themselves match at least one selection.
    if tf_seconds:
        # find candidate end events: events that individually satisfy any selection
        candidate_ends = []  # list of tuples (ev, ev_ts)
        for (e, t) in events_with_ts:
            if t is None:
                continue
            matched_any = False
            for sel_name, conds in selections.items():
                if eval_selection(conds, e):
                    matched_any = True
                    break
            if matched_any:
                candidate_ends.append((e, t))

        # sort by timestamp
        candidate_ends.sort(key=lambda x: x[1])
        seen_windows = set()
        for (ev, ev_ts) in candidate_ends:
            start = ev_ts - timedelta(seconds=tf_seconds)
            window_events = [e for (e, t) in events_with_ts if t and start <= t <= ev_ts]

            sel_results = {}
            contributing = {}
            for sel_name, conds in selections.items():
                res = False
                contrib = []
                for w_ev in window_events:
                    if eval_selection(conds, w_ev):
                        res = True
                        contrib.append(w_ev)
                sel_results[sel_name] = res
                contributing[sel_name] = contrib

            try:
                overall = eval_detection_condition(rule["detection_condition"], sel_results)
            except Exception:
                overall = False

            if overall:
                # Require at least two distinct contributing events across the true selections
                contrib_ids = set()
                for sel_name, contrib in contributing.items():
                    if not sel_results.get(sel_name):
                        continue
                    for ce in contrib:
                        # build identifier: prefer @timestamp + pid, fallback to JSON string
                        ts = ce.get("@timestamp") or ce.get("timestamp")
                        pid = None
                        proc = ce.get("process") if isinstance(ce, dict) else None
                        if isinstance(proc, dict):
                            pid = proc.get("pid")
                        if ts and pid is not None:
                            contrib_ids.add(f"{ts}|{pid}")
                        elif ts:
                            contrib_ids.add(ts)
                        else:
                            contrib_ids.add(json.dumps(ce, sort_keys=True))

                if len(contrib_ids) < 2:
                    # single event contributed to all true selections -> likely a false positive for chain rule
                    continue

                key = (start.isoformat(), ev_ts.isoformat())
                if key in seen_windows:
                    continue
                seen_windows.add(key)
                matched.append({
                    "window_start": start.isoformat(),
                    "window_end": ev_ts.isoformat(),
                    "anchor_event": ev,
                    "selection_results": sel_results,
                    "contributing": contributing,
                })
    else:
        # no timeframe: evaluate each event individually
        for (ev, ev_ts) in events_with_ts:
            sel_results = {}
            for sel_name, conds in selections.items():
                sel_results[sel_name] = eval_selection(conds, ev)
            try:
                overall = eval_detection_condition(rule["detection_condition"], sel_results)
            except Exception:
                overall = False
            if overall:
                matched.append({"event": ev, "selection_results": sel_results})
    return matched

# ---------------------------
# CLI
# ---------------------------
def load_jsonl(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        out = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
        return out


def validate_rule(rule_path, logs_path):
    with open(rule_path, "r", encoding="utf-8") as f:
        rule_text = f.read()
    events = load_jsonl(logs_path)
    matches = match_events_from_rule(rule_text, events)
    return matches



def main():
    p = argparse.ArgumentParser(description="Validate Sigma rule against ECS JSON logs")
    p.add_argument("--rule", "-r", required=True, help="Path to Sigma YAML rule")
    p.add_argument("--logs", "-l", required=True, help="Path to logs JSONL (one JSON per line)")
    args = p.parse_args()

    with open(args.rule, "r", encoding="utf-8") as f:
        rule_text = f.read()
    events = load_jsonl(args.logs)
    matches = match_events_from_rule(rule_text, events)
    print(f"Loaded {len(events)} events, found {len(matches)} matches.")
    for m in matches:
        if 'contributing' in m:
            print(f"Window: {m['window_start']} - {m['window_end']}")
            print("Anchor event:", json.dumps(m["anchor_event"], ensure_ascii=False))
            print("Selection results:", json.dumps(m["selection_results"], ensure_ascii=False))
            # summarize contributing events
            print("Contributing events:")
            for sel, evs in m.get("contributing", {}).items():
                if not evs:
                    continue
                print(f"  {sel}:")
                for ev in evs:
                    ts = ev.get("@timestamp") or ev.get("timestamp")
                    cmd = None
                    # try to extract a human-friendly process command/args
                    proc = ev.get("process", {})
                    cmd = proc.get("command_line") or proc.get("args") or proc.get("name")
                    print("    ", ts, "|", cmd)
            print("---")
        else:
            ev = m["event"]
            print(json.dumps(ev, ensure_ascii=False))
            print("Selection results:", json.dumps(m["selection_results"], ensure_ascii=False))
            print("---")


if __name__ == "__main__":
    main()
