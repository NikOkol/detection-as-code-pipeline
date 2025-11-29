import time
from pathlib import Path
import threading
from threading import Event
from flask import Flask, Response, render_template, jsonify, request
from .orchestrator import process_command
from ansi2html import Ansi2HTMLConverter
import json
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

app = Flask(__name__)

FILE_PATH = Path(__file__).parent / "run.log"
FILE_PATH.touch(exist_ok=True)


writer_thread = None

# Флаг для завершения приложения (например, при выходе)
app_stop_event = Event()

# Флаг, указывающий, что писатель завершил свою работу
writer_done = Event()

def read_file_generator(file_path: Path, stop_event: Event, writer_done_event: Event):
    """Генератор, который отдаёт новые строки, добавленные в файл.
       Завершается, когда писатель завершил свою работу и нет новых строк."""
    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # перейти в конец
        while True:
            if stop_event.is_set():
                # например, при завершении приложения — выходим
                break

            line = f.readline()
            if line:
                yield line.rstrip("\n\r")
                continue

            # Если писатель завершён и новых строк нет — выходим
            if writer_done_event.is_set():
                break

            time.sleep(0.01)


@app.route("/")
def index():
    # стартовая страница — выбор ОС
    return render_template("home.html")


def _load_techniques_for_os(os_name: str):
    """Загрузить уникальные идентификаторы техник для указанной ОС из CSV.
       Читает файл atomics/Indexes/Indexes-CSV/{os}-index.csv и возвращает уникальные
       значения второго столбца (Technique #) в порядке появления.
    """
    import csv

    base = Path(__file__).parents[1] / 'atomics' / 'Indexes' / 'Indexes-CSV'
    candidates = [
        base / f"{os_name.lower()}-index.csv",
        base / f"{os_name.lower()}_index.csv",
    ]

    ids = []
    for p in candidates:
        if not p.exists():
            continue
        try:
            with p.open('r', encoding='utf-8', errors='replace') as fh:
                reader = csv.reader(fh)
                # ожидаем, что первая строка — заголовок
                for i, row in enumerate(reader):
                    if i == 0:
                        continue
                    # защищаемся от коротких строк
                    if len(row) < 2:
                        continue
                    tech = row[1].strip()
                    if not tech:
                        continue
                    if tech not in ids:
                        ids.append(tech)
        except Exception:
            # не критично — попробуем следующий кандидат
            continue
        break

    return ids


@app.route('/run-pipeline')
def run_pipeline():
    """Страница для запуска pipeline: принимает query-param `os` = 'Windows' или 'Linux'"""
    os_name = request.args.get('os', 'Linux')

    techniques = _load_techniques_for_os(os_name)

    # Список правил — имена файлов из папки rules
    rules_dir = Path(__file__).parents[1] / 'rules'
    rules = []
    if rules_dir.exists():
        for f in sorted(rules_dir.iterdir()):
            if f.is_file() and (".yml" in f.name or ".yaml" in f.name):
                rules.append(f.name)

    return render_template('run_pipeline.html', file_name=FILE_PATH.name, techniques=techniques, rules=rules, os_name=os_name)


@app.route("/stream")
def stream():
    """Server-Sent Events endpoint"""
    def event_stream():
        conv = Ansi2HTMLConverter(inline=True)
        # Проход по генератору: отдаём все новые строки
        for line in read_file_generator(FILE_PATH, app_stop_event, writer_done):
            html = conv.convert(line, full=False)
            yield f"data: {html}\n\n"

        # Когда генератор вернулся — отправляем финальное событие 'done'
        yield "event: done\ndata: OK\n\n"

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(event_stream(), headers=headers, mimetype="text/event-stream")


@app.route('/results')
def results():
    """Показать файл validation_results.json для указанного pipeline."""
    os_name = request.args.get('os')
    pipeline_time = request.args.get('time')
    base = Path(__file__).parents[1]
    results_path = base / 'collected_artifacts' / f"{os_name}_artifacts_{pipeline_time}" / 'validation_results.json'

    exists = results_path.exists()
    items = []
    if exists:
        try:
            raw = results_path.read_text(encoding='utf-8', errors='replace')
            # Попробуем распарсить весь файл целиком (обычно это JSON-массив)
            seq = []
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    seq = parsed
                else:
                    seq = [parsed]
            except Exception:
                # Если не удалось, попробуем разбирать построчно (каждая строка -- json object/array)
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(parsed, list):
                        seq.extend(parsed)
                    else:
                        seq.append(parsed)

            for obj in seq:
                # ожидаем, что каждый объект содержит ключи 'event' и 'selection_results'
                sel = obj.get('selection_results', {}) if isinstance(obj, dict) else {}
                true_keys = [k for k, v in sel.items() if v]
                try:
                    item_json = json.dumps(obj, ensure_ascii=False, indent=2)
                except Exception:
                    item_json = str(obj)
                items.append({ 'item': obj, 'selection_true_keys': true_keys, 'item_json': item_json })
        except Exception:
            # чтение/парсинг не удалось — пометим как пустой
            items = []

    return render_template('results.html', os_name=os_name, pipeline_time=pipeline_time, results_path=str(f"{results_path.parent.name}/{results_path.name}"), exists=exists, items=items)


@app.route('/results-history')
def results_history():
    """Показать список доступных директорий в collected_artifacts как кнопки-ссылки."""
    base = Path(__file__).parents[1] / 'collected_artifacts'
    entries = []
    if base.exists() and base.is_dir():
        for p in sorted(base.iterdir()):
            if p.is_dir():
                name = p.name
                # format: <OS>_artifacts_<time>
                parts = name.split('_artifacts_')
                if len(parts) == 2:
                    os_name = parts[0]
                    time = parts[1]
                    entries.append({'dir': name, 'os': os_name, 'time': time})
                else:
                    # пропустим незнакомые имена
                    continue

    # sort alphabetically by directory name
    entries.sort(key=lambda e: e['dir'])

    return render_template('results_history.html', entries=entries)


@app.route("/start-writer", methods=["POST"])
def start_writer():
    global writer_thread

    # Если поток уже работает — сообщаем об этом
    if writer_thread and writer_thread.is_alive():
        return jsonify({"status": "already_running"})

    data = request.get_json() or {}
    os_name = data.get('os_name') or data.get('param') or data.get('param')
    techniques = data.get('selected_techs', 'T1217').split(',')
    rule_name = data.get('chosen_rule', 'T1217.yml')
    # Сбрасываем флаг завершения писателя (на случай повторного запуска)
    writer_done.clear()

    # Обёртка, чтобы гарантированно пометить writer_done в finally
    def writer_wrapper():
        try:
            # process_command теперь возвращает pipeline_time
            pipeline_time = process_command(os_name, techniques, rule_name)
            # Записываем маркер в лог, чтобы фронтенд мог отреагировать и показать кнопку
            try:
                with FILE_PATH.open('a', encoding='utf-8') as lf:
                    lf.write(f"__PIPELINE_DONE__|{os_name}|{pipeline_time}\n")
            except Exception:
                # если не удалось записать в лог — ничего не делаем
                pass
        except Exception as exc:
            # можно логировать исключение в файл/логи
            print("Writer raised:", exc)
        finally:
            # Сообщаем, что писатель завершил работу
            writer_done.set()

    writer_thread = threading.Thread(
        target=writer_wrapper,
        daemon=True
    )
    writer_thread.start()
    return jsonify({"status": "started"})


def main():
    """Запуск Flask-приложения."""
    try:
        print(f"Starting Flask tail for {FILE_PATH}")
        app.run(host="127.0.0.1", port=8080, threaded=True)
    finally:
        # при завершении приложения сигнализируем генератору выйти
        app_stop_event.set()

if __name__ == "__main__":
    main()
