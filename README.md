# detection-as-code-pipeline

Полезный и практический конвейер для тестирования правил обнаружения (Detection-as-Code).

Проект автоматизирует развёртывание тестовых виртуальных машин (Vagrant + Ansible), запуск техник (Atomic Red Team), сбор и нормализацию логов (Linux: auditd; Windows: Sysmon), а затем валидацию Sigma-подобных правил против ECS-нормализованных логов.

## Кратко

- Ядро: Python (модули в `src/`)
- UI: лёгкий Flask-интерфейс (`src/start_flask.py`), страница запуска конвейера и просмотра результатов
- Инфраструктура: Vagrant + Ansible для Linux и Windows образов (`Linux/`, `Windows/`)
- Нормализация: `src/normalizers/*` (auditd, sysmon)
- Правила: папка `rules/` (YAML — Sigma-подобные правила)
- Atomic techniques: `atomics/Indexes/Indexes-CSV` и связанное содержимое

## Что умеет этот репозиторий

- Разворачивать тестовые ВМ (Linux/Windows) через Vagrant/Ansible
- Выполнять набор техник (Atomic) внутри ВМ
- Собирать артефакты (логи) и нормализовать их в ECS-подобный формат
- Валидировать правила обнаружения (YAML) против нормализованных логов
- Публиковать прогресс через SSE и веб-интерфейс

## Быстрый старт (локально, macOS / Linux)

Ниже — минимальные шаги для запуска и тестирования (предполагается, что у вас установлены Vagrant, VirtualBox, Python 3.10+ и Ansible).

1. Клонировать репозиторий:

```bash
git clone <repo-url>
cd detection-as-code-pipeline
```

2. Создать и активировать виртуальное окружение Python (рекомендуется):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Установить зависимости:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

4. Добавьте своё Sigma-правило в rules/


5. Запустить веб-интерфейс (Flask) — он предоставляет UI для запуска pipeline и просмотра логов:

```bash
python manage.py start
```

Откройте браузер: http://127.0.0.1:8080

6. Через веб-интерфейс выберите ОС (Linux/Windows), техники и правило, затем запустите pipeline.

Альтернативы (CLI / отладка):

- Проверить статус ВМ:

```bash
python manage.py status
```

- Остановить все ВМ:

```bash
python manage.py halt
```

- Уничтожить ВМ (пример):

```bash
python manage.py destroy Linux
```

Можно запустить pipeline программно (например, для отладки):

```python
from src.orchestrator import process_command
# process_command(os_name, techniques=['T1217'], rule_name='T1217.yml')
process_command('Linux', techniques=['T1217'], rule_name='T1217.yml')
```

## Структура репозитория

- `manage.py` — простая CLI-обёртка для запуска Flask и управления ВМ
- `requirements.txt` — Python-зависимости
- `src/` — основная логика проекта
  - `orchestrator.py` — логика конвейера, работа с Vagrant/Ansible, сбор/нормализация/валидация
  - `start_flask.py` — Flask-приложение и SSE-стрим логов
  - `validator.py` — реализация проверки Sigma-подобных правил против нормализованных логов
  - `normalizers/` — нормализаторы (auditd, sysmon)
  - `templates/` — HTML-шаблоны для веб-интерфейса
- `Linux/`, `Windows/` — каталоги с Vagrant/Ansible для соответствующих ВМ
- `atomics/` — CSV-индексы техник и вспомогательные файлы Atomic
- `rules/` — YAML правила (Sigma-подобные)
- `collected_artifacts/` и `artifacts/` — куда сохраняются собранные результаты и логи

## Как работают ключевые части

- Оркестратор (`src/orchestrator.py`): создаёт snapshot ВМ (`base_setup`), восстанавливает его, выполняет Ansible-тэг `atomic`, собирает артефакты в `collected_artifacts/…`, запускает нормализаторы и затем валидатор правил (`src/validator.py`).
- Flask (`src/start_flask.py`) показывает веб-страницы, запускает writer-поток, который вызывает `process_command`, и отдаёт лог в браузер через SSE (`/stream`).
- Validator (`src/validator.py`) — реализует грубую, но практичную проверку Sigma-подобных YAML-правил против ECS-подобных JSONL-логов; в нём есть простая поддержка операторов (contains, re, exists и т.п.).

## Примеры использования HTTP API (для автоматизации)

- Запуск pipeline (через API) — POST к `/start-writer` с JSON телом, например:

```bash
curl -X POST http://127.0.0.1:8080/start-writer \
  -H 'Content-Type: application/json' \
  -d '{"os_name":"Linux","selected_techs":"T1217","chosen_rule":"T1217.yml"}'
```

- Просмотр результатов: web UI `Results` или открыть файлы в `collected_artifacts/<OS>_artifacts_<timestamp>/validation_results.json`.

## Предупреждения и советы

- Требуется рабочая виртуализация (VirtualBox/другой провайдер для Vagrant). На новых macOS может потребоваться разрешение на запуск гипервизора и настройка доступа.
- Ansible и Vagrant должны быть доступны в PATH.
- На macOS с использованием `ansible_runner` в `orchestrator.py` задана переменная окружения `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` для совместимости — это нормальная мера для использования ansible_runner на macOS.
- `requirements.txt` содержит зависимости, в том числе `Flask`, `ansible_runner`, `python_vagrant`, `Evtx` и т.д. Убедитесь, что версии совместимы с вашей системой.

## Отладка

- Логи исполнения пишутся в `src/run.log` (файл, который отдаётся через SSE).
- Результаты валидации: `collected_artifacts/<OS>_artifacts_<timestamp>/validation_results.json`.
- Если pipeline не исполняется — проверьте статусы Vagrant с помощью `python manage.py status` и логи Vagrant/Ansible (в соответствующих папках `Linux/` и `Windows/`).


## Ограничения

- Sysmon и Auditd не обеспечивают полного покрытия событий, создаваемых эмуляцией техник Atomic Red Team. При необходимости можно редактировать правила логирования перед запуском пайплайна:
```
/Linux/ansible/roles/atomic/files/atomic.rules
/Windows/ansible/project/roles/atomic/files/sysmon-config.xml
```