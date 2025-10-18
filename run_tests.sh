#!/usr/bin/env bash
set -euo pipefail

# 1) Поднять VM и пропровижнить через Ansible (если ещё не поднята)
vagrant up --provider=virtualbox

# 2) Провайжен (если нужно)
vagrant provision

# 3) Пример запуска atomic-тестов внутри VM: 
# запустим технику T1059 (Command and Scripting Interpreter)
# команда выполняет Python-обёртку и пишет вывод в /var/log/atomic/last_run.log

vagrant ssh -c "sudo /usr/local/bin/run_atomic.py T1083 |& sudo tee /var/log/atomic/last_run.log"

# 4) Собрать артефакты (syslog, journal, audit, osquery) и выгрузить их в папку проекта на хосте
vagrant ssh -c "sudo /usr/local/bin/collect_artifacts.sh"

# После выполнения архив с артефактами окажется в ./artifacts на машине-хозяине.
# Примечание: для запуска сразу нескольких техник: 'T1059,T1055'