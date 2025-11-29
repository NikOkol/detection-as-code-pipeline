#!/usr/bin/env python3
# Небольшая обёртка для запуска atomic-operator программно
import sys, logging, re, json
from atomic_operator import AtomicOperator as AO
from pathlib import Path

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')


def remove_technique_dup(path):
    """
    Удаляет дублирование паттерна T<цифры или точки>/ в пути.
    Пример: '/atomics/T1059.004/T1059.004/src/LinEnum.sh'
    → '/atomics/T1059.004/src/LinEnum.sh'
    """
    pattern = re.compile(r'/(?P<id>T[0-9]+(?:\.[0-9]+)*)/(?P=id)(?=/|$)')
    while True:
        new = pattern.sub(r'/\g<id>', path)
        if new == path:
            return new
        path = new


def _resolve_path_to_atomics_placeholder(string: str, path: str) -> str:
    try:
        string = string.replace("$PathToAtomicsFolder", path)
        string = remove_technique_dup(string)
    except:
        pass
    try:
        string = string.replace("PathToAtomicsFolder", path)
        string = remove_technique_dup(string)
    except:
        pass
    return string

class MyAtomicOperator(AO):
    # имя метода точно такое же, как в Base
    def _path_replacement(self, string, path):
        try:
            # используем нашу корректную реализацию
            return _resolve_path_to_atomics_placeholder(string, path)
        except Exception:
            # fallback — поведение по умолчанию (чтобы не ломать остальное)
            return super()._path_replacement(string, path)







if __name__ == '__main__':
    
    techniques = []
    with open(r"C:\Temp\atomics.csv", "r", encoding="utf-8") as f:
        techniques = f.read().strip().split(",")

    art = MyAtomicOperator()
    BASE_DIR = Path(__file__).resolve().parent
    atomics_path = ''
    # скачиваем atomics в /opt/atomic-red-team (если ещё не скачаны)
    try:
        atomics_path = art.get_atomics(BASE_DIR / '/atomic-red-team')
    except Exception:
        pass

    try:
        # Запустить выбранные техники (check_prereqs=True — попробует выполнить prereq команды)
        result = art.run(atomics_path=atomics_path, techniques=techniques)
        with open(r"C:\Temp\last_run.log", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
    except Exception as e:
        sys.exit(1)


