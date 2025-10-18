#!/usr/bin/env python3
# Небольшая обёртка для запуска atomic-operator программно
import sys
from atomic_operator import AtomicOperator

if __name__ == '__main__':
    techniques = ['all']
    if len(sys.argv) > 1:
        # передать техники как CSV: T1059,T1059.001
        techniques = sys.argv[1].split(',')

    art = AtomicOperator()

    # скачиваем atomics в /opt/atomic-red-team (если ещё не скачаны)
    try:
        art.get_atomics('/opt/atomic-red-team')
    except Exception:
        # если уже скачаны, игнорируем ошибку
        pass

    # Запустить выбранные техники (check_prereqs=True — попробует выполнить prereq команды)
    art.run(atomics_path='/opt/atomic-red-team', techniques=techniques, check_prereqs=True, cleanup=True)