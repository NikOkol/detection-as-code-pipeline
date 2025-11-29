#!/usr/bin/env python3
# Небольшая обёртка для запуска atomic-operator программно
import sys, os, logging, re, json, shutil
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



def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def safe_copy_file(src: Path, dst: Path) -> None:
    try:
        shutil.copy2(src, dst)
        logging.info(f"Copied {src} -> {dst}")
    except (PermissionError, OSError) as e:
        logging.warning(f"Failed to copy {src} -> {dst}: {e}")

def copy_tree(src: Path, dst: Path) -> None:
    """Recursively copy directory src to dst. Behaves like cp -r."""
    if not src.is_dir():
        logging.warning(f"Source directory {src} is not a directory.")
        return
    ensure_dir(dst)
    for root, dirs, files in os.walk(src):
        rel = Path(root).relative_to(src)
        target_root = dst / rel
        ensure_dir(target_root)
        for d in dirs:
            ensure_dir(target_root / d)
        for f in files:
            sfile = Path(root) / f
            tfile = target_root / f
            try:
                shutil.copy2(sfile, tfile)
            except (PermissionError, OSError) as e:
                logging.warning(f"Failed to copy {sfile} -> {tfile}: {e}")


def get_config_param(param_name: str) -> str:
    BASE_DIR = Path(__file__).resolve().parent
    config_path = BASE_DIR / "config.json"
    if not config_path.is_file():
        logging.error("config.json not found")
        sys.exit(1)

    try:
        with config_path.open() as f:
            config = json.load(f)
            param_value = config.get(param_name)
            if not param_value:
                logging.error(f"{param_name} not found in config.json")
                sys.exit(1)
            return param_value
    except Exception as e:
        logging.error(f"Failed to read config.json: {e}")
        sys.exit(1)


def collect_artifacts():
    art_dir_name = get_config_param("art_dir_name")

    ART_DIR = Path("/vagrant/artifacts") / art_dir_name
    logging.info(f"Collecting artifacts to {ART_DIR}")
    ensure_dir(ART_DIR)

    # Copy audit.log (to main folder)
    audit_src = Path("/var/log/audit/audit.log")
    if audit_src.is_file():
        safe_copy_file(audit_src, ART_DIR / audit_src.name)
    else:
        logging.warning(f"{audit_src} not found")

    # Copy atomic-specific last_run.log (if present)
    last_run = Path("/usr/local/bin/last_run.log")
    if last_run.is_file():
        safe_copy_file(last_run, ART_DIR / "last_run.log")

    logging.info(f"Artifacts saved to {ART_DIR}")



if __name__ == '__main__':
    
    techniques = get_config_param("atomics").split(",")

    art = MyAtomicOperator()

    atomics_path = ''
    # скачиваем atomics в /opt/atomic-red-team (если ещё не скачаны)
    try:
        atomics_path = art.get_atomics('/opt/atomic-red-team')
    except Exception:
        pass

    try:
        # Запустить выбранные техники (check_prereqs=True — попробует выполнить prereq команды)
        result = art.run(atomics_path=atomics_path, techniques=techniques)
        with open("/usr/local/bin/last_run.log", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
    except Exception as e:
        sys.exit(1)

    collect_artifacts()

