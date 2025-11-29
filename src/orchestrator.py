import vagrant, json, datetime, os
from contextlib import contextmanager
from pathlib import Path
from .normalizers.auditd_ecs import normalize_auditd
from .normalizers.sysmon_ecs import main as normalize_sysmon
from .validator import validate_rule
import ansible_runner
from Evtx.Evtx import Evtx

BASE_DIR = Path(__file__).resolve().parent.parent
log_file_path = Path(__file__).resolve().parent / "run.log"
os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES" # Для совместимости с ansible_runner на macOS


def vm_statuses():
    vagrant_dir_linux = BASE_DIR / "Linux"
    vagrant_dir_windows = BASE_DIR / "Windows"
    v_linux = vagrant.Vagrant(root=vagrant_dir_linux)
    v_windows = vagrant.Vagrant(root=vagrant_dir_windows)
    status_linux = v_linux.status()
    status_windows = v_windows.status()
    statuses = {
        "Linux": {s.name: s.state for s in status_linux},
        "Windows": {s.name: s.state for s in status_windows}
    }
    return statuses


def destroy_vm(os_name):
    if os_name not in ["Linux", "Windows"]:
        raise ValueError("os_name must be 'Linux' or 'Windows'")
    vagrant_dir = BASE_DIR / os_name
    v = vagrant.Vagrant(root=vagrant_dir)
    v.destroy()


def halt_all_vms():
    for os_name in ["Linux", "Windows"]:
        vagrant_dir = BASE_DIR / os_name
        v = vagrant.Vagrant(root=vagrant_dir)
        v.halt()


def log_write(message: str):
    with open(log_file_path, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def my_event_handler(event):
    if 'stdout' in event and event['stdout']:
        with open(log_file_path, 'a', encoding='utf-8') as f:
            f.write(event['stdout'] + '\n')
    # вернуть True чтобы событие сохранялось/обрабатывалось дальше
    return True


def out_file_cm():
    @contextmanager
    def cm():
        f = open(log_file_path, "a", encoding="utf-8")
        try:
            yield f  # это будет out_fh внутри библиотеки
        finally:
            f.close()
    return cm()



class LinuxPipeline:

    def __init__(self, techniques, rule_name=None):
        self.techniques = techniques
        self.rule_name = rule_name
        self.pipeline_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.atomic_log_dir = f"atomic_logs_{self.pipeline_time}"

    @property
    def vagrant_instance(self):
        vagrant_dir = BASE_DIR / "Linux"
        v = vagrant.Vagrant(root=vagrant_dir, out_cm=out_file_cm, err_cm=out_file_cm)
        return v
    
    def write_config(self):
        config_path = BASE_DIR / "Linux" / "ansible" / "files" / "config.json"
        with config_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        # 2. Обновляем значение параметра atomics
        data["atomics"] = ",".join(self.techniques)
        data["art_dir_name"] = self.atomic_log_dir

        # 3. Перезаписываем файл с обновленным значением
        with config_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    
    def process_logs(self):
        arts_dir = BASE_DIR / "Linux" / "artifacts"
        src_dir = arts_dir / self.atomic_log_dir
        dest_dir = BASE_DIR / "collected_artifacts" / f"Linux_artifacts_{self.pipeline_time}"
        dest_dir.mkdir(parents=True, exist_ok=True)

        if not src_dir.is_dir():
            log_write(f"\n=== Исходная директория с артефактами {src_dir} не найдена ===\n")
            return

        normalizers = {
            "audit.log": normalize_auditd
        }
        
        for item in src_dir.iterdir():
            if item.is_file():
                normalizer = normalizers.get(item.name)
                if normalizer:
                    dest_file = dest_dir / f"{item.stem}_ecs.jsonl"
                    log_write(f"\n=== Нормализация {item.name} в {dest_file.name} ===\n")
                    try:
                        normalizer(item, dest_file)
                    except Exception as e:
                        log_write(f"\n=== Ошибка нормализации {item}: {e} ===\n")
                    if self.rule_name:
                        # Валидируем нормализованный файл
                        log_write(f"\n=== Валидация {dest_file.name} по правилу {self.rule_name} ===\n")
                        rule_path = BASE_DIR / "rules" / f"{self.rule_name}"
                        results_path = dest_dir / f"validation_results.json"
                        try:
                            matches = validate_rule(rule_path, dest_file)
                            with results_path.open("a", encoding="utf-8") as results_fh:
                                results_fh.write(json.dumps(matches, ensure_ascii=False, indent=4) + "\n")
                            log_write(f"\n=== Валидация завершена, результаты в {results_path.name} ===\n")
                        except Exception as e:
                            log_write(f"\n=== Ошибка валидации {dest_file}: {e} ===\n")
                else:
                    dest_file = dest_dir / item.name
                    log_write(f"\n=== Копирование {item.name} в {dest_file} ===\n")
                    try:
                        with item.open("rb") as src_fh, dest_file.open("wb") as dest_fh:
                            dest_fh.write(src_fh.read())
                    except Exception as e:
                        log_write(f"\n=== Ошибка копирования {item}: {e} ===\n")

        log_write(f"\n=== Сбор артефактов завершён ===\n")


    def create_base_snapshot(self, dont_halt=False):

        log_write("\n=== Создание базового снимка 'base_setup' ===\n")
        v = self.vagrant_instance

        snapshot_list = v.snapshot_list()
        if "base_setup" in snapshot_list:
            return

        try:
            os.environ['ANSIBLE_TAGS'] = "setup"
            v.up()
            v.snapshot_save("base_setup")
            log_write("\n=== Базовый снимок 'base_setup' создан ===\n")
        finally:
            if not dont_halt:
                log_write("\n=== Останавливаем ВМ ===\n")
                v.halt()


    def reload_from_snapshot(self):
        v = self.vagrant_instance

        log_write("\n=== Восстанавливаем снимок 'base_setup' ===\n")

        snapshot_list = v.snapshot_list()
        if "base_setup" not in snapshot_list:
            log_write("\n=== Снимок 'base_setup' не существует ===\n")
            return
        
        self.write_config()

        try:
            v.snapshot_restore("base_setup")

            os.environ['ANSIBLE_TAGS'] = "atomic"

            log_write("\n=== Выполняем provision ===\n")
            v.provision()

            self.process_logs()
        finally:
            log_write("\n=== Останавливаем ВМ ===\n")
            v.halt()

        
    def get_status(self):
        v = self.vagrant_instance
        status = v.status()
        log_write("\n=== Статус Vagrant ===\n")
        for s in status:
            log_write(f"VM '{s.name}': {s.state}")


    def destroy_vm(self):
        v = self.vagrant_instance
        v.destroy()


    def full_pipeline(self):
        v = self.vagrant_instance
        self.write_config()
        os.environ['ANSIBLE_TAGS'] = "setup,atomic"
        v.up()
        v.destroy()

    def run(self):
        v = self.vagrant_instance
        snapshot_list = v.snapshot_list()

        if "base_setup" not in snapshot_list:
            self.create_base_snapshot(dont_halt=True)

        self.reload_from_snapshot()
        return self.pipeline_time



class WindowsPipeline:
    
    def __init__(self, techniques, rule_name):
        self.techniques = techniques
        self.rule_name = rule_name
        self.pipeline_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.atomic_log_dir = f"atomic_logs_{self.pipeline_time}"

    @property
    def vagrant_instance(self):
        vagrant_dir = BASE_DIR / "Windows"
        v = vagrant.Vagrant(root=vagrant_dir, out_cm=out_file_cm, err_cm=out_file_cm)
        return v
    
    def write_config(self):
        config_path = BASE_DIR / "Windows" / "ansible" / "project" / "roles" / "atomic" / "files" / "atomics.csv"

        with config_path.open("w", encoding="utf-8") as f:
            f.write(",".join(self.techniques))


    def process_logs(self):
        raw_logs_dir = BASE_DIR / "Windows" / "ansible" / "project" / "collected_logs" / self.atomic_log_dir
        with Evtx(raw_logs_dir / "sysmon.evtx") as log:
            # Открываем новый файл для записи XML
            with open(raw_logs_dir / "sysmon.xml", "w", encoding="utf-8") as f:
                f.write('<Events>\n')  # Начало корневого тега
                for record in log.records():
                    xml_str = record.xml()
                    f.write(xml_str + "\n")
                f.write('</Events>')  # Конец корневого тега
        dest_dir = BASE_DIR / "collected_artifacts" / f"Windows_artifacts_{self.pipeline_time}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        # Нормализация Sysmon
        dest_file = dest_dir / "sysmon_ecs.jsonl"
        log_write(f"\n=== Нормализация Sysmon в {dest_file.name} ===\n")
        try:
            normalize_sysmon(raw_logs_dir / "sysmon.xml", output_file=str(dest_file))
        except Exception as e:
            log_write(f"\n=== Ошибка нормализации Sysmon: {e} ===\n")
        # Валидация
        if self.rule_name:
            log_write(f"\n=== Валидация {dest_file.name} по правилу {self.rule_name} ===\n")
            rule_path = BASE_DIR / "rules" / f"{self.rule_name}"
            results_path = dest_dir / f"validation_results.json"
            try:
                matches = validate_rule(rule_path, dest_file)
                with results_path.open("a", encoding="utf-8") as results_fh:
                    results_fh.write(json.dumps(matches, ensure_ascii=False, indent=4) + "\n")
                log_write(f"\n=== Валидация завершена, результаты в {results_path.name} ===\n")
            except Exception as e:
                log_write(f"\n=== Ошибка валидации {dest_file.name}: {e} ===\n")




    def run_ansible(self, role):
        private_data_dir = str(BASE_DIR / "Windows" / "ansible")
        self.write_config()
        r = ansible_runner.run(
            private_data_dir=private_data_dir, 
            playbook=f"play_{role}.yml", 
            event_handler=my_event_handler,
            quiet=True,
            extravars={
                "art_dir_name": self.atomic_log_dir,
                "download_directory": "C:\\Temp\\Sysmon",
                "sysmon_config": "C:\\Temp\\sysmon-config.xml",
                "sysmon_zip_url": "https://download.sysinternals.com/files/Sysmon.zip"
            }
        )


    def create_base_snapshot(self, dont_halt=False):
        v = self.vagrant_instance
        snapshot_list = v.snapshot_list()

        if "base_setup" in snapshot_list:
            return

        try:
            v.up()
            self.run_ansible(role="setup")
            v.snapshot_save("base_setup")
        finally:
            if not dont_halt:
                v.halt()


    def reload_from_snapshot(self):
        v = self.vagrant_instance

        log_write("\n=== Восстанавливаем снимок 'base_setup' ===\n")

        snapshot_list = v.snapshot_list()
        if "base_setup" not in snapshot_list:
            print("\n=== Снимок 'base_setup' не существует ===\n")
            return
        
        try:
            v.snapshot_restore("base_setup")
            log_write("\n=== Выполняем запуск техник ===\n")
            self.run_ansible(role="atomic")
            log_write("\n=== Обрабатываем логи ===\n")
            self.process_logs()

        finally:
            print("\n=== Останавливаем ВМ ===\n")
            v.halt()

    
    def run(self):
        v = self.vagrant_instance
        snapshot_list = v.snapshot_list()

        if "base_setup" not in snapshot_list:
            self.create_base_snapshot(dont_halt=True)

        self.reload_from_snapshot()
        return self.pipeline_time


pipelines = {
    "Linux": LinuxPipeline,
    "Windows": WindowsPipeline
}


def process_command(os_name, techniques=["T1217"], rule_name="T1217.yml"):
    pipeline = pipelines[os_name](techniques, rule_name)
    return pipeline.run()
    


if __name__ == "__main__":
    # Пример использования
    process_command("full", techniques=["T1217"], rule_name="T1217.yml")


