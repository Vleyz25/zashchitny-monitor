from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import psutil
except ImportError:  # The UI can still explain the missing dependency.
    psutil = None

APP_NAME = "Защитный монитор"
POLL_INTERVAL_SECONDS = 2


@dataclass(frozen=True)
class FileReport:
    path: str
    size: int
    modified: str
    sha256: str
    signature: str
    signer: str
    indicators: tuple[str, ...]


@dataclass(frozen=True)
class ProcessSample:
    pid: int
    name: str
    path: str
    cpu_percent: float
    observed_at: datetime


@dataclass
class ProcessHistory:
    pid: int
    name: str
    path: str
    first_seen: datetime
    last_seen: datetime
    samples: int = 1
    peak_cpu_percent: float = 0.0


class ProcessMonitorSession:
    """Thread-safe summary of process and kernel-interrupt CPU observations."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: dict[int, ProcessHistory] = {}
        self._sample_count = 0
        self._interrupt_samples = 0
        self._interrupt_peak: float | None = None
        self._target_names = {"системные прерывания", "system interrupts"}

    def record(
        self,
        samples: list[ProcessSample],
        interrupt_cpu_percent: float | None = None,
    ) -> None:
        with self._lock:
            self._sample_count += 1
            if interrupt_cpu_percent is not None:
                self._interrupt_samples += 1
                self._interrupt_peak = max(self._interrupt_peak or 0.0, interrupt_cpu_percent)
            for sample in samples:
                history = self._history.get(sample.pid)
                if history is None:
                    self._history[sample.pid] = ProcessHistory(
                        pid=sample.pid,
                        name=sample.name,
                        path=sample.path,
                        first_seen=sample.observed_at,
                        last_seen=sample.observed_at,
                        peak_cpu_percent=max(0.0, sample.cpu_percent),
                    )
                else:
                    history.name = sample.name
                    history.path = sample.path or history.path
                    history.last_seen = sample.observed_at
                    history.samples += 1
                    history.peak_cpu_percent = max(history.peak_cpu_percent, sample.cpu_percent)

    def report(self) -> tuple[str, list[ProcessHistory]]:
        with self._lock:
            history = [ProcessHistory(**vars(item)) for item in self._history.values()]
            sample_count = self._sample_count
            interrupt_samples = self._interrupt_samples
            interrupt_peak = self._interrupt_peak
        history.sort(key=lambda item: item.peak_cpu_percent, reverse=True)
        target = [item for item in history if item.name.strip().casefold() in self._target_names]
        lines = [
            "ОТЧЁТ МОНИТОРИНГА ПРОЦЕССОВ",
            f"Снимков процессов: {sample_count}",
            f"Различных PID за сессию: {len(history)}",
            "",
        ]
        if target:
            lines.append("Совпадения с названием «Системные прерывания»:")
            for item in target:
                lines.append(
                    f"PID {item.pid} · {item.name} · пик CPU {item.peak_cpu_percent:.1f}% · "
                    f"путь: {item.path or 'Windows не предоставила путь'}"
                )
        else:
            lines.extend([
                "Процесс с точным названием «Системные прерывания / System interrupts» "
                "в доступном списке процессов не обнаружен.",
            ])
        lines.extend(["", "Системный счётчик прерываний:"])
        if interrupt_peak is None:
            lines.append("Счётчик Interrupt/DPC недоступен в этой версии Windows.")
        else:
            lines.append(
                f"Пик Interrupt/DPC: {interrupt_peak:.2f}% от общей мощности CPU "
                f"(измерений: {interrupt_samples}). Это оценка нагрузки ядра, не путь к EXE."
            )
        lines.extend([
            "",
            "Процессы с наибольшей зарегистрированной загрузкой CPU:",
        ])
        if not history:
            lines.append("Снимки ещё не успели собраться.")
        for item in history[:10]:
            lines.append(
                f"PID {item.pid} · {item.name} · пик {item.peak_cpu_percent:.1f}% · "
                f"наблюдений {item.samples} · путь: {item.path or 'недоступен'}"
            )
        lines.extend([
            "",
            "Важно: «Системные прерывания» в Windows обычно является системным псевдопроцессом, "
            "а не отдельным EXE-файлом. Высокая нагрузка может быть связана с драйвером или "
            "устройством; по этому названию нельзя определить файл майнера. Если путь недоступен, "
            "смотрите процессы с высокой CPU-нагрузкой и проверяйте драйверы/устройства отдельно.",
        ])
        return "\n".join(lines), history


def normalize_process_cpu(raw_percent: float, logical_cpu_count: int | None = None) -> float:
    """Convert psutil's per-core percentage to Task-Manager-style total capacity."""
    cores = logical_cpu_count or (psutil.cpu_count(logical=True) if psutil else None) or 1
    return max(0.0, raw_percent) / cores


def rank_process_samples(samples: list[ProcessSample]) -> list[ProcessSample]:
    return sorted(samples, key=lambda sample: sample.cpu_percent, reverse=True)


class WindowsInterruptSampler:
    """Estimate aggregate Windows interrupt/DPC CPU from per-core kernel counters."""

    class _ProcessorPerformanceInfo(__import__("ctypes").Structure):
        _fields_ = [
            ("IdleTime", __import__("ctypes").c_longlong),
            ("KernelTime", __import__("ctypes").c_longlong),
            ("UserTime", __import__("ctypes").c_longlong),
            ("DpcTime", __import__("ctypes").c_longlong),
            ("InterruptTime", __import__("ctypes").c_longlong),
            ("InterruptCount", __import__("ctypes").c_ulong),
        ]

    def __init__(self) -> None:
        self._previous_ticks: int | None = None
        self._previous_time: float | None = None

    @classmethod
    def read_interrupt_ticks(cls) -> int | None:
        if sys.platform != "win32":
            return None
        import ctypes

        count = os.cpu_count() or 1
        entry = cls._ProcessorPerformanceInfo
        buffer = (entry * count)()
        returned = ctypes.c_ulong()
        try:
            query = ctypes.WinDLL("ntdll").NtQuerySystemInformation
            query.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
            query.restype = ctypes.c_long
            status = query(8, ctypes.byref(buffer), ctypes.sizeof(buffer), ctypes.byref(returned))
            if status != 0:
                return None
            actual_count = min(count, returned.value // ctypes.sizeof(entry))
            return sum(buffer[index].InterruptTime + buffer[index].DpcTime for index in range(actual_count))
        except (AttributeError, OSError, ValueError):
            return None

    def sample(self) -> float | None:
        ticks = self.read_interrupt_ticks()
        now = time.perf_counter()
        previous_ticks, previous_time = self._previous_ticks, self._previous_time
        self._previous_ticks, self._previous_time = ticks, now
        if ticks is None or previous_ticks is None or previous_time is None:
            return None
        elapsed = now - previous_time
        if elapsed <= 0:
            return None
        capacity_ticks = elapsed * 10_000_000 * (os.cpu_count() or 1)
        return min(100.0, max(0.0, (ticks - previous_ticks) / capacity_ticks * 100))


def capture_process_samples(
    process_cache: dict[int, tuple[float, object]] | None = None,
) -> list[ProcessSample]:
    if psutil is None:
        raise RuntimeError("Не установлена зависимость psutil. Выполните: pip install -r requirements.txt")
    samples = []
    observed_at = datetime.now().astimezone()
    seen: set[int] = set()
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = proc.info
            pid = int(info["pid"])
            seen.add(pid)
            cached = process_cache.get(pid) if process_cache is not None else None
            if cached is not None and cached[0] == proc.create_time():
                raw_cpu_percent = float(cached[1].cpu_percent(interval=None))
            else:
                raw_cpu_percent = float(proc.cpu_percent(interval=None))
            cpu_percent = normalize_process_cpu(raw_cpu_percent)
            if process_cache is not None:
                process_cache[pid] = (proc.create_time(), proc)
            samples.append(ProcessSample(
                pid=pid,
                name=info.get("name") or "(без имени)",
                path=info.get("exe") or "",
                cpu_percent=cpu_percent,
                observed_at=observed_at,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if process_cache is not None:
        for pid in process_cache.keys() - seen:
            process_cache.pop(pid, None)
    return samples


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_signature(path: Path) -> tuple[str, str]:
    """Read Authenticode status using PowerShell without interpolating a path."""
    if sys.platform != "win32":
        return "Недоступно вне Windows", ""
    encoded_path = __import__("base64").b64encode(str(path).encode("utf-8")).decode("ascii")
    script = (
        "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded_path + "'));"
        "$s=Get-AuthenticodeSignature -LiteralPath $p;"
        "@{Status=[string]$s.Status;Signer=[string]$s.SignerCertificate.Subject} "
        "| ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return "Не удалось проверить", result.stderr.strip()[:300]
        info = json.loads(result.stdout.strip())
        return str(info.get("Status", "Неизвестно")), str(info.get("Signer", ""))
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return "Ошибка проверки", str(exc)


def inspect_file(file_path: str | Path) -> FileReport:
    path = Path(file_path).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("Выбранный путь не является обычным файлом.")
    stat = path.stat()
    signature, signer = get_signature(path)
    indicators: list[str] = []
    normalized = str(path).lower()
    temp_roots = (os.getenv("TEMP", "").lower(), os.getenv("TMP", "").lower())
    if any(root and normalized.startswith(root.rstrip("\\/") + os.sep.lower()) for root in temp_roots):
        indicators.append("Файл находится во временной папке — это повод проверить его, но не доказательство вредоносности.")
    if signature not in ("Valid", "Недоступно вне Windows"):
        indicators.append(f"Подпись: {signature}. Отсутствие подписи само по себе не означает заражение.")
    if not indicators:
        indicators.append("Простые эвристические признаки не обнаружены. Это не подтверждает безопасность файла.")
    return FileReport(
        path=str(path),
        size=stat.st_size,
        modified=datetime.fromtimestamp(stat.st_mtime).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        sha256=sha256_file(path),
        signature=signature,
        signer=signer,
        indicators=tuple(indicators),
    )


def list_processes() -> list[tuple[int, str, str]]:
    if psutil is None:
        raise RuntimeError("Не установлена зависимость psutil. Выполните: pip install -r requirements.txt")
    rows = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            rows.append((proc.info["pid"], proc.info.get("name") or "(без имени)", proc.info.get("exe") or ""))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return sorted(rows, key=lambda row: (row[1].casefold(), row[0]))


def run_defender_scan(file_path: str) -> str:
    """Ask Microsoft Defender to scan a specific file; never disable protection."""
    if sys.platform != "win32":
        raise RuntimeError("Проверка Microsoft Defender доступна только в Windows.")
    candidates = [
        Path(os.getenv("ProgramFiles", r"C:\Program Files"))
        / "Windows Defender" / "MpCmdRun.exe",
        Path(os.getenv("ProgramData", r"C:\ProgramData"))
        / "Microsoft" / "Windows Defender" / "Platform",
    ]
    executable = candidates[0] if candidates[0].is_file() else None
    if executable is None and candidates[1].is_dir():
        versions = sorted(candidates[1].glob("*/MpCmdRun.exe"), reverse=True)
        executable = versions[0] if versions else None
    if executable is None:
        raise RuntimeError("Не найден MpCmdRun.exe. Убедитесь, что Microsoft Defender установлен.")
    result = subprocess.run(
        [str(executable), "-Scan", "-ScanType", "3", "-File", str(Path(file_path).resolve())],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    details = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError(f"Defender завершил проверку с кодом {result.returncode}.\n{details[-1500:]}")
    return details[-2500:] or "Проверка завершена. Проверьте историю защиты Windows для результата и действий Defender."


def send_to_recycle_bin(file_path: str) -> None:
    """Move one confirmed file to the Windows Recycle Bin (recoverable by the user)."""
    if sys.platform != "win32":
        raise RuntimeError("Перемещение в Корзину поддерживается только в Windows.")
    import ctypes
    from ctypes import wintypes

    source = Path(file_path).expanduser().absolute()
    if source.is_symlink():
        raise ValueError("Разрешено перемещать только обычный файл, не папку или ссылку.")
    path = source.resolve(strict=True)
    if not path.is_file():
        raise ValueError("Разрешено перемещать только обычный файл, не папку или ссылку.")
    protected = [
        Path(os.getenv("WINDIR", r"C:\Windows")),
        Path(os.getenv("ProgramFiles", r"C:\Program Files")),
        Path(os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)")),
    ]
    for root in protected:
        try:
            path.relative_to(root.resolve())
        except ValueError:
            continue
        raise ValueError("Файлы Windows и Program Files этим приложением не удаляются.")
    if psutil is not None:
        for proc in psutil.process_iter(["exe"]):
            try:
                if proc.info.get("exe") and Path(proc.info["exe"]).resolve() == path:
                    raise ValueError("Файл запущен как процесс. Сначала завершите его штатными средствами Windows.")
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR), ("pTo", wintypes.LPCWSTR),
            ("fFlags", wintypes.WORD), ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    operation = SHFILEOPSTRUCTW()
    operation.wFunc = 3  # FO_DELETE
    operation.pFrom = str(path) + "\0\0"
    operation.fFlags = 0x0040  # FOF_ALLOWUNDO: use Recycle Bin
    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(operation))
    if result != 0 or operation.fAnyOperationsAborted:
        raise OSError(f"Windows не переместил файл в Корзину (код {result}).")


class AntivirusApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1040x720")
        self.minsize(820, 560)
        self.events: queue.Queue = queue.Queue()
        self.process_snapshot: dict[int, tuple[str, str]] = {}
        self.monitoring = False
        self.monitor_session: ProcessMonitorSession | None = None
        self.monitor_stop_event: threading.Event | None = None
        self.selected_file: str | None = None
        self._build_ui()
        self.after(150, self._drain_events)
        self.after(300, self.refresh_processes)

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)
        ttk.Label(root, text="Защитный монитор", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(root, text="Наблюдение за процессами и проверка файлов. Результаты — индикаторы, не диагноз.", wraplength=950).pack(anchor="w", pady=(2, 12))

        process_frame = ttk.LabelFrame(root, text="Процессы", padding=8)
        process_frame.pack(fill="both", expand=True)
        cols = ("pid", "name", "cpu", "path")
        self.process_tree = ttk.Treeview(process_frame, columns=cols, show="headings", height=11, selectmode="browse")
        for col, title, width in (("pid", "PID", 65), ("name", "Имя процесса", 190), ("cpu", "CPU %", 75), ("path", "Путь к файлу", 610)):
            self.process_tree.heading(col, text=title)
            self.process_tree.column(col, width=width, minwidth=65, stretch=col == "path")
        scroll = ttk.Scrollbar(process_frame, orient="vertical", command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scroll.set)
        self.process_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        controls = ttk.Frame(root)
        controls.pack(fill="x", pady=8)
        ttk.Button(controls, text="Обновить", command=self.refresh_processes).pack(side="left", padx=(0, 6))
        self.monitor_button = ttk.Button(controls, text="Начать мониторинг", command=self.toggle_monitor)
        self.monitor_button.pack(side="left", padx=6)
        ttk.Button(controls, text="Проверить файл процесса", command=self.inspect_selected_process).pack(side="left", padx=6)
        ttk.Button(controls, text="Выбрать файл…", command=self.choose_file).pack(side="left", padx=6)
        self.defender_button = ttk.Button(controls, text="Проверить Defender", command=self.scan_with_defender, state="disabled")
        self.defender_button.pack(side="left", padx=6)
        self.delete_button = ttk.Button(controls, text="В Корзину…", command=self.delete_selected, state="disabled")
        self.delete_button.pack(side="left", padx=6)

        report_frame = ttk.LabelFrame(root, text="Сведения и результаты", padding=8)
        report_frame.pack(fill="both", expand=True)
        self.report = tk.Text(report_frame, height=10, wrap="word", font=("Consolas", 10), state="disabled")
        report_scroll = ttk.Scrollbar(report_frame, orient="vertical", command=self.report.yview)
        self.report.configure(yscrollcommand=report_scroll.set)
        self.report.pack(side="left", fill="both", expand=True)
        report_scroll.pack(side="right", fill="y")
        self.status = tk.StringVar(value="Готово. Для доступа к данным некоторых процессов Windows может потребоваться запуск от имени администратора.")
        ttk.Label(root, textvariable=self.status, wraplength=970).pack(anchor="w", pady=(8, 0))

    def _set_report(self, text: str) -> None:
        self.report.configure(state="normal")
        self.report.delete("1.0", "end")
        self.report.insert("1.0", text)
        self.report.configure(state="disabled")

    def _background(self, function, on_success, on_error=None) -> None:
        def work():
            try:
                value = function()
                self.events.put((on_success, value))
            except Exception as exc:
                self.events.put((on_error or self._show_error, str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def _show_error(self, error: str) -> None:
        self.status.set("Операция не выполнена.")
        self._set_report(error)
        messagebox.showerror("Ошибка", error, parent=self)

    def _drain_events(self) -> None:
        while True:
            try:
                callback, value = self.events.get_nowait()
            except queue.Empty:
                break
            callback(value)
        self.after(150, self._drain_events)

    def refresh_processes(self) -> None:
        self._background(list_processes, self._show_processes)

    def _show_processes(self, rows) -> None:
        selected = self.process_tree.selection()
        selected_pid = self.process_tree.item(selected[0], "values")[0] if selected else None
        self.process_tree.delete(*self.process_tree.get_children())
        for pid, name, path in rows:
            self.process_tree.insert("", "end", iid=str(pid), values=(pid, name, "—", path))
        if selected_pid and self.process_tree.exists(selected_pid):
            self.process_tree.selection_set(selected_pid)
        self.status.set(f"Процессов в списке: {len(rows)} · {datetime.now().strftime('%H:%M:%S')}")

    def toggle_monitor(self) -> None:
        if self.monitoring:
            self.monitoring = False
            if self.monitor_stop_event is not None:
                self.monitor_stop_event.set()
            self.monitor_button.configure(text="Начать мониторинг")
            if self.monitor_session is not None:
                report, _history = self.monitor_session.report()
                self._set_report(report)
                self.status.set("Мониторинг остановлен. Отчёт собран по данным, замеченным во время этой сессии.")
            else:
                self.status.set("Мониторинг остановлен.")
            return
        if psutil is None:
            self._show_error("Не установлена зависимость psutil. Выполните: pip install -r requirements.txt")
            return
        self.monitor_session = ProcessMonitorSession()
        self.monitor_stop_event = threading.Event()
        self.monitoring = True
        self.monitor_button.configure(text="Остановить и показать отчёт")
        self.status.set("Мониторинг включён. Оставьте его работать, чтобы собрать сведения и загрузку CPU; остановка покажет отчёт.")
        thread = threading.Thread(
            target=self._monitor_loop,
            args=(self.monitor_session, self.monitor_stop_event),
            daemon=True,
        )
        thread.start()

    def _monitor_loop(self, session: ProcessMonitorSession, stop_event: threading.Event) -> None:
        try:
            process_cache: dict[int, tuple[float, object]] = {}
            interrupt_sampler = WindowsInterruptSampler()
            while not stop_event.is_set():
                samples = capture_process_samples(process_cache)
                interrupt_cpu = interrupt_sampler.sample()
                session.record(samples, interrupt_cpu)
                self.events.put((self._show_live_load, (samples, interrupt_cpu)))
                if stop_event.wait(POLL_INTERVAL_SECONDS):
                    break
        except Exception as exc:
            self.events.put((self._show_error, str(exc)))
            self.monitoring = False
            self.events.put((self._reset_monitor_button, None))

    def _reset_monitor_button(self, _value) -> None:
        self.monitor_button.configure(text="Начать мониторинг")

    def _show_live_load(self, data) -> None:
        samples, interrupt_cpu = data
        selected = self.process_tree.selection()
        selected_pid = selected[0] if selected else None
        ranked = rank_process_samples(samples)
        self.process_tree.delete(*self.process_tree.get_children())
        for sample in ranked:
            self.process_tree.insert(
                "", "end", iid=str(sample.pid),
                values=(sample.pid, sample.name, f"{sample.cpu_percent:.1f}", sample.path or "Недоступен"),
            )
        if selected_pid and self.process_tree.exists(selected_pid):
            self.process_tree.selection_set(selected_pid)
        top = ranked[0] if ranked else None
        top_text = f"Топ CPU: {top.name} {top.cpu_percent:.1f}% · PID {top.pid}" if top else "Процессы не прочитаны"
        interrupt_text = f" · Interrupt/DPC {interrupt_cpu:.1f}%" if interrupt_cpu is not None else ""
        self.status.set(f"Мониторинг работает · {top_text}{interrupt_text} · обновление каждые {POLL_INTERVAL_SECONDS} с")

    def _process_event(self, event) -> None:
        action, pid, name, path = event
        self.status.set(f"{action}: {name} · PID {pid} · {path or 'путь недоступен'}")

    def _selected_process(self):
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showinfo("Выберите процесс", "Выберите процесс в списке.", parent=self)
            return None
        return self.process_tree.item(selection[0], "values")

    def inspect_selected_process(self) -> None:
        row = self._selected_process()
        if not row:
            return
        pid, name, _cpu, path = row
        if not path or path == "Недоступен":
            messagebox.showwarning("Нет пути", "Windows не предоставила путь к файлу этого процесса.", parent=self)
            return
        self._inspect_path(path, f"Процесс: {name} · PID {pid}")

    def choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Выберите файл для анализа")
        if path:
            self._inspect_path(path, "Выбранный файл")

    def _inspect_path(self, path: str, context: str) -> None:
        self.status.set("Вычисление SHA-256 и проверка подписи…")
        self._background(lambda: inspect_file(path), lambda report: self._show_report(report, context))

    def _show_report(self, report: FileReport, context: str) -> None:
        self.selected_file = report.path
        self.defender_button.configure(state="normal")
        self.delete_button.configure(state="normal")
        lines = [
            f"{context}", f"Файл: {report.path}", f"Размер: {report.size:,} байт",
            f"Изменён: {report.modified}", f"SHA-256: {report.sha256}",
            f"Статус подписи Authenticode: {report.signature}",
            f"Издатель: {report.signer or 'не указан / неизвестен'}", "", "Индикаторы:",
            *(f"• {item}" for item in report.indicators), "",
            "Важно: локальная проверка не является антивирусным заключением. Проверьте файл Microsoft Defender; неизвестный файл не удаляйте только из-за отсутствия подписи.",
        ]
        self._set_report("\n".join(lines))
        self.status.set("Анализ файла завершён.")

    def scan_with_defender(self) -> None:
        if not self.selected_file:
            return
        path = self.selected_file
        if not messagebox.askyesno("Запустить проверку", f"Передать файл Microsoft Defender для проверки?\n\n{path}", parent=self):
            return
        self.status.set("Microsoft Defender проверяет файл…")
        self._background(lambda: run_defender_scan(path), self._show_defender_result)

    def _show_defender_result(self, details: str) -> None:
        self._set_report("Microsoft Defender завершил запуск проверки.\n\n" + details + "\n\nПроверьте приложение «Безопасность Windows» → «Защита от вирусов и угроз» → «Журнал защиты».")
        self.status.set("Проверка Defender завершена; итог смотрите в журнале защиты Windows.")
        messagebox.showinfo("Defender", "Проверка завершена. Результат и действия защиты смотрите в журнале защиты Windows.", parent=self)

    def delete_selected(self) -> None:
        if not self.selected_file:
            return
        path = self.selected_file
        if not messagebox.askyesno(
            "Переместить файл в Корзину?",
            "Файл будет перемещён в Корзину Windows, не удалён безвозвратно. Убедитесь, что проверили результат Defender и путь.\n\n" + path,
            icon="warning", parent=self,
        ):
            return
        self.status.set("Перемещение в Корзину…")
        self._background(lambda: send_to_recycle_bin(path), self._delete_success)

    def _delete_success(self, _value) -> None:
        old_path = self.selected_file
        self.selected_file = None
        self.defender_button.configure(state="disabled")
        self.delete_button.configure(state="disabled")
        self.status.set("Файл перемещён в Корзину Windows. Проверьте систему и автозагрузку отдельно.")
        messagebox.showinfo("Готово", f"Файл перемещён в Корзину:\n{old_path}\n\nЕсли файл был вредоносным, проверьте систему Microsoft Defender и проверьте автозагрузку.", parent=self)


if __name__ == "__main__":
    AntivirusApp().mainloop()
