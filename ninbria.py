from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "Ninbria"
APP_TITLE = f"{APP_NAME}"
SUPPORTED_TARGET_EXTS = {".nsp", ".nca", ".xci"}
LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
KV_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*[,=]\s*([^#;\r\n]+?)\s*$")


@dataclass(frozen=True)
class FileEntry:
    path: Path


@dataclass
class FilteredKeyset:
    path: Path | None
    skipped: list[str]
    kept: int
    tempdir: tempfile.TemporaryDirectory[str] | None = None

    def cleanup(self) -> None:
        if self.tempdir is not None:
            self.tempdir.cleanup()
            self.tempdir = None


FIXED_KEY_LENGTHS: dict[str, int] = {
    "aes_kek_generation_source": 32,
    "aes_key_generation_source": 32,
    "key_area_key_application_source": 32,
    "key_area_key_ocean_source": 32,
    "key_area_key_system_source": 32,
    "titlekek_source": 32,
    "header_kek_source": 32,
    "header_key_source": 32,
    "header_key": 64,
    "package2_key_source": 32,
    "per_console_key_source": 32,
    "xci_header_key": 32,
    "sd_card_kek_source": 32,
    "sd_card_nca_key_source": 32,
    "sd_card_save_key_source": 32,
    "save_mac_kek_source": 32,
    "save_mac_key_source": 32,
    "master_key_source": 32,
    "keyblob_mac_key_source": 32,
    "secure_boot_key": 32,
    "tsec_key": 32,
    "mariko_kek": 32,
    "mariko_bek": 32,
    "tsec_root_kek": 32,
    "package1_mac_kek": 32,
    "package1_kek": 32,
    "xci_t1_titlekey_kek_00": 32,
    "eticket_rsa_kek": 32,
    "eticket_rsa_kek_source": 32,
    "ssl_rsa_kek": 32,
    "ssl_rsa_kek_source": 32,
}

PATTERN_KEY_LENGTHS: list[tuple[re.Pattern[str], int]] = [
    (re.compile(r"^keyblob_key_source_[0-5][0-9a-f]?$"), 32),
    (re.compile(r"^keyblob_key_[0-5][0-9a-f]?$"), 32),
    (re.compile(r"^keyblob_mac_key_[0-5][0-9a-f]?$"), 32),
    (re.compile(r"^encrypted_keyblob_[0-5][0-9a-f]?$"), 352),
    (re.compile(r"^keyblob_[0-5][0-9a-f]?$"), 352),
    (re.compile(r"^master_kek_source_[0-9a-f]{2}$"), 32),
    (re.compile(r"^mariko_master_kek_source_[0-9a-f]{2}$"), 32),
    (re.compile(r"^mariko_aes_class_key_[0-9a-f]{2}$"), 32),
    (re.compile(r"^master_kek_[0-9a-f]{2}$"), 32),
    (re.compile(r"^master_key_[0-9a-f]{2}$"), 32),
    (re.compile(r"^package1_key_[0-9a-f]{2}$"), 32),
    (re.compile(r"^package2_key_[0-9a-f]{2}$"), 32),
    (re.compile(r"^package1_mac_key_[0-9a-f]{2}$"), 32),
    (re.compile(r"^titlekek_[0-9a-f]{2}$"), 32),
    (re.compile(r"^key_area_key_application_[0-9a-f]{2}$"), 32),
    (re.compile(r"^key_area_key_ocean_[0-9a-f]{2}$"), 32),
    (re.compile(r"^key_area_key_system_[0-9a-f]{2}$"), 32),
    (re.compile(r"^tsec_root_key_[0-9a-f]{2}$"), 32),
    (re.compile(r"^tsec_auth_signature_[0-9a-f]{2}$"), 512),
    (re.compile(r"^beta_nca0_exponent$"), 512),
]


def expected_key_length(name: str) -> int | None:
    name = name.lower()
    if name in FIXED_KEY_LENGTHS:
        return FIXED_KEY_LENGTHS[name]
    for pattern, length in PATTERN_KEY_LENGTHS:
        if pattern.match(name):
            return length
    return None


def redact(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        value = match.group(0)
        if len(value) <= 16:
            return value
        return f"{value[:8]}…{value[-4:]}"
    return LONG_HEX_RE.sub(replace, text)


def safe_stem(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]+", "_", path.stem).strip(" .") or "file"


def quote_cmd(args: Iterable[str]) -> str:
    quoted: list[str] = []
    for arg in args:
        text = str(arg)
        if not text:
            quoted.append('""')
        elif any(ch.isspace() for ch in text) or any(ch in text for ch in '()[]{}&^%$!\'";'):
            quoted.append('"' + text.replace('"', '\\"') + '"')
        else:
            quoted.append(text)
    return redact(" ".join(quoted))


class NinbriaGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1080x760")
        self.minsize(900, 640)
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_requested = threading.Event()
        self.entries: list[FileEntry] = []
        self.tool_var = tk.StringVar(value=self.default_tool_path())
        self.backend_var = tk.StringVar(value="Auto")
        self.keys_var = tk.StringVar(value=self.default_keys_path())
        self.out_var = tk.StringVar(value=str(Path.cwd() / "ninbria_extracted"))
        self.titlekey_var = tk.StringVar()
        self.extract_romfs_var = tk.BooleanVar(value=True)
        self.extract_exefs_var = tk.BooleanVar(value=True)
        self.extract_sections_var = tk.BooleanVar(value=False)
        self.plaintext_var = tk.BooleanVar(value=False)
        self.show_info_var = tk.BooleanVar(value=True)
        self.auto_extract_mode_var = tk.StringVar(value="Largest NCA only")
        self.disable_key_warnings_var = tk.BooleanVar(value=True)
        self.dev_keys_var = tk.BooleanVar(value=False)
        self.pass_keys_to_packages_var = tk.BooleanVar(value=False)
        self.filter_keys_var = tk.BooleanVar(value=True)
        self.create_widgets()
        self.after(100, self.drain_log_queue)

    @staticmethod
    def default_tool_path() -> str:
        script_dir = Path(__file__).resolve().parent
        if os.name == "nt":
            names = ["hactoolnet.exe", "hactoolnet", "hactool.exe", "hactool"]
        else:
            names = ["hactoolnet", "hactool", "hactoolnet.exe", "hactool.exe"]
        for name in names:
            local = script_dir / name
            if local.exists():
                return str(local)
            found = shutil.which(name)
            if found:
                return found
        return "hactoolnet.exe" if os.name == "nt" else "hactoolnet"

    @staticmethod
    def default_keys_path() -> str:
        home = Path.home()
        for rel in [".switch/prod.keys", ".switch/dev.keys"]:
            candidate = home / rel
            if candidate.exists():
                return str(candidate)
        return ""

    def create_widgets(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)
        self.create_tool_settings(root)
        self.create_file_list(root)
        self.create_options(root)
        self.create_actions(root)
        self.create_log(root)

    def create_tool_settings(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Tool, keys, and output", padding=10)
        frame.pack(fill=tk.X, pady=(0, 8))
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Tool exe:").grid(row=0, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        ttk.Entry(frame, textvariable=self.tool_var).grid(row=0, column=1, sticky=tk.EW, pady=3)
        ttk.Button(frame, text="Browse", command=self.browse_tool).grid(row=0, column=2, padx=(6, 0), pady=3)
        ttk.Label(frame, text="Backend:").grid(row=0, column=3, sticky=tk.W, padx=(16, 6))
        ttk.Combobox(frame, textvariable=self.backend_var, values=["Auto", "hactool", "hactoolnet"], state="readonly", width=12).grid(row=0, column=4, sticky=tk.W)
        ttk.Label(frame, text="Keys file:").grid(row=1, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        ttk.Entry(frame, textvariable=self.keys_var).grid(row=1, column=1, sticky=tk.EW, pady=3)
        key_buttons = ttk.Frame(frame)
        key_buttons.grid(row=1, column=2, sticky=tk.EW, padx=(6, 0), pady=3)
        ttk.Button(key_buttons, text="Browse", command=self.browse_keys).pack(side=tk.LEFT)
        ttk.Button(key_buttons, text="Clear", command=lambda: self.keys_var.set("")).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Checkbutton(frame, text="Filter incompatible key lines", variable=self.filter_keys_var).grid(row=1, column=3, columnspan=2, sticky=tk.W, padx=(16, 0))
        ttk.Label(frame, text="Output folder:").grid(row=2, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        ttk.Entry(frame, textvariable=self.out_var).grid(row=2, column=1, sticky=tk.EW, pady=3)
        out_buttons = ttk.Frame(frame)
        out_buttons.grid(row=2, column=2, sticky=tk.EW, padx=(6, 0), pady=3)
        ttk.Button(out_buttons, text="Browse", command=self.browse_output).pack(side=tk.LEFT)
        ttk.Button(out_buttons, text="Open", command=self.open_output).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Label(frame, text="Title key:").grid(row=3, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        ttk.Entry(frame, textvariable=self.titlekey_var, show="•").grid(row=3, column=1, sticky=tk.EW, pady=3)
        ttk.Label(frame, text="optional, not needed most of the time").grid(row=3, column=2, columnspan=3, sticky=tk.W, padx=(6, 0), pady=3)

    def create_file_list(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Files to process", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.file_tree = ttk.Treeview(frame, columns=("path",), show="headings", selectmode="extended")
        self.file_tree.heading("path", text="Path")
        self.file_tree.column("path", width=820, minwidth=360, stretch=True)
        self.file_tree.grid(row=0, column=0, sticky=tk.NSEW)
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        scroll.grid(row=0, column=1, sticky=tk.NS)
        self.file_tree.configure(yscrollcommand=scroll.set)
        buttons = ttk.Frame(frame)
        buttons.grid(row=0, column=2, sticky=tk.NS, padx=(8, 0))
        ttk.Button(buttons, text="Add NSP/NCA/XCI", command=self.add_files).pack(fill=tk.X, pady=(0, 6))
        ttk.Button(buttons, text="Remove selected", command=self.remove_selected).pack(fill=tk.X, pady=(0, 6))
        ttk.Button(buttons, text="Clear", command=self.clear_files).pack(fill=tk.X, pady=(0, 10))
        ttk.Button(buttons, text="Check tool", command=self.check_tool).pack(fill=tk.X)

    def create_options(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Extraction options", padding=10)
        frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Checkbutton(frame, text="Show info first", variable=self.show_info_var).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(frame, text="Extract RomFS", variable=self.extract_romfs_var).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(frame, text="Extract ExeFS", variable=self.extract_exefs_var).grid(row=0, column=2, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(frame, text="Extract sections 0-3", variable=self.extract_sections_var).grid(row=0, column=3, sticky=tk.W)
        ttk.Checkbutton(frame, text="Save plaintext NCA", variable=self.plaintext_var).grid(row=1, column=0, sticky=tk.W, padx=(0, 20), pady=(6, 0))
        ttk.Label(frame, text="After NSP/XCI unpack:").grid(row=2, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Combobox(frame, textvariable=self.auto_extract_mode_var, values=["Off", "Largest NCA only", "All NCAs"], state="readonly", width=18).grid(row=2, column=1, sticky=tk.W, pady=(8, 0))
        ttk.Checkbutton(frame, text="Disable key warnings", variable=self.disable_key_warnings_var).grid(row=2, column=2, sticky=tk.W, padx=(0, 20), pady=(8, 0))
        ttk.Checkbutton(frame, text="Use dev keys (-d)", variable=self.dev_keys_var).grid(row=2, column=3, sticky=tk.W, pady=(8, 0))
        ttk.Checkbutton(frame, text="Pass keys while unpacking NSP/XCI", variable=self.pass_keys_to_packages_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(6, 0))

    def create_actions(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=(0, 8))
        self.extract_button = ttk.Button(frame, text="Extract", command=self.start_extract)
        self.extract_button.pack(side=tk.LEFT)
        self.stop_button = ttk.Button(frame, text="Stop after current command", command=self.request_stop, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(frame, text="Clear log", command=self.clear_log).pack(side=tk.LEFT, padx=(8, 0))
        self.progress = ttk.Progressbar(frame, mode="indeterminate")
        self.progress.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(8, 0))

    def create_log(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Log", padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.log_text = tk.Text(frame, height=14, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scroll.grid(row=0, column=1, sticky=tk.NS)
        self.log_text.configure(yscrollcommand=scroll.set)

    def browse_tool(self) -> None:
        path = filedialog.askopenfilename(title="Select hactool or hactoolnet", filetypes=[("Executables", "*.exe *"), ("All files", "*")])
        if path:
            self.tool_var.set(path)

    def browse_keys(self) -> None:
        path = filedialog.askopenfilename(title="Select prod.keys or dev.keys", filetypes=[("Key files", "*.keys *.txt *"), ("All files", "*")])
        if path:
            self.keys_var.set(path)

    def browse_output(self) -> None:
        path = filedialog.askdirectory(title="Select output folder")
        if path:
            self.out_var.set(path)

    def open_output(self) -> None:
        path = Path(self.out_var.get()).expanduser()
        if not path.exists():
            messagebox.showinfo(APP_TITLE, f"Output folder does not exist yet:\n{path}")
            return
        try:
            if os.name == "nt":
                os.startfile(str(path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not open folder:\n{exc}")

    def add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Add NSP/NCA/XCI files", filetypes=[("Switch files", "*.nsp *.nca *.xci"), ("All files", "*")])
        self.add_paths(paths)

    def add_paths(self, paths: Iterable[str]) -> None:
        existing = {str(entry.path.resolve()).lower() for entry in self.entries if entry.path.exists()}
        for raw in paths:
            path = Path(raw).expanduser()
            try:
                key = str(path.resolve()).lower()
            except Exception:
                key = str(path).lower()
            if key in existing:
                continue
            if path.suffix.lower() not in SUPPORTED_TARGET_EXTS:
                messagebox.showwarning(APP_TITLE, f"Skipping unsupported file:\n{path}")
                continue
            self.entries.append(FileEntry(path=path))
            existing.add(key)
        self.refresh_tree()

    def refresh_tree(self) -> None:
        self.file_tree.delete(*self.file_tree.get_children())
        for index, entry in enumerate(self.entries):
            self.file_tree.insert("", tk.END, iid=str(index), values=(str(entry.path),))

    def remove_selected(self) -> None:
        selected = {int(iid) for iid in self.file_tree.selection()}
        if not selected:
            return
        self.entries = [entry for index, entry in enumerate(self.entries) if index not in selected]
        self.refresh_tree()

    def clear_files(self) -> None:
        self.entries.clear()
        self.refresh_tree()

    def clear_log(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def request_stop(self) -> None:
        self.stop_requested.set()
        self.log("Stop requested. Current command will finish first.")

    def log(self, message: str = "") -> None:
        self.log_queue.put(redact(message))

    def drain_log_queue(self) -> None:
        while True:
            try:
                message = self.log_queue.get_nowait()
            except queue.Empty:
                break
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
        self.after(100, self.drain_log_queue)

    def check_tool(self) -> None:
        tool = self.resolve_tool()
        if not tool:
            return
        try:
            result = subprocess.run([tool, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=15)
            self.log("=== Tool check ===")
            self.log(f"$ {quote_cmd([tool, '--help'])}")
            self.log((result.stdout or "").strip()[:4000])
            self.log(f"Exit code: {result.returncode}")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not run tool:\n{exc}")

    def resolve_tool(self) -> str | None:
        raw = self.tool_var.get().strip()
        if not raw:
            messagebox.showerror(APP_TITLE, "Select hactool or hactoolnet first.")
            return None
        path = Path(raw).expanduser()
        if path.exists():
            return str(path)
        found = shutil.which(raw)
        if found:
            return found
        messagebox.showerror(APP_TITLE, f"Tool not found:\n{raw}\n\nPut hactool or hactoolnet beside Ninbria, on PATH, or browse to it.")
        return None

    def backend(self, tool: str) -> str:
        selected = self.backend_var.get().strip().lower()
        if selected in {"hactool", "hactoolnet"}:
            return selected
        name = Path(tool).name.lower()
        return "hactoolnet" if "hactoolnet" in name else "hactool"

    def start_extract(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(APP_TITLE, "Extraction is already running.")
            return
        tool = self.resolve_tool()
        if not tool:
            return
        if not self.entries:
            messagebox.showerror(APP_TITLE, "Add at least one NSP, NCA, or XCI file.")
            return
        missing = [entry.path for entry in self.entries if not entry.path.exists()]
        if missing:
            messagebox.showerror(APP_TITLE, "These files do not exist:\n" + "\n".join(str(path) for path in missing[:10]))
            return
        titlekey = self.titlekey_var.get().strip().replace(" ", "")
        if titlekey and (len(titlekey) != 32 or not HEX_RE.match(titlekey)):
            messagebox.showerror(APP_TITLE, "Title key must be exactly 32 hexadecimal characters, or left blank.")
            return
        out = Path(self.out_var.get()).expanduser()
        out.mkdir(parents=True, exist_ok=True)
        self.stop_requested.clear()
        self.extract_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.progress.start(10)
        self.worker = threading.Thread(target=self.extract_worker, args=(tool, out), daemon=True)
        self.worker.start()

    def extract_worker(self, tool: str, out_root: Path) -> None:
        keyset = FilteredKeyset(path=None, skipped=[], kept=0)
        try:
            backend = self.backend(tool)
            self.log("=== Starting extraction ===")
            self.log(f"App: {APP_TITLE}")
            self.log(f"Backend: {backend}")
            self.log(f"Output: {out_root}")
            keyset = self.prepare_keyset()
            if keyset.path:
                self.log(f"Using keyset: {keyset.path}")
                if self.filter_keys_var.get():
                    self.log(f"Filtered keyset kept {keyset.kept} line(s), skipped {len(keyset.skipped)} line(s).")
                    for line in keyset.skipped[:30]:
                        self.log("  skipped: " + line)
                    if len(keyset.skipped) > 30:
                        self.log(f"  ... {len(keyset.skipped) - 30} more skipped key line(s)")
            else:
                self.log("No keyset selected. The backend may still use default ~/.switch key paths if supported.")
            for entry in self.entries:
                if self.stop_requested.is_set():
                    break
                suffix = entry.path.suffix.lower()
                target_out = out_root / safe_stem(entry.path)
                target_out.mkdir(parents=True, exist_ok=True)
                if suffix == ".nsp":
                    self.process_package(tool, keyset.path, entry.path, target_out, "pfs0")
                elif suffix == ".xci":
                    self.process_package(tool, keyset.path, entry.path, target_out, "xci")
                elif suffix == ".nca":
                    self.process_nca(tool, keyset.path, entry.path, target_out)
                else:
                    self.log(f"Skipping unsupported file: {entry.path}")
            self.log("=== Finished ===")
        except Exception as exc:
            self.log(f"Fatal error: {exc}")
            self.after(0, lambda: messagebox.showerror(APP_TITLE, f"Extraction failed:\n{exc}"))
        finally:
            keyset.cleanup()
            self.after(0, self.extract_done)

    def extract_done(self) -> None:
        self.progress.stop()
        self.extract_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)

    def prepare_keyset(self) -> FilteredKeyset:
        raw = self.keys_var.get().strip()
        if not raw:
            return FilteredKeyset(path=None, skipped=[], kept=0)
        src = Path(raw).expanduser()
        if not src.is_file():
            raise FileNotFoundError(f"Keys file does not exist: {src}")
        if not self.filter_keys_var.get():
            return FilteredKeyset(path=src, skipped=[], kept=0)
        tempdir = tempfile.TemporaryDirectory(prefix="ninbria_keyset_")
        dst = Path(tempdir.name) / "filtered.keys"
        skipped: list[str] = []
        kept = 0
        with src.open("r", encoding="utf-8", errors="replace") as source, dst.open("w", encoding="ascii", errors="ignore") as target:
            for line_no, original in enumerate(source, 1):
                stripped = original.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                    continue
                match = KV_RE.match(stripped)
                if not match:
                    skipped.append(f"line {line_no}: malformed or unsupported key syntax")
                    continue
                name = match.group(1).strip().lower()
                value = re.sub(r"\s+", "", match.group(2).strip())
                if not HEX_RE.match(value):
                    skipped.append(f"line {line_no}: {name}: non-hex value")
                    continue
                expected = expected_key_length(name)
                if expected is None:
                    skipped.append(f"line {line_no}: {name}: unknown key name")
                    continue
                if len(value) != expected:
                    skipped.append(f"line {line_no}: {name}: expected {expected} hex chars, got {len(value)}")
                    continue
                target.write(f"{name} = {value}\n")
                kept += 1
        return FilteredKeyset(path=dst, skipped=skipped, kept=kept, tempdir=tempdir)

    def common_args(self, key_path: Path | None, include_keys: bool) -> list[str]:
        args: list[str] = []
        if self.dev_keys_var.get():
            args.append("-d")
        if self.disable_key_warnings_var.get():
            args.append("--disablekeywarns")
        if include_keys and key_path:
            args.extend(["-k", str(key_path)])
        titlekey = self.titlekey_var.get().strip().replace(" ", "")
        if titlekey:
            args.append(f"--titlekey={titlekey}")
        return args

    def process_package(self, tool: str, key_path: Path | None, package: Path, out_dir: Path, intype: str) -> None:
        kind = "NSP" if intype == "pfs0" else "XCI"
        unpack_dir = out_dir / f"{safe_stem(package)}_{kind.lower()}"
        unpack_dir.mkdir(parents=True, exist_ok=True)
        self.log("")
        self.log(f"{kind}: {package}")
        self.log(f"Unpacking to: {unpack_dir}")
        cmd = [tool, *self.common_args(key_path, self.pass_keys_to_packages_var.get()), "-t", intype, "--outdir", str(unpack_dir), str(package)]
        if not self.run_cmd(cmd):
            return
        mode = self.auto_extract_mode_var.get()
        if mode == "Off" or self.stop_requested.is_set():
            return
        ncas = sorted(unpack_dir.rglob("*.nca"), key=lambda item: item.stat().st_size if item.exists() else 0, reverse=True)
        if not ncas:
            self.log("No NCAs found after unpacking.")
            return
        if mode == "Largest NCA only":
            ncas = ncas[:1]
        self.log(f"Auto-extracting {len(ncas)} NCA(s) from {kind}.")
        for nca in ncas:
            if self.stop_requested.is_set():
                break
            nca_out = out_dir / f"{safe_stem(nca)}_nca"
            self.process_nca(tool, key_path, nca, nca_out)

    def process_nca(self, tool: str, key_path: Path | None, nca: Path, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        self.log("")
        self.log(f"NCA: {nca}")
        self.log(f"Output: {out_dir}")
        if self.show_info_var.get():
            info_cmd = [tool, *self.common_args(key_path, True), "-t", "nca", str(nca)]
            self.run_cmd(info_cmd, allow_fail=True)
            if self.stop_requested.is_set():
                return
        cmd = [tool, *self.common_args(key_path, True), "-t", "nca"]
        if self.extract_romfs_var.get():
            cmd.extend(["--romfsdir", str(out_dir / "romfs")])
        if self.extract_exefs_var.get():
            cmd.extend(["--exefsdir", str(out_dir / "exefs")])
        if self.extract_sections_var.get():
            for index in range(4):
                cmd.extend([f"--section{index}dir", str(out_dir / f"section{index}")])
        if self.plaintext_var.get():
            cmd.extend(["--plaintext", str(out_dir / f"{safe_stem(nca)}.plaintext.nca")])
        cmd.append(str(nca))
        self.run_cmd(cmd, allow_fail=True)

    def run_cmd(self, cmd: list[str], allow_fail: bool = False) -> bool:
        self.log(f"$ {quote_cmd(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
            if proc.stdout is None:
                return False
            for line in proc.stdout:
                self.log(line.rstrip())
            code = proc.wait()
            self.log(f"Exit code: {code}")
            if code != 0:
                self.log_failure_hint()
                return False if not allow_fail else False
            return True
        except FileNotFoundError:
            self.log("Tool executable was not found.")
            return False
        except Exception as exc:
            self.log(f"Command error: {exc}")
            return False

    def log_failure_hint(self) -> None:
        self.log("Command failed. Common causes:")
        self.log("  - The NCA has no RomFS or ExeFS section to extract.")
        self.log("  - Encrypted content needs a valid local keyset or title key.")
        self.log("  - The filtered keyset skipped invalid or incompatible key lines.")
        self.log("  - Some update or patch NCAs require data from the matching base content, which this build intentionally does not wire in.")


def main() -> None:
    app = NinbriaGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
