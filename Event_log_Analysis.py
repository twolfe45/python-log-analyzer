from __future__ import annotations

import ctypes
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import sys
import tkinter as tk
from prettytable import PrettyTable
from tkinter import filedialog
from tkinter import ttk
from xml.etree import ElementTree as ET

import win32evtlog


# Event record used by the report.
@dataclass(frozen=True)
class EventRecord:
    timestamp: str
    log_name: str
    event_id: str
    level: str
    provider: str
    reason: str
    summary: str


# Main application window and report workflow.
class EventViewerReportApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Event Viewer Abnormal Event Report")
        self.root.geometry("1100x760")
        self.root.minsize(800, 520)

        self.records: list[EventRecord] = []
        self.last_report_text = ""
        self.last_report_path: Path | None = None

        self._build_ui()
        self._refresh_admin_state()
        self._write_intro()

    # Build the application UI.
    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Time frame").pack(side="left")
        self.timeframe_var = tk.StringVar(value="24 hours")
        self.timeframe_hours = {"24 hours": 24}
        self.timeframe_hours.update({f"{days} days": days * 24 for days in range(2, 15)})
        self.timeframe_combo = ttk.Combobox(
            top,
            textvariable=self.timeframe_var,
            values=list(self.timeframe_hours.keys()),
            width=12,
            state="readonly",
        )
        self.timeframe_combo.pack(side="left", padx=(6, 12))

        self.request_admin_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Request admin", variable=self.request_admin_var).pack(side="left", padx=(0, 12))

        ttk.Label(top, text="Max per log").pack(side="left")
        self.limit_var = tk.IntVar(value=200)
        self.limit_spin = tk.Spinbox(top, from_=10, to=2000, width=6, textvariable=self.limit_var)
        self.limit_spin.pack(side="left", padx=(6, 12))

        ttk.Button(top, text="Run Scan", command=self.run_scan).pack(side="left")
        ttk.Button(top, text="Copy Report", command=self.copy_report).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Save As Text", command=self.save_report_as).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Run as Admin", command=self.run_as_admin).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Clear", command=self.clear).pack(side="left", padx=(8, 0))

        self.admin_label = ttk.Label(top, text="")
        self.admin_label.pack(side="right")

        body = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        body.pack(fill="both", expand=True)

        self.output = tk.Text(body, wrap="none")
        y_scroll = ttk.Scrollbar(body, orient="vertical", command=self.output.yview)
        x_scroll = ttk.Scrollbar(body, orient="horizontal", command=self.output.xview)
        self.output.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.output.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        self.status = ttk.Label(self.root, text="Ready", padding=(10, 0, 10, 10))
        self.status.pack(fill="x")

    # Show the initial instructions.
    def _write_intro(self) -> None:
        intro = (
            "Run a scan to collect recent suspicious or noteworthy events from local Windows logs.\n"
            "The report is saved automatically as a text file in the current folder.\n"
            "For Security log access, run the program as administrator.\n"
        )
        self._set_output(intro)

    # Update the UI with current admin state.
    def _refresh_admin_state(self) -> None:
        if self._is_admin():
            self.admin_label.config(text="Administrator: Yes")
        else:
            self.admin_label.config(text="Administrator: No")

    # Check whether the process is elevated.
    def _is_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    # Relaunch the script elevated.
    def run_as_admin(self) -> None:
        script = Path(__file__).resolve()
        params = f'"{script}"'
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if result <= 32:
            self.status.config(text="Elevation request failed")
        else:
            self.status.config(text="Elevation request sent")

    # Clear the report display.
    def clear(self) -> None:
        self.records.clear()
        self.last_report_text = ""
        self.last_report_path = None
        self._write_intro()
        self.status.config(text="Cleared")

    # Run the event log scan and generate a report.
    def run_scan(self) -> None:
        hours = self._selected_timeframe_hours()
        limit = max(1, int(self.limit_var.get()))

        if self.request_admin_var.get() and not self._is_admin():
            self.status.config(text="Elevation request sent")
            self.run_as_admin()
            return

        self.status.config(text="Scanning event logs...")
        self.root.update_idletasks()

        records: list[EventRecord] = []
        issues: list[str] = []

        log_names = ("System", "Application", "Security") if self._is_admin() else ("System", "Application")

        for log_name in log_names:
            log_records, log_issue = self._scan_log(log_name, hours, limit)
            records.extend(log_records)
            if log_issue:
                issues.append(log_issue)

        records.sort(key=lambda item: item.timestamp, reverse=True)
        self.records = records
        self.last_report_text = self._build_report(records, issues, self.timeframe_var.get().strip(), limit)
        self._set_output(self.last_report_text)
        self.last_report_path = self._write_report_file(self.last_report_text)

        if records:
            self.status.config(text=f"Found {len(records)} noteworthy event(s)")
        else:
            self.status.config(text="No noteworthy events matched the current filters")

    # Convert the selected time frame into hours.
    def _selected_timeframe_hours(self) -> int:
        value = self.timeframe_var.get().strip().lower()
        return self.timeframe_hours.get(value, 24)

    # Copy the current report text to the clipboard.
    def copy_report(self) -> None:
        text = self.output.get("1.0", tk.END).strip()
        if not text:
            self.status.config(text="Nothing to copy")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.config(text="Report copied")

    # Save the current report to a chosen text file.
    def save_report_as(self) -> None:
        text = self.output.get("1.0", tk.END).strip()
        if not text:
            self.status.config(text="Nothing to save")
            return

        path = filedialog.asksaveasfilename(
            title="Save Event Report As",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=self.last_report_path.name if self.last_report_path else "event_report.txt",
        )
        if not path:
            self.status.config(text="Save cancelled")
            return

        output_path = Path(path)
        output_path.write_text(text + "\n", encoding="utf-8")
        self.last_report_path = output_path
        self.status.config(text=f"Saved to {output_path.name}")

    # Scan a single event log using a filtered XPath query.
    def _scan_log(self, log_name: str, hours: int, limit: int) -> tuple[list[EventRecord], str | None]:
        query = self._build_query(log_name, hours)
        records: list[EventRecord] = []

        try:
            handle = win32evtlog.EvtQuery(log_name, win32evtlog.EvtQueryReverseDirection, query)
        except Exception as exc:
            return records, f"{log_name}: {exc}"

        while len(records) < limit:
            batch_size = min(50, limit - len(records))
            try:
                events = win32evtlog.EvtNext(handle, batch_size)
            except Exception as exc:
                return records, f"{log_name}: {exc}"

            if not events:
                break

            for event in events:
                try:
                    xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    record = self._parse_event_xml(xml, log_name)
                except Exception:
                    continue
                if record:
                    records.append(record)

        issue = None
        if not records:
            issue = f"{log_name}: no matching events found"
        return records, issue

    # Build the XPath query for a log.
    def _build_query(self, log_name: str, hours: int) -> str:
        time_filter = f"TimeCreated[timediff(@SystemTime) <= {hours * 60 * 60 * 1000}]"
        event_ids = self._event_ids_for_log(log_name)

        conditions = ["Level=1", "Level=2", "Level=3"]
        conditions.extend(f"EventID={event_id}" for event_id in sorted(event_ids))

        return f"*[System[{time_filter} and ({' or '.join(conditions)})]]"

    # Return the suspicious event IDs for the selected log.
    def _event_ids_for_log(self, log_name: str) -> set[int]:
        if log_name == "System":
            return {41, 6008, 7031, 7034, 7040, 7045}
        if log_name == "Security":
            return {
                1100,
                1102,
                4625,
                4648,
                4672,
                4697,
                4719,
                4720,
                4722,
                4723,
                4724,
                4725,
                4726,
                4728,
                4729,
                4732,
                4733,
                4740,
                4768,
                4769,
                4771,
                4776,
            }
        return set()

    # Parse one event XML payload into a report record.
    def _parse_event_xml(self, xml: str, log_name: str) -> EventRecord | None:
        root = ET.fromstring(xml)
        namespace = root.tag.split("}", 1)[0].strip("{")
        ns = {"e": namespace}

        system = root.find("e:System", ns)
        if system is None:
            return None

        provider = ""
        provider_node = system.find("e:Provider", ns)
        if provider_node is not None:
            provider = provider_node.attrib.get("Name", "")

        event_id = self._text(system, "e:EventID", ns)
        level_num = self._text(system, "e:Level", ns)
        time_node = system.find("e:TimeCreated", ns)
        timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""

        event_data: list[str] = []
        for data in root.findall("e:EventData/e:Data", ns):
            value = (data.text or "").strip()
            if not value:
                continue
            name = data.attrib.get("Name", "").strip()
            event_data.append(f"{name}={value}" if name else value)

        reason = self._reason_for_event(log_name, event_id, level_num)
        summary = "; ".join(event_data[:4]) if event_data else reason
        summary = self._shorten(summary, 110)

        return EventRecord(
            timestamp=timestamp,
            log_name=log_name,
            event_id=event_id,
            level=self._level_label(level_num),
            provider=self._shorten(provider or log_name, 28),
            reason=self._shorten(reason, 28),
            summary=summary,
        )

    # Pull a namespaced text field from the XML.
    def _text(self, element: ET.Element, path: str, ns: dict[str, str]) -> str:
        value = element.findtext(path, default="", namespaces=ns)
        return (value or "").strip()

    # Label event levels in a human-friendly way.
    def _level_label(self, level_num: str) -> str:
        return {
            "1": "Critical",
            "2": "Error",
            "3": "Warning",
            "4": "Info",
            "0": "LogAlways",
        }.get(level_num, level_num or "Unknown")

    # Map event IDs and levels to a short reason.
    def _reason_for_event(self, log_name: str, event_id: str, level_num: str) -> str:
        event_id_int = None
        try:
            event_id_int = int(event_id)
        except ValueError:
            pass

        known_reasons = {
            41: "Kernel power loss",
            6008: "Unexpected shutdown",
            7031: "Service terminated",
            7034: "Service crashed",
            7040: "Service start changed",
            7045: "Service installed",
            1100: "Event log cleared",
            1102: "Security log cleared",
            4625: "Failed logon",
            4648: "Logon with explicit creds",
            4672: "Special privileges assigned",
            4697: "Service installed",
            4719: "Audit policy changed",
            4720: "User account created",
            4722: "User account enabled",
            4723: "Password change attempt",
            4724: "Password reset attempt",
            4725: "User account disabled",
            4726: "User account deleted",
            4728: "Added to global group",
            4729: "Removed from global group",
            4732: "Added to local group",
            4733: "Removed from local group",
            4740: "Account locked out",
            4768: "Kerberos ticket requested",
            4769: "Kerberos service ticket requested",
            4771: "Kerberos pre-auth failed",
            4776: "NTLM authentication attempt",
        }
        if event_id_int in known_reasons:
            return known_reasons[event_id_int]

        if level_num == "1":
            return "Critical event"
        if level_num == "2":
            return "Error event"
        if level_num == "3":
            return "Warning event"
        return f"{log_name} event"

    # Shorten text for the table.
    def _shorten(self, text: str, limit: int) -> str:
        clean = " ".join(text.split())
        if len(clean) <= limit:
            return clean
        return clean[: max(0, limit - 3)] + "..."

    # Build the final report text.
    def _build_report(self, records: list[EventRecord], issues: list[str], timeframe_label: str, limit: int) -> str:
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_state = "Yes" if self._is_admin() else "No"

        lines = [
            "Event Viewer Abnormal Event Report",
            f"Generated: {generated}",
            f"Computer: {os.environ.get('COMPUTERNAME', '')}",
            f"Administrator: {admin_state}",
            f"Time window: last {timeframe_label}",
            f"Maximum events per log: {limit}",
            f"Matched records: {len(records)}",
            "",
        ]

        if issues:
            lines.append("Scan notes:")
            for item in issues:
                lines.append(f"- {item}")
            lines.append("")

        if records:
            table = PrettyTable()
            table.field_names = ["Time", "Log", "Event ID", "Level", "Provider", "Reason", "Summary"]
            table.align = "l"
            table.max_width["Time"] = 24
            table.max_width["Log"] = 12
            table.max_width["Event ID"] = 8
            table.max_width["Level"] = 10
            table.max_width["Provider"] = 28
            table.max_width["Reason"] = 28
            table.max_width["Summary"] = 110
            for record in records:
                table.add_row(
                    [
                        self._shorten(record.timestamp, 24),
                        record.log_name,
                        record.event_id,
                        record.level,
                        record.provider,
                        record.reason,
                        record.summary,
                    ]
                )
            lines.append(str(table))
        else:
            lines.append("No noteworthy events matched the current filters.")

        counts = Counter(record.log_name for record in records)
        if counts:
            lines.append("")
            lines.append("By log:")
            for log_name, count in sorted(counts.items()):
                lines.append(f"- {log_name}: {count}")

        return "\n".join(lines)

    # Write the report text to a timestamped file in the current folder.
    def _write_report_file(self, text: str) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path.cwd() / f"event_report_{stamp}.txt"
        output_path.write_text(text + "\n", encoding="utf-8")
        return output_path

    # Replace the report display contents.
    def _set_output(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", text)
        self.output.configure(state="disabled")


# Application entry point.
def main() -> None:
    root = tk.Tk()
    EventViewerReportApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
