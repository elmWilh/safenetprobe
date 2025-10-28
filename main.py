from kivy.app import App
from kivy.lang import Builder
from kivy.properties import StringProperty, BooleanProperty, NumericProperty
from kivy.clock import mainthread, Clock
from threading import Thread
import json, os, time

import probe_core as core
from probe_core import api_probe
from network_info import get_network_snapshot

KV = """
BoxLayout:
    orientation: "vertical"
    padding: "12dp"
    spacing: "10dp"

    Label:
        text: "Safe Net Probe"
        font_size: "22sp"
        size_hint_y: None
        height: self.texture_size[1] + dp(6)

    BoxLayout:
        size_hint_y: None
        height: dp(64)
        spacing: dp(10)
        BoxLayout:
            orientation: "vertical"
            Label:
                text: "Сеть (локально)"
                size_hint_y: None
                height: dp(18)
            Label:
                id: net
                text: app.network_text
                text_size: self.width, None
                size_hint_y: None
                height: max(self.texture_size[1], dp(40))

    TextInput:
        id: hosts
        hint_text: "Хосты через запятую (example.com, google.com, ...)"
        text: "google.com,cloudflare.com,web.telegram.org,avito.ru,vk.com,yandex.ru,wikipedia.org,protonvpn.com"
        multiline: True
        size_hint_y: None
        height: dp(120)

    TextInput:
        id: dns
        hint_text: "DNS-резолверы (опц.): 1.1.1.1,8.8.8.8"
        text: "1.1.1.1,8.8.8.8"
        size_hint_y: None
        height: dp(44)

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(10)
        Button:
            text: "Сканировать"
            on_release: app.run_scan()
            disabled: app.busy
        Button:
            text: "Открыть HTML"
            on_release: app.open_report()
        Button:
            text: "Поделиться"
            on_release: app.share_report()

    BoxLayout:
        size_hint_y: None
        height: dp(28)
        spacing: dp(10)
        Label:
            id: counter
            text: f"Отсканировано: {app.done}/{app.total}"
            size_hint_x: 0.35
            halign: "left"
            valign: "middle"
            text_size: self.size
        ProgressBar:
            id: pbar
            max: max(1, app.total)
            value: app.done

    Label:
        id: status
        text: app.status_text
        text_size: self.width, None
        size_hint_y: None
        height: max(self.texture_size[1], dp(40))

    Label:
        text: "Логи"
        size_hint_y: None
        height: dp(24)

    ScrollView:
        size_hint_y: 0.5
        do_scroll_x: False
        TextInput:
            id: logs
            readonly: True
            text: app.logs_text
            font_size: "13sp"
            size_hint_y: None
            height: max(self.minimum_height, dp(220))
            cursor_blink: False
            background_color: 0.05,0.06,0.1,1
            foreground_color: 0.95,0.96,1,1

    Label:
        text: "Последний отчёт (сводка)"
        size_hint_y: None
        height: dp(24)

    ScrollView:
        GridLayout:
            id: results
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            row_default_height: self.width
            row_force_default: False
"""

class SafeProbeApp(App):
    status_text = StringProperty("Готов")
    busy = BooleanProperty(False)
    out_dir = StringProperty("")
    html_path = StringProperty("")
    json_path = StringProperty("")
    csv_path  = StringProperty("")
    logs_text = StringProperty("")
    total = NumericProperty(0)
    done = NumericProperty(0)
    network_text = StringProperty("—")

    def build(self):
        self.title = "Safe Net Probe"
        self.out_dir = self._default_out_dir()
        ui = Builder.load_string(KV)
        try:
            master = os.path.join(os.path.dirname(__file__), "hosts_master.txt")
            if os.path.exists(master):
                with open(master, "r", encoding="utf-8") as f:
                    ui.ids.hosts.text = f.read().strip()
        except Exception:
            pass
        Clock.schedule_interval(self._poll_progress, 0.5)
        Clock.schedule_interval(self._update_network, 3.0)
        self._update_network(0)
        return ui

    def _default_out_dir(self):
        base = os.path.expanduser("~/SafeNetProbe")
        os.makedirs(base, exist_ok=True)
        return base

    def _parse_hosts(self, raw):
        items = [x.strip() for x in raw.replace("\n", ",").split(",")]
        return [x for x in items if x]

    def run_scan(self):
        if self.busy: return
        hosts = self._parse_hosts(self.root.ids.hosts.text)
        if not hosts:
            self._set_status("Укажите хосты")
            return
        dns_raw = self.root.ids.dns.text.strip()
        dns_list = [x.strip() for x in dns_raw.split(",") if x.strip()] if dns_raw else None
        self.busy = True
        self.logs_text = ""
        self.total = len(hosts)
        self.done = 0
        self._set_status("Сканирование…")
        Thread(target=self._scan_thread, args=(hosts, dns_list), daemon=True).start()

    def _timestamp(self):
        return time.strftime("%Y%m%d_%H%M%S", time.gmtime())

    def _paths(self):
        ts = self._timestamp()
        html = os.path.join(self.out_dir, f"report_{ts}.html")
        jsn  = os.path.join(self.out_dir, f"report_{ts}.json")
        csv  = os.path.join(self.out_dir, f"report_{ts}.csv")
        return html, jsn, csv

    def _render_html(self, payload: dict) -> str:
        s = json.dumps(payload.get("summary"), ensure_ascii=False, indent=2)
        notes = payload.get("policy_fingerprint", [])
        rows = payload.get("results", [])
        head = """<!doctype html><meta charset="utf-8"><title>Network Availability Report</title>
        <style>body{font-family:system-ui,Roboto,Arial;margin:20px}table{border-collapse:collapse;width:100%}
        th,td{border:1px solid #ccc;padding:6px;font-size:14px}th{background:#f3f6fb;position:sticky;top:0}
        code{background:#f5f7fb;padding:1px 4px;border-radius:4px}</style>
        <h1>Network Availability Report</h1>"""
        parts = [head, f"<p>Generated at {payload.get('generated_at_utc')}</p>"]
        parts += ["<h2>Summary</h2><pre>", s, "</pre>"]
        parts += ["<h2>Policy fingerprint</h2><ul>"] + [f"<li>{n}</li>" for n in notes] + ["</ul>"]
        parts += ["<h2>Matrix</h2><table><tr><th>Host</th><th>Diag</th><th>HTTP</th><th>Best</th><th>Caps</th></tr>"]
        for r in rows:
            caps = ",".join(r.get("capabilities", []))
            parts += [f"<tr><td><b>{r['host']}</b></td><td>{r.get('diag','')}</td>"
                      f"<td>{r.get('http_mode','-')} {r.get('http_status','-')}</td>"
                      f"<td><code>{r.get('best_transport','-')}</code></td><td>{caps}</td></tr>"]
        parts += ["</table>"]
        return "".join(parts)

    def _scan_thread(self, hosts, dns_list):
        try:
            payload = api_probe(hosts=hosts, dns_servers=dns_list)
            html_path, json_path, csv_path = self._paths()
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            rows = payload.get("results", [])
            if rows:
                import csv as _csv
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    w = _csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                    w.writeheader()
                    for r in rows: w.writerow(r)
            html = self._render_html(payload)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
            self._done(html_path, json_path, csv_path, ok=True, payload=payload)
        except Exception as e:
            self._set_status(f"Ошибка: {type(e).__name__}: {e}")
            self.busy = False

    @mainthread
    def _done(self, html, jsn, csv, ok=True, payload=None):
        self.html_path, self.json_path, self.csv_path = html, jsn, csv
        pr = payload.get("progress") if isinstance(payload, dict) else None
        if pr:
            self.total = int(pr.get("total") or self.total)
            self.done = int(pr.get("done") or self.done)
        self._set_status(f"Готово: {self.done}/{self.total}. HTML → {html}")
        self._render_summary_cards(payload)
        self.busy = False

    @mainthread
    def _set_status(self, text):
        self.status_text = text

    def _read_progress_from_core(self):
        try:
            return dict(core._PROGRESS)
        except Exception:
            return None

    def _read_logs_from_core(self, limit=200):
        try:
            items = list(core._UI_LOGS)[-limit:]
            return "\n".join(f"[{i.get('ts','')}] {i.get('msg','')}" for i in items)
        except Exception:
            return ""

    def _poll_progress(self, dt):
        if self.busy:
            pr = self._read_progress_from_core()
            if pr:
                self.total = int(pr.get("total") or self.total or 1)
                self.done = int(pr.get("done") or 0)
            self.logs_text = self._read_logs_from_core(400)
            try:
                logs_widget = self.root.ids.logs
                logs_widget.cursor = (0, 10**9)
                logs_widget.scroll_y = 0
            except Exception:
                pass

    def _format_net_text(self, snap: dict):
        at = snap.get("active_transport") or "UNKNOWN"
        ip = snap.get("local_ip") or "—"
        parts = [f"{at} • IP: {ip}"]
        ssid = snap.get("wifi_ssid"); rssi = snap.get("wifi_rssi"); lnk = snap.get("wifi_link_mbps")
        if ssid or rssi is not None:
            parts.append(f"Wi-Fi: {ssid or '—'} ({'' if rssi is None else str(rssi)+' dBm'}){'' if not lnk else f', {lnk} Mbps'}")
        op = snap.get("cell_operator"); gen = snap.get("cell_generation"); dbm = snap.get("cell_signal_dbm")
        if op or gen or dbm is not None:
            parts.append(f"Cell: {op or '—'} {gen or ''} {'' if dbm is None else '('+str(dbm)+' dBm)'}")
        return "  |  ".join(parts)

    def _update_network(self, dt):
        try:
            snap = get_network_snapshot()
            self.network_text = self._format_net_text(snap)
        except Exception:
            self.network_text = "—"

    @mainthread
    def _render_summary_cards(self, payload: dict):
        grid = self.root.ids.results
        grid.clear_widgets()
        rows = payload.get("results", [])
        from kivy.uix.label import Label
        from kivy.uix.boxlayout import BoxLayout
        for r in rows[:50]:
            box = BoxLayout(orientation="vertical", size_hint_y=None, height="86dp", padding=("6dp",), spacing="4dp")
            t1 = f"[b]{r.get('host','')}[/b]  |  {r.get('diag','')}"
            t2 = f"HTTP: {r.get('http_mode','-')} {r.get('http_status','-')}  •  BEST: {r.get('best_transport','-')}"
            t3 = f"CAPS: {', '.join(r.get('capabilities', []))}"
            box.add_widget(Label(text=t1, markup=True, size_hint_y=None, height="24dp"))
            box.add_widget(Label(text=t2, size_hint_y=None, height="24dp"))
            box.add_widget(Label(text=t3, size_hint_y=None, height="24dp"))
            grid.add_widget(box)

    def open_report(self):
        if not self.html_path:
            self._set_status("Сначала сделайте скан")
            return
        try:
            from androidstorage4kivy import SharedStorage
            self._set_status("Открытие…")
        except Exception:
            import webbrowser
            webbrowser.open("file://" + self.html_path)
            return
        try:
            import android, jnius
            from jnius import autoclass
            from android import mActivity
            f = self.html_path
            Uri = autoclass('android.net.Uri')
            Intent = autoclass('android.content.Intent')
            File = autoclass('java.io.File')
            fobj = File(f)
            provider = autoclass('androidx.core.content.FileProvider')
            uri = provider.getUriForFile(mActivity, mActivity.getPackageName()+".fileprovider", fobj)
            intent = Intent(Intent.ACTION_VIEW)
            intent.setDataAndType(uri, "text/html")
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            mActivity.startActivity(intent)
        except Exception as e:
            self._set_status(f"Не удалось открыть: {e}")

    def share_report(self):
        if not self.html_path:
            self._set_status("Сначала сделайте скан")
            return
        try:
            from plyer import share
            share.share(filepath=self.html_path)
        except Exception as e:
            self._set_status(f"Не удалось поделиться: {e}")

if __name__ == "__main__":
    SafeProbeApp().run()
