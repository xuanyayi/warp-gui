import importlib.util
import io
import json
from pathlib import Path
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

from PyQt6.QtCore import QThread
from PyQt6.QtTest import QSignalSpy, QTest
from PyQt6.QtWidgets import QApplication

spec = importlib.util.spec_from_file_location("warp_gui", Path(__file__).parents[1] / "warp-gui.py")
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)


def command_result(args, **kwargs):
    if args == ["status"]:
        return json.dumps({"status": "Disconnected"}), True
    if args == ["registration", "show"]:
        return json.dumps({"account": {"type": "free"}}), True
    if args == ["settings"]:
        return json.dumps({"settings": {"operation_mode": "warp", "warp_tunnel_protocol": "masque"}}), True
    return "Success", True


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.worker = gui.WarpWorker(cli="/fake/warp-cli")

    def test_license_is_one_literal_argument_and_errors_are_redacted(self):
        key = 'key; $(touch /tmp/warp-gui-injection) "quoted"'
        errors = []
        self.worker.action_finished.connect(lambda *args: errors.append(args))
        with patch.object(gui.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "Invalid " + key)) as run:
            with patch.object(self.worker, "read_status", return_value={}):
                self.worker.perform_action("license", key)
        args, kwargs = run.call_args
        self.assertEqual(args[0][-3:], ["registration", "license", key])
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(errors, [("license", False, "Invalid [redacted]")])

    def test_missing_stderr_still_reports_exit_code(self):
        with patch.object(gui.subprocess, "run", return_value=subprocess.CompletedProcess([], 3, "", "")):
            output, ok = self.worker.run_cmd(["connect"])
        self.assertFalse(ok)
        self.assertIn("code 3", output)

    def test_timeout_does_not_echo_secret_command(self):
        with patch.object(gui.subprocess, "run", side_effect=subprocess.TimeoutExpired(["license", "secret"], 8)):
            output, ok = self.worker.run_cmd(["registration", "license", "secret"])
        self.assertFalse(ok)
        self.assertIn("timed out", output)
        self.assertNotIn("secret", output)

    def test_status_queries_reuse_details_but_force_and_expiry_refresh_them(self):
        with patch.object(self.worker, "run_cmd", side_effect=command_result) as run, patch.object(gui.time, "monotonic", return_value=10) as clock:
            self.assertEqual(self.worker.read_status()["protocol"], "MASQUE")
            self.worker.read_status()
            self.assertEqual(run.call_count, 4)
            self.worker.read_status(force=True)
            self.assertEqual(run.call_count, 7)
            clock.return_value = 71
            self.worker.read_status()
            self.assertEqual(run.call_count, 10)

    def test_failed_status_and_details_have_no_fabricated_defaults(self):
        with patch.object(self.worker, "run_cmd", return_value=("Daemon unavailable", False)):
            data = self.worker.read_status()
        self.assertEqual(data["status"], "Unknown")
        self.assertEqual(data["error"], "Daemon unavailable")
        self.assertIsNone(data["account_type"])
        self.assertIsNone(data["mode"])
        self.assertIsNone(data["protocol"])

    def test_failed_details_clear_previous_values(self):
        with patch.object(self.worker, "run_cmd", side_effect=command_result):
            self.worker.read_status()
        with patch.object(self.worker, "run_cmd", return_value=("Unavailable", False)):
            data = self.worker.read_status(force=True)
        self.assertIsNone(data["mode"])
        self.assertIsNone(data["protocol"])

    def test_invalid_json_or_shape_is_an_error(self):
        for output in ("not JSON", "[]", "null"):
            with self.subTest(output=output), patch.object(self.worker, "run_cmd", return_value=(output, True)):
                data, error = self.worker.query(["status"])
                self.assertEqual(data, {})
                self.assertTrue(error)

    def test_trace_failure_reports_unavailable(self):
        results = []
        self.worker.trace_finished.connect(lambda *args: results.append(args))
        with patch.object(gui.urllib.request, "urlopen", side_effect=OSError("Network unavailable")):
            self.worker.fetch_trace(7)
        self.assertEqual(results, [(7, {"error": "Network unavailable"})])

    def test_truncated_trace_reports_error_and_completes_job(self):
        results = []
        self.worker.trace_finished.connect(lambda *args: results.append(args))
        with patch.object(gui.urllib.request, "urlopen", side_effect=gui.HTTPException("Incomplete response")):
            self.worker.fetch_trace(8)
        self.assertEqual(results, [(8, {"error": "Incomplete response"})])

    def test_invalid_action_never_starts_command(self):
        with patch.object(self.worker, "run_cmd") as run:
            self.worker.perform_action("set_mode", "bad; command")
        run.assert_not_called()

    def test_modes_and_descriptions_match_scope(self):
        for mode in gui.MODE_COMMANDS:
            self.assertEqual(gui.normalize_mode(gui.MODE_COMMANDS[mode]), mode)
        self.assertEqual(gui.normalize_mode("WarpProxy on port 40000"), "Proxy")
        self.assertIsNone(gui.normalize_mode("FutureMode"))
        self.assertEqual(gui.connection_description("Doh")[1], "DNS only")
        self.assertEqual(gui.connection_description("Proxy")[1], "Proxy")
        self.assertEqual(gui.connection_description(None)[1], "Unknown mode")


class WindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.commands = patch.object(gui.WarpWorker, "run_cmd", autospec=True, side_effect=lambda worker, args, **kwargs: command_result(args, **kwargs))
        self.commands.start()
        self.trace = patch.object(gui.urllib.request, "urlopen", side_effect=lambda *args, **kwargs: io.BytesIO(b"colo=TEST\nip=203.0.113.1\nwarp=on\n"))
        self.trace.start()
        self.window = gui.WarpMainWindow()
        self.wait_for(lambda: not self.window._fetch_pending)
        self.window.poll_timer.stop()

    def tearDown(self):
        self.window.shutdown()
        self.window.tray.hide()
        self.window.deleteLater()
        self.app.processEvents()
        self.commands.stop()
        self.trace.stop()

    def wait_for(self, condition):
        deadline = time.monotonic() + 3
        while not condition() and time.monotonic() < deadline:
            self.app.processEvents()
            QTest.qWait(5)
        self.assertTrue(condition(), "Timed out waiting for Qt job")

    def status(self, state="Connected", mode="Warp", **extra):
        return {"status": state, "mode": mode, "account_type": "Free", "protocol": "MASQUE", **extra}

    def test_slow_poll_is_coalesced_and_action_runs_after_it(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def slow_read(force=False):
            calls.append((force, QThread.currentThread()))
            if len(calls) == 1:
                entered.set()
                release.wait(2)
            return self.status("Disconnected")
        with patch.object(self.window.worker, "read_status", side_effect=slow_read):
            self.window.trigger_fetch_status()
            self.wait_for(entered.is_set)
            for _ in range(10):
                self.window.trigger_fetch_status()
            self.window.begin_action("connect")
            self.assertFalse(self.window.toggle_switch.isEnabled())
            self.assertFalse(self.window.mode_combo.isEnabled())
            self.assertFalse(self.window.tray_toggle_action.isEnabled())
            release.set()
            self.wait_for(lambda: not self.window._fetch_pending and not self.window.is_busy)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(thread == self.window.worker_thread for _, thread in calls))
        self.assertTrue(self.window.toggle_switch.isEnabled())

    def test_unchanged_status_does_not_recreate_icons(self):
        with patch.object(gui, "make_icon", wraps=gui.make_icon) as icon:
            self.window.handle_status_update(self.status("Disconnected"))
            self.window.handle_status_update(self.status("Disconnected"))
        icon.assert_not_called()

    def test_dns_and_proxy_modes_do_not_query_direct_trace(self):
        requests = QSignalSpy(self.window.trace_requested)
        for mode in ("Doh", "Dot", "Proxy"):
            self.window.handle_status_update(self.status(mode=mode))
            self.assertNotIn("private and encrypted", self.window.status_desc.text())
        self.assertEqual(len(requests), 0)
        self.assertEqual(self.window.val_ip.text(), "Local proxy")

    def test_trace_arrives_on_gui_thread_and_is_cached(self):
        threads = []
        self.window.worker.trace_finished.connect(lambda *_: threads.append(QThread.currentThread()))
        self.window.handle_status_update(self.status())
        self.wait_for(lambda: not self.window._trace_pending)
        self.assertEqual(self.window.val_ip.text(), "TEST (203.0.113.1)")
        self.assertEqual(threads, [self.app.thread()])
        requests = QSignalSpy(self.window.trace_requested)
        self.window.handle_status_update(self.status())
        self.assertEqual(len(requests), 0)

    def test_stale_trace_cannot_overwrite_disconnection(self):
        generation = self.window._trace_generation
        self.window.handle_status_update(self.status("Disconnected"))
        self.window.handle_trace_finished(generation, {"colo": "OLD", "ip": "203.0.113.1"})
        self.assertEqual(self.window.val_ip.text(), "Offline / Direct")

    def test_failed_trace_never_claims_protection(self):
        self.window.trace_requested.disconnect(self.window.worker.fetch_trace)
        self.window.handle_status_update(self.status())
        self.window.handle_trace_finished(self.window._trace_generation, {"error": "Network unavailable"})
        self.assertEqual(self.window.val_ip.text(), "Trace unavailable")

    def test_stale_trace_cannot_overwrite_new_mode(self):
        self.window.trace_requested.disconnect(self.window.worker.fetch_trace)
        self.window.handle_status_update(self.status())
        generation = self.window._trace_generation
        self.window.handle_status_update(self.status(mode="Doh"))
        self.window.handle_trace_finished(generation, {"colo": "OLD", "ip": "203.0.113.1"})
        self.assertEqual(self.window.val_ip.text(), "Direct / DNS only")

    def test_duplicate_actions_are_ignored_while_busy(self):
        requests = QSignalSpy(self.window.action_requested)
        self.window.begin_action("connect")
        self.window.begin_action("disconnect")
        self.assertEqual(len(requests), 1)
        self.wait_for(lambda: not self.window.is_busy)

    def test_query_error_and_unknown_settings_are_visible(self):
        self.window.handle_status_update({"status": "Unknown", "error": "Daemon unavailable"})
        self.assertEqual(self.window.status_title.text(), "STATUS UNAVAILABLE")
        self.assertEqual(self.window.val_acc.text(), "Unknown")
        self.assertEqual(self.window.proto_combo.currentIndex(), -1)
        self.assertEqual(self.window.mode_combo.currentIndex(), -1)
        self.assertFalse(self.window.toggle_switch.isEnabled())

    def test_connecting_can_be_cancelled_and_locked_policy_disables_controls(self):
        self.window.handle_status_update(self.status("Connecting"))
        self.assertEqual(self.window.tray_toggle_action.text(), "Disconnect")
        self.assertTrue(self.window.toggle_switch.isChecked())
        self.assertEqual(self.window.poll_timer.interval(), 1000)
        self.window.handle_status_update(self.status("Disconnected", switch_locked=True))
        self.assertFalse(self.window.toggle_switch.isEnabled())
        self.assertFalse(self.window.mode_combo.isEnabled())

    def test_poll_interval_follows_window_visibility(self):
        self.assertEqual(self.window.poll_timer.interval(), 10000)
        self.window.show()
        self.assertEqual(self.window.poll_timer.interval(), 5000)
        self.window.hide()
        self.assertEqual(self.window.poll_timer.interval(), 10000)


if __name__ == "__main__":
    unittest.main()
