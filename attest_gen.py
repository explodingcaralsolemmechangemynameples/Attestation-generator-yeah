#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time

import frida

SYSTEM_APP = "com.oculus.appsafety"
THANK_YOU_MSG = "Thank you for using my tool!!!!!!!!!!!!!!!!!!!!!"


def log(msg=""):
    sys.stdout.write(f"{msg}\n")
    sys.stdout.flush()


class DotSpinner:
    def __init__(self, interval=0.2):
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        step = 0
        while not self._stop_event.is_set():
            if step < 3:
                sys.stdout.write(f"\r{'.' * (step + 1)}   ")
            else:
                sys.stdout.write("\r   ")
            sys.stdout.flush()
            step = (step + 1) % 4
            self._stop_event.wait(timeout=self.interval)
        sys.stdout.write("\r   \r")
        sys.stdout.flush()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()
            self._thread = None


def adb(args, timeout=10):
    try:
        r = subprocess.run(["adb"] + args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _is_ip_endpoint(target):
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", str(target).strip()))


def find_device_target():
    out = adb(["devices"])
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            return parts[0]
    return None


def _get_frida_device(target):
    if target and _is_ip_endpoint(target):
        for dev in frida.enumerate_devices():
            if dev.id == target or dev.name == target:
                return dev
        try:
            return frida.get_device_manager().add_remote_device(target)
        except Exception:
            pass

    if not target:
        return frida.get_usb_device(timeout=10)

    for dev in frida.enumerate_devices():
        if dev.id == target or dev.name == target:
            return dev

    try:
        return frida.get_device(target, timeout=10)
    except Exception:
        return frida.get_usb_device(timeout=10)


def resolve_pid(serial, target):
    if isinstance(target, int):
        return target
    s = str(target).strip()
    if s.isdigit():
        return int(s)
    adb_prefix = ["-s", serial] if serial else []
    out = adb(adb_prefix + ["shell", f"pidof {s} 2>/dev/null || ps -A | grep -E '\\s{s}(\\s|$)' | awk '{{print $2}}'"])
    for token in out.split():
        if token.isdigit():
            return int(token)
    return s


FRIDA_SCRIPT = r"""
import Java from "frida-java-bridge";

var _capturedDat = null;

function tryCaptureFromInstance(t) {
    try {
        if (!t) return false;
        var v = t.get();
        if (v !== null && v !== undefined) {
            var s = String(v);
            if (s.length > 20) {
                _capturedDat = s;
                return true;
            }
        }
    } catch (e) {}
    return false;
}

function scanLiveDat() {
    try {
        Java.perform(function () {
            Java.use("com.oculus.graphapi.GraphQLAuthToken");
            Java.choose("com.oculus.graphapi.GraphQLAuthToken", {
                onMatch: function (t) { tryCaptureFromInstance(t); },
                onComplete: function () {}
            });
        });
    } catch (e) {}
    return _capturedDat;
}

function getAttestationTokenSync(pkgName, dat) {
    return new Promise(function (resolve, reject) {
        Java.perform(function () {
            try {
                var PA = Java.use("com.oculus.appsafety.platformintegrity.PlatformAttestation");
                var TZ = Java.use("com.oculus.appsafety.platformintegrity.AttestationTzApp");
                var GQL = Java.use("com.oculus.appsafety.common.GraphQLQueryAppSafetyClient");
                var Logger = Java.use("horizonosx.com.oculus.os.telemetry.UnifiedTelemetryLogger");
                var Token = Java.use("com.oculus.graphapi.GraphQLAuthToken");
                var AT = Java.use("android.app.ActivityThread");
                var SR = Java.use("java.security.SecureRandom");
                var B64 = Java.use("android.util.Base64");

                var ctx = AT.currentApplication().getApplicationContext();
                var tzApp = TZ.$new();
                var token = Token.create(dat);
                var gqlClient = GQL.$new(token);
                var logger = Logger.getInstance(ctx);
                var pa = PA.$new(gqlClient, logger, ctx, tzApp);

                var raw = Java.array('byte', new Array(16).fill(0));
                SR.$new().nextBytes(raw);
                var b64 = String(B64.encodeToString(raw, B64.URL_SAFE.value | B64.NO_WRAP.value));
                var challengeBytes = Java.array('byte',
                    b64.split('').map(function (c) { return c.charCodeAt(0); })
                );

                var jwt = pa.getAttestationToken(challengeBytes, ctx, pkgName);
                resolve(JSON.stringify({ jwt: String(jwt), challenge: b64 }));
            } catch (e) {
                reject(new Error(String(e)));
            }
        });
    });
}

try {
    Java.perform(function () {
        try {
            var S = Java.use("com.oculus.appsafety.signals.SuperUserSafetySignal");
            var ArrayList = Java.use("java.util.ArrayList");
            S.checkBinaries.implementation = function () { return ArrayList.$new(); };
            S.checkPackages.implementation = function () { return ArrayList.$new(); };
        } catch (e) {}

        try {
            var Token = Java.use("com.oculus.graphapi.GraphQLAuthToken");
            Token.get.implementation = function () {
                var ret = this.get();
                if (ret) {
                    var s = String(ret);
                    if (s.length > 20) _capturedDat = s;
                }
                return ret;
            };
            Token.create.overload("java.lang.String").implementation = function (s) {
                if (s && s.length > 20) _capturedDat = String(s);
                return this.create(s);
            };
            Token.create.overload("android.content.Context", "java.lang.String").implementation = function (ctx, s) {
                if (s && s.length > 20) _capturedDat = String(s);
                return this.create(ctx, s);
            };
        } catch (e) {}

        scanLiveDat();
    });
} catch (e) {}

function dispatchCommand(msg) {
    var id = msg.id;
    var cmd = msg.cmd;
    var args = msg.args || [];
    var p;
    if (cmd === "getCapturedDat") {
        p = Promise.resolve(_capturedDat);
    } else if (cmd === "rescan") {
        p = Promise.resolve(scanLiveDat());
    } else if (cmd === "getAttestationToken") {
        p = getAttestationTokenSync(args[0], args[1]);
    } else {
        p = Promise.reject(new Error("unknown command: " + cmd));
    }
    p.then(function (res) {
        send({ type: "rpc_reply", id: id, ok: true, value: res });
    }, function (err) {
        send({ type: "rpc_reply", id: id, ok: false, error: String(err) });
    });
    recv(dispatchCommand);
}

recv(dispatchCommand);
"""


def compile_agent(source_code):
    cwd = os.path.dirname(os.path.abspath(__file__))
    entry_path = os.path.join(cwd, "_agent_entry.js")
    out_path = os.path.join(cwd, "_agent_out.js")
    with open(entry_path, "w", encoding="utf-8") as f:
        f.write(source_code)
    try:
        proc = subprocess.run(["frida-compile", entry_path, "-o", out_path], cwd=cwd, capture_output=True, text=True)
        if proc.returncode == 0 and os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8") as f:
                return f.read()
        raise RuntimeError(f"frida-compile failed (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    finally:
        for p in (entry_path, out_path):
            try:
                os.unlink(p)
            except OSError:
                pass


class AgentClient:
    def __init__(self, script):
        self.script = script
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._replies = {}
        self._counter = 0
        script.on("message", self._on_message)

    def _on_message(self, message, data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "rpc_reply":
                with self._cond:
                    self._replies[payload["id"]] = payload
                    self._cond.notify_all()
        elif message.get("type") == "error":
            log(f"[agent error] {message.get('description', message)}")

    def call(self, cmd, args=None, timeout=15.0):
        with self._cond:
            self._counter += 1
            req_id = self._counter
            self.script.post({"cmd": cmd, "args": args or [], "id": req_id})
            deadline = time.monotonic() + timeout
            while req_id not in self._replies:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(f"Agent call '{cmd}' timed out")
                self._cond.wait(timeout=rem)
            reply = self._replies.pop(req_id)
        if not reply.get("ok"):
            raise RuntimeError(reply.get("error", "Unknown agent error"))
        return reply.get("value")


def frida_attach(app_id=SYSTEM_APP, device_id=None):
    bundled = compile_agent(FRIDA_SCRIPT)
    device = _get_frida_device(device_id)
    target = resolve_pid(device_id, app_id)
    session = device.attach(target)
    script = session.create_script(bundled)
    client = AgentClient(script)
    script.load()
    return session, client


def capture_dat(client, timeout_attempts=20):
    for _ in range(timeout_attempts):
        captured = client.call("getCapturedDat")
        if captured:
            return captured
        captured = client.call("rescan")
        if captured:
            return captured
        time.sleep(0.25)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--package")
    ap.add_argument("--dat")
    ap.add_argument("--getdat", action="store_true")
    ap.add_argument("--app", default=SYSTEM_APP)
    args = ap.parse_args()

    if not args.getdat and not args.package:
        ap.error("the following arguments are required: --package (or pass --getdat)")

    log("Made by exploding car and deepseek thanks to gemini for fixing sum shi :3")
    log("Pulling ur shi :P")

    spinner = DotSpinner()
    spinner.start()

    try:
        target_device = find_device_target()
        if not target_device:
            spinner.stop()
            log("[!] No adb device found.")
            sys.exit(1)

        try:
            session, client = frida_attach(args.app, target_device)
        except Exception as e:
            spinner.stop()
            log(f"[!] Failed to attach: {e}")
            sys.exit(1)

        if args.getdat:
            dat = capture_dat(client)
            session.detach()
            spinner.stop()
            if not dat:
                log("[!] DAT not found.")
                sys.exit(1)
            log(f"I-I-I-Its not like I pulled ur dat cause you asked *hmph*\n{dat}")
            log(THANK_YOU_MSG)
            return

        dat = args.dat
        if not dat:
            dat = capture_dat(client)

        if not dat:
            session.detach()
            spinner.stop()
            log("[!] DAT not found. Pass --dat <token>.")
            sys.exit(1)

        try:
            jwt = json.loads(client.call("getAttestationToken", [args.package, dat], timeout=30.0))["jwt"]
        except Exception as e:
            session.detach()
            spinner.stop()
            log(f"[!] Failed: {e}")
            sys.exit(1)

        session.detach()
        spinner.stop()

        log(f"I-I-I-Its not like I pulled ur jwt cause you asked *hmph*\n{jwt}")
        log(THANK_YOU_MSG)

        with open("attestation_jwt.txt", "w") as f:
            f.write(jwt)
    finally:
        spinner.stop()


if __name__ == "__main__":
    main()