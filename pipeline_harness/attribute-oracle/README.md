# attribute-oracle — Pipeline Harness

`attribute-oracle` reproduces the CCS 2025 **hidden-attributes** vulnerability on a live
Zigbee network: it enumerates every attribute a device actually supports, compares that
against what the SmartThings platform exposes to find the **hidden** ones, and overwrites one
over the air to neutralize the device. It also ships an owner-facing view that surfaces those
same hidden attributes and alerts on changes.

## Flow

| Stage | What happens |
|---|---|
| [1 — Analysis object](../../1_analysis_object/attribute-oracle/README.md) | A live, isolated Zigbee network: SmartThings hub (reference platform), Hue motion sensor (victim), SONOFF ZBDongle-P + Zigbee2MQTT (our controller). |
| [2 — Preprocess](../../2_preprocess/attribute-oracle/README.md) | Start Mosquitto + Zigbee2MQTT, verify the environment, and join the sensor via a manually opened pairing window. |
| [3 — Security analysis](../../3_security_analysis/attribute-oracle/README.md) | Enumerate supported attributes, baseline the platform-visible set, diff for the hidden set, then over-the-air write one to neutralize the sensor. |
| [4 — Analysis output](../../4_analysis_output/attribute-oracle/README.md) | The hidden-attribute report and before/after neutralization evidence. |

## Architecture scope

We operate from the coordinator position (Architecture A): the SONOFF runs Zigbee2MQTT as our
own coordinator and the sensor is paired to it. The faithful rogue-join onto the victim's
existing network (Architecture B) is described as future work, not implemented — a Zigbee
network has a single coordinator, and a non-coordinator join needs custom firmware.

## Prerequisites (to be finalized in implementation)

- Host (macOS/Linux) with Docker, or Python 3.11+ and a local Mosquitto broker
- SONOFF ZBDongle-P (CC2652P) with Zigbee2MQTT coordinator firmware
- Philips Hue motion sensor; a SmartThings/Aeotec hub for the platform baseline
- SmartThings CLI/API access for the visible-attribute baseline

## Running (entry point to be added)

The end-to-end entry point will be `run.sh`, driving stages 2 and 3 in one invocation
(Zigbee2MQTT must stay up for the analysis to attach to it) and writing console output to
`4_analysis_output/attribute-oracle/last_run.log`.

```bash
./pipeline_harness/attribute-oracle/run.sh
```

> Status: scaffold only. `run.sh`, the Zigbee2MQTT config, and the Python engine are added in
> the implementation step.
