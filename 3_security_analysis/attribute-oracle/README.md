# attribute-oracle — Security Analysis

Implements the core of the CCS 2025 hidden-attributes finding against the live Zigbee
deployment, and hosts the owner-facing visibility tool that reuses the same engine.

The analysis has four moves:

**Enumerate (supported set).** Talk to Zigbee2MQTT over MQTT and issue ZCL **Discover
Attributes** across each of the victim sensor's clusters (Occupancy Sensing `0x0406`,
Illuminance `0x0400`, Temperature `0x0402`, Power `0x0001`, Basic `0x0000`, including Philips
manufacturer-specific attributes under manufacturer code `0x100B`). This yields everything
the device actually implements.

**Baseline (visible set).** Record what the SmartThings edge driver exposes, read via the
**SmartThings CLI/API**. (An agent-driven UI reader via `mobile-mcp` — the pattern the
umcci-checker tool uses — is a planned later adaptation.)

**Diff (hidden set).** `hidden = supported − visible`. Anything the device implements and will
read/write over the air, but the platform never surfaces, is a hidden attribute.

**Exploit.** Over-the-air write one hidden attribute to neutralize the sensor (primary target:
the manufacturer-specific sensitivity attribute `0x0030` on cluster `0x0406`), then verify the
sensor stops detecting and that no alert/event appears on the platform.

**Owner tool (defense), same engine.** The enumerate step also powers an owner-facing view:
list every device on the network with **all** of its attributes, and watch the Zigbee2MQTT
MQTT stream to **notify on any setting change** — whether the owner or an attacker made it.

Architecture note: we operate from the coordinator position (Architecture A). The faithful
rogue-join (Architecture B) is described in the project writeup as future work, not built here.

Files (to be added in implementation): the Python engine and `requirements.txt`
(`paho-mqtt` for the Z2M/MQTT interface). Run it through the
[harness](../../pipeline_harness/attribute-oracle/README.md) so output lands in stage 4.
