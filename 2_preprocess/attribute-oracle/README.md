# attribute-oracle — Preprocess

Preprocessing brings up the controller side of the live deployment from
[stage 1](../../1_analysis_object/attribute-oracle/README.md) and joins the victim device to
it, so the analysis in [stage 3](../../3_security_analysis/attribute-oracle/README.md) has a
network to talk to.

Two things happen here:

**Environment setup** — a local Mosquitto broker and Zigbee2MQTT are started against the
SONOFF ZBDongle-P (`docker-compose.yml`, `mosquitto.conf`, `configuration.yaml`, to be added
in implementation). An environment check verifies the dongle's serial port is present, the
broker is up, and the Zigbee2MQTT frontend/bridge is reachable before any analysis begins.

**Pairing** — the Hue motion sensor is factory-reset and joined to the Zigbee2MQTT network by
opening a pairing window manually (our deliberate stand-in for the attacker's network-entry
step; see the architecture note in the repo-root context). Zigbee2MQTT's device interview
reads the sensor's endpoints and clusters, which stage 3 then enumerates in full.

The Zigbee2MQTT runtime directory (`z2m-data/`) is **gitignored** — it holds the network key
and the device database and must never be committed.
