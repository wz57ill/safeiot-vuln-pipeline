# attribute-oracle — Analysis Object

The analysis object is a **live Zigbee deployment**, not a binary that can be committed —
so, as the stage-1 guidance allows, this README describes what the object is and how it
comes into existence.

The network has three roles:

| Role | Device | Purpose |
|---|---|---|
| Platform / reference | Aeotec Smart Home Hub 2 (SmartThings, Zigbee 3.0) | The "normal user" view — what the edge driver exposes. Used only to establish the *visible* attribute baseline. |
| Victim device | Philips Hue motion sensor (SML00x) | The device whose hidden attributes are discovered and then overwritten. |
| Controller / oracle | SONOFF ZBDongle-P (CC2652P) + Zigbee2MQTT | Our own coordinator; talks raw ZCL to enumerate every supported attribute and to perform the over-the-air write. |

The object "comes into existence" by pairing: the sensor is first joined to SmartThings to
record what the platform shows, then moved to the Zigbee2MQTT network (stage 2) for full
enumeration. See [`../../2_preprocess/attribute-oracle/`](../../2_preprocess/attribute-oracle/README.md).

All experiments run on an isolated network with the author's own devices (academic use).
No large artifacts are committed from this stage.
