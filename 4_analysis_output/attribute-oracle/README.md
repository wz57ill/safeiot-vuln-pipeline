# attribute-oracle — Analysis Output

A run produces a **hidden-attribute report** for the victim sensor and the **evidence that a
hidden attribute can be overwritten over the air to neutralize it**.

## Committed example (to be added)

| File | What it is |
|---|---|
| `hidden_attributes_report.json` | The machine-readable result: the device's supported attributes, the platform-visible set, and the computed hidden set. |
| `example_run.log` | A full reference run, from enumeration through the over-the-air write and the before/after walk-test. |
| (optional) evidence image | Before/after sensor state, or the platform screen still showing the sensor "healthy" after it was neutralized. |

Running through the harness also writes `last_run.log` here. That file is **gitignored** —
`example_run.log` is the version kept as the committed reference.
