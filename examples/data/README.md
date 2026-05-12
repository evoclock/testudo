# Demo data

The demo workflow `examples/workflow-meeting-debrief.json` references a small DuckDB table called `attendees`. v0.1 ships a generator that creates this table from a synthetic CSV; v0.2 swaps in a public dataset for richer demo runs.

## Generating the demo dataset (when v0.1 ships)

```bash
testudo demo init   # creates examples/data/demo.duckdb populated with synthetic attendees
```
