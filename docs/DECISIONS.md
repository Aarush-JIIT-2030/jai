# Technical decisions log

Record each decision with date, context, alternatives, chosen approach and evidence.

## Initial constraints
- Offline dataset replay only; no live network actions.
- Use five organiser-defined classes and the exact organiser label mapping.
- Keep official validation records untouched until final evaluation.
- Agent 2 anomaly scoring must be independent of Agent 1's predicted class.
- Fusion must retain both agent outputs, agreement/disagreement status and rationale.
- Model-performance claims are valid only when tied to a measured run of the referenced code and dataset revision.
