# flux-signatures

> Bytecode pattern detector that identifies loops, counters, accumulators, swaps, conditionals, and more in FLUX programs.

## What This Is

`flux-signatures` is a Python module that **analyzes FLUX bytecode** to detect common programming patterns — loops, counters, accumulators, multiply-accumulate (MAC), swap idioms, conditional branches, stack-heavy code, and more. It produces a `SignatureResult` with confidence scores, complexity estimates, and cycle predictions.

## Role in the FLUX Ecosystem

Static analysis complements dynamic tools in the FLUX toolchain:

- **`flux-decompiler`** shows *what* instructions exist; signatures shows *what patterns* they form
- **`flux-timeline`** confirms patterns dynamically; signatures detects them statically
- **`flux-profiler`** measures performance; signatures estimates complexity beforehand
- **`flux-coverage`** ensures all patterns are exercised in testing
- **`flux-debugger`** uses pattern knowledge to set intelligent breakpoints

## Key Features

| Feature | Description |
|---------|-------------|
| **Loop Detection** | Identifies backward jumps (95% confidence) |
| **Counter Pattern** | DEC + JNZ combinations |
| **Accumulator/MAC** | ADD/MUL with feedback to self |
| **Swap Idiom** | PUSH, PUSH, POP, POP register exchange |
| **Conditional Branches** | CMP + JZ/JNZ combinations |
| **Complexity Score** | 0.0–1.0 based on loops, branches, arithmetic |
| **Cycle Estimation** | Rough execution cycle prediction |
| **Markdown Reports** | `to_markdown()` for human-readable analysis |
| **Tag System** | Automatic tagging (loop, counter, accumulator, etc.) |

## Quick Start

```python
from flux_signatures import SignatureDetector

detector = SignatureDetector()

# Analyze a factorial loop
bytecode = [0x18, 0, 6, 0x18, 1, 1, 0x22, 1, 1, 0, 0x09, 0, 0x3D, 0, -6, 0, 0x00]
result = detector.analyze(bytecode)

print(f"Complexity: {result.complexity_score:.0%}")
print(f"Estimated cycles: {result.estimated_cycles}")
print(f"Tags: {', '.join(result.tags)}")

for pattern in result.patterns:
    print(f"  {pattern.pattern_type.value}: {pattern.description} "
          f"({pattern.confidence:.0%} confidence)")

# Generate markdown report
print(result.to_markdown())
```

## Running Tests

```bash
python -m pytest tests/ -v
# or
python signatures.py
```

## Related Fleet Repos

- [`flux-decompiler`](https://github.com/SuperInstance/flux-decompiler) — Bytecode to assembly
- [`flux-timeline`](https://github.com/SuperInstance/flux-timeline) — Dynamic execution tracing
- [`flux-profiler`](https://github.com/SuperInstance/flux-profiler) — Performance profiling
- [`flux-coverage`](https://github.com/SuperInstance/flux-coverage) — Code coverage analysis
- [`flux-debugger`](https://github.com/SuperInstance/flux-debugger) — Interactive step debugger

## License

Part of the [SuperInstance](https://github.com/SuperInstance) FLUX fleet.
