# FLUX Signatures — Bytecode Pattern Recognition

Detect common patterns in FLUX bytecode programs.

## Patterns Detected
- **Loop**: backward jumps
- **Counter**: DEC + JNZ pair
- **Accumulator**: ADD with feedback
- **MAC**: MUL with feedback (factorial-like)
- **Swap**: PUSH/PUSH/POP/POP sequence
- **Conditional**: CMP + JZ/JNZ pair
- **Copy**: MOV with distinct src/dst
- **Stack-heavy**: many PUSH operations

9 tests passing.
