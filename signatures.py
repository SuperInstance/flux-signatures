"""
FLUX Signatures — recognize common patterns in bytecode.

Identifies: loops, counters, accumulators, swaps, sorting patterns, etc.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


class PatternType(Enum):
    LOOP = "loop"
    COUNTER = "counter"
    ACCUMULATOR = "accumulator"
    SWAP = "swap"
    CONDITIONAL = "conditional"
    COPY = "copy"
    ARITHMETIC = "arithmetic"
    STACK_HEAVY = "stack_heavy"
    TAIL_RECURSION = "tail_recursion"
    MULTIPLY_ACCUMULATE = "multiply_accumulate"


@dataclass
class Pattern:
    pattern_type: PatternType
    confidence: float  # 0.0-1.0
    start_offset: int
    end_offset: int
    description: str
    registers_involved: List[int]


@dataclass
class SignatureResult:
    bytecode_length: int
    patterns: List[Pattern]
    complexity_score: float  # 0.0-1.0
    estimated_cycles: int
    tags: List[str]
    
    def to_markdown(self) -> str:
        lines = [f"# FLUX Signature Analysis\n"]
        lines.append(f"**Length:** {self.bytecode_length} bytes")
        lines.append(f"**Complexity:** {self.complexity_score:.0%}")
        lines.append(f"**Tags:** {', '.join(self.tags)}\n")
        for p in self.patterns:
            lines.append(f"- **{p.pattern_type.value}** ({p.confidence:.0%}): {p.description}")
            lines.append(f"  offsets {p.start_offset}-{p.end_offset}, regs: {p.registers_involved}")
        return "\n".join(lines)


OP_NAMES = {
    0x00:"HALT",0x08:"INC",0x09:"DEC",0x0C:"PUSH",0x0D:"POP",
    0x18:"MOVI",0x20:"ADD",0x21:"SUB",0x22:"MUL",0x23:"DIV",
    0x2C:"CMP_EQ",0x2D:"CMP_LT",0x3A:"MOV",0x3C:"JZ",0x3D:"JNZ",
}


def _decode(bc: List[int]) -> List[Tuple[int, str, List[int]]]:
    """Quick decode to (offset, mnemonic, operands)."""
    instrs = []
    i = 0
    while i < len(bc):
        op = bc[i]
        name = OP_NAMES.get(op, f"?")
        if op in (0x00, 0x01): size = 1
        elif op in (0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D): size = 2
        elif op in (0x18, 0x19, 0x1A): size = 3
        else: size = 4
        ops = list(bc[i+1:i+size])
        instrs.append((i, name, ops))
        i += size
    return instrs


class SignatureDetector:
    """Detect common patterns in FLUX bytecode."""
    
    def analyze(self, bytecode: List[int]) -> SignatureResult:
        instrs = _decode(bytecode)
        patterns = []
        tags = set()
        
        mnemonics = [m for _, m, _ in instrs]
        mnemonic_set = set(mnemonics)
        
        # Detect loops (backward jumps)
        for offset, name, ops in instrs:
            if name in ("JZ", "JNZ"):
                off_byte = ops[1] if len(ops) > 1 else 0
                signed = off_byte - 256 if off_byte > 127 else off_byte
                target = offset + signed
                if target < offset:  # backward jump = loop
                    reg = ops[0] if ops else 0
                    patterns.append(Pattern(
                        PatternType.LOOP, 0.95, target, offset + 4,
                        f"Loop from {target} to {offset} using R{reg}",
                        [reg]
                    ))
                    tags.add("loop")
        
        # Detect counter (DEC + JNZ)
        for i, (offset, name, ops) in enumerate(instrs):
            if name == "DEC":
                reg = ops[0]
                # Check if next instruction is JNZ with same reg
                for j in range(i+1, min(i+3, len(instrs))):
                    _, n2, o2 = instrs[j]
                    if n2 == "JNZ" and o2 and o2[0] == reg:
                        patterns.append(Pattern(
                            PatternType.COUNTER, 0.9, offset, instrs[j][0]+4,
                            f"Counter pattern: DEC R{reg} + JNZ",
                            [reg]
                        ))
                        tags.add("counter")
        
        # Detect accumulator (ADD/MUL in loop)
        for offset, name, ops in instrs:
            if name in ("ADD", "MUL"):
                rd = ops[0] if ops else 0
                rs1 = ops[1] if len(ops) > 1 else 0
                if rd == rs1:  # result feeds back to input
                    ptype = PatternType.ACCUMULATOR if name == "ADD" else PatternType.MULTIPLY_ACCUMULATE
                    patterns.append(Pattern(
                        ptype, 0.8, offset, offset + 4,
                        f"{'Accumulator' if name == 'ADD' else 'MAC'}: {name} R{rd}, R{rd}, R{ops[2] if len(ops)>2 else '?'}",
                        [rd]
                    ))
                    tags.add("accumulator" if name == "ADD" else "mac")
        
        # Detect swap (PUSH, PUSH, POP, POP)
        push_pop = [1 if n in ("PUSH","POP") else 0 for _, n, _ in instrs]
        for i in range(len(push_pop)-3):
            if push_pop[i:i+4] == [1,1,1,1]:
                regs_used = []
                for j in range(4):
                    if instrs[i+j][2]:
                        regs_used.append(instrs[i+j][2][0])
                if len(set(regs_used[:2])) == 2 and regs_used[:2] == list(reversed(regs_used[2:4])):
                    patterns.append(Pattern(
                        PatternType.SWAP, 0.85, instrs[i][0], instrs[i+3][0]+2,
                        f"Swap pattern: R{regs_used[0]} <-> R{regs_used[1]}",
                        regs_used[:2]
                    ))
                    tags.add("swap")
        
        # Detect conditional (CMP + JZ/JNZ)
        for i, (offset, name, ops) in enumerate(instrs):
            if name.startswith("CMP"):
                for j in range(i+1, min(i+3, len(instrs))):
                    if instrs[j][1] in ("JZ", "JNZ"):
                        patterns.append(Pattern(
                            PatternType.CONDITIONAL, 0.85, offset, instrs[j][0]+4,
                            f"Conditional: {name} + {instrs[j][1]}",
                            [ops[1] if len(ops)>1 else 0, ops[2] if len(ops)>2 else 0]
                        ))
                        tags.add("conditional")
        
        # Detect copy (MOV Rdst, Rsrc, Rsrc where src==dst field but dst != src)
        for offset, name, ops in instrs:
            if name == "MOV" and len(ops) >= 2:
                rd, rs = ops[0], ops[1]
                if rd != rs and len(ops) >= 3 and rs == ops[2]:
                    patterns.append(Pattern(
                        PatternType.COPY, 0.7, offset, offset + 4,
                        f"Copy: R{rs} -> R{rd}",
                        [rd, rs]
                    ))
                    tags.add("copy")
        
        # Stack-heavy
        push_count = sum(1 for _, n, _ in instrs if n == "PUSH")
        if push_count > 3:
            patterns.append(Pattern(
                PatternType.STACK_HEAVY, 0.7, 0, len(bytecode),
                f"Stack-heavy: {push_count} PUSH operations",
                []
            ))
            tags.add("stack_heavy")
        
        # Complexity score
        has_loop = any(p.pattern_type == PatternType.LOOP for p in patterns)
        has_cond = any(p.pattern_type == PatternType.CONDITIONAL for p in patterns)
        has_arith = "ADD" in mnemonic_set or "MUL" in mnemonic_set
        complexity = (0.3 if has_loop else 0) + (0.2 if has_cond else 0) + (0.2 if has_arith else 0) + (0.1 if "DIV" in mnemonic_set else 0) + min(0.2, len(instrs) * 0.01)
        complexity = min(1.0, complexity)
        
        # Estimate cycles (rough: 1-8 per instruction based on type)
        cycle_map = {"ADD":2,"SUB":2,"MUL":4,"DIV":8,"MOVI":2,"JZ":2,"JNZ":2}
        est = sum(cycle_map.get(m, 1) for _, m, _ in instrs)
        if has_loop: est *= 10  # rough loop multiplier
        
        return SignatureResult(
            bytecode_length=len(bytecode), patterns=patterns,
            complexity_score=complexity, estimated_cycles=est,
            tags=sorted(tags)
        )


# ── Tests ──────────────────────────────────────────────

import unittest


class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.detector = SignatureDetector()
    
    def test_loop_detection(self):
        bc = [0x18,0,5, 0x08,1, 0x09,0, 0x3D,0,0xFA,0, 0x00]
        result = self.detector.analyze(bc)
        loop_patterns = [p for p in result.patterns if p.pattern_type == PatternType.LOOP]
        self.assertGreater(len(loop_patterns), 0)
    
    def test_counter_detection(self):
        bc = [0x18,0,5, 0x09,0, 0x3D,0,0xFC,0, 0x00]
        result = self.detector.analyze(bc)
        counter_patterns = [p for p in result.patterns if p.pattern_type == PatternType.COUNTER]
        self.assertGreater(len(counter_patterns), 0)
    
    def test_accumulator(self):
        bc = [0x18,0,10, 0x18,1,0, 0x20,1,1,0, 0x09,0, 0x3D,0,0xF8,0, 0x00]
        result = self.detector.analyze(bc)
        acc = [p for p in result.patterns if p.pattern_type == PatternType.ACCUMULATOR]
        self.assertGreater(len(acc), 0)
    
    def test_swap_detection(self):
        bc = [0x0C,0, 0x0C,1, 0x0D,1, 0x0D,0, 0x00]
        result = self.detector.analyze(bc)
        swaps = [p for p in result.patterns if p.pattern_type == PatternType.SWAP]
        self.assertGreater(len(swaps), 0)
    
    def test_conditional(self):
        bc = [0x2C,0,0,1, 0x3C,0,2,0, 0x00]
        result = self.detector.analyze(bc)
        conds = [p for p in result.patterns if p.pattern_type == PatternType.CONDITIONAL]
        self.assertGreater(len(conds), 0)
    
    def test_tags(self):
        bc = [0x18,0,5, 0x09,0, 0x3D,0,0xFA,0, 0x00]
        result = self.detector.analyze(bc)
        self.assertIn("loop", result.tags)
    
    def test_complexity_score(self):
        simple = self.detector.analyze([0x18,0,42, 0x00])
        complex_bc = [0x18,0,10, 0x18,1,0, 0x20,1,1,0, 0x2C,2,0,1, 0x3C,2,2,0, 0x09,0, 0x3D,0,0xF0,0, 0x00]
        complex_r = self.detector.analyze(complex_bc)
        self.assertGreater(complex_r.complexity_score, simple.complexity_score)
    
    def test_markdown(self):
        bc = [0x18,0,5, 0x09,0, 0x3D,0,0xFA,0, 0x00]
        result = self.detector.analyze(bc)
        md = result.to_markdown()
        self.assertIn("loop", md.lower())
    
    def test_mac_detection(self):
        # factorial-like: MUL with feedback
        bc = [0x18,0,6, 0x18,1,1, 0x22,1,1,0, 0x09,0, 0x3D,0,0xFA,0, 0x00]
        result = self.detector.analyze(bc)
        mac = [p for p in result.patterns if p.pattern_type == PatternType.MULTIPLY_ACCUMULATE]
        self.assertGreater(len(mac), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
