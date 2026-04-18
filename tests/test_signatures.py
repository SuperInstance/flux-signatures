"""
Comprehensive pytest tests for flux-signatures.

Covers: PatternType enum, Pattern dataclass, SignatureResult (structure,
to_markdown), OP_NAMES table, _decode helper, SignatureDetector.analyze
(loop, counter, accumulator, MAC, swap, conditional, copy, stack-heavy,
complexity scoring, cycle estimation, tags).
"""
import pytest
from signatures import (
    PatternType,
    Pattern,
    SignatureResult,
    OP_NAMES,
    _decode,
    SignatureDetector,
)


# ── PatternType ────────────────────────────────────────────────────────────

class TestPatternType:
    def test_all_types_exist(self):
        expected = {
            "loop", "counter", "accumulator", "swap", "conditional",
            "copy", "arithmetic", "stack_heavy", "tail_recursion",
            "multiply_accumulate",
        }
        actual = {p.value for p in PatternType}
        assert actual == expected

    def test_type_values_are_strings(self):
        for pt in PatternType:
            assert isinstance(pt.value, str)


# ── Pattern ────────────────────────────────────────────────────────────────

class TestPattern:
    def test_create_pattern(self):
        p = Pattern(
            PatternType.LOOP, 0.9, 0, 10,
            "test loop", [0, 1]
        )
        assert p.pattern_type == PatternType.LOOP
        assert p.confidence == 0.9
        assert p.start_offset == 0
        assert p.end_offset == 10
        assert p.description == "test loop"
        assert p.registers_involved == [0, 1]

    def test_confidence_range(self):
        p_low = Pattern(PatternType.COUNTER, 0.0, 0, 4, "low", [])
        p_high = Pattern(PatternType.COUNTER, 1.0, 0, 4, "high", [])
        assert p_low.confidence == 0.0
        assert p_high.confidence == 1.0

    def test_empty_registers(self):
        p = Pattern(PatternType.STACK_HEAVY, 0.7, 0, 20, "stack", [])
        assert p.registers_involved == []


# ── SignatureResult ────────────────────────────────────────────────────────

class TestSignatureResult:
    def _make_result(self, patterns=None, complexity=0.5, cycles=100, tags=None):
        return SignatureResult(
            bytecode_length=20,
            patterns=patterns or [],
            complexity_score=complexity,
            estimated_cycles=cycles,
            tags=tags or [],
        )

    def test_create_result(self):
        r = self._make_result()
        assert r.bytecode_length == 20
        assert r.patterns == []
        assert r.complexity_score == 0.5
        assert r.estimated_cycles == 100
        assert r.tags == []

    def test_to_markdown_basic(self):
        r = self._make_result(
            patterns=[Pattern(PatternType.LOOP, 0.95, 0, 10, "test loop", [0])],
            tags=["loop"],
        )
        md = r.to_markdown()
        assert "FLUX Signature Analysis" in md
        assert "20 bytes" in md
        assert "50%" in md
        assert "loop" in md

    def test_to_markdown_with_patterns(self):
        r = self._make_result(
            patterns=[
                Pattern(PatternType.LOOP, 0.9, 0, 10, "loop desc", [0]),
                Pattern(PatternType.COUNTER, 0.85, 4, 12, "counter desc", [1]),
            ],
            tags=["loop", "counter"],
        )
        md = r.to_markdown()
        assert "loop" in md.lower()
        assert "counter" in md.lower()
        assert "90%" in md
        assert "85%" in md

    def test_to_markdown_no_patterns(self):
        r = self._make_result(tags=[])
        md = r.to_markdown()
        assert "FLUX Signature Analysis" in md
        assert "20 bytes" in md

    def test_to_markdown_complexity_display(self):
        r = self._make_result(complexity=1.0)
        md = r.to_markdown()
        assert "100%" in md

        r2 = self._make_result(complexity=0.0)
        md2 = r2.to_markdown()
        assert "0%" in md2

    def test_to_markdown_tags_comma_separated(self):
        r = self._make_result(tags=["loop", "counter", "accumulator"])
        md = r.to_markdown()
        assert "loop, counter, accumulator" in md


# ── OP_NAMES ───────────────────────────────────────────────────────────────

class TestOPNAMES:
    def test_expected_opcodes(self):
        expected_opcodes = {
            0x00: "HALT", 0x08: "INC", 0x09: "DEC",
            0x0C: "PUSH", 0x0D: "POP",
            0x18: "MOVI", 0x20: "ADD", 0x21: "SUB",
            0x22: "MUL", 0x23: "DIV",
            0x2C: "CMP_EQ", 0x2D: "CMP_LT",
            0x3A: "MOV", 0x3C: "JZ", 0x3D: "JNZ",
        }
        for code, name in expected_opcodes.items():
            assert OP_NAMES[code] == name

    def test_values_are_strings(self):
        for code, name in OP_NAMES.items():
            assert isinstance(name, str)


# ── _decode ────────────────────────────────────────────────────────────────

class TestDecode:
    def test_halt(self):
        instrs = _decode([0x00])
        assert len(instrs) == 1
        offset, name, ops = instrs[0]
        assert offset == 0
        assert name == "HALT"
        assert ops == []

    def test_inc(self):
        instrs = _decode([0x08, 3])
        assert len(instrs) == 1
        _, name, ops = instrs[0]
        assert name == "INC"
        assert ops == [3]

    def test_dec(self):
        instrs = _decode([0x09, 5])
        _, name, ops = instrs[0]
        assert name == "DEC"
        assert ops == [5]

    def test_push(self):
        instrs = _decode([0x0C, 7])
        _, name, ops = instrs[0]
        assert name == "PUSH"
        assert ops == [7]

    def test_pop(self):
        instrs = _decode([0x0D, 2])
        _, name, ops = instrs[0]
        assert name == "POP"
        assert ops == [2]

    def test_movi(self):
        instrs = _decode([0x18, 0, 42])
        _, name, ops = instrs[0]
        assert name == "MOVI"
        assert ops == [0, 42]

    def test_add(self):
        instrs = _decode([0x20, 2, 0, 1])
        _, name, ops = instrs[0]
        assert name == "ADD"
        assert ops == [2, 0, 1]

    def test_sub(self):
        instrs = _decode([0x21, 2, 0, 1])
        _, name, ops = instrs[0]
        assert name == "SUB"

    def test_mul(self):
        instrs = _decode([0x22, 2, 0, 1])
        _, name, ops = instrs[0]
        assert name == "MUL"

    def test_jz(self):
        instrs = _decode([0x3C, 0, 10, 0])
        _, name, ops = instrs[0]
        assert name == "JZ"
        assert ops == [0, 10, 0]

    def test_jnz(self):
        instrs = _decode([0x3D, 0, 0xFC, 0])
        _, name, ops = instrs[0]
        assert name == "JNZ"
        assert ops == [0, 0xFC, 0]

    def test_unknown_opcode(self):
        instrs = _decode([0xFF, 0, 0, 0])
        _, name, ops = instrs[0]
        assert name == "?"

    def test_multiple_instructions(self):
        bc = [0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00]
        instrs = _decode(bc)
        assert len(instrs) == 4
        assert instrs[0][1] == "MOVI"
        assert instrs[1][1] == "MOVI"
        assert instrs[2][1] == "ADD"
        assert instrs[3][1] == "HALT"

    def test_empty_bytecode(self):
        instrs = _decode([])
        assert instrs == []

    def test_offsets_are_correct(self):
        bc = [0x00, 0x18, 0, 42]
        instrs = _decode(bc)
        assert instrs[0][0] == 0  # HALT at offset 0
        assert instrs[1][0] == 1  # MOVI at offset 1

    def test_instruction_sizes(self):
        # 1-byte: HALT (0x00), NOP (0x01)
        assert len(_decode([0x00])) == 1
        assert len(_decode([0x00, 0x00])) == 2  # two HALTs

        # 2-byte: INC, DEC, PUSH, POP
        assert len(_decode([0x08, 0, 0x00])) == 2  # INC + HALT
        assert len(_decode([0x09, 0, 0x00])) == 2  # DEC + HALT
        assert len(_decode([0x0C, 0, 0x00])) == 2  # PUSH + HALT
        assert len(_decode([0x0D, 0, 0x00])) == 2  # POP + HALT

        # 3-byte: MOVI
        assert len(_decode([0x18, 0, 42, 0x00])) == 2  # MOVI + HALT

        # 4-byte: ADD, SUB, MUL, JZ, JNZ
        assert len(_decode([0x20, 0, 0, 0, 0x00])) == 2  # ADD + HALT


# ── SignatureDetector ──────────────────────────────────────────────────────

class TestSignatureDetector:
    def setup_method(self):
        self.detector = SignatureDetector()

    # -- Loop detection --

    def test_backward_jump_detected_as_loop(self):
        """JNZ with negative offset should be detected as a loop."""
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        result = self.detector.analyze(bc)
        loops = [p for p in result.patterns if p.pattern_type == PatternType.LOOP]
        assert len(loops) > 0
        assert loops[0].confidence == 0.95

    def test_forward_jump_not_loop(self):
        """JZ/JNZ with positive offset should NOT be detected as a loop."""
        bc = [0x2C, 0, 0, 1, 0x3C, 0, 10, 0, 0x00]
        result = self.detector.analyze(bc)
        loops = [p for p in result.patterns if p.pattern_type == PatternType.LOOP]
        assert len(loops) == 0

    def test_loop_registers_captured(self):
        bc = [0x18, 0, 5, 0x09, 3, 0x3D, 3, 0xFA, 0, 0x00]
        result = self.detector.analyze(bc)
        loops = [p for p in result.patterns if p.pattern_type == PatternType.LOOP]
        assert len(loops) > 0
        assert 3 in loops[0].registers_involved

    # -- Counter detection --

    def test_dec_jnz_counter(self):
        """DEC + JNZ on same register = counter pattern."""
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFC, 0, 0x00]
        result = self.detector.analyze(bc)
        counters = [p for p in result.patterns if p.pattern_type == PatternType.COUNTER]
        assert len(counters) > 0
        assert counters[0].confidence == 0.9

    def test_dec_without_jnz_no_counter(self):
        """DEC without following JNZ should not produce counter pattern."""
        bc = [0x18, 0, 5, 0x09, 0, 0x00]
        result = self.detector.analyze(bc)
        counters = [p for p in result.patterns if p.pattern_type == PatternType.COUNTER]
        assert len(counters) == 0

    def test_dec_jnz_different_reg_no_counter(self):
        """DEC R0 + JNZ R1 should not match counter pattern."""
        bc = [0x09, 0, 0x3D, 1, 0xFC, 0, 0x00]
        result = self.detector.analyze(bc)
        counters = [p for p in result.patterns if p.pattern_type == PatternType.COUNTER]
        assert len(counters) == 0

    # -- Accumulator detection --

    def test_add_feedback_accumulator(self):
        """ADD R1, R1, R0 (rd == rs1) = accumulator."""
        bc = [0x18, 0, 10, 0x18, 1, 0, 0x20, 1, 1, 0, 0x09, 0, 0x3D, 0, 0xF8, 0, 0x00]
        result = self.detector.analyze(bc)
        accs = [p for p in result.patterns if p.pattern_type == PatternType.ACCUMULATOR]
        assert len(accs) > 0
        assert accs[0].confidence == 0.8

    def test_add_no_feedback_no_accumulator(self):
        """ADD R2, R0, R1 (rd != rs1) should not be accumulator."""
        bc = [0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00]
        result = self.detector.analyze(bc)
        accs = [p for p in result.patterns if p.pattern_type == PatternType.ACCUMULATOR]
        assert len(accs) == 0

    # -- MAC detection --

    def test_mul_feedback_mac(self):
        """MUL R1, R1, R0 (rd == rs1) = multiply-accumulate."""
        bc = [0x18, 0, 6, 0x18, 1, 1, 0x22, 1, 1, 0, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        result = self.detector.analyze(bc)
        macs = [p for p in result.patterns if p.pattern_type == PatternType.MULTIPLY_ACCUMULATE]
        assert len(macs) > 0
        assert macs[0].confidence == 0.8

    # -- Swap detection --

    def test_push_push_pop_pop_swap(self):
        """PUSH R0, PUSH R1, POP R1, POP R0 = swap."""
        bc = [0x0C, 0, 0x0C, 1, 0x0D, 1, 0x0D, 0, 0x00]
        result = self.detector.analyze(bc)
        swaps = [p for p in result.patterns if p.pattern_type == PatternType.SWAP]
        assert len(swaps) > 0
        assert swaps[0].confidence == 0.85

    def test_same_reg_no_swap(self):
        """PUSH R0, PUSH R0, POP R0, POP R0 should not be detected as swap."""
        bc = [0x0C, 0, 0x0C, 0, 0x0D, 0, 0x0D, 0, 0x00]
        result = self.detector.analyze(bc)
        swaps = [p for p in result.patterns if p.pattern_type == PatternType.SWAP]
        assert len(swaps) == 0

    # -- Conditional detection --

    def test_cmp_eq_jz_conditional(self):
        """CMP_EQ + JZ = conditional."""
        bc = [0x2C, 0, 0, 1, 0x3C, 0, 2, 0, 0x00]
        result = self.detector.analyze(bc)
        conds = [p for p in result.patterns if p.pattern_type == PatternType.CONDITIONAL]
        assert len(conds) > 0

    def test_cmp_lt_jnz_conditional(self):
        """CMP_LT + JNZ = conditional."""
        bc = [0x2D, 0, 1, 2, 0x3D, 0, 5, 0, 0x00]
        result = self.detector.analyze(bc)
        conds = [p for p in result.patterns if p.pattern_type == PatternType.CONDITIONAL]
        assert len(conds) > 0

    # -- Copy detection --

    def test_mov_copy(self):
        """MOV R1, R0, R0 (dst != src, rs == ops[2]) = copy."""
        bc = [0x18, 0, 42, 0x3A, 1, 0, 0, 0x00]
        result = self.detector.analyze(bc)
        copies = [p for p in result.patterns if p.pattern_type == PatternType.COPY]
        assert len(copies) > 0

    def test_mov_same_reg_no_copy(self):
        """MOV R0, R0, R0 (dst == src) should not be copy."""
        bc = [0x3A, 0, 0, 0, 0x00]
        result = self.detector.analyze(bc)
        copies = [p for p in result.patterns if p.pattern_type == PatternType.COPY]
        assert len(copies) == 0

    # -- Stack-heavy detection --

    def test_stack_heavy(self):
        """Many PUSH instructions should trigger stack-heavy."""
        bc = [0x0C, 0, 0x0C, 1, 0x0C, 2, 0x0C, 3, 0x0C, 4, 0x00]
        result = self.detector.analyze(bc)
        stacks = [p for p in result.patterns if p.pattern_type == PatternType.STACK_HEAVY]
        assert len(stacks) > 0

    def test_not_stack_heavy(self):
        """Few PUSH instructions should not trigger stack-heavy."""
        bc = [0x0C, 0, 0x0C, 1, 0x00]
        result = self.detector.analyze(bc)
        stacks = [p for p in result.patterns if p.pattern_type == PatternType.STACK_HEAVY]
        assert len(stacks) == 0


# ── SignatureResult Fields ────────────────────────────────────────────────

class TestSignatureResultFields:
    def setup_method(self):
        self.detector = SignatureDetector()

    def test_bytecode_length(self):
        bc = [0x18, 0, 42, 0x00]
        result = self.detector.analyze(bc)
        assert result.bytecode_length == 4

    def test_estimated_cycles_simple(self):
        """Simple program: MOVI (2 cycles) + HALT (1 cycle) = 3."""
        result = self.detector.analyze([0x18, 0, 42, 0x00])
        assert result.estimated_cycles == 3

    def test_estimated_cycles_with_arithmetic(self):
        """ADD costs 2 cycles per instruction."""
        bc = [0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00]
        result = self.detector.analyze(bc)
        # MOVI(2) + MOVI(2) + ADD(2) + HALT(1) = 7
        assert result.estimated_cycles == 7

    def test_estimated_cycles_loop_multiplier(self):
        """Loops multiply estimated cycles by 10."""
        bc_loop = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        r_loop = self.detector.analyze(bc_loop)
        bc_no_loop = [0x18, 0, 5, 0x09, 0, 0x00]
        r_no_loop = self.detector.analyze(bc_no_loop)
        # Loop should be at least ~10x the non-loop estimate
        assert r_loop.estimated_cycles >= r_no_loop.estimated_cycles * 5

    def test_complexity_simple(self):
        """Simple program (MOVI + HALT) should have low complexity."""
        result = self.detector.analyze([0x18, 0, 42, 0x00])
        assert result.complexity_score < 0.5

    def test_complexity_higher_with_loop(self):
        """Program with loop should have higher complexity than without."""
        simple = self.detector.analyze([0x18, 0, 42, 0x00])
        loop_bc = [0x18, 0, 10, 0x18, 1, 0, 0x20, 1, 1, 0,
                    0x2C, 2, 0, 1, 0x3C, 2, 2, 0,
                    0x09, 0, 0x3D, 0, 0xF0, 0, 0x00]
        complex_r = self.detector.analyze(loop_bc)
        assert complex_r.complexity_score > simple.complexity_score

    def test_complexity_capped_at_1(self):
        result = self.detector.analyze([0x18, 0, 42, 0x00])
        assert result.complexity_score <= 1.0

    def test_complexity_non_negative(self):
        result = self.detector.analyze([0x18, 0, 42, 0x00])
        assert result.complexity_score >= 0.0


# ── Tags ───────────────────────────────────────────────────────────────────

class TestTags:
    def setup_method(self):
        self.detector = SignatureDetector()

    def test_loop_tag(self):
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        result = self.detector.analyze(bc)
        assert "loop" in result.tags

    def test_counter_tag(self):
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFC, 0, 0x00]
        result = self.detector.analyze(bc)
        assert "counter" in result.tags

    def test_accumulator_tag(self):
        bc = [0x18, 0, 10, 0x18, 1, 0, 0x20, 1, 1, 0, 0x09, 0, 0x3D, 0, 0xF8, 0, 0x00]
        result = self.detector.analyze(bc)
        assert "accumulator" in result.tags

    def test_mac_tag(self):
        bc = [0x18, 0, 6, 0x18, 1, 1, 0x22, 1, 1, 0, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        result = self.detector.analyze(bc)
        assert "mac" in result.tags

    def test_swap_tag(self):
        bc = [0x0C, 0, 0x0C, 1, 0x0D, 1, 0x0D, 0, 0x00]
        result = self.detector.analyze(bc)
        assert "swap" in result.tags

    def test_conditional_tag(self):
        bc = [0x2C, 0, 0, 1, 0x3C, 0, 2, 0, 0x00]
        result = self.detector.analyze(bc)
        assert "conditional" in result.tags

    def test_copy_tag(self):
        bc = [0x18, 0, 42, 0x3A, 1, 0, 0, 0x00]
        result = self.detector.analyze(bc)
        assert "copy" in result.tags

    def test_stack_heavy_tag(self):
        bc = [0x0C, 0, 0x0C, 1, 0x0C, 2, 0x0C, 3, 0x0C, 4, 0x00]
        result = self.detector.analyze(bc)
        assert "stack_heavy" in result.tags

    def test_tags_sorted(self):
        result = self.detector.analyze([0x18, 0, 42, 0x00])
        assert result.tags == sorted(result.tags)

    def test_empty_bytecode(self):
        result = self.detector.analyze([])
        assert result.bytecode_length == 0
        assert result.patterns == []
        assert result.complexity_score == 0.0  # no instructions → no complexity
        assert result.estimated_cycles == 0
        assert result.tags == []


# ── Markdown Output ────────────────────────────────────────────────────────

class TestMarkdownOutput:
    def setup_method(self):
        self.detector = SignatureDetector()

    def test_markdown_heading(self):
        result = self.detector.analyze([0x18, 0, 42, 0x00])
        md = result.to_markdown()
        assert md.startswith("# FLUX Signature Analysis")

    def test_markdown_length_display(self):
        bc = [0x18, 0, 42, 0x00]
        result = self.detector.analyze(bc)
        md = result.to_markdown()
        assert f"{len(bc)} bytes" in md

    def test_markdown_contains_pattern_details(self):
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        result = self.detector.analyze(bc)
        md = result.to_markdown()
        assert "offsets" in md.lower() or "offset" in md.lower()
        assert "regs" in md.lower()

    def test_markdown_is_string(self):
        result = self.detector.analyze([0x00])
        md = result.to_markdown()
        assert isinstance(md, str)


# ── Edge Cases ─────────────────────────────────────────────────────────────

class TestEdgeCases:
    def setup_method(self):
        self.detector = SignatureDetector()

    def test_single_halt(self):
        result = self.detector.analyze([0x00])
        assert result.bytecode_length == 1
        assert result.estimated_cycles == 1

    def test_unknown_opcodes(self):
        result = self.detector.analyze([0xFF, 0xFE, 0x00])
        assert result.bytecode_length == 3

    def test_truncated_instruction(self):
        """Incomplete instruction should not crash."""
        result = self.detector.analyze([0x20, 0])  # ADD needs 4 bytes
        assert result.bytecode_length == 2

    def test_mixed_known_unknown(self):
        bc = [0x18, 0, 10, 0xFF, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00]
        result = self.detector.analyze(bc)
        assert result.bytecode_length == len(bc)

    def test_large_bytecode(self):
        bc = [0x18, 0, 1] * 100 + [0x00]
        result = self.detector.analyze(bc)
        assert result.bytecode_length == 301

    def test_multiple_patterns_same_type(self):
        """Multiple loops in the same bytecode."""
        # Two separate backward jumps
        bc = [
            0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFA, 0,  # loop 1
            0x18, 1, 3, 0x09, 1, 0x3D, 1, 0xFA, 0,  # loop 2
            0x00
        ]
        result = self.detector.analyze(bc)
        loops = [p for p in result.patterns if p.pattern_type == PatternType.LOOP]
        assert len(loops) >= 2

    def test_complex_program_analysis(self):
        """Full factorial-like program."""
        # Compute factorial of 6: 6 * 5 * 4 * 3 * 2 * 1 = 720
        bc = [0x18, 0, 6, 0x18, 1, 1,
              0x22, 1, 1, 0,  # MUL R1, R1, R0
              0x09, 0,        # DEC R0
              0x3D, 0, 0xFA, 0,  # JNZ R0, -6
              0x00]
        result = self.detector.analyze(bc)
        assert result.complexity_score > 0.5
        assert "loop" in result.tags
        assert "mac" in result.tags
        assert "counter" in result.tags
        assert result.estimated_cycles > 0
