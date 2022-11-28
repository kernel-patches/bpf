/* Test cases for verifier.c:find_equal_scalars() and Co */

/* Use a map lookup as a way to get a pointer to some valid memory
 * location with size known to verifier.
 */
#define MAKE_POINTER_TO_48_BYTES(reg)			\
	BPF_MOV64_IMM(BPF_REG_0, 0),			\
	BPF_LD_MAP_FD(BPF_REG_1, 0),			\
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),		\
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),		\
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),		\
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),	\
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),		\
	BPF_EXIT_INSN(),				\
	BPF_MOV64_REG((reg), BPF_REG_0)

/* See comment in verifier.c:mark_equal_scalars_as_read().
 *
 * r9 = ... some pointer with range X ...
 * r6 = ... unbound scalar ID=a ...
 * r7 = ... unbound scalar ID=b ...
 * if (r6 > r7) goto +1
 * r6 = r7
 * if (r6 > X) goto exit
 * r9 += r7
 * *(u64 *)r9 = Y
 */
{
	"scalar ids: ID mapping in regsafe()",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	/* r7 = ktime_get_ns() */
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/* r6 = ktime_get_ns() */
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/* if r6 > r7 goto +1 */
	BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 1),
	/* r6 = r7 */
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_7),
	/* a noop to get to add new parent state */
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),
	/* if r6 >= 10 exit(0) */
	BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 10, 2),
	/* r9[r7] = 42 */
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_7),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	/* exit(0) */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr_unpriv = "register with unbounded min value",
	.result_unpriv = REJECT,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},

#undef MAKE_POINTER_TO_48_BYTES
