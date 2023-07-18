// vim:set ts=8 sts=8 sw=8 tw=80 cc=80 noet:
#define _GNU_SOURCE

// This is a simplistic ppc32 interpreter according to the Power ISA 2.07b
// #define DEBUG

#if !defined(NANOLIBC)
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>
#else
#include "nanolibc.h"
#define	assert(x)
#define	fflush(x)
#endif

#define	WARNING(msg, ...) printf(msg, __VA_ARGS__)

#include <elf.h>

#define STACK_ADDRESS	0xf6fff000
#define STACK_SIZE	(1024 * 1024)
#define STACK_BASE	(STACK_ADDRESS - STACK_SIZE)

#define	PLATFORM	"power8"
#define	RANDOM_SIZE	16

typedef int8_t		s8;
typedef int16_t		s16;
typedef int32_t		s32;
typedef int64_t		s64;

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;

typedef double		f64;

typedef struct {
	u8*	memory;
	u64	pc;
	u64	gpr[32];
	f64	fpr[32];
	u64	xer;
	u64	ctr;
	u64	lr;
	u32	cr;
	u32	fpscr;
	u32	vrsave;
	int	ppc64;
} CPU;

typedef struct {
	u32	lk:1;
	u32	aa:1;
	u32	li:24;
	u32	opcd:6;
} I_FORM;

typedef struct {
	u32	lk:1;
	u32	aa:1;
	u32	bd:14;
	u32	bi:5;
	u32	bo:5;
	u32	opcd:6;
} B_FORM;

typedef struct {
	u32	unused3:1;
	u32	one:1;
	u32	unused2:3;
	u32	lev:7;
	u32	unused1:14;
	u32	opcd:6;
} SC_FORM;

typedef struct {
	u32	d:16;
	u32	ra:5;
	u32	rt:5;
	u32	opcd:6;
} D_FORM;

typedef struct {
	u32	si:16;
	u32	ra:5;
	u32	l:1;
	u32	unused:1;
	u32	bf:3;
	u32	opcd:6;
} D_FORM1;

typedef struct {
	u32	xo:2;
	u32	ds:14;
	u32	ra:5;
	u32	rt:5;
	u32	opcd:6;
} DS_FORM;

typedef struct {
	u32	rc:1;
	u32	xo:10;
	u32	rb:5;
	u32	ra:5;
	u32	rt:5;
	u32	opcd:6;
} X_FORM;

typedef struct {
	u32	rc:1;
	u32	xo:10;
	u32	rb:5;
	u32	ra:5;
	u32	l:1;
	u32	unused:1;
	u32	bf:3;
	u32	opcd:6;
} X_FORM1;

typedef struct {
	u32	unused:1;
	u32	xo:10;
	u32	spr:10;
	u32	rt:5;
	u32	opcd:6;
} XFX_FORM;

typedef struct {
	u32	lk:1;
	u32	xo:10;
	u32	bh:2;
	u32	unused:3;
	u32	bi:5;
	u32	bo:5;
	u32	opcd:6;
} XL_FORM;

typedef struct {
	u32	unused:1;
	u32	xo:10;
	u32	bb:5;
	u32	ba:5;
	u32	bt:5;
	u32	opcd:6;
} XL_FORM1;

typedef struct {
	u32	rc:1;
	u32	xo:9;
	u32	oe:1;
	u32	rb:5;
	u32	ra:5;
	u32	rt:5;
	u32	opcd:6;
} XO_FORM;

typedef struct {
	u32	rc:1;
	u32	me:5;
	u32	mb:5;
	u32	rb:5;
	u32	ra:5;
	u32	rs:5;
	u32	opcd:6;
} M_FORM;

#define	XER_SO	(1 << 31)
#define	XER_OV	(1 << 30)
#define	XER_CA	(1 << 29)

#define	CR0_LT	(1 << 31)
#define	CR0_GT	(1 << 30)
#define	CR0_EQ	(1 << 29)
#define	CR0_SO	(1 << 28)

#define RA0(x)	((x) == 0 ? 0 : (cpu->gpr[x]))

#define BO(bo, bit)	(((bo) & (1 << (4 - (bit)))) != 0)
#define	CR(cr, bit)	(((cr) & (1 << (63 - (bit)))) != 0)

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define	GETI16(x)	(x)
#define	GETI32(x)	(x)
#define	GETI64(x)	(x)
#define	SETI16(x)	(x)
#define	SETI32(x)	(x)
#define	SETI64(x)	(x)
#else
#define	GETI16(x)	__builtin_bswap16(x)
#define	GETI32(x)	__builtin_bswap32(x)
#define	GETI64(x)	__builtin_bswap64(x)
#define	SETI16(x)	__builtin_bswap16(x)
#define	SETI32(x)	__builtin_bswap32(x)
#define	SETI64(x)	__builtin_bswap64(x)
#endif

#define ADDR(x)		(cpu->ppc64 ? (x) : ((u32) (x)))
#define	READMEM8(x)	cpu->memory[ADDR(x)]
#define	READMEM16(x)	GETI16(*((u16*) &cpu->memory[ADDR(x)]))
#define	READMEM32(x)	GETI32(*((u32*) &cpu->memory[ADDR(x)]))
#define	READMEM64(x)	GETI64(*((u64*) &cpu->memory[ADDR(x)]))

#define	WRITEMEM8(a, x)  cpu->memory[ADDR(a)] = (u8) (x)
#define	WRITEMEM16(a, x) *((u16*) &cpu->memory[ADDR(a)]) = SETI16((u16) (x))
#define	WRITEMEM32(a, x) *((u32*) &cpu->memory[ADDR(a)]) = SETI32((u32) (x))
#define	WRITEMEM64(a, x) *((u64*) &cpu->memory[ADDR(a)]) = SETI64((u64) (x))

/* errno ids */
#define	PPC_EBADF	9
#define	PPC_EINVAL	22
#define	PPC_ENOSYS	38

/* syscall numbers */
#define PPC_SYS_exit	1
#define PPC_SYS_read	3
#define PPC_SYS_write	4
#define PPC_SYS_uname	122

/* Feature definitions in AT_HWCAP. */
#define	PPC_FEATURE_32			0x80000000 /* 32-bit mode. */
#define	PPC_FEATURE_64			0x40000000 /* 64-bit mode. */
#define	PPC_FEATURE_601_INSTR		0x20000000 /* 601 chip, Old POWER ISA. */
#define	PPC_FEATURE_HAS_ALTIVEC		0x10000000 /* SIMD/Vector Unit. */
#define	PPC_FEATURE_HAS_FPU		0x08000000 /* Floating Point Unit. */
#define	PPC_FEATURE_HAS_MMU		0x04000000 /* Memory Management Unit. */
#define	PPC_FEATURE_HAS_4xxMAC		0x02000000 /* 4xx Multiply Accumulator. */
#define	PPC_FEATURE_UNIFIED_CACHE	0x01000000 /* Unified I/D cache. */
#define	PPC_FEATURE_HAS_SPE		0x00800000 /* Signal Processing ext. */
#define	PPC_FEATURE_HAS_EFP_SINGLE	0x00400000 /* SPE Float. */
#define	PPC_FEATURE_HAS_EFP_DOUBLE	0x00200000 /* SPE Double. */
#define	PPC_FEATURE_NO_TB		0x00100000 /* 601/403gx have no timebase */
#define	PPC_FEATURE_POWER4		0x00080000 /* POWER4 ISA 2.00 */
#define	PPC_FEATURE_POWER5		0x00040000 /* POWER5 ISA 2.02 */
#define	PPC_FEATURE_POWER5_PLUS		0x00020000 /* POWER5+ ISA 2.03 */
#define	PPC_FEATURE_CELL_BE		0x00010000 /* CELL Broadband Engine */
#define	PPC_FEATURE_BOOKE		0x00008000 /* ISA Category Embedded */
#define	PPC_FEATURE_SMT			0x00004000 /* Simultaneous Multi-Threading */
#define	PPC_FEATURE_ICACHE_SNOOP	0x00002000
#define	PPC_FEATURE_ARCH_2_05		0x00001000 /* ISA 2.05 */
#define	PPC_FEATURE_PA6T		0x00000800 /* PA Semi 6T Core */
#define	PPC_FEATURE_HAS_DFP		0x00000400 /* Decimal FP Unit */
#define	PPC_FEATURE_POWER6_EXT		0x00000200 /* P6 + mffgpr/mftgpr */
#define	PPC_FEATURE_ARCH_2_06		0x00000100 /* ISA 2.06 */
#define	PPC_FEATURE_HAS_VSX		0x00000080 /* P7 Vector Extension. */
#define	PPC_FEATURE_PSERIES_PERFMON_COMPAT 0x00000040
#define	PPC_FEATURE_TRUE_LE		0x00000002
#define	PPC_FEATURE_PPC_LE		0x00000001

/* Feature definitions in AT_HWCAP2. */
#define	PPC_FEATURE2_ARCH_2_07		0x80000000 /* ISA 2.07 */
#define	PPC_FEATURE2_HAS_HTM		0x40000000 /* Hardware Transactional Memory */
#define	PPC_FEATURE2_HAS_DSCR		0x20000000 /* Data Stream Control Register */
#define	PPC_FEATURE2_HAS_EBB		0x10000000 /* Event Base Branching */
#define	PPC_FEATURE2_HAS_ISEL		0x08000000 /* Integer Select */
#define	PPC_FEATURE2_HAS_TAR		0x04000000 /* Target Address Register */
#define	PPC_FEATURE2_HAS_VEC_CRYPTO	0x02000000 /* Target supports vector instruction. */
#define	PPC_FEATURE2_HTM_NOSC		0x01000000 /* Kernel aborts transaction when a syscall is made. */
#define	PPC_FEATURE2_ARCH_3_00		0x00800000 /* ISA 3.0 */
#define	PPC_FEATURE2_HAS_IEEE128	0x00400000 /* VSX IEEE Binary Float 128-bit */

/* (fictive) cache sizes */
#define	DCACHE_LINE_SIZE		0x20
#define	ICACHE_LINE_SIZE		0x20

/* auxv keys */
#define	PAGE_SIZE	4096
#define	HWCAP		(PPC_FEATURE_32 | PPC_FEATURE_HAS_ALTIVEC \
				| PPC_FEATURE_HAS_FPU | PPC_FEATURE_HAS_VSX)
#define	HWCAP2		(PPC_FEATURE2_ARCH_2_07)
#define	AT_NULL		0
#define	AT_PHDR		3
#define	AT_PHENT	4
#define	AT_PHNUM	5
#define	AT_PAGESZ	6
#define	AT_BASE		7
#define	AT_FLAGS	8
#define	AT_ENTRY	9
#define	AT_UID		11
#define	AT_EUID		12
#define	AT_GID		13
#define	AT_EGID		14
#define	AT_PLATFORM	15
#define	AT_HWCAP	16
#define	AT_DCACHEBSIZE	19
#define	AT_ICACHEBSIZE	20
#define	AT_UCACHEBSIZE	21
#define	AT_IGNOREPPC	22
#define	AT_SECURE	23
#define	AT_BASE_PLATFORM 24
#define	AT_RANDOM	25
#define	AT_HWCAP2	26
#define	AT_EXECFN	31

int translate_errno(int err)
{
	switch(err) {
		case EBADF:
			return PPC_EBADF;
		case EINVAL:
			return PPC_EINVAL;
		case ENOSYS:
			return PPC_ENOSYS;
		default:
			return err;
	}
}

u64 ppc_sys_read(void* mem, int* err, u64 fildes, void* buf, u64 nbyte)
{
	ssize_t result = read(fildes, buf, nbyte);
	if(result == -1) {
		*err = 1;
		return translate_errno(errno);
	} else {
		return result;
	}
}

u64 ppc_sys_write(void* mem, int* err, u64 fildes, void* buf, u64 nbyte)
{
	ssize_t result = write(fildes, buf, nbyte);
	if(result == -1) {
		*err = 1;
		return translate_errno(errno);
	} else {
		return result;
	}
}

#define HANDLE_ERROR(cmd, ...) { \
	result = (cmd(cpu->memory, &err, __VA_ARGS__)); \
	cpu->gpr[3] = result; \
	if(err) { \
		cpu->cr |= CR0_SO; \
	} \
}

void sc(CPU* cpu, int lev)
{
	int err = 0;
	u64 result;
	u64 u2, u3;
	u64 s1;
	if(lev) {
		WARNING("invalid lev %d\n", lev);
		exit(1);
	}
	if(cpu->ppc64) {
		s1 = cpu->gpr[3];
		u2 = cpu->gpr[4];
		u3 = cpu->gpr[5];
	} else {
		s1 = (s32) cpu->gpr[3];
		u2 = (u32) cpu->gpr[4];
		u3 = (u32) cpu->gpr[5];
	}
	switch(cpu->gpr[0]) {
		case PPC_SYS_exit:
			exit(s1);
			break;
		case PPC_SYS_read:
			HANDLE_ERROR(ppc_sys_read, s1, &cpu->memory[u2], u3);
			break;
		case PPC_SYS_write:
			HANDLE_ERROR(ppc_sys_write, s1, &cpu->memory[u2], u3);
			break;
		default:
			WARNING("unknown syscall %ld\n", cpu->gpr[0]);
			cpu->gpr[3] = PPC_ENOSYS; // ENOSYS
			cpu->cr |= CR0_SO;
			break;
	}
}

#define BIT(i)	(1L << (63 - (i)))

u64 generate_mask(int mstart, int mstop)
{
	u64 m = 0;
	if(mstart == mstop) {
		return BIT(mstart);
	}
	if(mstart < mstop) {
		for(int i = mstart; i <= mstop; i++) {
			m |= BIT(i);
		}
	} else {
		for(int i = mstart; i <= 63; i++) {
			m |= BIT(i);
		}
		for(int i = 0; i <= mstop; i++) {
			m |= BIT(i);
		}
	}
	return m;
}

#define ROTL32(x, n)	(((x) << ((n) & 0x1f)) | (((u32) (x)) >> (32 - ((n) & 0x1f))))
#define ROTL64(x, n)	(((x) << ((n) & 0x3f)) | (((u64) (x)) >> (64 - ((n) & 0x3f))))

#define	UPDATE_CR0(val) { \
	s64 v = cpu->ppc64 ? val : (s32) val; \
	u32 cr = 0; \
	if(v < 0) { \
		cr |= CR0_LT; \
	} \
	if(v > 0) { \
		cr |= CR0_GT; \
	} \
	if(v == 0) { \
		cr |= CR0_EQ; \
	} \
	if(cpu->xer & XER_SO) { \
		cr |= CR0_SO; \
	} \
	cpu->cr = cr | (cpu->cr & 0x0FFFFFFF); \
}

#define	UPDATE_CR0_ROTATE(val) { \
	s64 v = cpu->ppc64 ? val : (s32) val; \
	u32 cr = 0; \
	if(v < 0) { \
		cr |= CR0_LT; \
	} \
	if(v > 0) { \
		cr |= CR0_GT; \
	} \
	if(v == 0) { \
		cr |= CR0_EQ; \
	} \
	cpu->cr = cr | (cpu->cr & 0x1FFFFFFF); \
}

#define UPDATE_CA(val) { \
	  if(val) { \
		  cpu->xer |= XER_CA; \
	  } else { \
		  cpu->xer &= ~XER_CA; \
	  } \
}

#ifdef DEBUG
void dump(CPU* cpu, u64 oldpc)
{
	u64* fpr = (u64*) cpu->fpr;
	const char* text =
		"In function:\n"
		"executing %016lx:\n"
		"NIP %08lx   LR %08lx CTR %08lx XER %08x CPU#0\n"
		"MSR 00000000 HID0 00000000  HF 00000000 iidx 0 didx 0\n"
		"GPR00 %016lx %016lx %016lx %016lx\n"
		"GPR04 %016lx %016lx %016lx %016lx\n"
		"GPR08 %016lx %016lx %016lx %016lx\n"
		"GPR12 %016lx %016lx %016lx %016lx\n"
		"GPR16 %016lx %016lx %016lx %016lx\n"
		"GPR20 %016lx %016lx %016lx %016lx\n"
		"GPR24 %016lx %016lx %016lx %016lx\n"
		"GPR28 %016lx %016lx %016lx %016lx\n"
		"CR %08x  [ -  -  -  -  -  -  -  E  ]             RES 00000000\n"
		"FPR00 %016lx %016lx %016lx %016lx\n"
		"FPR04 %016lx %016lx %016lx %016lx\n"
		"FPR08 %016lx %016lx %016lx %016lx\n"
		"FPR12 %016lx %016lx %016lx %016lx\n"
		"FPR16 %016lx %016lx %016lx %016lx\n"
		"FPR20 %016lx %016lx %016lx %016lx\n"
		"FPR24 %016lx %016lx %016lx %016lx\n"
		"FPR28 %016lx %016lx %016lx %016lx\n"
		"FPSCR 00000000\n\n";
	printf(text, oldpc, cpu->pc, cpu->lr, cpu->ctr, cpu->xer,
			cpu->gpr[ 0], cpu->gpr[ 1], cpu->gpr[ 2], cpu->gpr[ 3],
			cpu->gpr[ 4], cpu->gpr[ 5], cpu->gpr[ 6], cpu->gpr[ 7],
			cpu->gpr[ 8], cpu->gpr[ 9], cpu->gpr[10], cpu->gpr[11],
			cpu->gpr[12], cpu->gpr[13], cpu->gpr[14], cpu->gpr[15],
			cpu->gpr[16], cpu->gpr[17], cpu->gpr[18], cpu->gpr[19],
			cpu->gpr[20], cpu->gpr[21], cpu->gpr[22], cpu->gpr[23],
			cpu->gpr[24], cpu->gpr[25], cpu->gpr[26], cpu->gpr[27],
			cpu->gpr[28], cpu->gpr[29], cpu->gpr[30], cpu->gpr[31],
			cpu->cr,
			fpr[ 0], fpr[ 1], fpr[ 2], fpr[ 3],
			fpr[ 4], fpr[ 5], fpr[ 6], fpr[ 7],
			fpr[ 8], fpr[ 9], fpr[10], fpr[11],
			fpr[12], fpr[13], fpr[14], fpr[15],
			fpr[16], fpr[17], fpr[18], fpr[19],
			fpr[20], fpr[21], fpr[22], fpr[23],
			fpr[24], fpr[25], fpr[26], fpr[27],
			fpr[28], fpr[29], fpr[30], fpr[31]);
	fflush(stdout);
}
#endif

#define ADD_OVERFLOW(a, b) \
	__builtin_add_overflow_p(a, b, (__typeof__ ((a) + (b))) 0)

static inline int carry(long x, long y, int ca) {
	long r;
	int c1 = __builtin_add_overflow(x, y, &r);
	int c2 = ADD_OVERFLOW(r, ca ? 1 : 0);
	return c1 | c2;
}

void step(CPU* cpu)
{
	int ctr_ok, cond_ok;
	int b, c, n;
	s64 sa, sb;
	u64 ua, ub, prod;
	u64 mask, shift;
	u64 ea;
	u64 nia;
	u64 bit;

	u32 insn = READMEM32(cpu->pc);
	I_FORM*   iform   = (I_FORM*)   &insn;
	B_FORM*   bform   = (B_FORM*)   &insn;
	SC_FORM*  scform  = (SC_FORM*)  &insn;
	D_FORM*   dform   = (D_FORM*)   &insn;
	D_FORM1*  dform1  = (D_FORM1*)  &insn;
	DS_FORM*  dsform  = (DS_FORM*)  &insn;
	X_FORM*   xform   = (X_FORM*)   &insn;
	X_FORM1*  xform1  = (X_FORM1*)  &insn;
	XFX_FORM* xfxform = (XFX_FORM*) &insn;
	XL_FORM*  xlform  = (XL_FORM*)  &insn;
	XL_FORM1* xlform1 = (XL_FORM1*) &insn;
	XO_FORM*  xoform  = (XO_FORM*)  &insn;
	M_FORM*   mform   = (M_FORM*)   &insn;
	u32 op = iform->opcd;
	switch(op) {
		case 7: // mulli
			cpu->gpr[dform->rt] = (s32) (cpu->gpr[dform->ra] *
				(s16) dform->d); // si = d
			cpu->pc += 4;
			break;
		case 8: // subfic
			ua = cpu->gpr[dform->ra];
			ub = (s16) dform->d;
			cpu->gpr[dform->rt] = ~ua + ub + 1;
			UPDATE_CA(carry(~ua, ub, 1));
			cpu->pc += 4;
			break;
		case 10: // cmpli
			if(dform1->l) {
				ua = cpu->gpr[dform1->ra];
			} else {
				ua = (u32) cpu->gpr[dform1->ra];
			}
			if(ua < (u16) dform1->si) {
				c = 0b1000;
			} else if(ua > (u16) dform1->si) {
				c = 0b0100;
			} else {
				c = 0b0010;
			}
			mask = 0xF << (32 - dform1->bf * 4 - 4);
			shift = 32 - dform1->bf * 4 - 4;
			c |= (cpu->xer & XER_SO) ? 1 : 0;
			cpu->cr = (cpu->cr & ~mask) | (c << shift);
			cpu->pc += 4;
			break;
		case 11: // cmpi
			if(dform1->l) {
				sa = cpu->gpr[dform1->ra];
			} else {
				sa = (s32) cpu->gpr[dform1->ra];
			}
			if(sa < (s16) dform1->si) {
				c = 0b1000;
			} else if(sa > (s16) dform1->si) {
				c = 0b0100;
			} else {
				c = 0b0010;
			}
			mask = 0xF << (32 - dform1->bf * 4 - 4);
			shift = 32 - dform1->bf * 4 - 4;
			c |= (cpu->xer & XER_SO) ? 1 : 0;
			cpu->cr = (cpu->cr & ~mask) | (c << shift);
			cpu->pc += 4;
			break;
		// TODO: 12 = addic, 13 = addic.
		case 14: // addi
			cpu->gpr[dform->rt] = RA0(dform->ra) + (s16) dform->d;
			cpu->pc += 4;
			break;
		case 15: // addis
			cpu->gpr[dform->rt] = RA0(dform->ra) +
				(((s16) dform->d) << 16);
			cpu->pc += 4;
			break;
		case 16: // bc/bca/bcl/bcla
			nia = cpu->pc + 4;
			if(!BO(bform->bo, 2)) {
				cpu->ctr--;
				if(cpu->ppc64) {
					ctr_ok = (cpu->ctr != 0) ^
						BO(bform->bo, 3);
				} else {
					ctr_ok = ((u32) cpu->ctr != 0) ^
						BO(bform->bo, 3);
				}
			} else {
				ctr_ok = 1;
			}
			cond_ok = BO(bform->bo, 0) ||
				(CR(cpu->cr, bform->bi + 32) == BO(bform->bo, 1));
			if(ctr_ok && cond_ok) {
				if(bform->aa) {
					nia = (s16) (bform->bd << 2);
				} else {
					nia = cpu->pc + (s16) (bform->bd << 2);
				}
			}
			if(bform->lk) {
				cpu->lr = cpu->pc + 4;
			}
			cpu->pc = nia;
			break;
		case 17: // sc
			if(scform->one) {
				cpu->pc += 4;
				sc(cpu, scform->lev);
			} else {
				WARNING("0x%016lx: invalid form: opcode %d\n",
						cpu->pc, op);
				exit(1);
			}
			break;
		case 18: // b/ba/bl/bla
			if(iform->aa) {
				nia = ((s32) (iform->li << 8) >> 6);
			} else {
				nia = cpu->pc + ((s32) (iform->li << 8) >> 6);
			}
			if(iform->lk) {
				cpu->lr = cpu->pc + 4;
			}
			cpu->pc = nia;
			break;
		case 19:
			switch(xlform->xo) {
				case 16: // bclr/bclrl
					nia = cpu->pc + 4;
					if(!BO(xlform->bo, 2)) {
						cpu->ctr--;
						if(cpu->ppc64) {
							ctr_ok = (cpu->ctr != 0) ^
								BO(xlform->bo, 3);
						} else {
							ctr_ok = ((s32) cpu->ctr != 0) ^
								BO(xlform->bo, 3);
						}
					} else {
						ctr_ok = 1;
					}
					cond_ok = BO(xlform->bo, 0) ||
						(CR(cpu->cr, xlform->bi + 32) == BO(xlform->bo, 1));
					if(ctr_ok && cond_ok) {
						nia = cpu->lr & ~0x3;
					}
					if(xlform->lk) {
						cpu->lr = cpu->pc + 4;
					}
					cpu->pc = nia;
					break;
				case 33: // crnor
					ua = (cpu->cr & BIT(32 + xlform1->ba)) != 0;
					ub = (cpu->cr & BIT(32 + xlform1->bb)) != 0;
					bit = !(ua || ub) ? 1 : 0;
					mask = ~BIT(32 + xlform1->bt);
					shift = 63 - (32 + xlform1->bt);
					cpu->cr = (cpu->cr & mask) | (bit << shift);
					cpu->pc += 4;
					break;
				case 129: // crandc
					ua = (cpu->cr & BIT(32 + xlform1->ba)) != 0;
					ub = (cpu->cr & BIT(32 + xlform1->bb)) != 0;
					bit = (ua && !ub) ? 1 : 0;
					mask = ~BIT(32 + xlform1->bt);
					shift = 63 - (32 + xlform1->bt);
					cpu->cr = (cpu->cr & mask) | (bit << shift);
					cpu->pc += 4;
					break;
				case 193: // crxor
					ua = (cpu->cr & BIT(32 + xlform1->ba)) != 0;
					ub = (cpu->cr & BIT(32 + xlform1->bb)) != 0;
					bit = (ua ^ ub) ? 1 : 0;
					mask = ~BIT(32 + xlform1->bt);
					shift = 63 - (32 + xlform1->bt);
					cpu->cr = (cpu->cr & mask) | (bit << shift);
					cpu->pc += 4;
					break;
				case 225: // crnand
					ua = (cpu->cr & BIT(32 + xlform1->ba)) != 0;
					ub = (cpu->cr & BIT(32 + xlform1->bb)) != 0;
					bit = !(ua && ub) ? 1 : 0;
					mask = ~BIT(32 + xlform1->bt);
					shift = 63 - (32 + xlform1->bt);
					cpu->cr = (cpu->cr & mask) | (bit << shift);
					cpu->pc += 4;
					break;
				case 257: // crand
					ua = (cpu->cr & BIT(32 + xlform1->ba)) != 0;
					ub = (cpu->cr & BIT(32 + xlform1->bb)) != 0;
					bit = (ua && ub) ? 1 : 0;
					mask = ~BIT(32 + xlform1->bt);
					shift = 63 - (32 + xlform1->bt);
					cpu->cr = (cpu->cr & mask) | (bit << shift);
					cpu->pc += 4;
					break;
				case 289: // creqv
					ua = (cpu->cr & BIT(32 + xlform1->ba)) != 0;
					ub = (cpu->cr & BIT(32 + xlform1->bb)) != 0;
					bit = !(ua ^ ub) ? 1 : 0;
					mask = ~BIT(32 + xlform1->bt);
					shift = 63 - (32 + xlform1->bt);
					cpu->cr = (cpu->cr & mask) | (bit << shift);
					cpu->pc += 4;
					break;
				case 417: // crorc
					ua = (cpu->cr & BIT(32 + xlform1->ba)) != 0;
					ub = (cpu->cr & BIT(32 + xlform1->bb)) != 0;
					bit = (ua || !ub) ? 1 : 0;
					mask = ~BIT(32 + xlform1->bt);
					shift = 63 - (32 + xlform1->bt);
					cpu->cr = (cpu->cr & mask) | (bit << shift);
					cpu->pc += 4;
					break;
				case 449: // cror
					ua = (cpu->cr & BIT(32 + xlform1->ba)) != 0;
					ub = (cpu->cr & BIT(32 + xlform1->bb)) != 0;
					bit = (ua || ub) ? 1 : 0;
					mask = ~BIT(32 + xlform1->bt);
					shift = 63 - (32 + xlform1->bt);
					cpu->cr = (cpu->cr & mask) | (bit << shift);
					cpu->pc += 4;
					break;
				case 528: // bcctr/bcctrl
					nia = cpu->pc + 4;
					cond_ok = BO(xlform->bo, 0) ||
						(CR(cpu->cr, xlform->bi + 32) == BO(xlform->bo, 1));
					if(cond_ok) {
						if(cpu->ppc64) {
							nia = cpu->ctr & ~0x3;
						} else {
							nia = (u32) (cpu->ctr & ~0x3);
						}
					}
					if(xlform->lk) {
						cpu->lr = cpu->pc + 4;
					}
					cpu->pc = nia;
					break;
				default:
					WARNING("0x%016lx: unknown opcode %d, xo %d\n",
							cpu->pc, op, xlform->xo);
					exit(1);
			}
			break;
		case 20: // rlwimi/rlwimi.
			mask = generate_mask(mform->mb + 32, mform->me + 32);
			ua = cpu->gpr[mform->ra];
			ub = (u32) cpu->gpr[mform->rs];
			shift = mform->rb; // rb = sh
			cpu->gpr[mform->ra] = (ROTL32(ub, shift) & mask) | (ua & ~mask);
			if(mform->rc) {
				UPDATE_CR0(cpu->gpr[mform->ra]);
			}
			cpu->pc += 4;
			break;
		case 21: // rlwinm/rlwinm.
			mask = generate_mask(mform->mb + 32, mform->me + 32);
			ua = cpu->gpr[mform->rs];
			if(mform->rb == 0 && mform->mb == 0) { // rb = sh
				u64 r = (u32) ua & mask;
				cpu->gpr[mform->ra] = r;
				if(mform->rc) {
					UPDATE_CR0_ROTATE(r);
				}
			} else {
				u32 s = (u32) ua;
				u32 r = ROTL32(s, mform->rb); // rb = sh
				cpu->gpr[mform->ra] = r & mask;
				if(mform->rc) {
					UPDATE_CR0_ROTATE(r & mask);
				}
			}
			cpu->pc += 4;
			break;
		case 23: // rlwnm/rlwnm.
			mask = generate_mask(mform->mb + 32, mform->me + 32);
			ua = cpu->gpr[mform->rs];
			ub = cpu->gpr[mform->rb] & 0x1f;
			cpu->gpr[mform->ra] = ROTL32((u32) ua, ub) & mask;
			if(mform->rc) {
				UPDATE_CR0_ROTATE(cpu->gpr[mform->ra]);
			}
			cpu->pc += 4;
			break;
		case 24: // ori
			cpu->gpr[dform->ra] = cpu->gpr[dform->rt] | dform->d; // d = ui
			cpu->pc += 4;
			break;
		case 25: // oris
			cpu->gpr[dform->ra] = cpu->gpr[dform->rt] |
				(dform->d << 16); // d = ui
			cpu->pc += 4;
			break;
		case 26: // xori
			cpu->gpr[dform->ra] = cpu->gpr[dform->rt] ^ dform->d; // d = ui
			cpu->pc += 4;
			break;
		case 27: // xoris
			cpu->gpr[dform->ra] = cpu->gpr[dform->rt] ^
				(dform->d << 16); // d = ui
			cpu->pc += 4;
			break;
		case 28: // andi.
			cpu->gpr[dform->ra] = cpu->gpr[dform->rt] & dform->d; // d = ui
			UPDATE_CR0(cpu->gpr[dform->ra]);
			cpu->pc += 4;
			break;
		case 29: // andis.
			cpu->gpr[dform->ra] = cpu->gpr[dform->rt] &
				(dform->d << 16); // d = ui
			UPDATE_CR0(cpu->gpr[dform->ra]);
			cpu->pc += 4;
			break;
		case 31:
			switch(xform->xo) {
				case 0: // cmp
					if(xform1->l) {
						sa = cpu->gpr[xform1->ra];
						sb = cpu->gpr[xform1->rb];
					} else {
						sa = (s32) cpu->gpr[xform1->ra];
						sb = (s32) cpu->gpr[xform1->rb];
					}
					if(sa < sb) {
						c = 0b1000;
					} else if(sa > sb) {
						c = 0b0100;
					} else {
						c = 0b0010;
					}
					mask = 0xF << (32 - xform1->bf * 4 - 4);
					shift = 32 - xform1->bf * 4 - 4;
					c |= (cpu->xer & XER_SO ? 1 : 0);
					cpu->cr = (cpu->cr & ~mask) | (c << shift);
					cpu->pc += 4;
					break;
				case 21: // ldzx
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = READMEM64(ea);
					cpu->pc += 4;
					break;
				case 23: // lwzx
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = READMEM32(ea);
					cpu->pc += 4;
					break;
				case 24: // slw/swl.
					n = (int) cpu->gpr[xform->rb] & 0x1f;
					cpu->gpr[xform->ra] = cpu->gpr[xform->rt] << n; // rt = rs
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 26: // cntlzw/cntlzw.
					if((u32) cpu->gpr[xform->rt] == 0) {
						cpu->gpr[xform->ra] = 32;
					} else {
						cpu->gpr[xform->ra] = __builtin_clz((u32) cpu->gpr[xform->rt]); // rt = rs
					}
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 28: // and/and.
					cpu->gpr[xform->ra] = cpu->gpr[xform->rt] &
						cpu->gpr[xform->rb];
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 32: // cmpl
					if(xform1->l) {
						ua = cpu->gpr[xform1->ra];
						ub = cpu->gpr[xform1->rb];
					} else {
						ua = (u32) cpu->gpr[xform1->ra];
						ub = (u32) cpu->gpr[xform1->rb];
					}
					if(ua < ub) {
						c = 0b1000;
					} else if(ua > ub) {
						c = 0b0100;
					} else {
						c = 0b0010;
					}
					mask = 0xF << (32 - xform1->bf * 4 - 4);
					shift = 32 - xform1->bf * 4 - 4;
					c |= (cpu->xer & XER_SO ? 1 : 0);
					cpu->cr = (cpu->cr & ~mask) | (c << shift);
					cpu->pc += 4;
					break;
				case 53: // ldzux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = READMEM64(ea);
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 55: // lwzux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = READMEM32(ea);
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 60: // andc/andc.
					cpu->gpr[xform->ra] = cpu->gpr[xform->rt] &
							~cpu->gpr[xform->rb];
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 87: // lbzx
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = READMEM8(ea);
					cpu->pc += 4;
					break;
				case 119: // lbzux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = READMEM8(ea);
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 124: // nor/nor.
					cpu->gpr[xform->ra] = ~(cpu->gpr[xform->rt] |
							cpu->gpr[xform->rb]);
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 149: // stdx
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					WRITEMEM64(ea, cpu->gpr[xform->rt]); // rt = rs
					cpu->pc += 4;
					break;
				case 151: // stwx
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					WRITEMEM32(ea, cpu->gpr[xform->rt]); // rt = rs
					cpu->pc += 4;
					break;
				case 181: // stdux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					WRITEMEM64(ea, cpu->gpr[xform->rt]); // rt = rs
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 183: // stwux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					WRITEMEM32(ea, cpu->gpr[xform->rt]); // rt = rs
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 215: // stbx
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					WRITEMEM8(ea, cpu->gpr[xform->rt]); // rt = rs
					cpu->pc += 4;
					break;
				case 247: // stbux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					WRITEMEM8(ea, cpu->gpr[xform->rt]); // rt = rs
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 278: // dcbt
					// nothing
					cpu->pc += 4;
					break;
				case 279: // lhzx
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = READMEM16(ea);
					cpu->pc += 4;
					break;
				case 284: // eqv/eqv.
					cpu->gpr[xform->ra] = ~(cpu->gpr[xform->rt] ^
							cpu->gpr[xform->rb]);
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 311: // lhzux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = READMEM16(ea);
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 316: // xor/xor.
					cpu->gpr[xform->ra] = cpu->gpr[xform->rt] ^
						cpu->gpr[xform->rb];
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 339: // mfspr
					n = ((xfxform->spr & 0x1f) << 5) | ((xfxform->spr >> 5) & 0x1f);
					switch(n) {
						case 1:
							cpu->gpr[xfxform->rt] = cpu->xer;
							break;
						case 8:
							cpu->gpr[xfxform->rt] = cpu->lr;
							break;
						case 9:
							cpu->gpr[xfxform->rt] = cpu->ctr;
							break;
						default:
							WARNING("mfspr: spr %d not implemented\n", n);
							exit(1);
					}
					cpu->pc += 4;
					break;
				case 341: // lwax
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = (s32) READMEM32(ea);
					cpu->pc += 4;
					break;
				case 343: // lhax
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = (s16) READMEM16(ea);
					cpu->pc += 4;
					break;
				case 373: // lwaux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = (s32) READMEM32(ea);
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 375: // lhaux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					cpu->gpr[xform->rt] = (s16) READMEM16(ea);
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 407: // sthx
					b = RA0(xform->ra);
					ea = b + cpu->gpr[xform->rb];
					WRITEMEM16(ea, cpu->gpr[xform->rt]); // rt = rs
					cpu->pc += 4;
					break;
				case 412: // orc/orc.
					cpu->gpr[xform->ra] = cpu->gpr[xform->rt] |
							~cpu->gpr[xform->rb];
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 439: // sthux
					ea = cpu->gpr[xform->ra] + cpu->gpr[xform->rb];
					WRITEMEM16(ea, cpu->gpr[xform->rt]); // rt = rs
					cpu->gpr[xform->ra] = ea;
					cpu->pc += 4;
					break;
				case 444: // or/or.
					cpu->gpr[xform->ra] = cpu->gpr[xform->rt] |
						cpu->gpr[xform->rb];
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 467: // mtspr
					n = ((xfxform->spr & 0x1f) << 5) | ((xfxform->spr >> 5) & 0x1f);
					switch(n) {
						case 1:
							cpu->xer = cpu->gpr[xfxform->rt]; // rt = rs
							break;
						case 8:
							cpu->lr = cpu->gpr[xfxform->rt]; // rt = rs
							break;
						case 9:
							cpu->ctr = cpu->gpr[xfxform->rt]; // rt = rs
							break;
						default:
							WARNING("mtspr: spr %d not implemented\n", n);
							exit(1);
					}
					cpu->pc += 4;
					break;
				case 476: // nand/nand.
					cpu->gpr[xform->ra] = ~(cpu->gpr[xform->rt] &
							cpu->gpr[xform->rb]);
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 536: // srw/srw.
					n = (int) cpu->gpr[xform->rb] & 0x1f;
					cpu->gpr[xform->ra] = cpu->gpr[xform->rt] >> n; // rt = rs
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 792: // sraw/sraw.
					sa = (s32) cpu->gpr[xform->rt]; // rt = rs
					n = (int) cpu->gpr[xform->rb] & 0x1f;
					mask = generate_mask(32 + (32 - n), 63);
					cpu->gpr[xform->ra] = sa >> n;
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					UPDATE_CA((sa < 0) && ((sa & mask) != 0));
					cpu->pc += 4;
					break;
				case 824: // srawi/srawi.
					sa = (s32) cpu->gpr[xform->rt]; // rt = rs
					n = xform->rb; // rb = sh
					mask = generate_mask(32 + (32 - n), 63);
					cpu->gpr[xform->ra] = sa >> n;
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					UPDATE_CA((sa < 0) && ((sa & mask) != 0));
					cpu->pc += 4;
					break;
				case 922: // extsh/extsh.
					b = cpu->gpr[xform->rt]; // rt = rs
					cpu->gpr[xform->ra] = (s16) b;
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 954: // extsb/extsb.
					b = cpu->gpr[xform->rt]; // rt = rs
					cpu->gpr[xform->ra] = (s8) b;
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				case 986: // extsw/extsw.
					b = cpu->gpr[xform->rt]; // rt = rs
					cpu->gpr[xform->ra] = (s32) b;
					if(xform->rc) {
						UPDATE_CR0(cpu->gpr[xform->ra]);
					}
					cpu->pc += 4;
					break;
				default:
					switch(xoform->xo) {
						case 8: // subfc/subfc./subfco/subfco.
							ua = cpu->gpr[xoform->ra];
							ub = cpu->gpr[xoform->rb];
							cpu->gpr[xoform->rt] = ~ua + ub + 1;
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							if(xoform->oe) {
								WARNING("0x%016lx: oe not supported\n",
										cpu->pc);
								exit(1);
							}
							UPDATE_CA(carry(~ua, ub, 1));
							cpu->pc += 4;
							break;
						// TODO: 10 = // addc/addc./addco/addco.
						case 11: // mulhwu/mulhwu.
							prod = ((u32) cpu->gpr[xoform->ra]) *
								(u64) ((u32) cpu->gpr[xoform->rb]);
							cpu->gpr[xoform->rt] = (s32) (prod >> 32);
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							cpu->pc += 4;
							break;
						case 40: // subf/subf./subfo/subfo.
							cpu->gpr[xoform->rt] =
								~cpu->gpr[xoform->ra] +
								cpu->gpr[xoform->rb] + 1;
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							if(xoform->oe) {
								WARNING("0x%016lx: oe not supported\n",
										cpu->pc);
								exit(1);
							}
							cpu->pc += 4;
							break;
						case 75: // mulhw/mulhw.
							prod = ((s32) cpu->gpr[xoform->ra]) *
								(s64) ((s32) cpu->gpr[xoform->rb]);
							cpu->gpr[xoform->rt] = (s32) (prod >> 32);
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							cpu->pc += 4;
							break;
						case 104: // neg/neg./nego/nego.
							cpu->gpr[xoform->rt] = ~cpu->gpr[xoform->ra] + 1;
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							if(xoform->oe) {
								WARNING("0x%016lx: oe not supported\n",
										cpu->pc);
								exit(1);
							}
							cpu->pc += 4;
							break;
						case 136: // subfe/subfe./subfeo/subfeo.
							cpu->gpr[xoform->rt] = cpu->gpr[xoform->rb] -
								cpu->gpr[xoform->ra] - ((cpu->xer & XER_SO) ? 1 : 0);
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							if(xoform->oe) {
								WARNING("0x%016lx: oe not supported\n",
										cpu->pc);
								exit(1);
							}
							cpu->pc += 4;
							break;
						case 235: // mullw/mullw./mullwo/mullwo.
							prod = ((s32) cpu->gpr[xoform->ra]) *
								(s64) ((s32) cpu->gpr[xoform->rb]);
							cpu->gpr[xoform->rt] = prod;
							if(xoform->rc) {
								UPDATE_CR0(prod);
							}
							if(xoform->oe) {
								WARNING("0x%016lx: oe not supported\n",
										cpu->pc);
								exit(1);
							}
							cpu->pc += 4;
							break;
						case 266: // add/add./addo/addo.
							cpu->gpr[xoform->rt] =
								cpu->gpr[xoform->ra] +
								cpu->gpr[xoform->rb];
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							if(xoform->oe) {
								WARNING("0x%016lx: oe not supported\n",
										cpu->pc);
								exit(1);
							}
							cpu->pc += 4;
							break;
						case 459: // divwu/divwu./divwuo/divwuo.
							cpu->gpr[xoform->rt] = (u32) cpu->gpr[xoform->ra] /
								(u32) cpu->gpr[xoform->rb];
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							if(xoform->oe) {
								WARNING("0x%016lx: oe not supported\n",
										cpu->pc);
								exit(1);
							}
							cpu->pc += 4;
							break;
						case 491: // divw/divw./divwo/divwo.
							cpu->gpr[xoform->rt] = (s32) cpu->gpr[xoform->ra] /
								(s32) cpu->gpr[xoform->rb];
							if(xoform->rc) {
								UPDATE_CR0(cpu->gpr[xoform->rt]);
							}
							if(xoform->oe) {
								WARNING("0x%016lx: oe not supported\n",
										cpu->pc);
								exit(1);
							}
							cpu->pc += 4;
							break;
						default:
							WARNING("0x%016lx: unknown opcode %d, xo %d\n",
									cpu->pc,
									op,
									xform->xo);
							exit(1);
					}
			}
			break;
		case 32: // lwz
			b = RA0(dform->ra);
			ea = b + (s16) dform->d;
			cpu->gpr[dform->rt] = READMEM32(ea);
			cpu->pc += 4;
			break;
		case 33: // lwzu
			b = cpu->gpr[dform->ra];
			ea = b + (s16) dform->d;
			cpu->gpr[dform->rt] = READMEM32(ea);
			cpu->gpr[dform->ra] = ea;
			cpu->pc += 4;
			break;
		case 34: // lbz
			b = RA0(dform->ra);
			ea = b + (s16) dform->d;
			cpu->gpr[dform->rt] = READMEM8(ea);
			cpu->pc += 4;
			break;
		case 35: // lbzu
			b = cpu->gpr[dform->ra];
			ea = b + (s16) dform->d;
			cpu->gpr[dform->rt] = READMEM8(ea);
			cpu->gpr[dform->ra] = ea;
			cpu->pc += 4;
			break;
		case 36: // stw
			b = RA0(dform->ra);
			ea = b + (s16) dform->d;
			WRITEMEM32(ea, cpu->gpr[dform->rt]); // rt = rs
			cpu->pc += 4;
			break;
		case 37: // stwu
			ea = cpu->gpr[dform->ra] + (s16) dform->d;
			WRITEMEM32(ea, cpu->gpr[dform->rt]); // rt = rs
			cpu->gpr[dform->ra] = ea;
			cpu->pc += 4;
			break;
		case 38: // stb
			b = RA0(dform->ra);
			ea = b + (s16) dform->d;
			WRITEMEM8(ea, cpu->gpr[dform->rt]); // rt = rs
			cpu->pc += 4;
			break;
		case 39: // stbu
			ea = cpu->gpr[dform->ra] + (s16) dform->d;
			WRITEMEM8(ea, cpu->gpr[dform->rt]); // rt = rs
			cpu->gpr[dform->ra] = ea;
			cpu->pc += 4;
			break;
		case 40: // lhz
			b = RA0(dform->ra);
			ea = b + (s16) dform->d;
			cpu->gpr[dform->rt] = READMEM16(ea);
			cpu->pc += 4;
			break;
		case 41: // lhzu
			b = cpu->gpr[dform->ra];
			ea = b + (s16) dform->d;
			cpu->gpr[dform->rt] = READMEM16(ea);
			cpu->gpr[dform->ra] = ea;
			cpu->pc += 4;
			break;
		case 42: // lha
			b = RA0(dform->ra);
			ea = b + (s16) dform->d;
			cpu->gpr[dform->rt] = (s16) READMEM16(ea);
			cpu->pc += 4;
			break;
		case 43: // lhau
			b = cpu->gpr[dform->ra];
			ea = b + (s16) dform->d;
			cpu->gpr[dform->rt] = (s16) READMEM16(ea);
			cpu->gpr[dform->ra] = ea;
			cpu->pc += 4;
			break;
		case 44: // sth
			b = RA0(dform->ra);
			ea = b + (s16) dform->d;
			WRITEMEM16(ea, cpu->gpr[dform->rt]); // rt = rs
			cpu->pc += 4;
			break;
		case 45: // sthu
			ea = cpu->gpr[dform->ra] + (s16) dform->d;
			WRITEMEM16(ea, cpu->gpr[dform->rt]); // rt = rs
			cpu->gpr[dform->ra] = ea;
			cpu->pc += 4;
			break;
		case 58:
			switch(dsform->xo) {
				case 0: // ld
					b = RA0(dsform->ra);
					ea = b + (s16) (dsform->ds << 2);
					cpu->gpr[dsform->rt] = READMEM64(ea);
					cpu->pc += 4;
					break;
				case 1: // ldu
					ea = cpu->gpr[dsform->ra] + (s16) (dsform->ds << 2);
					cpu->gpr[dsform->rt] = READMEM64(ea);
					cpu->gpr[dsform->ra] = ea;
					cpu->pc += 4;
					break;
				case 2: // lwa
					b = RA0(dsform->ra);
					ea = b + (s16) (dsform->ds << 2);
					cpu->gpr[dsform->rt] = (s32) READMEM32(ea);
					cpu->pc += 4;
					break;
				default:
					WARNING("0x%016lx: unknown opcode %d, xo %d\n",
							cpu->pc, op, dsform->xo);
					exit(1);
			}
			break;
		case 62:
			switch(dsform->xo) {
				case 0:
					b = RA0(dsform->ra);
					ea = b + (s16) (dsform->ds << 2);
					WRITEMEM64(ea, cpu->gpr[dsform->rt]); // rt = rs
					cpu->pc += 4;
					break;
				case 1:
					ea = cpu->gpr[dsform->ra] + (s16) (dsform->ds << 2);
					WRITEMEM64(ea, cpu->gpr[dsform->rt]); // rt = rs
					cpu->gpr[dsform->ra] = ea;
					cpu->pc += 4;
					break;
				default:
					WARNING("0x%016lx: unknown opcode %d, xo %d\n",
							cpu->pc, op, dsform->xo);
					exit(1);
			}
			break;
		default:
			WARNING("0x%016lx: unknown opcode %d\n", cpu->pc, op);
			exit(1);
	}
}

static inline int align16B(int x)
{
	if((x & 0xf) != 0) {
		return x + 0x10 - (x & 0xf);
	} else {
		return x;
	}
}

static inline u64 str(void* mem, u64 ptr, const char* s)
{
	size_t len = strlen(s);
	memcpy((char*) mem + ptr, s, len + 1);
	return ptr + len + 1;
}

static inline u64 set_pair(void* mem, u64 ptr, int key, int value)
{
	u32* p = (u32*) ((char*) mem + ptr);
	p[0] = SETI32(key);
	p[1] = SETI32(value);
	return ptr + 8;
}

int main(int argc, char** argv, char** envp)
{
	if(argc < 2) {
		printf("usage: %s program\n", *argv);
		return 1;
	}

	const char* filename = argv[1];
	const char* progname = filename; // TODO: realpath

	int file = open(filename, O_RDONLY);
	if(file < 0) {
		perror("fopen");
		return 1;
	}

	Elf32_Ehdr elf32;
	read(file, &elf32, sizeof(elf32));

	if(elf32.e_ident[EI_MAG0] != ELFMAG0 || elf32.e_ident[EI_MAG1] != ELFMAG1
			|| elf32.e_ident[EI_MAG2] != ELFMAG2 ||
			elf32.e_ident[EI_MAG3] != ELFMAG3) {
		printf("not an elf file!\n");
		return 1;
	}

	if(elf32.e_ident[EI_CLASS] != ELFCLASS32) {
		printf("not a 32bit file!\n");
		return 1;
	}

	if(elf32.e_ident[EI_DATA] != ELFDATA2MSB) {
		printf("not a big endian file!\n");
		return 1;
	}

	if(elf32.e_ident[EI_VERSION] != EV_CURRENT) {
		printf("invalid elf version\n");
		return 1;
	}

	if(GETI16(elf32.e_machine) != EM_PPC) {
		printf("not a ppc executable\n");
		return 1;
	}

	if(GETI16(elf32.e_type) == ET_EXEC) {
		printf("loading executable\n");
	} else if(GETI16(elf32.e_type) == ET_DYN) {
		printf("loading pie executable\n");
	} else {
		printf("invalid type: %d\n", GETI16(elf32.e_type));
		return 1;
	}

	CPU cpu;
	memset(&cpu, 0, sizeof(cpu));

	cpu.pc = GETI32(elf32.e_entry);

	printf("entry point: 0x%08x\n", (u32) cpu.pc);

	u32 phoff = GETI32(elf32.e_phoff);
	u16 phnum = GETI16(elf32.e_phnum);
	u16 phentsize = GETI16(elf32.e_phentsize);
	u32 size = phnum * phentsize;

	// printf("program headers: %d [starting at %d, size %d]\n", phnum, phoff,
	//		size);

	lseek(file, phoff, SEEK_SET);
	Elf32_Phdr* phdr = (Elf32_Phdr*) malloc(size);
	if(phdr == NULL) {
		return 1;
	}
	read(file, phdr, size);

	// find lowest address
	u32 minaddr = 0xFFFFFFFF;
	for(int i = 0; i < phnum; i++) {
		u32 type = GETI32(phdr[i].p_type);
		if(type == PT_LOAD || type == PT_PHDR) {
			if(GETI32(phdr[i].p_vaddr) < minaddr) {
				minaddr = GETI32(phdr[i].p_vaddr);
			}
		}
	}
	printf("lowest segment address is 0x%08x\n", minaddr);

	// allocate RAM base address
	cpu.memory = (u8*) mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE |
			MAP_ANONYMOUS, -1, 0);
	if(cpu.memory == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	munmap(cpu.memory, 4096);

	// map stack
	void* stack = &cpu.memory[STACK_BASE];
	void* stack_base = mmap(stack, STACK_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if(stack_base == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	if(stack_base != stack) {
		printf("error: stack memory mapped to wrong address %p instead of %p\n",
				stack_base, stack);
		return 1;
	}
	cpu.gpr[1] = STACK_ADDRESS;

	// map segments
	for(int i = 0; i < phnum; i++) {
		u32 type = GETI32(phdr[i].p_type);
		if(type == PT_LOAD || type == PT_PHDR) {
			u32 addr = GETI32(phdr[i].p_vaddr);
			u32 off = GETI32(phdr[i].p_offset);
			u32 size = GETI32(phdr[i].p_memsz);
			int flags = GETI32(phdr[i].p_flags);
			int prot = PROT_NONE;
			if(flags & PF_R) {
				prot |= PROT_READ;
			}
			if(flags & PF_W) {
				prot |= PROT_WRITE;
			}
			if(flags & PF_X) {
				prot |= PROT_EXEC;
			}
			printf("mapping segment %d to 0x%08x [%d bytes] with permissions %c%c%c\n",
					i, addr, size,
					flags & PF_R ? 'R' : '-',
					flags & PF_W ? 'W' : '-',
					flags & PF_X ? 'X' : '-');
			u32 mapaddr = addr & ~4095;
			u32 mapoff = off;
			if(mapaddr < addr) {
				mapoff -= addr - mapaddr;
			}
			u32 mapsize = size & ~4095;
			if(mapsize < size) {
				mapsize += 4096;
			}
			void* ptr = ((u8*) cpu.memory) + mapaddr;
			void* result = mmap(ptr, mapsize, prot, MAP_PRIVATE |
					MAP_FIXED, file, mapoff);
			if(result == MAP_FAILED) {
				perror("mmap");
				return 1;
			}
			if(result != ptr) {
				printf("error: segment mapped to wrong address %p instead of %p\n",
						result, ptr);
				return 1;
			}
		}
	}
	close(file);

	printf("stack: 0x%016lx - 0x%016lx\n", cpu.gpr[1] - STACK_SIZE, cpu.gpr[1]);
	memset(&cpu.memory[cpu.gpr[1] - STACK_SIZE], 0, STACK_SIZE);

	int ptrsz = 4;
	int string_size = strlen(progname) + 1;

	// argv
	int argcnt = argc - 1;
	for(int i = 0; i < argcnt; i++) {
		string_size += strlen(argv[i + 1]) + 1;
	}

	// envp
	int envcnt = 0;
	for(char** p = envp; *p; p++) {
		string_size += strlen(*p) + 1;
		envcnt++;
	}

	int auxvcnt = 24;
	int auxv_data_size = strlen(PLATFORM) + 1 + RANDOM_SIZE;
	int pointers_size = (argcnt + envcnt + 3 + (auxvcnt * 2)) * ptrsz;

	string_size = align16B(string_size);
	auxv_data_size = align16B(auxv_data_size);
	pointers_size = align16B(pointers_size);

	size = string_size + auxv_data_size + pointers_size;

	u64 r1 = cpu.gpr[1];
	r1 -= size;
	cpu.gpr[1] = r1;

	printf("stack pointer: 0x%016lx\n", r1);

	long ptr = r1 + pointers_size + auxv_data_size;
	ptr = r1 + pointers_size + auxv_data_size;
	u64* ptr_args = (u64*) malloc(argcnt * sizeof(u64));
	u64* ptr_env = (u64*) malloc(envcnt * sizeof(u64));

	for(int i = 0; i < argcnt; i++) {
		ptr_args[i] = ptr;
		ptr = str(cpu.memory, ptr, argv[i + 1]);
	}

	for(int i = 0; i < envcnt; i++) {
		ptr_env[i] = ptr;
		ptr = str(cpu.memory, ptr, envp[i]);
	}

	u64 ptr_execfn = ptr;
	ptr = str(cpu.memory, ptr, progname);

	assert(ptr - (r1 + pointers_size + auxv_data_size) <= string_size);

	// auxv data
	ptr = r1 + pointers_size;
	u64 ptr_random = ptr;
	for(int i = 0; i < RANDOM_SIZE / 4; i++) {
		*((u32*) &cpu.memory[ptr]) = random();
		ptr += 4;
	}

	u64 ptr_platform = ptr;
	ptr = str(cpu.memory, ptr, PLATFORM);

	assert((ptr - (r1 + pointers_size)) < auxv_data_size);

	// pointers
	ptr = r1;

	// argc
	*((u32*) &cpu.memory[ptr]) = SETI32(argcnt);
	ptr += ptrsz;

	// argv
	for(int i = 0; i < argcnt; i++) {
		*((u32*) &cpu.memory[ptr]) = SETI32(ptr_args[i]);
		ptr += ptrsz;
	}

	// (nil)
	*((u32*) &cpu.memory[ptr]) = 0;
	ptr += ptrsz;

	// env
	for(int i = 0; i < envcnt; i++) {
		*((u32*) &cpu.memory[ptr]) = SETI32(ptr_env[i]);
		ptr += ptrsz;
	}
	// (nil)
	*((u32*) &cpu.memory[ptr]) = 0;
	ptr += ptrsz;

	// auxv
	ptr = set_pair(cpu.memory, ptr, AT_IGNOREPPC, AT_IGNOREPPC);
	ptr = set_pair(cpu.memory, ptr, AT_IGNOREPPC, AT_IGNOREPPC);
	ptr = set_pair(cpu.memory, ptr, AT_DCACHEBSIZE, DCACHE_LINE_SIZE);
	ptr = set_pair(cpu.memory, ptr, AT_ICACHEBSIZE, ICACHE_LINE_SIZE);
	ptr = set_pair(cpu.memory, ptr, AT_UCACHEBSIZE, 0);
	// ptr = set_pair(cpu.memory, ptr, AT_PHDR, (int) (load_addr + elf.e_phoff));
	ptr = set_pair(cpu.memory, ptr, AT_PHENT, phentsize);
	ptr = set_pair(cpu.memory, ptr, AT_PHNUM, phnum);
	ptr = set_pair(cpu.memory, ptr, AT_PAGESZ, PAGE_SIZE);
	ptr = set_pair(cpu.memory, ptr, AT_BASE, 0);
	ptr = set_pair(cpu.memory, ptr, AT_FLAGS, 0);
	ptr = set_pair(cpu.memory, ptr, AT_ENTRY, cpu.pc);
	ptr = set_pair(cpu.memory, ptr, AT_UID, getuid());
	ptr = set_pair(cpu.memory, ptr, AT_EUID, geteuid());
	ptr = set_pair(cpu.memory, ptr, AT_GID, getuid());
	ptr = set_pair(cpu.memory, ptr, AT_EGID, getegid());
	ptr = set_pair(cpu.memory, ptr, AT_PLATFORM, (int) ptr_platform);
	ptr = set_pair(cpu.memory, ptr, AT_HWCAP, HWCAP);
	ptr = set_pair(cpu.memory, ptr, AT_SECURE, 0);
	ptr = set_pair(cpu.memory, ptr, AT_BASE_PLATFORM, (int) ptr_platform);
	ptr = set_pair(cpu.memory, ptr, AT_RANDOM, (int) ptr_random);
	ptr = set_pair(cpu.memory, ptr, AT_HWCAP2, HWCAP2);
	ptr = set_pair(cpu.memory, ptr, AT_EXECFN, (int) ptr_execfn);
	ptr = set_pair(cpu.memory, ptr, AT_NULL, 0);

	free(ptr_env);
	free(ptr_args);
	free(phdr);

	printf("starting execution...\n");

	while(1) {
#ifdef DEBUG
		u64 oldpc = cpu.pc;
#endif
		step(&cpu);
#ifdef DEBUG
		dump(&cpu, oldpc);
#endif
	}
}
