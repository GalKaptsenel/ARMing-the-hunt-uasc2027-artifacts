//
// smc_probe.ko -- issue controlled EL2 operations from an ioctl so an EL0 prime+probe harness
// (smc_bench) can measure whether each one flushes/perturbs the normal-world BTB. The op runs at
// EL2 on the caller's core, between the EL0 prime and the EL0 probe, so its effect on the primed
// BTB entry is directly observable.
//
//   SMC_DO       : N x arm_smccc_smc(SMCCC_VERSION)  -- real EL3 round trips (read-only, safe)
//   SMC_NOP      : N x do-nothing call               -- same loop, no SMC (EL0<->EL2 baseline)
//   OP_ICIALLU   : N x `ic iallu`                     -- instruction-cache invalidate (A15-era BP trick)
//   OP_TLBI      : N x `tlbi vmalle1`                 -- TLB maintenance; does it touch the BTB?
//   OP_SCTLR     : N x rewrite SCTLR_EL1 with its OWN value + isb -- touches the MMU-control register
//                  but keeps M=1, so NO MMU-off hazard.
//   OP_BARRIER   : N x `dsb sy; isb`                  -- negative control
//   OP_MMUTOGGLE : ONE SCTLR_EL1.M 1->0->1 toggle via an identity-mapped trampoline (the A57/A72
//                  firmware BP-invalidation trick). Safe-guarded: private TTBR0 idmap, dry-run
//                  validation with M=1 before the real toggle, geometry bail-out, register-only
//                  M=0 window. Returns -EOPNOTSUPP if the idmap could not be built.
//
// Build: make KDIR=/usr/src/linux-headers-$(uname -r).  Load: sudo insmod smc_probe.ko; chmod 666 /dev/smc_probe

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/irqflags.h>
#include <linux/arm-smccc.h>

#define SMC_DO       0x5301u
#define SMC_NOP      0x5302u
#define OP_ICIALLU   0x5303u
#define OP_TLBI      0x5304u
#define OP_SCTLR     0x5305u
#define OP_BARRIER   0x5306u
#define OP_MMUTOGGLE 0x5307u
#define OP_CFPRCTX   0x5308u                 // CFP RCTX, Xt (FEAT_SPECRES) -- restrict control-flow prediction
#define OP_WA1_FEAT  0x5309u                 // query SMCCC_ARCH_WORKAROUND_1 availability
#define OP_WA1_DO    0x530Au                 // invoke SMCCC_ARCH_WORKAROUND_1 (firmware BP invalidation)
#define SMCCC_VERSION_FID   0x80000000u      // standard, read-only: returns implemented SMCCC version
#define SMCCC_ARCH_FEATURES 0x80000001u
#define SMCCC_ARCH_WA1      0x80008000u
static int g_have_specres;                   // set at init from ID_AA64ISAR1_EL1.SPECRES

// ---- identity-mapped MMU-toggle trampoline -------------------------------------------------------
// The trampoline runs at VA==PA (via a private TTBR0 idmap) so that when SCTLR.M is cleared and
// translation stops, the PC (== the physical address) still fetches the right instructions.
static u64          g_ttbr0_idmap;           // TTBR0_EL1 value (ASID 0) pointing at our top table
static void       (*g_validate)(void);       // VA==PA of a lone `ret` (dry-run mapping test, M=1)
static void       (*g_toggle)(void);          // VA==PA of the M:1->0->1 sequence
static u32         *g_code;                   // trampoline code page (linear alias, writable)
static u64         *g_tbl[4];                 // our page tables (levels g_start..3)
static int          g_start;                  // top translation level of our idmap
static int          g_ready;                  // 1 if the toggle is safe to run

static int level_index(u64 va, int level) {
	int shift = 12 + 9 * (3 - level);
	return (int)((va >> shift) & 0x1ff);
}

static int build_toggle(void)
{
	u32 *code = NULL;
	u64 phys = 0;
	u64 tcr = 0;
	u64 mair = 0;
	u64 pte = 0;
	int t0sz = 0;
	int va_bits = 0;
	int nlevels = 0;
	int start = 0;
	int level = 0;
	int normal_idx = 0;
	int index = 0;

	asm volatile("mrs %0, tcr_el1"  : "=r"(tcr));    // VHE: redirects to TCR_EL2 (same running regime)
	t0sz = (int)(tcr & 0x3f);
	va_bits = 64 - t0sz;
	if (((va_bits - 12) % 9) != 0) {                 // only clean, non-concatenated geometries
		pr_warn("smc_probe: unsupported T0SZ=%d (va_bits=%d); MMU-toggle disabled\n", t0sz, va_bits);
		return -EOPNOTSUPP;
	}
	nlevels = (va_bits - 12) / 9;
	start = 4 - nlevels;
	if (start < 0 || start > 3) {
		return -EOPNOTSUPP;
	}
	asm volatile("mrs %0, mair_el1" : "=r"(mair));
	normal_idx = -1;
	for (index = 0; index < 8; ++index) {
		if (((mair >> (8 * index)) & 0xff) == 0xff) {   // Normal Write-Back attr index
			normal_idx = index;
			break;
		}
	}
	if (normal_idx < 0) {
		pr_warn("smc_probe: no Normal-WB MAIR attr; MMU-toggle disabled\n");
		return -EOPNOTSUPP;
	}

	code = (u32 *)__get_free_page(GFP_KERNEL);
	if (!code) {
		return -ENOMEM;
	}
	phys = virt_to_phys(code);
	if (phys >= (1UL << va_bits)) {                   // trampoline PA must be reachable via TTBR0
		free_page((unsigned long)code);
		pr_warn("smc_probe: trampoline PA %llx out of VA range; MMU-toggle disabled\n",
			(unsigned long long)phys);
		return -EOPNOTSUPP;
	}

	code[0] = 0xD65F03C0;   // ret                 -- validate entry (P+0): lone ret, M=1 dry run
	code[1] = 0xD280002B;   // mov  x11, #1         -- toggle entry (P+4)
	code[2] = 0xD5381009;   // mrs  x9,  sctlr_el1
	code[3] = 0x8A2B012A;   // bic  x10, x9, x11    -- clear M bit
	code[4] = 0xD518100A;   // msr  sctlr_el1, x10  -- MMU OFF
	code[5] = 0xD5033FDF;   // isb
	code[6] = 0xD5181009;   // msr  sctlr_el1, x9   -- restore original SCTLR (MMU ON)
	code[7] = 0xD5033FDF;   // isb
	code[8] = 0xD65F03C0;   // ret

	for (index = 0; index < 9; ++index) {              // clean D + invalidate I to PoU (PIPT: by PA)
		unsigned long addr = (unsigned long)&code[index];
		asm volatile("dc cvau, %0" :: "r"(addr) : "memory");
	}
	asm volatile("dsb ish" ::: "memory");
	for (index = 0; index < 9; ++index) {
		unsigned long addr = (unsigned long)&code[index];
		asm volatile("ic ivau, %0" :: "r"(addr) : "memory");
	}
	asm volatile("dsb ish\n isb\n" ::: "memory");

	for (level = start; level <= 3; ++level) {
		g_tbl[level] = (u64 *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
		if (!g_tbl[level]) {
			goto oom;
		}
	}
	// RO + executable (survives WXN), Normal-WB, inner-shareable, AF set, global, not-guarded (no BTI)
	pte = (phys & 0x0000FFFFFFFFF000UL) | 3UL | (1UL << 10) | (3UL << 8) | (2UL << 6) | ((u64)normal_idx << 2)
	      | (1UL << 54);   // UXN=1 (no EL0 exec); PXN=0 (EL1 exec)
	for (level = start; level < 3; level++) {
		g_tbl[level][level_index(phys, level)] = virt_to_phys(g_tbl[level + 1]) | 3UL;   // table descriptor
	}
	g_tbl[3][level_index(phys, 3)] = pte;
	asm volatile("dsb ish" ::: "memory");

	g_ttbr0_idmap = virt_to_phys(g_tbl[start]);        // ASID 0
	g_validate = (void (*)(void))(unsigned long)(phys + 0);
	g_toggle   = (void (*)(void))(unsigned long)(phys + 4);
	g_code = code;
	g_start = start;
	g_ready = 1;
	pr_info("smc_probe: MMU-toggle idmap ready (P=%llx va_bits=%d start_lvl=%d normal_idx=%d)\n",
		(unsigned long long)phys, va_bits, start, normal_idx);
	return 0;
oom:
	for (index = start; index <= 3; ++index) {
		if (g_tbl[index]) {
			free_page((unsigned long)g_tbl[index]);
			g_tbl[index] = NULL;
		}
	}
	free_page((unsigned long)code);
	return -ENOMEM;
}

static void free_toggle(void)
{
	int index;
	if (g_code) {
		free_page((unsigned long)g_code);
		g_code = NULL;
	}
	for (index = 0; index < 4; ++index) {
		if (g_tbl[index]) {
			free_page((unsigned long)g_tbl[index]);
			g_tbl[index] = NULL;
		}
	}
	g_ready = 0;
}

static void do_mmu_toggle(void)
{
	unsigned long flags = 0;
	unsigned long daif = 0;
	unsigned long ttbr0_save = 0;

	preempt_disable();
	raw_local_irq_save(flags);
	asm volatile("mrs %0, daif" : "=r"(daif));
	asm volatile("msr daifset, #0xf" ::: "memory");           // mask D,A,I,F for the whole window
	asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0_save));
	asm volatile("msr ttbr0_el1, %0" :: "r"(g_ttbr0_idmap) : "memory");
	asm volatile("isb");
	asm volatile("tlbi vmalle1\n dsb nsh\n isb\n" ::: "memory");
	g_validate();                                             // dry-run at VA==PA with M=1 (recoverable if wrong)
	g_toggle();                                               // the real SCTLR.M 1->0->1
	asm volatile("msr ttbr0_el1, %0" :: "r"(ttbr0_save) : "memory");
	asm volatile("isb");
	asm volatile("tlbi vmalle1\n dsb nsh\n isb\n" ::: "memory");
	asm volatile("msr daif, %0" :: "r"(daif) : "memory");
	raw_local_irq_restore(flags);
	preempt_enable();
}

// --------------------------------------------------------------------------------------------------
static noinline long nop_work(long value){
	asm volatile("" : "+r"(value) :: "memory");
	return value;
}

static long smc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int count = (int)arg;
	int index = 0;
	struct arm_smccc_res res = { 0 };

	res.a0 = 0;
	if (cmd == SMC_DO) {
		for (index = 0; index < count; ++index) {
			arm_smccc_smc(SMCCC_VERSION_FID, 0, 0, 0, 0, 0, 0, 0, &res);
		}
		return (long)res.a0;
	} else if (cmd == SMC_NOP) {
		volatile long accumulator = 0;
		for (index = 0; index < count; ++index) {
			accumulator += nop_work(index);
		}
		return 0;
	} else if (cmd == OP_ICIALLU) {
		for (index = 0; index < count; ++index) {
			asm volatile("ic iallu\n dsb ish\n isb\n" ::: "memory");
		}
		return 0;
	} else if (cmd == OP_TLBI) {
		for (index = 0; index < count; ++index) {
			asm volatile("tlbi vmalle1\n dsb ish\n isb\n" ::: "memory");
		}
		return 0;
	} else if (cmd == OP_SCTLR) {
		unsigned long sctlr_value = 0;
		asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr_value));   // read current (M=1); rewrite same value
		for (index = 0; index < count; ++index) {
			asm volatile("msr sctlr_el1, %0\n isb\n" :: "r"(sctlr_value) : "memory");
		}
		return 0;
	} else if (cmd == OP_BARRIER) {
		for (index = 0; index < count; ++index) {
			asm volatile("dsb sy\n isb\n" ::: "memory");
		}
		return 0;
	} else if (cmd == OP_CFPRCTX) {
		unsigned long ttbr0 = 0;
		unsigned long asid = 0;
		unsigned long context = 0;
		// sweep plausible RCTX context operands so we can't miss a real flush by mis-encoding Xt:
		// {0, NS|EL0, NS|EL0|ASID, ASID, EL1, NS|EL1} -- covers EL0/EL1 x NS x current-ASID.
		unsigned long contexts[6] = { 0 };
		if (!g_have_specres) {
			return -EOPNOTSUPP;
		}
		asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
		asid = ttbr0 >> 48;
		contexts[0] = 0;
		contexts[1] = (1UL << 27);                 // NS, EL0
		contexts[2] = (1UL << 27) | asid;          // NS, EL0, current ASID
		contexts[3] = asid;
		contexts[4] = (1UL << 25);                 // EL1
		contexts[5] = (1UL << 27) | (1UL << 25);   // NS, EL1
		for (index = 0; index < 6; ++index) {
			context = contexts[index];
			// CFP RCTX, Xt == SYS #3, C7, C3, #4, Xt
			asm volatile("sys #3, c7, c3, #4, %0" :: "r"(context) : "memory");
		}
		asm volatile("dsb sy\n isb\n" ::: "memory");
		return 0;
	} else if (cmd == OP_WA1_FEAT) {
		// SMCCC_ARCH_FEATURES(ARCH_WORKAROUND_1): 0 = impl+needed, 1 = not needed, -1 = not supported
		arm_smccc_smc(SMCCC_ARCH_FEATURES, SMCCC_ARCH_WA1, 0, 0, 0, 0, 0, 0, &res);
		return (long)res.a0;
	} else if (cmd == OP_WA1_DO) {
		for (index = 0; index < count; ++index) {
			arm_smccc_smc(SMCCC_ARCH_WA1, 0, 0, 0, 0, 0, 0, 0, &res);
		}
		return 0;
	} else if (cmd == OP_MMUTOGGLE) {
		if (!g_ready) {
			return -EOPNOTSUPP;
		}
		do_mmu_toggle();
		return 0;
	}
	return -EINVAL;
}

static const struct file_operations smc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = smc_ioctl,
};
static struct miscdevice smc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "smc_probe",
	.fops = &smc_fops,
	.mode = 0666,
};

static int __init smc_init(void)
{
	u64 isar1 = 0;
	int ret = misc_register(&smc_dev);
	if (ret) {
		return ret;
	}
	asm volatile("mrs %0, id_aa64isar1_el1" : "=r"(isar1));   // SPECRES = bits [43:40]
	g_have_specres = ((isar1 >> 40) & 0xf) != 0;
	pr_info("smc_probe: FEAT_SPECRES (CFP/DVP/CPP RCTX) %s (ID_AA64ISAR1_EL1.SPECRES=%llu)\n",
		g_have_specres ? "present" : "absent", (isar1 >> 40) & 0xf);
	build_toggle();          // best-effort; ioctl returns -EOPNOTSUPP if this failed
	return 0;
}
static void __exit smc_exit(void)
{
	misc_deregister(&smc_dev);
	free_toggle();
}
module_init(smc_init);
module_exit(smc_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("controlled EL1-op issuer (incl. idmap MMU-toggle) for BTB flush characterization");
