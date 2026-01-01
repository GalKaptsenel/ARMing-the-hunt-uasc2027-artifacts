#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Globally toggle SCTLR_EL1.DSSBS (default PSTATE.SSBS on exception entry) on all CPUs");

/* dssbs=1 -> DSSBS=1: every exception entry defaults SSBS=1 => Spectre-v4 store-bypass ALLOWED
 * (mitigation OFF) system-wide. dssbs=0 -> restore mitigated default. Restored to 0 on unload. */
static int dssbs = 1;
module_param(dssbs, int, 0);

#define DSSBS_BIT (1ULL << 44)

static void set_dssbs(void *arg) {
    unsigned long enable = (unsigned long)arg;
    u64 sctlr = 0;
    asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    if (enable) {
        sctlr |= DSSBS_BIT;
    } else {
        sctlr &= ~DSSBS_BIT;
    }
    asm volatile("msr sctlr_el1, %0" :: "r"(sctlr));
    asm volatile("isb");
    /* also flip the CURRENT context's live PSTATE.SSBS (bit12 of the SSBS special reg S3_3_C4_C2_6)
     * so this cpu's in-flight EL1 runs unmitigated now */
    {
        u64 ssbs = 0;
        asm volatile("mrs %0, S3_3_C4_C2_6" : "=r"(ssbs));
        if (enable) {
            ssbs |= (1ULL << 12);
        } else {
            ssbs &= ~(1ULL << 12);
        }
        asm volatile("msr S3_3_C4_C2_6, %0" :: "r"(ssbs));
        asm volatile("isb");
    }
}

static u64 get_sctlr(void) {
    u64 sctlr = 0;
    asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    return sctlr;
}

static int __init dssbs_ctl_init(void) {
    pr_info("dssbs_ctl: SCTLR_EL1=%llx  DSSBS was %llu ; setting DSSBS=%d on all CPUs\n",
            get_sctlr(), (get_sctlr() >> 44) & 1, dssbs);
    on_each_cpu(set_dssbs, (void *)(unsigned long)dssbs, 1);
    pr_info("dssbs_ctl: now SCTLR_EL1=%llx  DSSBS=%llu\n", get_sctlr(), (get_sctlr() >> 44) & 1);
    return 0;
}

static void __exit dssbs_ctl_exit(void) {
    on_each_cpu(set_dssbs, (void *)0UL, 1);   /* restore DSSBS=0 (mitigated) on unload */
    pr_info("dssbs_ctl: restored DSSBS=0 on unload (SCTLR_EL1=%llx)\n", get_sctlr());
}
module_init(dssbs_ctl_init);
module_exit(dssbs_ctl_exit);
