#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/cpu.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Research");
MODULE_DESCRIPTION("Full raw PMU access for EL0 (ARMv8-A)");

static void pmu_enable_cpu(void *info) {
    u64 value = 0;
    (void)info;

    /* PMUSERENR_EL0: let EL0 read the counters/cycles and use the software increment. */
    asm volatile("mrs %0, pmuserenr_el0" : "=r"(value));
    value |= (1 << 0);   /* EN: EL0 counter/type register read   */
    value |= (1 << 1);   /* SW: EL0 software increment           */
    value |= (1 << 2);   /* CR: EL0 cycle-counter read           */
    value |= (1 << 3);   /* ER: EL0 event-counter read           */
    asm volatile("msr pmuserenr_el0, %0" :: "r"(value));

    /* PMCR_EL0: reset the cycle (C) and event (P) counters, leave the PMU disabled (E=0). */
    asm volatile("mrs %0, pmcr_el0" : "=r"(value));
    value |= (1 << 1) | (1 << 2);
    value &= ~(1ULL << 0);
    asm volatile("msr pmcr_el0, %0" :: "r"(value));

    asm volatile("msr pmovsclr_el0, %0" :: "r"(0xffffffff));    /* clear overflow flags   */
    asm volatile("msr pmcntenset_el0, %0" :: "r"(0xffffffff));  /* enable all counters    */

    /* PMCR_EL0.E: switch the PMU on. */
    asm volatile("mrs %0, pmcr_el0" : "=r"(value));
    value |= (1 << 0);
    asm volatile("msr pmcr_el0, %0" :: "r"(value));

    isb();
}

static void pmu_disable_cpu(void *info) {
    u64 value = 0;
    (void)info;

    asm volatile("mrs %0, pmcr_el0" : "=r"(value));
    value &= ~(1 << 0);  // disable PMU
    asm volatile("msr pmcr_el0, %0" :: "r"(value));

    value = 0;
    asm volatile("msr pmuserenr_el0, %0" :: "r"(value));
}

static int __init raw_pmu_init(void) {
    pr_info("[raw_pmu] Enabling full EL0 raw PMU access\n");
    on_each_cpu(pmu_enable_cpu, NULL, 1);
    return 0;
}

static void __exit raw_pmu_exit(void) {
    pr_info("[raw_pmu] Disabling PMU access\n");
    on_each_cpu(pmu_disable_cpu, NULL, 1);
}

module_init(raw_pmu_init);
module_exit(raw_pmu_exit);
