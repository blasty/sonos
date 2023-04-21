#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/uaccess.h>

// this messy parameterization is because I had issues when
// resolving these kernel symbols automagically
#define ADDR_PARAM(name) \
    static unsigned long addr_##name; \
    module_param_named(name, addr_##name, ulong, 0);

ADDR_PARAM(sonos_blob_encdec)
ADDR_PARAM(kmalloc)
ADDR_PARAM(kfree)
ADDR_PARAM(flush_dcache_area)

#define INPUT_A_BASE 0xffffffc0050fe000
#define OUTPUT_A_BASE 0xffffffc0050ff000
#define INPUT_B_BASE 0xffffffc005000000
#define OUTPUT_B_BASE 0xffffffc005040000
#define STORAGE_BASE 0xffffffc005080000
#define HAXBUF_BASE 0xffffffc006000000

#define SHARED_BUFFER_SIZE (1024 * 128)
#define HAXBUF_SIZE (1024 * 1024)

static struct dentry *debugfs_root = NULL;
static uint8_t g_dec_input_buf[SHARED_BUFFER_SIZE];
static uint8_t g_dec_output_buf[SHARED_BUFFER_SIZE];
static uint8_t *g_haxbuf;
static uint64_t g_rv;

typedef void *(*sonos_blob_encdec_f)(bool, uint8_t *, size_t, uint8_t *, size_t *, char *, size_t);
typedef void *(*_kmalloc_f)(size_t size, gfp_t flags);
typedef void *(*_kfree_f)(void *addr);
typedef void (*_flush_dcache_area_f)(void *addr, size_t len);

static sonos_blob_encdec_f sonos_blob_encdec;
static _kmalloc_f kkmalloc;
static _kfree_f kkfree;
static _flush_dcache_area_f _flush_dcache_area;

static noinline long smc_exec(uint64_t function_id, uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    register long x0 asm("x0") = function_id;
    register long x1 asm("x1") = arg0;
    register long x2 asm("x2") = arg1;
    register long x3 asm("x3") = arg2;
    asm volatile(
        __asmeq("%0", "x0")
            __asmeq("%1", "x1")
                __asmeq("%2", "x2")
                    __asmeq("%3", "x3") "smc #0\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3));

    return x0;
}

static ssize_t smc_read_file(
    struct file *file, char __user *userbuf, size_t count, loff_t *ppos)
{
    if (count != 8)
    {
        return -EINVAL;
    }

    if (*ppos != 0)
    {
        return -EINVAL;
    }

    if (copy_to_user(userbuf, &g_rv, 8))
    {
        return -EFAULT;
    }

    return 8;
}

static ssize_t smc_write_file(
    struct file *file, const char __user *userbuf, size_t count, loff_t *ppos)
{
    char buf[80];
    uint64_t arg0, arg1, arg2, arg3;

    count = min_t(size_t, count, (sizeof(buf) - 1));
    if (copy_from_user(buf, userbuf, count))
        return -EFAULT;

    buf[count] = 0;

    sscanf(buf, "%llx %llx %llx %llx", &arg0, &arg1, &arg2, &arg3);

    g_rv = smc_exec(arg0, arg1, arg2, arg3);

    printk(KERN_ALERT "hax: SMC call %llx returns: %llx\n", arg0, g_rv);

    return count;
}

static ssize_t shared_write(uint8_t *base, struct file *file, const char __user *userbuf, size_t count, loff_t *ppos)
{
    if (*ppos >= SHARED_BUFFER_SIZE)
    {
        count = 0;
        goto out;
    }

    if (*ppos + count > SHARED_BUFFER_SIZE)
    {
        count = SHARED_BUFFER_SIZE - *ppos;
    }

    if (copy_from_user(base + *ppos, userbuf, count))
    {
        return -EFAULT;
    }
    *ppos += count;

out:
    return count;
}

static ssize_t shared_read(uint8_t *base, struct file *file, char __user *userbuf, size_t count, loff_t *ppos)
{
    if (*ppos >= SHARED_BUFFER_SIZE)
    {
        count = 0;
        goto out;
    }

    if (*ppos + count > SHARED_BUFFER_SIZE)
    {
        count = SHARED_BUFFER_SIZE - *ppos;
    }

    if (copy_to_user(userbuf, base + *ppos, count))
    {
        return -EFAULT;
    }
    *ppos += count;

out:
    return count;
}

#define GEN_SHARED_READ(NAME, BASE)                                          \
    static ssize_t shared_##NAME##_read(                                     \
        struct file *file, char __user *userbuf, size_t count, loff_t *ppos) \
    {                                                                        \
        return shared_read((uint8_t *)(BASE), file, userbuf, count, ppos);   \
    }

#define GEN_SHARED_WRITE(NAME, BASE)                                           \
    static ssize_t shared_##NAME##_write(                                      \
        struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
    {                                                                          \
        return shared_write((uint8_t *)BASE, file, buf, count, ppos);          \
    }

#define GEN_FILE_OPS(NAME)                                           \
    static const struct file_operations shared_##NAME##_file_ops = { \
        .owner = THIS_MODULE,                                        \
        .open = simple_open,                                         \
        .write = shared_##NAME##_write,                              \
        .read = shared_##NAME##_read,                                \
    };

#define GEN_NODE(NAME, BASE)     \
    GEN_SHARED_READ(NAME, BASE)  \
    GEN_SHARED_WRITE(NAME, BASE) \
    GEN_FILE_OPS(NAME)

GEN_NODE(input_a, INPUT_A_BASE)
GEN_NODE(output_a, OUTPUT_A_BASE)
GEN_NODE(input_b, INPUT_B_BASE)
GEN_NODE(output_b, OUTPUT_B_BASE)
GEN_NODE(storage, STORAGE_BASE)
GEN_NODE(haxbuf, HAXBUF_BASE)
GEN_NODE(dec_input, HAXBUF_BASE)
GEN_NODE(dec_output, HAXBUF_BASE)

static ssize_t dec_trigger_write(struct file *file, const char __user *userbuf, size_t count, loff_t *ppos)
{
    uint32_t *p32 = (uint32_t *)(g_dec_input_buf);
    size_t pOutLen = SHARED_BUFFER_SIZE;

    uint32_t buf_len = p32[0];
    uint32_t modifier_len = p32[1];

    uint8_t *encbuf = g_dec_input_buf + 8 + 8;
    char *modifier = (char *)(g_dec_input_buf + 8);

    printk(KERN_ALERT "starting decrypt of size 0x%08x\n", buf_len);
    printk(KERN_ALERT "modifier is '%s' (len 0x%x)\n", modifier, modifier_len);

    memset(g_dec_output_buf, 0, SHARED_BUFFER_SIZE);

    if (sonos_blob_encdec != (sonos_blob_encdec_f)0)
    {
        if (sonos_blob_encdec(
                false,
                encbuf, buf_len, g_dec_output_buf, &pOutLen,
                modifier, modifier_len) != 0)
        {
            printk(KERN_ALERT "sonos_blob_encdec failed.\n");
        }
        else
        {
            printk(KERN_ALERT "sonos_blob_encdec OK. pOutLen = 0x%lx\n", pOutLen);
        }
    }
    else
    {
        memset(g_dec_output_buf, 0xAA, 0x40);
    }

    return count;
}

static const struct file_operations smc_file_ops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .write = smc_write_file,
    .read = smc_read_file,
};

static const struct file_operations dec_trigger_file_ops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .write = dec_trigger_write,
};

static int __init hax_init(void)
{

    sonos_blob_encdec = (sonos_blob_encdec_f)addr_sonos_blob_encdec;
    kkmalloc = (_kmalloc_f)addr_kmalloc;
    kkfree = (_kfree_f)addr_kfree;
    _flush_dcache_area = (_flush_dcache_area_f)addr_flush_dcache_area;

    printk(KERN_ALERT "hax: HELLO!\n");
    printk(KERN_ALERT "hax: sonos_blob_encdec = 0x%p\n", sonos_blob_encdec);

    memset(g_dec_input_buf, 0, SHARED_BUFFER_SIZE);
    memset(g_dec_output_buf, 0, SHARED_BUFFER_SIZE);

    g_haxbuf = kkmalloc(HAXBUF_SIZE, GFP_KERNEL);

    debugfs_root = debugfs_create_dir("hax", NULL);
    if (IS_ERR(debugfs_root) || !debugfs_root)
    {
        pr_warn("hax: failed to create hax debugfs directory\n");
        debugfs_root = NULL;
        return -1;
    }

#define REGISTER_NODE(NAME)                                          \
    if (!debugfs_create_file(                                        \
            #NAME, S_IFREG | S_IRUGO, debugfs_root,                  \
            NULL, &NAME##_file_ops))                                 \
    {                                                                \
        printk(KERN_ALERT "hax: failed to create %s file\n", #NAME); \
        return -1;                                                   \
    }

#define REGISTER_NODE_SIZE(NAME, SIZE)                               \
    if (!debugfs_create_file_size(                                   \
            #NAME, S_IFREG | S_IRUGO, debugfs_root,                  \
            NULL, &shared_##NAME##_file_ops, SIZE))                  \
    {                                                                \
        printk(KERN_ALERT "hax: failed to create %s file\n", #NAME); \
        return -1;                                                   \
    }

    REGISTER_NODE(smc)
    REGISTER_NODE(dec_trigger)

    REGISTER_NODE_SIZE(input_a, SHARED_BUFFER_SIZE)
    REGISTER_NODE_SIZE(output_a, SHARED_BUFFER_SIZE)
    REGISTER_NODE_SIZE(input_b, SHARED_BUFFER_SIZE)
    REGISTER_NODE_SIZE(output_b, SHARED_BUFFER_SIZE)
    REGISTER_NODE_SIZE(storage, SHARED_BUFFER_SIZE)
    REGISTER_NODE_SIZE(haxbuf, SHARED_BUFFER_SIZE)
    REGISTER_NODE_SIZE(dec_input, SHARED_BUFFER_SIZE)
    REGISTER_NODE_SIZE(dec_output, SHARED_BUFFER_SIZE)

    printk(KERN_ALERT "hax: registered all debugfs nodes!\n");

    return 0;
}

static void __exit hax_exit(void)
{
    printk(KERN_ALERT "hax: exiting...\n");
    if (debugfs_root)
        debugfs_remove_recursive(debugfs_root);
    if (g_haxbuf != (uint8_t *)0)
    {
        kkfree(g_haxbuf);
    }
}

module_init(hax_init);
module_exit(hax_exit);

MODULE_DESCRIPTION("hax module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("blasty <peter@haxx.in>");
