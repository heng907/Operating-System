#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/utsname.h>      // hostname, release
#include <linux/mm.h>
#include <linux/sysinfo.h>      // si_meminfo
#include <linux/cpumask.h>      // num_online_cpus, num_possible_cpus
#include <linux/timekeeping.h>  // ktime_get_boottime_seconds
#include <linux/sched.h>
#include <linux/sched/signal.h> // for_each_process

#define KFETCH_NUM_INFO 6

#define KFETCH_RELEASE   (1 << 0)
#define KFETCH_NUM_CPUS  (1 << 1)
#define KFETCH_CPU_MODEL (1 << 2)
#define KFETCH_MEM       (1 << 3)
#define KFETCH_UPTIME    (1 << 4)
#define KFETCH_NUM_PROCS (1 << 5)

#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

#define DEVICE_NAME "kfetch" // /dev/kfetch
#define KFETCH_BUF_SIZE 2048 // read

static int kfetch_major;
static struct class *kfetch_class;
static struct cdev kfetch_cdev;

static DEFINE_MUTEX(kfetch_mutex);       
static char *kfetch_buf;                 
static int info_mask = KFETCH_FULL_INFO; 

/* ===== kfetch_read() helper functions ===== */

/* hostname + kernel release */
static void get_uts(char *hostname, 
                    size_t hlen,
                    char *release, 
                    size_t rlen)
{
    strscpy(hostname, init_uts_ns.name.nodename, hlen);
    strscpy(release, init_uts_ns.name.release, rlen);
}

/* get CPU model */
static void get_cpu_model(char *model, size_t len)
{
    strscpy(model, init_uts_ns.name.machine, len);
}

/* get CPUs number: online / total */
static void get_cpu_nums(int *online, int *total)
{
    *online = num_online_cpus();
    *total  = num_possible_cpus();
}

/* get Memory infotmation: free / total (MB) */
static void get_meminfo_mb(unsigned long *free_mb,
                           unsigned long *total_mb)
{
    struct sysinfo i;

    si_meminfo(&i);

    *total_mb = (i.totalram * (unsigned long long)PAGE_SIZE) >> 20;
    *free_mb  = (i.freeram  * (unsigned long long)PAGE_SIZE) >> 20;
}

/* get Uptime in minutes */
static unsigned long get_uptime_minutes(void)
{
    u64 secs = ktime_get_boottime_seconds();
    return (unsigned long)(secs / 60);
}

/* get Process number */
static int get_num_procs(void)
{
    struct task_struct *p;
    int cnt = 0;

    rcu_read_lock();
    for_each_process(p) {
        if (p->pid == p->tgid)
            cnt++;
    }
    rcu_read_unlock();

    return cnt;
}

/* ========= file operations: open / release / write / read ========= */

/* ===== kfetch open ===== */
static int kfetch_open(struct inode *inode, struct file *file)
{
    // avoid race condition
    if (!mutex_trylock(&kfetch_mutex))
        return -EBUSY;
    return 0;
}

/* ===== kfetch release ===== */
static int kfetch_release(struct inode *inode, struct file *file)
{
    mutex_unlock(&kfetch_mutex);
    return 0;
}

/* ===== kfetch write ===== */
static ssize_t kfetch_write(struct file *filp,
                            const char __user *buffer,
                            size_t length,
                            loff_t *offset)
{
    int mask_info;

    if (length < sizeof(int))
        return -EINVAL;

    if (copy_from_user(&mask_info, buffer, sizeof(int))) {
        pr_alert("kfetch: Failed to copy mask from user\n");
        return -EFAULT;
    }

    info_mask = mask_info & KFETCH_FULL_INFO;

    return sizeof(int);
}

/* ===== kfetch read ===== */
static ssize_t kfetch_read(struct file *filp,
                           char __user *buffer,
                           size_t length,
                           loff_t *offset)
{
    size_t len = 0;

    if (*offset > 0)
        return 0;

    if (!kfetch_buf)
        return -ENOMEM;

    /* access information */

    char hostname[64];
    char release[64];
    char cpu_model[64];
    int online_cpus, total_cpus;
    unsigned long free_mb, total_mb;
    unsigned long uptime_min;
    int procs;

    get_uts(hostname, sizeof(hostname), release, sizeof(release));
    get_cpu_model(cpu_model, sizeof(cpu_model));
    get_cpu_nums(&online_cpus, &total_cpus);
    get_meminfo_mb(&free_mb, &total_mb);
    procs = get_num_procs();
    uptime_min = get_uptime_minutes();
    

    /* device info. */
    static char info_lines[16][128];
    int n_info = 0;

    scnprintf(info_lines[n_info], 
              sizeof(info_lines[n_info]),
              "%s", hostname);
    n_info++;

    {
        int hlen = strnlen(hostname, sizeof(hostname));
        int i;

        if (hlen >= sizeof(info_lines[n_info]))
            hlen = sizeof(info_lines[n_info]) - 1;

        for (i = 0; i < hlen; i++)
            info_lines[n_info][i] = '-';
        info_lines[n_info][hlen] = '\0';
        n_info++;
    }

    if (info_mask & KFETCH_RELEASE) {
        scnprintf(info_lines[n_info],
                  sizeof(info_lines[n_info]),
                  "Kernel: %s",
                  release);
        n_info++;
    }

    if (info_mask & KFETCH_CPU_MODEL) {
        scnprintf(info_lines[n_info], 
                  sizeof(info_lines[n_info]),
                  "CPU: %s", 
                  cpu_model);
        n_info++;
    }

    if (info_mask & KFETCH_NUM_CPUS) {
        scnprintf(info_lines[n_info], 
                  sizeof(info_lines[n_info]),
                  "CPUs: %d / %d", 
                  online_cpus, 
                  total_cpus);
        n_info++;
    }

    if (info_mask & KFETCH_MEM) {
        scnprintf(info_lines[n_info], 
                  sizeof(info_lines[n_info]),
                  "Mem: %lu MB / %lu MB", 
                  free_mb, 
                  total_mb);
        n_info++;
    }

    if (info_mask & KFETCH_NUM_PROCS) {
        scnprintf(info_lines[n_info], 
                  sizeof(info_lines[n_info]),
                  "Procs: %d", 
                  procs);
        n_info++;
    }

    if (info_mask & KFETCH_UPTIME) {
        scnprintf(info_lines[n_info], 
                  sizeof(info_lines[n_info]),
                  "Uptime: %lu mins", 
                  uptime_min);
        n_info++;
    }


    /* combine logo and info. */

    static const char *logo[] = {
        "        .-.         ",
        "       (.. |        ",
        "       <>  |        ",
        "      / --- \\      ",
        "     ( |   | )      ",
        "   |\\\\_)__(_//|   ",
        "  <__)------(__>    ",
    };
    
    
    const int LOGO_LINES = ARRAY_SIZE(logo);

    int max_lines = (LOGO_LINES > n_info) ? LOGO_LINES : n_info;
    // int i;
    int max_logo_width = 0;

    for (int i = 0; i < LOGO_LINES; i++) {
        int w = strlen(logo[i]);
        if (w > max_logo_width)
            max_logo_width = w;
    }
    len = 0;

    for (int i = 0; i < max_lines && len < KFETCH_BUF_SIZE - 1; i++) {

        /* Left side (logo), width fixed to max_logo_width */
        if (i < LOGO_LINES) {
            len += scnprintf(kfetch_buf + len,
                            KFETCH_BUF_SIZE - len,
                            "%-*s", 
                            max_logo_width, 
                            logo[i]);
        } else {
            len += scnprintf(kfetch_buf + len,
                            KFETCH_BUF_SIZE - len,
                            "%*s", 
                            max_logo_width, 
                            "");
        }

        /* Right side info */
        if (i < n_info) {
            len += scnprintf(kfetch_buf + len,
                            KFETCH_BUF_SIZE - len,
                            "  %s", 
                            info_lines[i]);
        }

        len += scnprintf(kfetch_buf + len,
                        KFETCH_BUF_SIZE - len,
                        "\n");
    }

    /* copy to user */

    if (len > length)
        len = length;

    if (copy_to_user(buffer, kfetch_buf, len)) {
        pr_alert("kfetch: Failed to copy data to user\n");
        return -EFAULT;
    }

    *offset += len;
    return len;
}

/* ========= file_operations ========= */

static const struct file_operations kfetch_ops = {
    .owner   = THIS_MODULE,
    .read    = kfetch_read,
    .write   = kfetch_write,
    .open    = kfetch_open,
    .release = kfetch_release,
};

/* ========= module init / exit ========= */

static int __init kfetch_init(void)
{
    dev_t dev;
    int ret;

    kfetch_buf = kmalloc(KFETCH_BUF_SIZE, GFP_KERNEL);
    if (!kfetch_buf)
        return -ENOMEM;

    /* dynamic access major/minor */
    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("kfetch: alloc_chrdev_region failed\n");
        kfree(kfetch_buf);
        return ret;
    }
    kfetch_major = MAJOR(dev);

    cdev_init(&kfetch_cdev, &kfetch_ops);
    kfetch_cdev.owner = THIS_MODULE;

    ret = cdev_add(&kfetch_cdev, dev, 1);
    if (ret < 0) {
        pr_err("kfetch: cdev_add failed\n");
        unregister_chrdev_region(dev, 1);
        kfree(kfetch_buf);
        return ret;
    }

    kfetch_class = class_create("kfetch_class");
    if (IS_ERR(kfetch_class)) {
        pr_err("kfetch: class_create failed\n");
        cdev_del(&kfetch_cdev);
        unregister_chrdev_region(dev, 1);
        kfree(kfetch_buf);
        return PTR_ERR(kfetch_class);
    }

    if (!device_create(kfetch_class, NULL, dev, NULL, DEVICE_NAME)) {
        pr_err("kfetch: device_create failed\n");
        class_destroy(kfetch_class);
        cdev_del(&kfetch_cdev);
        unregister_chrdev_region(dev, 1);
        kfree(kfetch_buf);
        return -EINVAL;
    }

    pr_info("kfetch: module loaded, /dev/%s (major=%d)\n",
            DEVICE_NAME, kfetch_major);
    return 0;
}

static void __exit kfetch_exit(void)
{
    dev_t dev = MKDEV(kfetch_major, 0);

    device_destroy(kfetch_class, dev);
    class_destroy(kfetch_class);
    cdev_del(&kfetch_cdev);
    unregister_chrdev_region(dev, 1);

    kfree(kfetch_buf);

    pr_info("kfetch: module unloaded\n");
}

module_init(kfetch_init);
module_exit(kfetch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("111550129");
MODULE_DESCRIPTION("kfetch_mod - System Information Fetching Kernel Module");
