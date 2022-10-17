#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/mman.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("lddlinan <00107082@163.com>");
MODULE_DESCRIPTION("ptrace extensions");


#define DEVICE_NAME "ptracexx"
#define CLASS_NAME "ptracexx"
static int major_number;
static struct class*  mClass  = NULL;
static struct device* mDevice = NULL;

enum {
    PTRACEXX_REMAP = 1,
};

typedef struct {
    int pid;
    unsigned long old_start, old_end;
    unsigned long new_start, new_end;
} RemapDataT;

typedef union {
    RemapDataT remap;
} IoctlDataT;

static long ptracexx_ioctl(struct file *_f, unsigned int cmd, unsigned long val) {
    struct task_struct *task;
    struct pid *pid;
    IoctlDataT data;
    unsigned long rc;
    int k;
    const char *user_ptr = (const char*) val;
    switch(cmd) {
        case PTRACEXX_REMAP:
            k = copy_from_user(&data, user_ptr, sizeof(data));
            if (k != 0) {
                printk("fail to copy from user, left %d/%ld\n", k, sizeof(data));
                return -1;
            }
            printk("ioctl remap for pid %d, [%lx->%lx) ==> [%lx->%lx)\n", data.remap.pid, data.remap.old_start, data.remap.old_end, data.remap.new_start, data.remap.new_end);
            pid = find_pid_ns(data.remap.pid, &init_pid_ns);
            if (pid == NULL) {
                printk("pid not found\n");
                return -1;
            }
            task = get_pid_task(pid, PIDTYPE_PID);
            if (task == NULL) {
                printk("task not found\n");
                return -1;
            }
            rc = mremap_task(task,
                    data.remap.old_start, data.remap.old_end-data.remap.old_start,
                    data.remap.new_end-data.remap.new_start,
                    MREMAP_FIXED|MREMAP_MAYMOVE, data.remap.new_start);
            if (IS_ERR((void*)rc)) {
                printk("remap failed: %ld\n", rc);
                return -1;
            }
            break;
        default:
            return -1;
    }
    return 0;
}
struct file_operations fops = {
    .unlocked_ioctl = ptracexx_ioctl,
    .compat_ioctl = ptracexx_ioctl
};

static int __init ptracexx_module_init(void) {
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number<0) return major_number;
    mClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(mClass)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(mClass);
    }
    mDevice = device_create(mClass, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(mDevice)) {
        class_destroy(mClass);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(mDevice);
    }
    return 0;
}

static void __exit ptracexx_module_exit(void) {
    device_destroy(mClass, MKDEV(major_number, 0));
    class_unregister(mClass);
    class_destroy(mClass);
    unregister_chrdev(major_number, DEVICE_NAME);
}


module_init(ptracexx_module_init);
module_exit(ptracexx_module_exit);
