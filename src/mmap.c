// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — mmap.c
 * Simple shared ring (kernel-allocated via vzalloc) mmapped to user-space
 *
 * Notes:
 *  - This is optional; not used by ioctl fast-paths.
 *  - We choose vmalloc memory to avoid high-order allocation failures.
 *  - Mapping uses remap_vmalloc_range(); size must be page-aligned.
 */

#include "kpm.h"

#define IV_RING_PAGES_MIN   4u
#define IV_RING_PAGES_MAX   (1u << IV_RING_MAX_ORDER) /* from kpm.h */
#define IV_RING_DEFAULT_PG  8u

static const struct vm_operations_struct iv_ring_vm_ops;

int iv_mmap_init(struct iv_dev *iv)
{
    size_t pages = IV_RING_DEFAULT_PG;
    size_t bytes;

    if (!iv) return -EINVAL;

    if (pages < IV_RING_PAGES_MIN) pages = IV_RING_PAGES_MIN;
    if (pages > IV_RING_PAGES_MAX) pages = IV_RING_PAGES_MAX;

    bytes = pages * PAGE_SIZE;

    iv->ring_virt = vzalloc(bytes);
    if (!iv->ring_virt)
        return -ENOMEM;

    iv->ring_len = bytes;
    spin_lock_init(&iv->ring_lock);

    iv_pr_info("mmap ring allocated: %zu bytes (%zu pages)\n", bytes, pages);
    return 0;
}

void iv_mmap_fini(struct iv_dev *iv)
{
    if (!iv) return;
    if (iv->ring_virt) {
        /* zeroize before free for hygiene */
        iv_zeroize(iv->ring_virt, iv->ring_len);
        vfree(iv->ring_virt);
        iv->ring_virt = NULL;
        iv->ring_len = 0;
    }
}

static void iv_ring_vma_open(struct vm_area_struct *vma)
{
    iv_pr_dbg("mmap: VMA open (vm_start=%lx vm_end=%lx)\n",
              vma->vm_start, vma->vm_end);
}

static void iv_ring_vma_close(struct vm_area_struct *vma)
{
    iv_pr_dbg("mmap: VMA close (vm_start=%lx vm_end=%lx)\n",
              vma->vm_start, vma->vm_end);
}

static const struct vm_operations_struct iv_ring_vm_ops = {
    .open  = iv_ring_vma_open,
    .close = iv_ring_vma_close,
};

/*
 * Map the kernel ring buffer into user VMA.
 * User must mmap exactly iv->ring_len bytes, offset must be 0.
 */
int iv_mmap_file(struct file *filp, struct vm_area_struct *vma)
{
    struct iv_dev *iv = filp ? filp->private_data : NULL;
    size_t vma_len;

    if (!iv || !iv->ring_virt || iv->ring_len == 0)
        return -ENODEV;

    vma_len = vma->vm_end - vma->vm_start;

    if (vma->vm_pgoff != 0)
        return -EINVAL;

    if (vma_len != iv->ring_len)
        return -EINVAL;

    /* VMA hygiene */
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
#ifdef VM_IO
    vma->vm_flags |= VM_IO;
#endif

    if (remap_vmalloc_range(vma, iv->ring_virt, 0))
        return -EAGAIN;

    vma->vm_ops = &iv_ring_vm_ops;
    iv_ring_vma_open(vma);
    return 0;
}
