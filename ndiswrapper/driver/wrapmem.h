#ifndef _WRAPMEM_H_

/* uncomment following line to get information about memory used by
 * both ndiswrapper and Windows driver by reading
 * /proc/net/ndiswrapper/debug; this will also show allocation
 * information in KERN_DEBUG when ndiswrapper module is unloaded,
 * which indicates if memory is being leaked */

//#define ALLOC_INFO 1

enum alloc_type { ALLOC_TYPE_ATOMIC, ALLOC_TYPE_NON_ATOMIC,
		  ALLOC_TYPE_VMALLOC, ALLOC_TYPE_MAX };

int wrapmem_init(void);
void wrapmem_exit(void);
void *slack_kmalloc(size_t size);
void slack_kfree(void *ptr);
struct net_device *wrap_alloc_etherdev(int sizeof_priv);
void wrap_free_netdev(struct net_device *dev);

#ifdef ALLOC_INFO
void *wrap_kmalloc(size_t size, gfp_t flags);
void wrap_kfree(const void *ptr);
void *wrap_vmalloc(unsigned long size);
void wrap_vfree(void *ptr);
int alloc_size(enum alloc_type type);

#ifndef _WRAPMEM_C_
#define kmalloc(size, flags) wrap_kmalloc(size, flags)
#define kfree(ptr) wrap_kfree(ptr)
#define vmalloc(size) wrap_vmalloc(size)
#define vfree(ptr) wrap_vfree(ptr)
#endif
#endif

#endif
