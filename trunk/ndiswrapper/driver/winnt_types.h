/*
 *  Copyright (C) 2003-2004 Pontus Fuchs, Giridhar Pemmasani
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#ifndef WINNT_TYPES_H
#define WINNT_TYPES_H

#define TRUE 1
#define FALSE 0

#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2

#define STATUS_WAIT_0			0
#define STATUS_SUCCESS                  0
#define STATUS_ALERTED                  0x00000101
#define STATUS_TIMEOUT                  0x00000102
#define STATUS_PENDING                  0x00000103
#define STATUS_FAILURE                  0xC0000001
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_MORE_PROCESSING_REQUIRED 0xC0000016
#define STATUS_BUFFER_TOO_SMALL         0xC0000023
#define STATUS_RESOURCES                0xC000009A
#define STATUS_NOT_SUPPORTED            0xC00000BB
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_INVALID_PARAMETER_2      0xC00000F0
#define STATUS_CANCELLED                0xC0000120

#define IS_PENDING                      0x01
#define CALL_ON_CANCEL                  0x20
#define CALL_ON_SUCCESS                 0x40
#define CALL_ON_ERROR                   0x80

#define IRP_MJ_DEVICE_CONTROL           0x0E
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0F
#define IRP_MJ_MAXIMUM_FUNCTION           0x1b

#define THREAD_WAIT_OBJECTS 3
#define MAX_WAIT_OBJECTS 64

#define NOTIFICATION_TIMER 1

#define LOW_PRIORITY 		1
#define LOW_REALTIME_PRIORITY	16
#define HIGH_PRIORITY		32
#define MAXIMUM_PRIORITY	32

#ifdef CONFIG_X86_64
#define STDCALL
#define _FASTCALL
#define FASTCALL_DECL_1(decl1) decl1
#define FASTCALL_DECL_2(decl1,decl2) decl1, decl2
#define FASTCALL_DECL_3(decl1,decl2,decl3) decl1, decl2, decl3
#define FASTCALL_ARGS_1(arg1) arg1
#define FASTCALL_ARGS_2(arg1,arg2) arg1, arg2
#define FASTCALL_ARGS_3(arg1,arg2,arg3) arg1, arg2, arg3
#else 
#define STDCALL __attribute__((__stdcall__, regparm(0)))
#define _FASTCALL __attribute__((__stdcall__)) __attribute__((regparm (3)))
#define FASTCALL_DECL_1(decl1) int _dummy1_, int _dummy2_, decl1
#define FASTCALL_DECL_2(decl1,decl2) int _dummy1_, decl2, decl1
#define FASTCALL_DECL_3(decl1,decl2,decl3) int _dummy1_, decl2, decl1, decl3
#define FASTCALL_ARGS_1(arg1) 0, 0, arg1
#define FASTCALL_ARGS_2(arg1,arg2) 0, arg2, arg1
#define FASTCALL_ARGS_3(arg1,arg2,arg3) 0, arg2, arg1, arg3
#endif

#define NOREGPARM __attribute__((regparm(0)))
#define packed __attribute__((packed))

typedef __u8	BOOLEAN;
typedef __u8	BYTE;
typedef __u8	*LPBYTE;
typedef __s8	CHAR;
typedef __u8	UCHAR;
typedef __s16	SHORT;
typedef __u16	USHORT;
typedef __u16	WORD;
typedef __s32	INT;
typedef __u32	UINT;
typedef __u32	DWORD;
typedef __u32	LONG;
typedef __u32	ULONG;
typedef __u64	ULONGLONG;
typedef __u64	ULONGULONG;

typedef CHAR CCHAR;
typedef size_t SIZE_T;
typedef SHORT wchar_t;
typedef SHORT CSHORT;
typedef long long LARGE_INTEGER;

typedef LONG NTSTATUS;

typedef LONG KPRIORITY;
typedef INT NT_STATUS;
typedef LARGE_INTEGER	PHYSICAL_ADDRESS;
typedef UCHAR KIRQL;
typedef CHAR KPROCESSOR_MODE;

#ifdef CONFIG_X86_64
typedef __u64 ULONG_PTR;
#else
typedef __u32 ULONG_PTR;
#endif

typedef ULONG_PTR	KAFFINITY;

struct ansi_string {
	USHORT len;
	USHORT buflen;
	char *buf;
};

struct unicode_string {
	USHORT len;
	USHORT buflen;
	wchar_t *buf;
};

struct slist_entry {
	struct slist_entry *next;
};

union slist_head {
	ULONGLONG align;
	struct {
		struct slist_entry  *next;
		USHORT depth;
		USHORT sequence;
	} list;
};

struct list_entry {
	struct list_entry *fwd_link;
	struct list_entry *bwd_link;
};

struct dispatch_header {
	UCHAR type;
	UCHAR absolute;
	UCHAR size;
	UCHAR inserted;
	LONG signal_state;
	struct list_head wait_list_head;
};

struct kevent {
	struct dispatch_header header;
};

/* KSPIN_LOCK is typedef to ULONG_PTR, where ULONG_PTR is 32-bit
 * 32-bit platforms, 64-bit on 64 bit platforms; it is NOT pointer to
 * unsigned long  */
/* spinlock_t is 32-bits, provided CONFIG_DEBUG_SPINLOCK is disabled;
 * so for x86 32-bits, we can safely typedef KSPIN_LOCK to
 * spinlock_t */

#ifdef CONFIG_DEBUG_SPINLOCK
struct wrap_spinlock {
	spinlock_t spinlock;
	KIRQL use_bh;
};
typedef struct wrap_spinlock *KSPIN_LOCK;
#define WRAP_SPINLOCK(lock) &((lock)->spinlock)
#define K_SPINLOCK(lock) &((*lock)->spinlock)

#else

typedef union {
	spinlock_t spinlock;
	ULONG_PTR ntoslock;
} KSPIN_LOCK;
struct wrap_spinlock {
	KSPIN_LOCK klock;
	KIRQL use_bh;
};

#define WRAP_SPINLOCK(lock) &((lock)->klock.spinlock)
#define K_SPINLOCK(lock) &(lock)->spinlock
#endif

struct kdpc {
	SHORT type;
	UCHAR number;
	UCHAR importance;
	struct list_entry dpc_list_entry;

	void *func;
	void *ctx;
	void *arg1;
	void *arg2;
	KSPIN_LOCK lock;
};

enum pool_type {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
};

enum memory_caching_type {
	MM_NON_CACHED = FALSE,
	MM_CACHED = TRUE,
	MM_WRITE_COMBINED = 2,
	MM_HARDWARE_COHERENT_CACHED,
	MM_NON_CACHED_UNORDERED,
	MM_USWC_CACHED,
	MM_MAXIMUM_CACHE_TYPE
};

struct mdl {
	struct mdl* next;
	CSHORT size;
	CSHORT mdlflags;
	void *process;
	void *mappedsystemva;
	void *startva;
	ULONG bytecount;
	ULONG byteoffset;
};

#define MmGetMdlBaseVa(mdl) ((mdl)->startva)
#define MmGetMdlByteCount(mdl) ((mdl)->bytecount)
#define MmGetMdlVirtualAddress(mdl) ((void *)((char *)(mdl)->startva +	\
					      (mdl)->byteoffset))
#define MmGetMdlByteOffset(mdl) ((mdl)->byteoffset)


struct device_queue_entry {
	struct list_entry list_entry;
	ULONG sort_key;
	BOOLEAN inserted;
};

struct wait_ctx_block {
	struct device_queue_entry wait_queue_entry;
	void *dev_routine;
	void *dev_ctx;
	ULONG map_reg_count;
	void *current_irp;
	void *buffer_chaining_dpc;
};

struct kdevice_queue {
	USHORT type;
	USHORT size;
	struct list_entry devlist_head;
	KSPIN_LOCK lock;
	BOOLEAN busy;
};

struct kdpc;
struct irp;

struct device_object {
	SHORT type;
	USHORT size;
	LONG ref_count;
	void *drv_obj;
	struct device_object *next_dev;
	void *attached_dev;
	struct irp *current_irp;
	void *io_timer;
	ULONG flags;
	ULONG characteristics;
	void *vpb;
	void *dev_ext;
	BYTE stack_size;
	union {
		struct list_entry list_entry;
		struct wait_ctx_block wcb;
	} queue;
	ULONG align_req;
	struct kdevice_queue dev_queue;
	struct kdpc dpc;
	UINT active_threads;
	void *security_desc;
	struct kevent dev_lock;
	USHORT sector_size;
	USHORT spare;
	void *dev_obj_ext;
	void *reserved;

	/* ndiswrapper-specific data */
	union {
		struct usb_device *usb;
	} device;
	void *handle;
};

struct io_status_block {
	NT_STATUS status;
	ULONG status_info;
};

#ifdef CONFIG_X86_64
#define POINTER_ALIGNMENT
#else
#define POINTER_ALIGNMENT __attribute__((aligned(8)))
#endif

#ifndef CONFIG_X86_64
#pragma pack(push,4)
#endif
struct io_stack_location {
	UCHAR major_fn;
	UCHAR minor_fn;
	UCHAR flags;
	UCHAR control;
	union {
		struct {
			void *security_context;
			ULONG options;
			USHORT POINTER_ALIGNMENT file_attributes;
			USHORT share_access;
			ULONG POINTER_ALIGNMENT ea_length;
		} create;
		struct {
			ULONG length;
			ULONG POINTER_ALIGNMENT key;
			LARGE_INTEGER byte_offset;
		} read;
		/* FIXME: this structure is not complete */
		struct {
			ULONG output_buf_len;
			ULONG input_buf_len; /*align to pointer size*/
			ULONG code; /*align to pointer size*/
			void *type3_input_buf;
		} ioctl;
		struct {
			void *arg1;
			void *arg2;
			void *arg3;
			void *arg4;
		} generic;
	} params;
	struct device_object *dev_obj;
	void *file_obj;
	ULONG (*completion_handler)(struct device_object *,
				    struct irp *, void *) STDCALL;
	void *handler_arg;
};
#ifndef CONFIG_X86_64
#pragma pack(pop)
#endif

struct kapc {
	CSHORT type;
	CSHORT size;
	ULONG spare0;
	struct kthread *thread;
	struct list_entry apc_list_entry;
	void *kernele_routine;
	void *rundown_routine;
	void *normal_routine;
	void *normal_context;
	void *sys_arg1;
	void *sys_arg2;
	CCHAR apc_state_index;
	KPROCESSOR_MODE apc_mode;
	BOOLEAN inserted;
};

struct kdevice_queue_entry {
	struct list_entry dev_list_entry;
	ULONG sort_key;
	BOOLEAN inserted;
};

enum irp_work_type {
	IRP_WORK_NONE,
	IRP_WORK_COMPLETE,
	IRP_WORK_CANCEL,
};

struct irp {
	SHORT type;
	USHORT size;
	struct mdl *mdl;
	ULONG flags;
	union {
		struct irp *master_irp;
		void *sys_buf;
	} associated_irp;

	struct list_entry thread_list_entry;

	struct io_status_block io_status;
	KPROCESSOR_MODE requestor_mode;
	BOOLEAN pending_returned;
	CHAR stack_size;
	CHAR stack_pos;
	BOOLEAN cancel;
	KIRQL cancel_irql;

	CCHAR apc_env;
	UCHAR alloc_flags;

	struct io_status_block *user_status;
	struct kevent *user_event;

	union {
		struct {
			void *user_apc_routine;
			void *user_apc_context;
		} async_params;
		LARGE_INTEGER alloc_size;
	} overlay;

	void (*cancel_routine)(struct device_object *, struct irp *) STDCALL;
	void *user_buf;

	union {
		struct {
			union {
				struct kdevice_queue_entry dev_q_entry;
				struct {
					void *driver_context[4];
				} context;
			} dev_q;
			void *thread;
			char *aux_buf;
			struct {
				struct list_entry list_entry;
				union {
					struct io_stack_location *
					current_stack_location;
					ULONG packet_type;
				} packet;
			} packet_list;
			void *file_object;
		} overlay;
		struct kapc apc;
		void *completion_key;
	} tail;

	/* ndiswrapper extension */
	enum irp_work_type irp_work_type;
	struct list_head completed_list;
	struct list_head cancel_list;
};

#define IRP_CUR_STACK_LOC(irp)						\
	(irp)->tail.overlay.packet_list.packet.current_stack_location
#define IRP_DRIVER_CONTEXT(irp)					\
	(irp)->tail.overlay.dev_q.context.driver_context

enum nt_obj_type {
	NT_OBJ_EVENT,
	NT_OBJ_MUTEX,
	NT_OBJ_THREAD,
	NT_OBJ_TIMER,
};

struct ktimer {
	struct dispatch_header dispatch_header;
	ULONGLONG due_time;
	struct list_entry timer_list;
	/* the space for kdpc is used for wrapper timer */
	/* struct kdpc *kdpc; */
	struct wrapper_timer *wrapper_timer;
	LONG period;
};

struct kmutex {
	struct dispatch_header dispatch_header;
	union {
		struct list_entry list_entry;
		UINT count;
	} u;
	void *owner_thread;
	BOOLEAN abandoned;
	BOOLEAN apc_disable;
};

enum work_queue_type {
	CriticalWorkQueue,
	DelayedWorkQueue,
	HyperCriticalWorkQueue,
	MaximumWorkQueue
};

enum wait_type {
	WaitAll,
	WaitAny
};

struct wait_block {
	struct list_entry list_entry;
	void *thread;
	struct dispatch_header *object;
	struct wait_block *next;
	USHORT wait_key;
	USHORT wait_type;
};

enum event_type {
	NotificationEvent,
	SynchronizationEvent
};

enum mm_page_priority {
	LowPagePriority,
	NormalPagePriority = 16,
	HighPagePriority = 32
};

enum kinterrupt_mode {
	LevelSensitive,
	Latched
};

enum ntos_wait_reason {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel,
	MaximumWaitReason
};

typedef enum ntos_wait_reason KWAIT_REASON;

typedef STDCALL void *LOOKASIDE_ALLOC_FUNC(enum pool_type pool_type,
					   SIZE_T size, ULONG tag);
typedef STDCALL void LOOKASIDE_FREE_FUNC(void *);

struct npaged_lookaside_list {
	union slist_head head;
	USHORT depth;
	USHORT maxdepth;
	ULONG totalallocs;
	ULONG allocmisses;
	ULONG totalfrees;
	ULONG freemisses;
	enum pool_type pool_type;
	ULONG tag;
	ULONG size;
	LOOKASIDE_ALLOC_FUNC *alloc_func;
	LOOKASIDE_FREE_FUNC *free_func;
	struct list_entry listent;
	ULONG lasttotallocs;
	ULONG lastallocmisses;
	ULONG pad[2];
	KSPIN_LOCK obsolete;
};

enum device_registry_property {
	DevicePropertyDeviceDescription,
	DevicePropertyHardwareID,
	DevicePropertyCompatibleIDs,
	DevicePropertyBootConfiguration,
	DevicePropertyBootConfigurationTranslated,
	DevicePropertyClassName,
	DevicePropertyClassGuid,
	DevicePropertyDriverKeyName,
	DevicePropertyManufacturer,
	DevicePropertyFriendlyName,
	DevicePropertyLocationInformation,
	DevicePropertyPhysicalDeviceObjectName,
	DevicePropertyBusTypeGuid,
	DevicePropertyLegacyBusType,
	DevicePropertyBusNumber,
	DevicePropertyEnumeratorName,
	DevicePropertyAddress,
	DevicePropertyUINumber,
	DevicePropertyInstallState,
	DevicePropertyRemovalPolicy
};

enum trace_information_class {
	TraceIdClass,
	TraceHandleClass,
	TraceEnableFlagsClass,
	TraceEnableLevelClass,
	GlobalLoggerHandleClass,
	EventLoggerHandleClass,
	AllLoggerHandlesClass,
	TraceHandleByNameClass
};

#endif /* WINNT_TYPES_H */
