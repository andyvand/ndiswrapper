/*
 *  Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
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
#define STATUS_ACCESS_DENIED            0xC0000022
#define STATUS_BUFFER_TOO_SMALL         0xC0000023
#define STATUS_RESOURCES                0xC000009A
#define STATUS_NOT_SUPPORTED            0xC00000BB
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_INSUFFICIENT_RESOURCES	0xC000009A
#define STATUS_INVALID_PARAMETER_2      0xC00000F0
#define STATUS_CANCELLED                0xC0000120

#define IS_PENDING                      0x01
#define CALL_ON_CANCEL                  0x20
#define CALL_ON_SUCCESS                 0x40
#define CALL_ON_ERROR                   0x80

#define IRP_MJ_CREATE			0x0
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

typedef u8	BOOLEAN;
typedef u8	BYTE;
typedef u8	*LPBYTE;
typedef s8	CHAR;
typedef u8	UCHAR;
typedef s16	SHORT;
typedef u16	USHORT;
typedef u16	WORD;
typedef s32	INT;
typedef u32	UINT;
typedef u32	DWORD;
typedef u32	LONG;
typedef u32	ULONG;
typedef s64	LONGLONG;
typedef u64	ULONGLONG;
typedef u64	ULONGULONG;

typedef CHAR CCHAR;
typedef SHORT wchar_t;
typedef SHORT CSHORT;
typedef long long LARGE_INTEGER;

typedef LONG NTSTATUS;

typedef LONG KPRIORITY;
typedef LARGE_INTEGER PHYSICAL_ADDRESS;
typedef UCHAR KIRQL;
typedef CHAR KPROCESSOR_MODE;

/* ULONG_PTR is 32 bits on 32-bit platforms and 64 bits on 64-bit
 * platform, which is same as 'unsigned long' in Linux */
typedef unsigned long ULONG_PTR;

typedef ULONG_PTR SIZE_T;
typedef ULONG_PTR KAFFINITY;
typedef ULONG ACCESS_MASK;

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

struct nt_slist {
	struct nt_slist *next;
};

union nt_slist_head {
	ULONGLONG align;
	struct {
		struct nt_slist *next;
		USHORT depth;
		USHORT sequence;
	} list;
};

struct nt_list {
	struct nt_list *next;
	struct nt_list *prev;
};

typedef ULONG_PTR KSPIN_LOCK;

struct kdpc;
typedef STDCALL void (*DPC)(struct kdpc *kdpc, void *ctx, void *arg1,
			    void *arg2);

struct kdpc {
	SHORT type;
	UCHAR number;
	UCHAR importance;
	struct nt_list list;

	DPC func;
	void *ctx;
	void *arg1;
	void *arg2;
	KSPIN_LOCK *lock;
};

enum pool_type {
	NonPagedPool, PagedPool, NonPagedPoolMustSucceed, DontUseThisType,
	NonPagedPoolCacheAligned, PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS, MaxPoolType,
	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1
};

enum memory_caching_type_orig {
	MmFrameBufferCached = 2
};

enum memory_caching_type {
	MmNonCached = FALSE, MmCached = TRUE,
	MmWriteCombined = MmFrameBufferCached, MmHardwareCoherentCached,
	MmNonCachedUnordered, MmUSWCCached, MmMaximumCacheType
};

enum lock_operation {
	IoReadAccess, IoWriteAccess, IoModifyAccess
};

struct mdl {
	struct mdl* next;
	CSHORT size;
	CSHORT flags;
	void *process;
	void *mappedsystemva;
	void *startva;
	ULONG bytecount;
	ULONG byteoffset;
};

#define MDL_MAPPED_TO_SYSTEM_VA		0x0001
#define MDL_PAGES_LOCKED		0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL	0x0004
#define MDL_ALLOCATED_FIXED_SIZE	0x0008
#define MDL_PARTIAL			0x0010
#define MDL_PARTIAL_HAS_BEEN_MAPPED	0x0020
#define MDL_IO_PAGE_READ		0x0040
#define MDL_WRITE_OPERATION		0x0080
#define MDL_PARENT_MAPPED_SYSTEM_VA	0x0100
#define MDL_FREE_EXTRA_PTES		0x0200
#define MDL_IO_SPACE			0x0800
#define MDL_NETWORK_HEADER		0x1000
#define MDL_MAPPING_CAN_FAIL		0x2000
#define MDL_ALLOCATED_MUST_SUCCEED	0x4000
#define MDL_CACHE_ALLOCATED		0x8000

#define MmGetMdlBaseVa(mdl) ((mdl)->startva)
#define MmGetMdlByteCount(mdl) ((mdl)->bytecount)
#define MmGetMdlVirtualAddress(mdl) ((void *)((char *)(mdl)->startva +	\
					      (mdl)->byteoffset))
#define MmGetMdlByteOffset(mdl) ((mdl)->byteoffset)
#define MmGetSystemAddressForMdl(mdl) ((mdl)->mappedsystemva)
#define MmInitializeMdl(mdl, baseva, length) {				\
		(mdl)->next = NULL;					\
		(mdl)->size = MmSizeOfMdl(baseva, length);		\
		(mdl)->flags = 0;					\
		(mdl)->startva = (void *)((ULONG_PTR)baseva &		\
					  ~(PAGE_SIZE - 1));		\
		(mdl)->byteoffset = (ULONG)((ULONG_PTR)baseva &		\
					    (PAGE_SIZE - 1));		\
		(mdl)->bytecount = length;				\
	}

struct kdevice_queue_entry {
	struct nt_list list;
	ULONG sort_key;
	BOOLEAN inserted;
};

struct kdevice_queue {
	USHORT type;
	USHORT size;
	struct nt_list list;
	KSPIN_LOCK lock;
	BOOLEAN busy;
};

struct wait_context_block {
	struct kdevice_queue_entry wait_queue_entry;
	void *device_routine;
	void *device_context;
	ULONG num_regs;
	void *device_object;
	void *current_irp;
	void *buffer_chaining_dpc;
};

struct dispatch_header {
	UCHAR type;
	UCHAR absolute;
	UCHAR size;
	UCHAR inserted;
	LONG signal_state;
	struct nt_list wait_list;
};

/* objects that use dispatch_header have it as the first field, so
 * whenever we need to initialize dispatch_header, we can convert that
 * object into a kevent and access dispatch_header */
struct kevent {
	struct dispatch_header dh;
};

struct wrapper_timer;
struct ktimer {
	struct dispatch_header dh;
	ULONGLONG due_time;
	struct nt_list list;
	/* We can't fit Linux timer in this structure. Instead of
	 * padding the ktimer structure, we replace *kdpc field with
	 * *wrapper_timer and allocate memory for it when ktimer is
	 * initialized */
	/* struct kdpc *kdpc; */
	struct wrapper_timer *wrapper_timer;
	LONG period;
};

struct kmutex {
	struct dispatch_header dh;
	struct nt_list list;
	void *owner_thread;
	BOOLEAN abandoned;
	BOOLEAN apc_disable;
};

struct ksemaphore {
	struct dispatch_header dh;
	LONG limit;
};

struct obj_mgr_obj {
	struct dispatch_header dh;
	struct nt_list list;
	void *handle;
	LONG ref_count;
};

struct irp;
struct dev_obj_ext;
struct driver_object;

struct device_object {
	CSHORT type;
	USHORT size;
	LONG ref_count;
	struct driver_object *drv_obj;
	struct device_object *next;
	struct device_object *attached;
	struct irp *current_irp;
	void *io_timer;
	ULONG flags;
	ULONG characteristics;
	void *vpb;
	void *dev_ext;
	CCHAR stack_size;
	union {
		struct nt_list queue_list;
		struct wait_context_block wcb;
	} queue;
	ULONG align_req;
	struct kdevice_queue dev_queue;
	struct kdpc dpc;
	ULONG active_threads;
	void *security_desc;
	struct kevent lock;
	USHORT sector_size;
	USHORT spare1;
	struct dev_obj_ext *dev_obj_ext;
	void *reserved;

	/* ndiswrapper-specific data */
	union {
		struct usb_device *usb;
	} device;
	void *handle;
};

struct dev_obj_ext {
	CSHORT type;
	CSHORT size;
	struct device_object *dev_obj;
};

struct io_status_block {
	NTSTATUS status;
	ULONG status_info;
};

#define DEVICE_TYPE ULONG

struct driver_extension;

struct driver_object {
	CSHORT type;
	CSHORT size;
	struct device_object *dev_obj;
	ULONG flags;
	void *driver_start;
	ULONG driver_size;
	void *driver_section;
	struct driver_extension *drv_ext;
	struct unicode_string driver_name;
	struct unicode_string *hardware_database;
	void *fast_io_dispatch;
	void *driver_init;
	void *driver_start_io;
	void (*driver_unload)(struct driver_object *driver) STDCALL;
	void *major_func[IRP_MJ_MAXIMUM_FUNCTION + 1];
};

struct driver_extension {
	struct drier_object *drv_obj;
	void *add_device_func;
	ULONG count;
	struct unicode_string service_key_name;
	struct nt_list custom_ext;
};

struct custom_ext {
	struct nt_list list;
	void *client_id;
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
	struct nt_list list;
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

enum irp_work_type {
	IRP_WORK_NONE, IRP_WORK_COMPLETE, IRP_WORK_CANCEL,
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

	struct nt_list threads;

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
				struct nt_list list;
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
	NT_OBJ_EVENT = 10, NT_OBJ_MUTEX, NT_OBJ_THREAD, NT_OBJ_TIMER,
	NT_OBJ_SEMAPHORE,
};

struct common_body_header {
	CSHORT type;
	CSHORT size;
};

struct object_header {
	struct unicode_string name;
	struct nt_list list;
	LONG ref_count;
	LONG handle_count;
	BOOLEAN close_in_process;
	BOOLEAN permanent;
	BOOLEAN inherit;
	void *parent;
	void *object_type;
	void *security_desc;
	CSHORT type;
	CSHORT size;
};

enum work_queue_type {
	CriticalWorkQueue, DelayedWorkQueue, HyperCriticalWorkQueue,
	MaximumWorkQueue
};

enum wait_type {
	WaitAll, WaitAny
};

struct wait_block {
	struct nt_list list_entry;
	void *thread;
	void *object;
	struct wait_block *next;
	USHORT wait_key;
	USHORT wait_type;
};

enum event_type {NotificationEvent, SynchronizationEvent};

enum mm_page_priority {
	LowPagePriority, NormalPagePriority = 16, HighPagePriority = 32
};

enum kinterrupt_mode {
	LevelSensitive, Latched
};

enum ntos_wait_reason {
	Executive, FreePage, PageIn, PoolAllocation, DelayExecution,
	Suspended, UserRequest, WrExecutive, WrFreePage, WrPageIn,
	WrPoolAllocation, WrDelayExecution, WrSuspended, WrUserRequest,
	WrEventPair, WrQueue, WrLpcReceive, WrLpcReply, WrVirtualMemory,
	WrPageOut, WrRendezvous, Spare2, Spare3, Spare4, Spare5, Spare6,
	WrKernel, MaximumWaitReason
};

typedef enum ntos_wait_reason KWAIT_REASON;

typedef STDCALL void *LOOKASIDE_ALLOC_FUNC(enum pool_type pool_type,
					   SIZE_T size, ULONG tag);
typedef STDCALL void LOOKASIDE_FREE_FUNC(void *);

struct npaged_lookaside_list {
	union nt_slist_head head;
	USHORT depth;
	USHORT maxdepth;
	ULONG totalallocs;
	union {
		ULONG allocmisses;
		ULONG allochits;
	} u1;
	ULONG totalfrees;
	union {
		ULONG freemisses;
		ULONG freehits;
	} u2;
	enum pool_type pool_type;
	ULONG tag;
	ULONG size;
	LOOKASIDE_ALLOC_FUNC *alloc_func;
	LOOKASIDE_FREE_FUNC *free_func;
	struct nt_list list;
	ULONG lasttotallocs;
	union {
		ULONG lastallocmisses;
		ULONG lastallochits;
	} u3;
	ULONG pad[2];
#ifndef X86_64
	KSPIN_LOCK obsolete;
#endif
};

enum device_registry_property {
	DevicePropertyDeviceDescription, DevicePropertyHardwareID,
	DevicePropertyCompatibleIDs, DevicePropertyBootConfiguration,
	DevicePropertyBootConfigurationTranslated,
	DevicePropertyClassName, DevicePropertyClassGuid,
	DevicePropertyDriverKeyName, DevicePropertyManufacturer,
	DevicePropertyFriendlyName, DevicePropertyLocationInformation,
	DevicePropertyPhysicalDeviceObjectName, DevicePropertyBusTypeGuid,
	DevicePropertyLegacyBusType, DevicePropertyBusNumber,
	DevicePropertyEnumeratorName, DevicePropertyAddress,
	DevicePropertyUINumber, DevicePropertyInstallState,
	DevicePropertyRemovalPolicy
};

enum trace_information_class {
	TraceIdClass, TraceHandleClass, TraceEnableFlagsClass,
	TraceEnableLevelClass, GlobalLoggerHandleClass, EventLoggerHandleClass,
	AllLoggerHandlesClass, TraceHandleByNameClass
};

struct kinterrupt;
typedef BOOLEAN (*PKSERVICE_ROUTINE)(struct kinterrupt *interrupt,
				     void *context) STDCALL;
typedef BOOLEAN (*PKSYNCHRONIZE_ROUTINE)(void *context) STDCALL;

struct kinterrupt {
	ULONG vector;
	KAFFINITY processor_enable_mask;
	KSPIN_LOCK lock;
	KSPIN_LOCK *actual_lock;
	BOOLEAN shareable;
	BOOLEAN floating_save;
	CHAR processor_number;
	PKSERVICE_ROUTINE service_routine;
	void *service_context;
	struct nt_list list;
	KIRQL irql;
	KIRQL synch_irql;
	enum kinterrupt_mode interrupt_mode;
};

struct time_fields {
	CSHORT year;
	CSHORT month;
	CSHORT day;
	CSHORT hour;
	CSHORT minute;
	CSHORT second;
	CSHORT milliseconds;
	CSHORT weekday;
};

struct object_attributes {
	ULONG length;
	void *root_dir;
	struct unicode_string *name;
	ULONG attributes;
	void *security_descr;
	void *security_qos;
};

typedef void (*PCALLBACK_FUNCTION)(void *context, void *arg1, void *arg2);

struct callback_object;
struct callback_func {
	PCALLBACK_FUNCTION func;
	void *context;
	struct nt_list list;
	struct callback_object *object;
};

struct callback_object {
	KSPIN_LOCK lock;
	struct nt_list list;
	struct nt_list callback_funcs;
	BOOLEAN allow_multiple_callbacks;
	struct object_attributes *attributes;
};

/* some of the functions below are slightly different from DDK's
 * implementation; e.g., Insert functions return appropriate
 * pointer */

/* instead of using Linux's lists, we implement list manipulation
 * functions because nt_list is used by drivers and we don't want to
 * worry about Linux's list being different from nt_list (right now
 * they are same, but in future they could be different) */

static inline void InitializeListHead(struct nt_list *head)
{
	head->next = head->prev = head;
}

static inline BOOLEAN IsListEmpty(struct nt_list *head)
{
	if (head->next == head)
		return TRUE;
	else
		return FALSE;
}

static inline void RemoveEntryList(struct nt_list *entry)
{
	struct nt_list *prev, *next;

	next = entry->next;
	prev = entry->prev;
	prev->next = next;
	next->prev = prev;
}

static inline struct nt_list *RemoveHeadList(struct nt_list *head)
{
	struct nt_list *next, *entry;

	if (IsListEmpty(head))
		return NULL;
	else {
		entry = head->next;
		next = entry->next;
		head->next = next;
		next->prev = head;
		return entry;
	}
}

static inline struct nt_list *RemoveTailList(struct nt_list *head)
{
	struct nt_list *prev, *entry;

	if (IsListEmpty(head))
		return NULL;
	else {
		entry = head->prev;
		prev = entry->prev;
		head->prev = prev;
		prev->next = head;
		return entry;
	}
}

static inline struct nt_list *InsertHeadList(struct nt_list *head,
					     struct nt_list *entry)
{
	struct nt_list *next, *first;

	if (IsListEmpty(head))
		first = NULL;
	else
		first = head->next;

	next = head->next;
	entry->next = next;
	entry->prev = head;
	next->prev = entry;
	head->next = entry;
	return first;
}

static inline struct nt_list *InsertTailList(struct nt_list *head,
					     struct nt_list *entry)
{
	struct nt_list *prev, *last;

	if (IsListEmpty(head))
		last = NULL;
	else
		last = head->prev;

	prev = head->prev;
	entry->next = head;
	entry->prev = prev;
	prev->next = entry;
	head->prev = entry;
	return last;
}

#define nt_list_for_each(pos, head)					\
	for (pos = (head)->next; prefetch(pos->next), pos != (head);	\
	     pos = pos->next)

static inline struct nt_slist *
PushEntryList(union nt_slist_head *head, struct nt_slist *entry)
{
	struct nt_slist *oldhead;

	oldhead = head->list.next;
	entry->next = head->list.next;
	head->list.next = entry;
	head->list.depth++;
	head->list.sequence++;
	return oldhead;
}

static inline struct nt_slist *PopEntryList(union nt_slist_head *head)
{
	struct nt_slist *first;

	first = head->list.next;
	if (first) {
		head->list.next = first->next;
		head->list.depth--;
		head->list.sequence++;
	}
	return first;
}

/* device object flags */
#define DO_VERIFY_VOLUME		0x00000002
#define DO_BUFFERED_IO			0x00000004
#define DO_EXCLUSIVE			0x00000008
#define DO_DIRECT_IO			0x00000010
#define DO_MAP_IO_BUFFER		0x00000020
#define DO_DEVICE_HAS_NAME		0x00000040
#define DO_DEVICE_INITIALIZING		0x00000080
#define DO_SYSTEM_BOOT_PARTITION	0x00000100
#define DO_LONG_TERM_REQUESTS		0x00000200
#define DO_NEVER_LAST_DEVICE		0x00000400
#define DO_SHUTDOWN_REGISTERED		0x00000800
#define DO_BUS_ENUMERATED_DEVICE	0x00001000
#define DO_POWER_PAGABLE		0x00002000
#define DO_POWER_INRUSH			0x00004000
#define DO_LOW_PRIORITY_FILESYSTEM	0x00010000

/* Various supported device types (used with IoCreateDevice()) */

#define FILE_DEVICE_BEEP		0x00000001
#define FILE_DEVICE_CD_ROM		0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM	0x00000003
#define FILE_DEVICE_CONTROLLER		0x00000004
#define FILE_DEVICE_DATALINK		0x00000005
#define FILE_DEVICE_DFS			0x00000006
#define FILE_DEVICE_DISK		0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM	0x00000008
#define FILE_DEVICE_FILE_SYSTEM		0x00000009
#define FILE_DEVICE_INPORT_PORT		0x0000000A
#define FILE_DEVICE_KEYBOARD		0x0000000B
#define FILE_DEVICE_MAILSLOT		0x0000000C
#define FILE_DEVICE_MIDI_IN		0x0000000D
#define FILE_DEVICE_MIDI_OUT		0x0000000E
#define FILE_DEVICE_MOUSE		0x0000000F
#define FILE_DEVICE_MULTI_UNC_PROVIDER	0x00000010
#define FILE_DEVICE_NAMED_PIPE		0x00000011
#define FILE_DEVICE_NETWORK		0x00000012
#define FILE_DEVICE_NETWORK_BROWSER	0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM	0x00000014
#define FILE_DEVICE_NULL		0x00000015
#define FILE_DEVICE_PARALLEL_PORT	0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD	0x00000017
#define FILE_DEVICE_PRINTER		0x00000018
#define FILE_DEVICE_SCANNER		0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT	0x0000001A
#define FILE_DEVICE_SERIAL_PORT		0x0000001B
#define FILE_DEVICE_SCREEN		0x0000001C
#define FILE_DEVICE_SOUND		0x0000001D
#define FILE_DEVICE_STREAMS		0x0000001E
#define FILE_DEVICE_TAPE		0x0000001F
#define FILE_DEVICE_TAPE_FILE_SYSTEM	0x00000020
#define FILE_DEVICE_TRANSPORT		0x00000021
#define FILE_DEVICE_UNKNOWN		0x00000022
#define FILE_DEVICE_VIDEO		0x00000023
#define FILE_DEVICE_VIRTUAL_DISK	0x00000024
#define FILE_DEVICE_WAVE_IN		0x00000025
#define FILE_DEVICE_WAVE_OUT		0x00000026
#define FILE_DEVICE_8042_PORT		0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR	0x00000028
#define FILE_DEVICE_BATTERY		0x00000029
#define FILE_DEVICE_BUS_EXTENDER	0x0000002A
#define FILE_DEVICE_MODEM		0x0000002B
#define FILE_DEVICE_VDM			0x0000002C
#define FILE_DEVICE_MASS_STORAGE	0x0000002D
#define FILE_DEVICE_SMB			0x0000002E
#define FILE_DEVICE_KS			0x0000002F
#define FILE_DEVICE_CHANGER		0x00000030
#define FILE_DEVICE_SMARTCARD		0x00000031
#define FILE_DEVICE_ACPI		0x00000032
#define FILE_DEVICE_DVD			0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO	0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM	0x00000035
#define FILE_DEVICE_DFS_VOLUME		0x00000036
#define FILE_DEVICE_SERENUM		0x00000037
#define FILE_DEVICE_TERMSRV		0x00000038
#define FILE_DEVICE_KSEC		0x00000039
#define FILE_DEVICE_FIPS		0x0000003A

/* Device characteristics */

#define FILE_REMOVABLE_MEDIA		0x00000001
#define FILE_READ_ONLY_DEVICE		0x00000002
#define FILE_FLOPPY_DISKETTE		0x00000004
#define FILE_WRITE_ONCE_MEDIA		0x00000008
#define FILE_REMOTE_DEVICE		0x00000010
#define FILE_DEVICE_IS_MOUNTED		0x00000020
#define FILE_VIRTUAL_VOLUME		0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME	0x00000080
#define FILE_DEVICE_SECURE_OPEN		0x00000100

#endif /* WINNT_TYPES_H */
