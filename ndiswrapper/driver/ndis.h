#ifndef NDIS_H
#define NDIS_H

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/netdevice.h>
#define STDCALL __attribute__((__stdcall__))
#define packed __attribute__((packed))

#define NDIS_STATUS_SUCCESS     0x00000000
#define NDIS_STATUS_FAILIURE    0xc0000001
#define NDIS_STATUS_BAD_VERSION 0xc0010004
#define NDIS_STATUS_BAD_CHAR    0xc0010005

int getSp(void);

struct packed miniport_char
{
	__u8 majorVersion;
	__u8 minorVersion;
	__u16 reserved1;
	__u32 reserved2;
	void * CheckForHangTimer;
	void * DisableInterruptHandler;
	void * EnableInterruptHandler;
	STDCALL void (*halt)(void *ctx);
	STDCALL void (*handle_interrupt)(void *ctx);
	STDCALL void (*init)(unsigned int *OpenErrorStatus, unsigned int *SelectedmediumIndex, unsigned int *MediumArray, unsigned int MediumArraySize, void *ndis_handle, void *conf_handle);
	STDCALL void (*isr)(unsigned int *taken, unsigned int *callme, void *ctx);
	STDCALL unsigned int (*query)(void *ctx, unsigned int oid, char *buffer, unsigned int buflen, unsigned int *written, unsigned int *needed);
	void * ReconfigureHandler;
	void * ResetHandler;		//s
	void * SendHandler;
	STDCALL unsigned int (*setinfo)(void *ctx, unsigned int oid, char *buffer, unsigned int buflen, unsigned int *written, unsigned int *needed);
	void * TransferDataHandler;
	void * ReturnPacketHandler;	//s
	void * SendPacketsHandler;	//s
/*
	void * AllocateCompleteHandler;
	void * CoCreateVcHandler;
	void * CoDeleteVcHandler;	
	void * CoActivateVcHandler;
	void * CoDeactivateVcHandler;
	void * CoSendPacketsHandler;
	void * CoRequestHandler;
*/	
	
};


struct ndis_irq
{
	int irq;
	struct ndis_handle *handle;

	/* Taken by ISR, DisableInterrupt and SynchronizeWithInterrupt */
	spinlock_t spinlock;

};

/*
  This struct contains function pointers that the drivers references directly via macros,
  so it's important that they are at the correct position hence the paddings.
 */
struct packed ndis_handle
{
	char fill1[232];
	void *indicate_receive_packet;
	void *send_complete;
	char fill2[140];
	void *indicate_status;
	void *indicate_status_complete;
	char fill3[200];
	void *image;
	STDCALL unsigned int (*entry)(void *obj, char *p2);
	struct miniport_char miniport_char;
	struct pci_dev *pci_dev;
	struct net_device *net_dev;
	void *adapter_ctx;
	struct work_struct irq_bh;

	int irq;
	unsigned long mem_start;
	unsigned long mem_end;

	struct net_device_stats stats;
};



struct packed ustring
{
	__u16 x;
	__u16 y;
	char *buf;
};

struct ndis_timer
{
	struct timer_list timer;
	struct work_struct bh;
	void *func;
	void *ctx;
	int repeat;
};

struct packed ndis_resource_entry
{
	__u8 type;
	__u8 share;
	__u16 flags;
	__u32 param1;
	__u32 param2;
	__u32 param3;
};

struct packed ndis_resource_list
{
	__u16 version;
	__u16 revision;
	__u32 length;
	struct ndis_resource_entry list[0];
};

struct packed ndis_phy_address
{
	__u32 low;
	__u32 high;
};

#endif /* NDIS_H */
