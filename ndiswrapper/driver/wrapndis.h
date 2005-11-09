#include "ndis.h"
#include "wrapper.h"
#include "pnp.h"

NDIS_STATUS miniport_reset(struct wrapper_dev *wd);
NDIS_STATUS miniport_query_info_needed(struct wrapper_dev *wd,
				       ndis_oid oid, void *buf,
				       ULONG bufsize, ULONG *needed);
NDIS_STATUS miniport_query_info(struct wrapper_dev *wd, ndis_oid oid,
				void *buf, ULONG bufsize);
NDIS_STATUS miniport_set_info(struct wrapper_dev *wd, ndis_oid oid,
			      void *buf, ULONG bufsize);
NDIS_STATUS miniport_query_int(struct wrapper_dev *wd, ndis_oid oid,
			       ULONG *data);
NDIS_STATUS miniport_set_int(struct wrapper_dev *wd, ndis_oid oid,
			     ULONG data);
NDIS_STATUS miniport_surprise_remove(struct wrapper_dev *wd);
NDIS_STATUS miniport_set_pm_state(struct wrapper_dev *wd,
				     enum ndis_pm_state);
void hangcheck_add(struct wrapper_dev *wd);
void hangcheck_del(struct wrapper_dev *wd);
void sendpacket_done(struct wrapper_dev *wd, struct ndis_packet *packet);
int ndiswrapper_suspend_pci(struct pci_dev *pdev, pm_message_t state);
int ndiswrapper_resume_pci(struct pci_dev *pdev);

int ndiswrapper_suspend_usb(struct usb_interface *intf, pm_message_t state);
int ndiswrapper_resume_usb(struct usb_interface *intf);

NDIS_STATUS ndis_reinit(struct wrapper_dev *wd);
NDIS_STATUS miniport_init(struct wrapper_dev *wd);
void miniport_halt(struct wrapper_dev *wd);

void check_capa(struct wrapper_dev *wd);

struct net_device *init_netdev(struct wrapper_dev **pwd,
			       struct ndis_device *device,
			       struct ndis_driver *driver);

struct iw_statistics *get_wireless_stats(struct net_device *dev);
STDCALL NTSTATUS NdisAddDevice(struct driver_object *drv_obj,
			       struct device_object *pdo);
void NdisDeleteDevice(struct device_object *pdo);
