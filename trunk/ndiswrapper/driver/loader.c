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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/kmod.h>

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <net/iw_handler.h>
#include <linux/rtnetlink.h>

#include <asm/uaccess.h>

#include "ndis.h"
#include "loader.h"
#include "wrapper.h"

static spinlock_t loader_lock;
static struct ndis_device *ndis_devices;
static unsigned int num_ndis_devices;
struct list_head ndis_drivers;
static struct pci_device_id *ndiswrapper_pci_devices;
static struct usb_device_id *ndiswrapper_usb_devices;
static struct pci_driver ndiswrapper_pci_driver;
static struct usb_driver ndiswrapper_usb_driver;

/* load driver for given device, if not already loaded */
static struct ndis_driver *ndiswrapper_load_driver(struct ndis_device *device)
{
	char v[10], d[10], sv[10], sd[10];
	int err, found;
	struct ndis_driver *ndis_driver;

	TRACEENTER1("device: %04X:%04X:%04X:%04X", device->vendor,
		    device->device, device->subvendor, device->subdevice);
	found = 0;
	spin_lock(&loader_lock);
	list_for_each_entry(ndis_driver, &ndis_drivers, list) {
		if (strcmp(ndis_driver->name, device->driver_name) == 0) {
			DBGTRACE1("driver %s already loaded",
				  ndis_driver->name);
			found = 1;
			break;
		}
	}
	spin_unlock(&loader_lock);

	snprintf(v, sizeof(v), "%d", device->vendor);
	snprintf(d, sizeof(v), "%d", device->device);
	snprintf(sv, sizeof(v), "%d", device->subvendor);
	snprintf(sd, sizeof(v), "%d", device->subdevice);

	if (found)
		TRACEEXIT1(return ndis_driver);
	else {
		char *argv[] = {"loadndisdriver", 
#if defined DEBUG && DEBUG >= 1
				"1",
#else
				"0",
#endif
				NDISWRAPPER_VERSION, device->driver_name,
				v, d, sv, sd, NULL};
		char *env[] = {NULL};

		DBGTRACE1("loading driver %s", device->driver_name);
		err = call_usermodehelper("/sbin/loadndisdriver", argv, env
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
					  , 1
#endif
			);

		if (err) {
			ERROR("loadndiswrapper failed (%d); check system log "
			      "for messages from 'loadndisdriver'", err);
			TRACEEXIT1(return NULL);
		}

		found = 0;
		spin_lock(&loader_lock);
		list_for_each_entry(ndis_driver, &ndis_drivers, list) {
			if (strcmp(ndis_driver->name,
				   device->driver_name) == 0) {
				found = 1;
				break;
			}
		}
		spin_unlock(&loader_lock);
		if (!found) {
			ERROR("couldn't load driver '%s'",
			      device->driver_name);
			TRACEEXIT1(return NULL);
		}

		DBGTRACE1("driver %s is loaded", ndis_driver->name);
	}
	TRACEEXIT1(return ndis_driver);
}

/*
 * Called by PCI-subsystem for each PCI-card found.
 *
 * This function should not be marked __devinit because ndiswrapper
 * adds PCI_id's dynamically.
 */
static int ndiswrapper_add_one_pci_dev(struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	int res;
	struct ndis_device *device;
	struct ndis_driver *driver;
	struct ndis_handle *handle;
	struct net_device *dev;
	struct miniport_char *miniport;

	TRACEENTER1("ent: %p", ent);

	DBGTRACE1("called for %04x:%04x:%04x:%04x", pdev->vendor, pdev->device,
		  pdev->subsystem_vendor, pdev->subsystem_device);

	device = &ndis_devices[ent->driver_data];

	driver = ndiswrapper_load_driver(device);
	if (!driver) {
		res = -ENODEV;
		goto out_nodev;
	}

	dev = ndis_init_netdev(&handle, device, driver);
	if (!dev) {
		ERROR("couldn't initialize network device");
		res = -ENOMEM;
		goto out_nodev;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	SET_NETDEV_DEV(dev, &pdev->dev);
#endif

	handle->dev.pci = pdev;
	handle->device = device;
	pci_set_drvdata(pdev, handle);
	device->handle = handle;

	res = pci_enable_device(pdev);
	if (res)
		goto out_enable;

	res = pci_request_regions(pdev, driver->name);
	if (res)
		goto out_regions;

	pci_set_power_state(pdev, 0);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)
	pci_restore_state(pdev, NULL);
#endif

	DBGTRACE1("%s", "calling ndis init routine");
	if ((res = miniport_init(handle))) {
		ERROR("Windows driver couldn't initialize the device (%08X)",
			res);
		res = -EINVAL;
		goto out_start;
	}

	handle->hw_status = 0;
	handle->wrapper_work = 0;

	/* do we need to power up the card explicitly? */
	miniport_set_int(handle, OID_PNP_SET_POWER, NdisDeviceStateD0);
	miniport = &handle->driver->miniport_char;
	/* According NDIS, pnp_event_notify should be called whenever power
	 * is set to D0
	 * Only NDIS 5.1 drivers are required to supply this function; some
	 * drivers don't seem to support it (at least Orinoco)
	 */
	/*
	if (miniport->pnp_event_notify) {
		DBGTRACE3("%s", "calling pnp_event_notify");
		miniport->pnp_event_notify(handle, NDIS_PNP_PROFILE_CHANGED,
					 &profile_inf, sizeof(profile_inf));
	}
	*/

	miniport_reset(handle);

	/* Wait a little to let card power up otherwise ifup might fail after
	   boot */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ);

	if (setup_dev(handle->net_dev)) {
		ERROR("couldn't setup network device");
		res = -EINVAL;
		goto out_setup;
	}
	atomic_inc(&driver->users);
	TRACEEXIT1(return 0);

out_setup:
	miniport_halt(handle);
out_start:
	pci_release_regions(pdev);
out_regions:
	pci_disable_device(pdev);
out_enable:
	free_netdev(dev);
out_nodev:
	TRACEEXIT1(return res);
}

/*
 * Remove one PCI-card.
 */
static void __devexit ndiswrapper_remove_one_pci_dev(struct pci_dev *pdev)
{
	struct ndis_handle *handle;

	TRACEENTER1("%p", pdev);

	handle = (struct ndis_handle *)pci_get_drvdata(pdev);

	TRACEENTER1("%p", handle);

	if (!handle)
		TRACEEXIT1(return);

	atomic_dec(&handle->driver->users);
	ndiswrapper_remove_one_dev(handle);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int ndiswrapper_add_one_usb_dev(struct usb_interface *intf,
				       const struct usb_device_id *usb_id)
#else
static void *ndiswrapper_add_one_usb_dev(struct usb_device *udev,
					 unsigned int ifnum,
					 const struct usb_device_id *usb_id)
#endif
{
	int res;
	struct ndis_device *device;
	struct ndis_driver *driver;
	struct ndis_handle *handle;
	struct net_device *dev;
	struct miniport_char *miniport;
//	unsigned long profile_inf = NDIS_POWER_PROFILE_AC;

	TRACEENTER1("vendor: %04x, product: %04x",
		    usb_id->idVendor, usb_id->idProduct);

	device = &ndis_devices[usb_id->driver_info];
	driver = ndiswrapper_load_driver(device);
	if (!driver) {
		res = -ENODEV;
		goto out_nodev;
	}
	dev = ndis_init_netdev(&handle, device, driver);
	if (!dev) {
		ERROR("couldn't initialize network device");
		res = -ENOMEM;
		goto out_nodev;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	SET_NETDEV_DEV(dev, &intf->dev);

	handle->dev.usb = interface_to_usbdev(intf);
	handle->intf    = intf;
	usb_set_intfdata(intf, handle);
#else
	handle->dev.usb = udev;
#endif

	TRACEENTER1("calling ndis init routine");
	if ((res = miniport_init(handle))) {
		ERROR("Windows driver couldn't initialize the device (%08X)",
			res);
		res = -EINVAL;
		goto out_start;
	}

	handle->hw_status = 0;
	handle->wrapper_work = 0;

	/* do we need to power up the card explicitly? */
	miniport_set_int(handle, OID_PNP_SET_POWER, NdisDeviceStateD0);
	miniport = &handle->driver->miniport_char;
	/*
	if (miniport->pnp_event_notify) {
		DBGTRACE3("%s", "calling pnp_event_notify");
		miniport->pnp_event_notify(handle->adapter_ctx,
					   NDIS_PNP_PROFILE_CHANGED,
					   &profile_inf, sizeof(profile_inf));
		DBGTRACE3("%s", "done");
	}
	*/

	miniport_reset(handle);
	/* wait here seems crucial; without this delay, at least
	 * prism54 driver crashes (why?) */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(3*HZ);

	if (setup_dev(handle->net_dev)) {
		ERROR("couldn't setup network device");
		res = -EINVAL;
		goto out_setup;
	}

	atomic_inc(&driver->users);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	TRACEEXIT1(return 0);
#else
	TRACEEXIT1(return handle);
#endif

out_setup:
	miniport_halt(handle);
out_start:
	free_netdev(dev);
out_nodev:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	TRACEEXIT1(return res);
#else
	TRACEEXIT1(return NULL);
#endif
}
#endif // CONFIG_USB

#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static void
ndiswrapper_remove_one_usb_dev(struct usb_interface *intf)
{
	struct ndis_handle *handle;

	TRACEENTER1("");
	handle = (struct ndis_handle *)usb_get_intfdata(intf);

	if (!handle)
		TRACEEXIT1(return);
	usb_set_intfdata(intf, NULL);
	atomic_dec(&handle->driver->users);
	ndiswrapper_remove_one_dev(handle);
}
#else
static void
ndiswrapper_remove_one_usb_dev(struct usb_device *udev, void *ptr)
{
	struct ndis_handle *handle = (struct ndis_handle *)ptr;

	TRACEENTER1("");

	if (!handle || !handle->dev.usb)
		TRACEEXIT1(return);
	handle->dev.usb = NULL;
	atomic_dec(&handle->driver->users);
	ndiswrapper_remove_one_dev(handle);
}
#endif
#endif /* CONFIG_USB */

/* load the driver files from userspace. */
static int load_sys_files(struct ndis_driver *driver,
			  struct load_driver *load_driver)
{
	int i, err;

	TRACEENTER1("");

	DBGTRACE1("num_pe_images = %d", load_driver->nr_sys_files);
	DBGTRACE1("loading driver: %s", load_driver->name);
	memcpy(driver->name, load_driver->name, MAX_DRIVER_NAME_LEN);
	DBGTRACE1("driver: %s", driver->name);
	err = 0;
	driver->num_pe_images = 0;
	for (i = 0; i < load_driver->nr_sys_files; i++) {
		struct pe_image *pe_image;
		pe_image = &driver->pe_images[driver->num_pe_images];

		pe_image->name[MAX_DRIVER_NAME_LEN-1] = 0;
		memcpy(pe_image->name, load_driver->sys_files[i].name,
		       MAX_DRIVER_NAME_LEN);
		DBGTRACE1("image size: %lu bytes",
			  (unsigned long)load_driver->sys_files[i].size);

#ifdef CONFIG_X86_64
#ifdef PAGE_KERNEL_EXECUTABLE
		pe_image->image = __vmalloc(load_driver->sys_files[i].size,
					    GFP_KERNEL | __GFP_HIGHMEM,
					    PAGE_KERNEL_EXECUTABLE);
#elif defined PAGE_KERNEL_EXEC
		pe_image->image = __vmalloc(load_driver->sys_files[i].size,
					    GFP_KERNEL | __GFP_HIGHMEM,
					    PAGE_KERNEL_EXEC);
#else
#error x86_64 should have either PAGE_KERNEL_EXECUTABLE or PAGE_KERNEL_EXEC
#endif
#else
		pe_image->image = vmalloc(load_driver->sys_files[i].size);
#endif
		if (!pe_image->image) {
			ERROR("couldn't allocate memory");
			break;
		}
		DBGTRACE1("image is at %p", pe_image->image);

		if (copy_from_user(pe_image->image,
				   load_driver->sys_files[i].data,
				   load_driver->sys_files[i].size)) {
			ERROR("couldn't load file %s",
			      load_driver->sys_files[i].name);
			break;
		}
		pe_image->size = load_driver->sys_files[i].size;
		driver->num_pe_images++;
	}

	if (load_pe_images(driver->pe_images, driver->num_pe_images)) {
		ERROR("unable to prepare driver '%s'", load_driver->name);
		err = -EINVAL;
	}

	if (driver->num_pe_images < load_driver->nr_sys_files || err) {
		for (i = 0; i < driver->num_pe_images; i++)
			if (driver->pe_images[i].image)
				vfree(driver->pe_images[i].image);
		driver->num_pe_images = 0;
		TRACEEXIT1(return -EINVAL);
	} else {
		TRACEEXIT1(return 0);
	}

}

/* load firmware files from userspace */
static int load_bin_files(struct ndis_driver *driver,
			  struct load_driver *load_driver)
{
	struct ndis_bin_file *bin_files;
	int i;

	TRACEENTER1("loading bin files for driver %s", load_driver->name);
	bin_files = kmalloc(load_driver->nr_bin_files * sizeof(*bin_files),
			    GFP_KERNEL);
	if (!bin_files) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return -ENOMEM);
	}
	memset(bin_files, 0, load_driver->nr_bin_files * sizeof(*bin_files));

	driver->num_bin_files = 0;
	for (i = 0; i < load_driver->nr_bin_files; i++) {
		struct ndis_bin_file *bin_file = &bin_files[i];
		struct load_driver_file *load_bin_file =
			&load_driver->bin_files[i];

		memcpy(bin_file->name, load_bin_file->name,
		       MAX_DRIVER_NAME_LEN);
		bin_file->size = load_bin_file->size;
		bin_file->data = vmalloc(load_bin_file->size);
		if (!bin_file->data) {
			ERROR("cound't allocate memory");
			break;
		}
		if (copy_from_user(bin_file->data, load_bin_file->data,
				   load_bin_file->size)) {
			ERROR("couldn't load file %s", load_bin_file->name);
			break;
		}

		DBGTRACE2("loaded bin file %s", bin_file->name);
		driver->num_bin_files++;
	}
	if (driver->num_bin_files < load_driver->nr_bin_files) {
		for (i = 0; i < driver->num_bin_files; i++)
			vfree(bin_files[i].data);
		kfree(bin_files);
		driver->num_bin_files = 0;
		TRACEEXIT1(return -EINVAL);
	} else {
		driver->bin_files = bin_files;
		TRACEEXIT1(return 0);
	}
}

/* load settnigs for a device */
static int load_settings(struct ndis_driver *ndis_driver,
			 struct load_driver *load_driver)
{
	int i, found, nr_settings;
	struct ndis_device *ndis_device;

	TRACEENTER1("");

	found = 0;
	spin_lock(&loader_lock);
	for (i = 0; i < num_ndis_devices; i++) {
		if (ndis_devices[i].vendor == load_driver->vendor &&
		    ndis_devices[i].device == load_driver->device &&
		    ndis_devices[i].subvendor == load_driver->subvendor &&
		    ndis_devices[i].subdevice == load_driver->subdevice) {
			found = 1;
			break;
		}
	}
	spin_unlock(&loader_lock);

	if (!found) {
		ERROR("device %04X:%04X:%04X:%04X is not registered",
		      load_driver->vendor, load_driver->device,
		      load_driver->subvendor, load_driver->subdevice);
		TRACEEXIT1(return -EINVAL);
	}

	nr_settings = 0;
	ndis_device = &ndis_devices[i];
	for (i = 0; i < load_driver->nr_settings; i++) {
		struct load_device_setting *load_setting =
			&load_driver->settings[i];
		struct device_setting *setting;

		setting = kmalloc(sizeof(*setting), GFP_KERNEL);
		if (!setting) {
			ERROR("couldn't allocate memory");
			break;
		}
		memset(setting, 0, sizeof(*setting));
		memcpy(setting->name, load_setting->name,
		       MAX_NDIS_SETTING_NAME_LEN);
		memcpy(setting->value, load_setting->value,
		       MAX_NDIS_SETTING_VALUE_LEN);
		DBGTRACE2("copied setting %s", load_setting->name);
		setting->config_param.type = NDIS_CONFIG_PARAM_NONE;

		if (strcmp(setting->name, "ndis_version") == 0)
			memcpy(ndis_driver->version, setting->value,
			       sizeof(ndis_driver->version));
		spin_lock(&loader_lock);
		list_add(&setting->list, &ndis_device->settings);
		spin_unlock(&loader_lock);
		nr_settings++;
	}
	/* it is not a fatal error if some settings couldn't be loaded */
	if (nr_settings > 0)
		TRACEEXIT1(return 0);
	else
		TRACEEXIT1(return -EINVAL);
}

/* this function is called while holding load_lock spinlock */
static void unload_ndis_device(struct ndis_device *device)
{
	TRACEENTER1("unloading device %04X:%04X:%04X:%04X, driver %s",
		    device->vendor, device->device, device->subvendor,
		    device->subdevice, device->driver_name);

	while (!list_empty(&device->settings)) {
		struct device_setting *setting;
		struct ndis_config_param *param;

		setting = list_entry(device->settings.next,
				     struct device_setting, list);
		param = &setting->config_param;
		if (param->type == NDIS_CONFIG_PARAM_STRING)
			RtlFreeUnicodeString(&param->data.ustring);
		list_del(&setting->list);
		kfree(setting);
	}
	TRACEEXIT1(return);
}

/* at the time this function is called, devices are deregistered, so
 * safe to remove the driver without any checks */
static void unload_ndis_driver(struct ndis_driver *driver)
{
	int i;

	DBGTRACE1("freeing %d images", driver->num_pe_images);
	if (driver->driver_unload)
		driver->driver_unload(driver);
	for (i = 0; i < driver->num_pe_images; i++)
		if (driver->pe_images[i].image)
			vfree(driver->pe_images[i].image);

	DBGTRACE1("freeing %d bin files", driver->num_bin_files);
	for (i = 0; i < driver->num_bin_files; i++)
		vfree(driver->bin_files[i].data);
	if (driver->bin_files)
		kfree(driver->bin_files);

	kfree(driver);
	TRACEEXIT1(return);
}

/* call the entry point of the driver */
static int start_driver(struct ndis_driver *driver)
{
	int i, ret, res;
	struct unicode_string reg_string;
	char *reg_path = "0/0t0m0p0";

	TRACEENTER1("");

	reg_string.buf = (wchar_t *)reg_path;

	reg_string.buflen = reg_string.len = strlen(reg_path);
	for (ret = res = 0, i = 0; i < driver->num_pe_images; i++)
		/* dlls are already started by loader */
		if (driver->pe_images[i].type == IMAGE_FILE_EXECUTABLE_IMAGE) {
			UINT (*entry)(void *obj,
				      struct unicode_string *p2) STDCALL;

			entry = driver->pe_images[i].entry;
			DBGTRACE1("entry: %p, %p", entry, *entry);
			res = LIN2WIN2(entry, (void *)driver, &reg_string);
			ret |= res;
			DBGTRACE1("entry returns %08X", res);
			DBGTRACE1("driver version: %d.%d",
				  driver->miniport_char.majorVersion,
				  driver->miniport_char.minorVersion);
			driver->entry = entry;
		}

	if (ret) {
		ERROR("driver initialization failed: %08X", ret);
		TRACEEXIT1(return -EINVAL);
	}

	TRACEEXIT1(return 0);
}

/*
 * add driver to list of loaded driver but make sure this driver is
 * not loaded before.
 */
static int add_driver(struct ndis_driver *driver)
{
	struct ndis_driver *tmp;

	TRACEENTER1("");
	spin_lock(&loader_lock);
	list_for_each_entry(tmp, &ndis_drivers, list) {
		if (strcmp(tmp->name, driver->name) == 0) {
			spin_unlock(&loader_lock);
			ERROR("cannot add duplicate driver");
			TRACEEXIT1(return -EBUSY);
		}
	}
	list_add(&driver->list, &ndis_drivers);
	spin_unlock(&loader_lock);

	TRACEEXIT1(return 0);
}

/* load a driver from userspace and initialize it */
static int load_ndis_driver(struct load_driver *load_driver)
{
	struct ndis_driver *ndis_driver;

	ndis_driver = kmalloc(sizeof(*ndis_driver), GFP_KERNEL);
	if (!ndis_driver) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return -EINVAL);
	}
	memset(ndis_driver, 0, sizeof(*ndis_driver));
	ndis_driver->bustype = -1;

	if (load_sys_files(ndis_driver, load_driver) ||
	    load_bin_files(ndis_driver, load_driver) ||
	    load_settings(ndis_driver, load_driver) ||
	    start_driver(ndis_driver) ||
	    add_driver(ndis_driver)) {
		unload_ndis_driver(ndis_driver);
		TRACEEXIT1(return -EINVAL);
	} else {
		printk(KERN_INFO "%s: driver %s (%s) added\n",
		       DRIVER_NAME, ndis_driver->name, ndis_driver->version);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
		add_taint(TAINT_PROPRIETARY_MODULE);
		/* older kernels don't seem to have a way to set
		 * tainted information */
#endif
		TRACEEXIT1(return 0);
	}
}

/* register all devices (for all drivers) installed */
static int register_devices(struct load_devices *load_devices)
{
	int i, res, num_pci, num_usb;
	struct load_device *devices;

	devices = NULL;
	ndiswrapper_pci_devices = NULL;
	ndiswrapper_usb_devices = NULL;
	ndis_devices = NULL;
	devices = vmalloc(load_devices->count * sizeof(struct load_device));
	if (!devices) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return -ENOMEM);
	}

	if (copy_from_user(devices, load_devices->devices,
			   load_devices->count * sizeof(struct load_device))) {
		ERROR("couldn't copy from user space");
		goto err;
	}

	num_pci = num_usb = 0;
	for (i = 0; i < load_devices->count; i++)
		if (devices[i].bustype == NDIS_PCI_BUS)
			num_pci++;
		else if (devices[i].bustype == NDIS_USB_BUS)
			num_usb++;
		else
			WARNING("bus type %d is not valid",
				devices[i].bustype);
	num_ndis_devices = num_pci + num_usb;
	if (num_pci > 0) {
		ndiswrapper_pci_devices =
			kmalloc((num_pci + 1) * sizeof(struct pci_device_id),
				GFP_KERNEL);
		if (!ndiswrapper_pci_devices) {
			ERROR("couldn't allocate memory");
			goto err;
		}
		memset(ndiswrapper_pci_devices, 0,
		       (num_pci + 1) * sizeof(struct pci_device_id));
	}

	if (num_usb > 0) {
		ndiswrapper_usb_devices =
			kmalloc((num_usb + 1) * sizeof(struct usb_device_id),
				GFP_KERNEL);
		if (!ndiswrapper_usb_devices) {
			ERROR("couldn't allocate memory");
			goto err;
		}
		memset(ndiswrapper_usb_devices, 0,
		       (num_usb + 1) * sizeof(struct usb_device_id));
	}

	ndis_devices = vmalloc(num_ndis_devices * sizeof(*ndis_devices));
	if (!ndis_devices) {
		ERROR("couldn't allocate memory");
		goto err;
	}

	memset(ndis_devices, 0, num_ndis_devices * sizeof(*ndis_devices));
	num_usb = num_pci = 0;
	for (i = 0; i < load_devices->count; i++) {
		struct load_device *device = &devices[i];
		struct ndis_device *ndis_device;

		ndis_device = &ndis_devices[num_pci + num_usb];

		INIT_LIST_HEAD(&ndis_device->settings);
		memcpy(&ndis_device->driver_name, device->driver_name,
		       sizeof(ndis_device->driver_name));
		ndis_device->bustype = device->bustype;

		ndis_device->vendor = device->vendor;
		ndis_device->device = device->device;
		ndis_device->subvendor = device->subvendor;
		ndis_device->subdevice = device->subdevice;

		memcpy(&ndis_device->driver_name, device->driver_name,
		       sizeof(ndis_device->driver_name));

		if (device->bustype == NDIS_PCI_BUS) {
			ndiswrapper_pci_devices[num_pci].vendor =
				device->vendor;
			ndiswrapper_pci_devices[num_pci].device =
				device->device;
			if (device->subvendor == DEV_ANY_ID)
				ndiswrapper_pci_devices[num_pci].subvendor =
					PCI_ANY_ID;
			else
				ndiswrapper_pci_devices[num_pci].subvendor =
					device->subvendor;
			if (device->subdevice == DEV_ANY_ID)
				ndiswrapper_pci_devices[num_pci].subdevice =
					PCI_ANY_ID;
			else
				ndiswrapper_pci_devices[num_pci].subdevice =
					device->subdevice;
			ndiswrapper_pci_devices[num_pci].class = 0;
			ndiswrapper_pci_devices[num_pci].class_mask = 0;
			ndiswrapper_pci_devices[num_pci].driver_data =
				num_pci + num_usb;
			num_pci++;
			DBGTRACE1("pci device %d added", num_pci);
			DBGTRACE1("adding %04x:%04x:%04x:%04x to pci idtable",
				  device->vendor, device->device,
				  device->subvendor, device->subdevice);
		} else if (device->bustype == NDIS_USB_BUS) {
			ndiswrapper_usb_devices[num_usb].idVendor =
				device->vendor;
			ndiswrapper_usb_devices[num_usb].idProduct =
				device->device;
			ndiswrapper_usb_devices[num_usb].match_flags =
				USB_DEVICE_ID_MATCH_DEVICE;
			ndiswrapper_usb_devices[num_usb].driver_info =
				num_pci + num_usb;
			num_usb++;
			DBGTRACE1("usb device %d added", num_usb);
			DBGTRACE1("adding %04x:%04x to usb idtable",
				  device->vendor, device->device);
		}
	}

	if (ndiswrapper_pci_devices) {
		memset(&ndiswrapper_pci_driver, 0,
			       sizeof(ndiswrapper_pci_driver));
		ndiswrapper_pci_driver.name = DRIVER_NAME;
		ndiswrapper_pci_driver.id_table = ndiswrapper_pci_devices;
		ndiswrapper_pci_driver.probe = ndiswrapper_add_one_pci_dev;
		ndiswrapper_pci_driver.remove =
			__devexit_p(ndiswrapper_remove_one_pci_dev);
		ndiswrapper_pci_driver.suspend = ndiswrapper_suspend_pci;
		ndiswrapper_pci_driver.resume = ndiswrapper_resume_pci;
		res = pci_register_driver(&ndiswrapper_pci_driver);
		if (res < 0) {
			ERROR("couldn't register ndiswrapper pci driver");
			goto err;
		}
	}
	if (ndiswrapper_usb_devices) {
		memset(&ndiswrapper_usb_driver, 0,
			       sizeof(ndiswrapper_usb_driver));
		ndiswrapper_usb_driver.owner = THIS_MODULE;
		ndiswrapper_usb_driver.name = DRIVER_NAME;
		ndiswrapper_usb_driver.id_table = ndiswrapper_usb_devices;
		ndiswrapper_usb_driver.probe = ndiswrapper_add_one_usb_dev;
		ndiswrapper_usb_driver.disconnect =
			ndiswrapper_remove_one_usb_dev;
		res = usb_register(&ndiswrapper_usb_driver);
		if (res < 0) {
			ERROR("couldn't register ndiswrapper usb driver");
			goto err;
		}
	}

	vfree(devices);
	TRACEEXIT1(return 0);

err:
	if (ndis_devices)
		vfree(ndis_devices);
	ndis_devices = NULL;
	if (ndiswrapper_usb_devices)
		kfree(ndiswrapper_usb_devices);
	ndiswrapper_usb_devices = NULL;
	if (ndiswrapper_pci_devices)
		kfree(ndiswrapper_pci_devices);
	ndiswrapper_pci_devices = NULL;
	if (devices)
		vfree(devices);
	TRACEEXIT1(return -EINVAL);
}

static int wrapper_ioctl(struct inode *inode, struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	struct load_driver *load_driver;
	struct load_devices devices;
	int res;

	TRACEENTER1("cmd: %u (%lu, %lu)", cmd,
		    (unsigned long)NDIS_REGISTER_DEVICES, 
		    (unsigned long)NDIS_LOAD_DRIVER);

	res = 0;
	switch (cmd) {
	case NDIS_REGISTER_DEVICES:
		DBGTRACE1("adding devices at %p", (void *)arg);
		res = copy_from_user(&devices, (void *)arg, sizeof(devices));
		if (!res)
			res = register_devices(&devices);
		if (res)
			TRACEEXIT1(return -EINVAL);
		TRACEEXIT1(return 0);
		break;
	case NDIS_LOAD_DRIVER:
		DBGTRACE1("loading driver at %p", (void *)arg);
		load_driver = vmalloc(sizeof(*load_driver));
		if (!load_driver)
			TRACEEXIT1(return -ENOMEM);
		res = copy_from_user(load_driver, (void *)arg,
				     sizeof(*load_driver));
		if (!res)
			res = load_ndis_driver(load_driver);
		vfree(load_driver);
		if (res)
			TRACEEXIT1(return -EINVAL);
		else
			TRACEEXIT1(return 0);
		break;
	default:
		ERROR("Unknown ioctl %u", cmd);
		TRACEEXIT1(return -EINVAL);
		break;
	}

	TRACEEXIT1(return 0);
}

static int wrapper_ioctl_release(struct inode *inode, struct file *file)
{
	TRACEENTER1("");
	return 0;
}

static struct file_operations wrapper_fops = {
	.owner          = THIS_MODULE,
	.ioctl		= wrapper_ioctl,
	.release	= wrapper_ioctl_release,
};

static struct miscdevice wrapper_misc = {
	.name   = DRIVER_NAME,
	.fops   = &wrapper_fops
};

int loader_init(void)
{
	int err;

	INIT_LIST_HEAD(&ndis_drivers);
	spin_lock_init(&loader_lock);
	if ((err = misc_register(&wrapper_misc)) < 0 ) {
		ERROR("couldn't register module (%d)", err);
		TRACEEXIT1(return err);
	}
	TRACEEXIT1(return 0);
}

void loader_exit(void)
{
	int i;

	TRACEENTER1("");
	misc_deregister(&wrapper_misc);

	if (ndiswrapper_usb_devices) {
		usb_deregister(&ndiswrapper_usb_driver);
		kfree(ndiswrapper_usb_devices);
		ndiswrapper_usb_devices = NULL;
	}
	if (ndiswrapper_pci_devices) {
		pci_unregister_driver(&ndiswrapper_pci_driver);
		kfree(ndiswrapper_pci_devices);
		ndiswrapper_pci_devices = NULL;
	}
	spin_lock(&loader_lock);
	if (ndis_devices) {
		for (i = 0; i < num_ndis_devices; i++)
			unload_ndis_device(&ndis_devices[i]);

		vfree(ndis_devices);
		ndis_devices = NULL;
	}

	while (!list_empty(&ndis_drivers)) {
		struct ndis_driver *driver;

		driver = list_entry(ndis_drivers.next,
				    struct ndis_driver, list);
		list_del(&driver->list);
		unload_ndis_driver(driver);
	}
	spin_unlock(&loader_lock);
	TRACEEXIT1(return);
}
