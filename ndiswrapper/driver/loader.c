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
#include "pe_linker.h"
#include "wrapper.h"

/* List of loaded drivers */
LIST_HEAD(ndis_driverlist);
static struct ndis_spinlock driverlist_lock;

/*
 * Called by PCI-subsystem for each PCI-card found.
 *
 * This function should not be marked __devinit because ndiswrapper
 * adds PCI_id's dynamically.
 */
static int ndis_init_one_pci(struct pci_dev *pdev,
		      const struct pci_device_id *ent)
{
	int res = 0;
	struct ndis_device *device = (struct ndis_device *) ent->driver_data;
	struct ndis_driver *driver = device->driver;
	struct ndis_handle *handle;
	struct net_device *dev;
	struct miniport_char *miniport;

	TRACEENTER1("%04x:%04x:%04x:%04x", ent->vendor, ent->device,
		    ent->subvendor, ent->subdevice);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	dev = ndis_init_netdev(&handle, device, driver, &pdev->dev);
#else
	dev = ndis_init_netdev(&handle, device, driver, NULL);
#endif
	if (!dev) {
		printk(KERN_ERR "Unable to alloc etherdev\n");
		res = -ENOMEM;
		goto out_nodev;
	}

	handle->dev.pci = pdev;
	pci_set_drvdata(pdev, handle);

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

	DBGTRACE1("%s", "Calling ndis init routine");
	if ((res = miniport_init(handle))) {
		ERROR("Windows driver couldn't initialize the device (%08X)",
			res);
		res = -EINVAL;
		goto out_start;
	}

	handle->hw_status = 0;
	handle->wrapper_work = 0;

	/* do we need to power up the card explicitly? */
	miniport_set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D0);
	miniport = &handle->driver->miniport_char;
	/* According NDIS, pnp_event_notify should be called whenever power
	 * is set to D0
	 * Only NDIS 5.1 drivers are required to supply this function; some
	 * drivers don't seem to support it (at least Orinoco)
	 */
	/*
	if (miniport->pnp_event_notify) {
		INFO("%s", "calling pnp_event_notify");
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
		ERROR("%s", "Couldn't setup interface");
		res = -EINVAL;
		goto out_setup;
	}
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
 * Called by USB-subsystem for each USB device found.
 *
 * This function should not be marked __devinit because ndiswrapper
 * adds id's dynamically.
 */
#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int ndis_init_one_usb(struct usb_interface *intf,
			     const struct usb_device_id *usb_id)
#else
static void *ndis_init_one_usb(struct usb_device *udev, unsigned int ifnum,
			       const struct usb_device_id *usb_id)
#endif
{
	int res;
	struct ndis_device *device =
		(struct ndis_device *)usb_id->driver_info;
	struct ndis_driver *driver = device->driver;
	struct ndis_handle *handle;
	struct net_device *dev;
	struct miniport_char *miniport;
//	unsigned long profile_inf = NDIS_POWER_PROFILE_AC;

	TRACEENTER1("%04x:%04x\n", usb_id->idVendor, usb_id->idProduct);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	dev = ndis_init_netdev(&handle, device, driver, &intf->dev);
#else
	dev = ndis_init_netdev(&handle, device, driver, NULL);
#endif
	if (!dev) {
		ERROR("%s", "Unable to alloc etherdev\n");
		res = -ENOMEM;
		goto out_nodev;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	handle->dev.usb = interface_to_usbdev(intf);
	handle->intf    = intf;
	usb_set_intfdata(intf, handle);
#else
	handle->dev.usb = udev;
#endif

	TRACEENTER1("%s", "Calling ndis init routine");
	if ((res = miniport_init(handle))) {
		ERROR("Windows driver couldn't initialize the device (%08X)",
			res);
		res = -EINVAL;
		goto out_start;
	}

	handle->hw_status = 0;
	handle->wrapper_work = 0;

	/* do we need to power up the card explicitly? */
	miniport_set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D0);
	miniport = &handle->driver->miniport_char;
	/*
	if (miniport->pnp_event_notify) {
		INFO("%s", "calling pnp_event_notify");
		miniport->pnp_event_notify(handle->adapter_ctx, NDIS_PNP_PROFILE_CHANGED,
					 &profile_inf, sizeof(profile_inf));
		INFO("%s", "done");
	}
	*/

	miniport_reset(handle);
	/* wait here seems crucial; without this delay, at least
	 * prism54 driver crashes (why?) */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(3*HZ);

	if (setup_dev(handle->net_dev)) {
		ERROR("%s", "Couldn't setup interface");
		res = -EINVAL;
		goto out_setup;
	}

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
#endif /* CONFIG_USB */

/*
 * Remove one PCI-card.
 */
static void __devexit ndis_remove_one_pci(struct pci_dev *pdev)
{
	struct ndis_handle *handle =
		(struct ndis_handle *)pci_get_drvdata(pdev);

	TRACEENTER1("");

	ndis_remove_one(handle);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

/*
 * Remove one USB device.
 */
#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static void __devexit ndis_remove_one_usb(struct usb_interface *intf)
{
	struct ndis_handle *handle =
		(struct ndis_handle *)usb_get_intfdata(intf);

	TRACEENTER1("");

	ndis_remove_one(handle);
}
#else
static void __devexit ndis_remove_one_usb(struct usb_device *udev, void *ptr)
{
	struct ndis_handle *handle = (struct ndis_handle *)ptr;

	TRACEENTER1("");

	ndis_remove_one(handle);
}
#endif
#endif /* CONFIG_USB */

/* load the driver from userspace. */
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
		DBGTRACE1("image size: %d bytes",
			  load_driver->sys_files[i].size);

		pe_image->image = vmalloc(load_driver->sys_files[i].size);
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

/* load a file from userspace and put on list of files. */
static int load_bin_files(struct ndis_driver *driver,
			  struct load_driver *load_driver)
{
	struct ndis_bin_file **bin_files;
	int i;

	TRACEENTER1("loading bin files for driver %s", load_driver->name);
	bin_files = kmalloc(load_driver->nr_bin_files * sizeof(*bin_files),
			    GFP_KERNEL);
	if (!bin_files) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return -ENOMEM);
	}
	memset(bin_files, 0, sizeof(*bin_files));

	driver->nr_bin_files = 0;
	for (i = 0; i < load_driver->nr_bin_files; i++) {
		struct ndis_bin_file *bin_file;
		struct load_driver_file *load_bin_file =
			&load_driver->bin_files[i];

		bin_file = kmalloc(sizeof(*bin_file), GFP_KERNEL);
		if (!bin_file) {
			ERROR("couldn't allocate memory");
			break;
		}
		memset(bin_file, 0, sizeof(*bin_file));

		memcpy(bin_file->name, load_bin_file->name,
		       MAX_DRIVER_NAME_LEN);
		bin_file->size = load_bin_file->size;

		bin_file->data = vmalloc(load_bin_file->size);
		if (!bin_file->data) {
			ERROR("cound't allocate memory");
			kfree(bin_file);
			break;
		}

		if (copy_from_user(bin_file->data, load_bin_file->data,
				   load_bin_file->size)) {
			ERROR("couldn't load file %s", load_bin_file->name);
			kfree(bin_file->data);
			kfree(bin_file);
			continue;
		}

		DBGTRACE2("loaded bin file %s", bin_file->name);
		bin_files[driver->nr_bin_files] = bin_file;
		driver->nr_bin_files++;
	}
	if (driver->nr_bin_files < load_driver->nr_bin_files) {
		for (i = 0; i < driver->nr_bin_files; i++) {
			vfree(bin_files[i]->data);
			kfree(bin_files[i]);
		}
		kfree(bin_files);
		driver->nr_bin_files = 0;
		TRACEEXIT1(return -EINVAL);
	} else {
		driver->bin_files = bin_files;
		TRACEEXIT1(return 0);
	}
}

static int load_settings(struct ndis_device *device,
			 struct load_device *load_device)
{
	int i, nr_settings;

	TRACEENTER1("");

	nr_settings = 0;
	for (i = 0; i < load_device->nr_settings; i++) {
		struct load_device_setting *load_setting =
			&load_device->settings[i];
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

		if (strcmp(setting->name, "ndis_version") == 0) {
			memcpy(device->driver->version, setting->value,
			       MAX_NDIS_SETTING_VALUE_LEN);
		}
		list_add(&setting->list, &device->settings);
		nr_settings++;
	}
	/* it is not a fatal error if some settings couldn't be loaded */
	if (nr_settings > 0)
		TRACEEXIT1(return 0);
	else
		TRACEEXIT1(return -EINVAL);
}

/* add devices handled by driver */
static int load_devices(struct ndis_driver *driver,
			struct load_driver *load_driver)
{
	struct ndis_device **devices;
	int i;

	TRACEENTER1("");
	devices = kmalloc(load_driver->nr_devices * sizeof(*devices),
			  GFP_KERNEL);
	if (!devices) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return -ENOMEM);
	}
	memset(devices, 0, sizeof(*devices));

	driver->nr_devices = 0;
	for (i = 0; i < load_driver->nr_devices; i++) {
		struct load_device *load_device;
		struct ndis_device *device;

		load_device = &load_driver->devices[i];
		if ((driver->bustype >= 0) &&
		    (driver->bustype != load_device->bustype)) {
			ERROR("Each driver can only support a single bustype");
			continue;
		}

		if (load_device->bustype != NDIS_USB_BUS &&
		    load_device->bustype != NDIS_PCI_BUS) {
			ERROR("invalid device type %d", load_device->bustype);
			continue;
		}

		device = kmalloc(sizeof(*device), GFP_KERNEL);
		if (!device) {
			ERROR("couldn't allocate memory");
			break;
		}
		memset(device, 0, sizeof(*device));
		device->bustype = load_device->bustype;
		device->vendor = load_device->vendor;
		device->device = load_device->device;
		device->pci_subvendor = load_device->pci_subvendor;
		device->pci_subdevice = load_device->pci_subdevice;
		device->fuzzy = load_device->fuzzy;
		device->driver = driver;

		INIT_LIST_HEAD(&device->settings);
		if (load_settings(device, load_device)) {
			kfree(device);
			continue;
		}
		driver->bustype = device->bustype;
		devices[driver->nr_devices] = device;
		driver->nr_devices++;
	}

	/* it is not a fatal error if some devices couldn't be loaded */
	if (driver->nr_devices > 0) {
		driver->devices = devices;
		TRACEEXIT1(return 0);
	} else {
		kfree(devices);
		TRACEEXIT1(return -EINVAL);
	}
}

/* Delete a driver. This implies deleting all cards for the handle too. */
static void unload_ndis_driver(struct ndis_driver *driver)
{
	int i;

	TRACEENTER1("unloading driver %s", driver->name);
	if (driver->dev_registered) {
		if (driver->bustype == NDIS_PCI_BUS)
			pci_unregister_driver(&driver->driver.pci);
#ifdef CONFIG_USB
		else
			usb_deregister(&driver->driver.usb);
#endif
	}
#ifdef DEBUG_CRASH_ON_INIT
	if (driver->bustype == NDIS_PCI_BUS) {
		struct pci_dev *pdev = 0;
		pdev = pci_find_device(driver->idtable.pci[0].vendor,
				       driver->idtable.pci[0].device, pdev);
		if (pdev)
			ndis_remove_one_pci(pdev);
	}
#endif
	ndis_spin_lock(&driverlist_lock);
	if (driver->list.next)
		list_del(&driver->list);
	ndis_spin_unlock(&driverlist_lock);

	/* idtable for both pci and usb devices */
	if (driver->idtable.pci)
		kfree(driver->idtable.pci);

	for (i = 0; i < driver->num_pe_images; i++)
		if (driver->pe_images[i].image)
			vfree(driver->pe_images[i].image);

	for (i = 0; i < driver->nr_bin_files; i++) {
		vfree(driver->bin_files[i]->data);
		kfree(driver->bin_files[i]);
	}
	kfree(driver->bin_files);

	for (i = 0; i < driver->nr_devices; i++) {
		struct ndis_device *device = driver->devices[i];
		struct list_head *cur, *tmp;

		list_for_each_safe(cur, tmp, &device->settings) {
			struct device_setting *setting =
				(struct device_setting *)cur;
			struct ndis_config_param *param =
				&setting->config_param;

			if (param->type == NDIS_CONFIG_PARAM_STRING)
				RtlFreeUnicodeString(&param->data.ustring);

			kfree(setting);
		}
		kfree(device);
	}
	kfree(driver->devices);

	kfree(driver);
}

static unsigned int call_entry(struct ndis_driver *driver)
{
	int i, ret, res;
	struct ustring reg_string;
	char *reg_path = "\0\0t0m0p0";

	reg_string.buf = reg_path;
	reg_string.buflen = reg_string.len = strlen(reg_path);
	for (ret = res = 0, i = 0; i < driver->num_pe_images; i++)
		/* dlls are already started by loader */
		if (driver->pe_images[i].type == COFF_CHAR_IMAGE) {
			unsigned int (*entry)(void *obj,
					      struct ustring *p2) STDCALL;
			entry = driver->pe_images[i].entry;
			TRACEENTER1("Calling NDIS driver entry at %08X "
				    "rva(%08X)",
				    (int)entry,
				    (int)entry -
				    (int)driver->pe_images[i].image);
			DBGTRACE1("entry: %p, %p", entry, *entry);
			res = entry((void*)driver, &reg_string);
			ret |= res;
			DBGTRACE1("entry returns %08X", res);
			DBGTRACE1("Past entry: Version: %d.%dn",
				  driver->miniport_char.majorVersion,
				  driver->miniport_char.minorVersion);
			/* Dump addresses of driver suppoled callbacks */
#if defined DEBUG && DEBUG >= 1
			if (res == 0) {
				int j;
				int *adr;
				char *name[] = {
					"CheckForHangTimer",
					"DisableInterruptHandler",
					"EnableInterruptHandler",
					"halt",
					"HandleInterruptHandler",
					"init",
					"ISRHandler",
					"query",
					"ReconfigureHandler",
					"ResetHandler",
					"SendHandler",
					"SetInformationHandler",
					"TransferDataHandler",
					"ReturnPacketHandler",
					"SendPacketsHandler",
					"AllocateCompleteHandler",
				};

				adr = (int*) &driver->miniport_char.hangcheck;

				for (j = 0; j < 16; j++)
					DBGTRACE1("%08X (rva %08X):%s", adr[j],
						  adr[j] ? adr[j] -
						  (int)driver->pe_images[i].image : 0,
						  name[j]);
			}
#endif
		}
	return ret;
}

/* register driver with pci/usb subsystem. */
static int start_driver(struct ndis_driver *driver)
{
	int i, res;
	struct ndis_device *device;

	TRACEENTER1("");
	if (driver->dev_registered) {
		ERROR("driver %s already registered", driver->name);
		TRACEEXIT1(return -EINVAL);
	}

	res = call_entry(driver);
	if (res) {
		ERROR("driver initialization failed: %08X", res);
		TRACEEXIT1(return -EINVAL);
	}

	if (driver->bustype == NDIS_PCI_BUS) {
		driver->idtable.pci =
			kmalloc(sizeof(struct pci_device_id) *
				(driver->nr_devices+1), GFP_KERNEL);
		if (!driver->idtable.pci)
			TRACEEXIT1(return -ENOMEM);
		memset(driver->idtable.pci, 0,
			sizeof(struct pci_device_id) * (driver->nr_devices+1));

		for (i = 0; i < driver->nr_devices; i++) {
			device = driver->devices[i];

			driver->idtable.pci[i].vendor = device->vendor;
			driver->idtable.pci[i].device = device->device;
			driver->idtable.pci[i].subvendor =
				device->pci_subvendor;
			driver->idtable.pci[i].subdevice =
				device->pci_subdevice;
			driver->idtable.pci[i].class = 0;
			driver->idtable.pci[i].class_mask = 0;
			driver->idtable.pci[i].driver_data =
				(unsigned long) device;

			DBGTRACE1("Adding %04x:%04x:%04x:%04x to pci idtable",
			          device->vendor, device->device,
			          device->pci_subvendor,
			          device->pci_subdevice);
		}

		memset(&driver->driver.pci, 0, sizeof(driver->driver.pci));
		driver->driver.pci.name = driver->name;
		driver->driver.pci.id_table = driver->idtable.pci;
		driver->driver.pci.probe = ndis_init_one_pci;
		driver->driver.pci.remove = __devexit_p(ndis_remove_one_pci);
		driver->driver.pci.suspend = ndis_suspend_pci;
		driver->driver.pci.resume = ndis_resume_pci;
#ifndef DEBUG_CRASH_ON_INIT
		res = pci_module_init(&driver->driver.pci);
		if (res) {
			ERROR("couldn't register driver %s", driver->name);
			TRACEEXIT1(return -EINVAL);
		} else {
			driver->dev_registered = 1;
			TRACEEXIT1(return 0);
		}
#endif
	} else if (driver->bustype == NDIS_USB_BUS) {
#ifdef CONFIG_USB
		driver->idtable.usb =
			kmalloc(sizeof(struct usb_device_id) *
			        (driver->nr_devices+1), GFP_KERNEL);
		if (!driver->idtable.usb)
			TRACEEXIT1(return -ENOMEM);
		memset(driver->idtable.usb, 0,
		       sizeof(struct usb_device_id) * (driver->nr_devices+1));

		for (i = 0; i < driver->nr_devices; i++) {
			device = driver->devices[i];
			driver->idtable.usb[i].match_flags =
				USB_DEVICE_ID_MATCH_DEVICE;
			driver->idtable.usb[i].idVendor = device->vendor;
			driver->idtable.usb[i].idProduct = device->device;
			driver->idtable.usb[i].driver_info =
				(unsigned long) device;

			DBGTRACE1("Adding %04x:%04x to usb idtable\n",
			          device->vendor, device->device);
		}

		memset(&driver->driver.usb, 0, sizeof(driver->driver.usb));
		driver->driver.usb.name = driver->name;
		driver->driver.usb.id_table = driver->idtable.usb;
		driver->driver.usb.probe = ndis_init_one_usb;
		driver->driver.usb.disconnect =
			__devexit_p(ndis_remove_one_usb);
		res = usb_register(&driver->driver.usb);
		if (res) {
			ERROR("couldn't register driver %s", driver->name);
			TRACEEXIT1(return -EINVAL);
		} else {
			driver->dev_registered = 1;
			TRACEEXIT1(return 0);
		}
#else
		printk(KERN_ERR "driver %s requires USB support, but USB "
		       "is not supported in this kernel", driver->name);
		TRACEEXIT1(return -EINVAL);
#endif
	} else {
		printk(KERN_ERR "bus type %d of driver %s unsupported\n",
		       driver->bustype, driver->name);
		TRACEEXIT1(return -EINVAL);
	}

	TRACEEXIT1(return -EINVAL);
}

/*
 * add driver to list of loaded driver but make sure this driver is
 * not loaded before.
 */
static int add_driver(struct ndis_driver *driver)
{
	struct ndis_driver *tmp;
	int dup = 0;

	TRACEENTER1("");
	ndis_spin_lock(&driverlist_lock);
	list_for_each_entry(tmp, &ndis_driverlist, list) {
		if (strcmp(tmp->name, driver->name) == 0) {
			dup = 1;
			break;
		}
	}

	if (!dup)
		list_add(&driver->list, &ndis_driverlist);
	ndis_spin_unlock(&driverlist_lock);

	if (dup) {
		ERROR("cannot add duplicate driver");
		TRACEEXIT1(return -EBUSY);
	}

	TRACEEXIT1(return 0);
}

static int load_ndis_driver(struct load_driver *load_driver)
{
	struct ndis_driver *ndis_driver;

	ndis_driver = kmalloc(sizeof(struct ndis_driver), GFP_KERNEL);
	if (!ndis_driver) {
		ERROR("coudln't allocate memory");
		TRACEEXIT1(return -EINVAL);
	}
	memset(ndis_driver, 0, sizeof(*ndis_driver));
	ndis_driver->bustype = -1;

	if (load_devices(ndis_driver, load_driver) ||
	    load_sys_files(ndis_driver, load_driver) ||
	    load_bin_files(ndis_driver, load_driver) ||
	    add_driver(ndis_driver) ||
	    start_driver(ndis_driver)) {
		unload_ndis_driver(ndis_driver);
		TRACEEXIT1(return -EINVAL);
	} else
		TRACEEXIT1(return 0);
}

static int wrapper_ioctl(struct inode *inode, struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	struct load_driver *load_driver;
	int res;

	TRACEENTER1("cmd: %u (%u)", cmd, NDIS_ADD_DRIVER);

	res = 0;
	switch (cmd) {
	case NDIS_ADD_DRIVER:
		DBGTRACE1("loading driver at %p", (void *)arg);
		load_driver = vmalloc(sizeof(*load_driver));
		if (!load_driver)
			TRACEEXIT1(return -ENOMEM);
		res = copy_from_user(load_driver, (void *)arg,
				     sizeof(struct load_driver));
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
	.name   = DRV_NAME,
	.fops   = &wrapper_fops
};

int loader_init(void)
{
	int err;

	ndis_spin_lock_init(&driverlist_lock);
	if ((err = misc_register(&wrapper_misc)) < 0 ) {
		ERROR("couldn't register module (%d)", err);
		TRACEEXIT1(return err);
	}
	TRACEEXIT(return 0);
}

void loader_exit(void)
{
	struct ndis_driver *driver;

	while (!list_empty(&ndis_driverlist)) {
		driver = (struct ndis_driver*) ndis_driverlist.next;
		unload_ndis_driver(driver);
	}

	misc_deregister(&wrapper_misc);
}
