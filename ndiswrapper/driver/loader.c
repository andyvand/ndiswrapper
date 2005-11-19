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

#include "ndis.h"
#include "loader.h"
#include "wrapndis.h"
#include "pnp.h"

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

KSPIN_LOCK loader_lock;
struct wrap_device *wrap_devices;
static unsigned int num_wrap_devices;
struct nt_list wrap_drivers;
static struct pci_device_id *wrap_pci_devices;
static struct pci_driver wrap_pci_driver;
#if defined(CONFIG_USB)
static struct usb_device_id *wrap_usb_devices;
static struct usb_driver wrap_usb_driver;
#endif

extern int debug;

/* load driver for given device, if not already loaded */
struct wrap_driver *load_wrap_driver(struct wrap_device *device)
{
	int err, found;
	struct wrap_driver *wrap_driver;
	KIRQL irql;

	TRACEENTER1("device: %04X:%04X:%04X:%04X", device->vendor,
		    device->device, device->subvendor, device->subdevice);
	found = 0;
	wrap_driver = NULL;
	irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(wrap_driver, &wrap_drivers, list) {
		if (strcmp(wrap_driver->name, device->driver->name) == 0) {
			DBGTRACE1("driver %s already loaded",
				  wrap_driver->name);
			found = 1;
			break;
		}
	}
	kspin_unlock_irql(&loader_lock, irql);

	if (found)
		TRACEEXIT1(return wrap_driver);
	else {
		char *argv[] = {"loadndisdriver", 
#if defined DEBUG && DEBUG >= 1
				"1",
#else
				"0",
#endif
				UTILS_VERSION, device->driver->name,
				device->conf_file_name, NULL};
		char *env[] = {NULL};

		DBGTRACE1("loading driver %s", device->driver->name);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
		/* wait for the driver to load and initialize */
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
#endif
		found = 0;
		irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
		nt_list_for_each_entry(wrap_driver, &wrap_drivers, list) {
			if (strcmp(wrap_driver->name,
				   device->driver->name) == 0) {
				found = 1;
				break;
			}
		}
		kspin_unlock_irql(&loader_lock, irql);

		if (!found) {
			ERROR("couldn't load driver '%s'",
			      device->driver->name);
			TRACEEXIT1(return NULL);
		}

		DBGTRACE1("driver %s is loaded", wrap_driver->name);
	}
	TRACEEXIT1(return wrap_driver);
}

/* load the driver files from userspace. */
static int load_sys_files(struct wrap_driver *driver,
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
		pe_image->image =
			__vmalloc(load_driver->sys_files[i].size,
				  GFP_KERNEL | __GFP_HIGHMEM,
				  PAGE_KERNEL_EXECUTABLE);
#elif defined PAGE_KERNEL_EXEC
		pe_image->image =
			__vmalloc(load_driver->sys_files[i].size,
				  GFP_KERNEL | __GFP_HIGHMEM,
				  PAGE_KERNEL_EXEC);
#else
#error x86_64 should have either PAGE_KERNEL_EXECUTABLE or PAGE_KERNEL_EXEC
#endif
#else
		/* hate to play with kernel macros, but PAGE_KERNEL_EXEC is
		 * not available to modules! */
#ifdef cpu_has_nx
		if (cpu_has_nx)
			pe_image->image =
				__vmalloc(load_driver->sys_files[i].size,
					  GFP_KERNEL | __GFP_HIGHMEM,
					  __pgprot(__PAGE_KERNEL & ~_PAGE_NX));
		else
			pe_image->image =
				vmalloc(load_driver->sys_files[i].size);
#else
			pe_image->image =
				vmalloc(load_driver->sys_files[i].size);
#endif
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
		ERROR("couldn't prepare driver '%s'", load_driver->name);
		err = -EINVAL;
	}

	if (driver->num_pe_images < load_driver->nr_sys_files || err) {
		for (i = 0; i < driver->num_pe_images; i++)
			if (driver->pe_images[i].image)
				vfree(driver->pe_images[i].image);
		driver->num_pe_images = 0;
		TRACEEXIT1(return -EINVAL);
	} else
		TRACEEXIT1(return 0);
}

/* load firmware files from userspace */
static int load_bin_files(struct wrap_driver *driver,
			  struct load_driver *load_driver)
{
	struct wrap_bin_file *bin_files;
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
		struct wrap_bin_file *bin_file = &bin_files[i];
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
static int load_settings(struct wrap_driver *wrap_driver,
			 struct load_driver *load_driver)
{
	int i, nr_settings;
	struct wrap_device *wd;
	KIRQL irql;

	TRACEENTER1("");

	wd = NULL;
	irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
	for (i = 0; i < num_wrap_devices; i++) {
		if (strcmp(wrap_devices[i].conf_file_name,
			   load_driver->conf_file_name) == 0) {
			wd = &wrap_devices[i];
			break;
		}
	}
	kspin_unlock_irql(&loader_lock, irql);
	if (!wd) {
		ERROR("conf file %s not found",
		      wrap_devices[i].conf_file_name);
		TRACEEXIT1(return -EINVAL);
	}

	nr_settings = 0;
	for (i = 0; i < load_driver->nr_settings; i++) {
		struct load_device_setting *load_setting =
			&load_driver->settings[i];
		struct wrap_device_setting *setting;

		setting = kmalloc(sizeof(*setting), GFP_KERNEL);
		if (!setting) {
			ERROR("couldn't allocate memory");
			break;
		}
		memset(setting, 0, sizeof(*setting));
		memcpy(setting->name, load_setting->name,
		       MAX_SETTING_NAME_LEN);
		memcpy(setting->value, load_setting->value,
		       MAX_SETTING_VALUE_LEN);
		DBGTRACE2("copied setting %s", load_setting->name);

		if (strcmp(setting->name, "driver_version") == 0)
			memcpy(wrap_driver->version, setting->value,
			       sizeof(wrap_driver->version));
		irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
		InsertTailList(&wd->settings, &setting->list);
		kspin_unlock_irql(&loader_lock, irql);
		nr_settings++;
	}
	/* it is not a fatal error if some settings couldn't be loaded */
	if (nr_settings > 0)
		TRACEEXIT1(return 0);
	else
		TRACEEXIT1(return -EINVAL);
}

/* this function is called while holding load_lock spinlock */
static void unload_wrap_device(struct wrap_device *device)
{
	struct nt_list *cur;
	TRACEENTER1("unloading device %p (%04X:%04X:%04X:%04X), driver %s",
		    device, device->vendor, device->device, device->subvendor,
		    device->subdevice, device->driver->name);

	while ((cur = RemoveHeadList(&device->settings))) {
		struct wrap_device_setting *setting;
		setting = container_of(cur, struct wrap_device_setting, list);
		kfree(setting);
	}
	TRACEEXIT1(return);
}

/* at the time this function is called, devices are deregistered, so
 * safe to remove the driver without any checks */
static void unload_wrap_driver(struct wrap_driver *driver)
{
	int i;
	struct driver_object *drv_obj;

	DBGTRACE1("freeing %d images", driver->num_pe_images);
	drv_obj = driver->drv_obj;
	for (i = 0; i < driver->num_pe_images; i++)
		if (driver->pe_images[i].image) {
			DBGTRACE1("freeing image at %p",
				  driver->pe_images[i].image);
			vfree(driver->pe_images[i].image);
		}

	DBGTRACE1("freeing %d bin files", driver->num_bin_files);
	for (i = 0; i < driver->num_bin_files; i++) {
		DBGTRACE1("freeing image at %p", driver->bin_files[i].data);
		vfree(driver->bin_files[i].data);
	}
	if (driver->bin_files)
		kfree(driver->bin_files);

	RtlFreeUnicodeString(&drv_obj->name);
	/* this frees driver */
	free_custom_ext(drv_obj->drv_ext);
	kfree(drv_obj->drv_ext);
	kfree(drv_obj);
	TRACEEXIT1(return);
}

/* call the entry point of the driver */
static int start_wrap_driver(struct wrap_driver *driver)
{
	int i;
	NTSTATUS ret, res;
	struct driver_object *drv_obj;
	UINT (*entry)(struct driver_object *obj,
		      struct unicode_string *path) STDCALL;

	TRACEENTER1("%s", driver->name);
	drv_obj = driver->drv_obj;
	for (ret = res = 0, i = 0; i < driver->num_pe_images; i++)
		/* dlls are already started by loader */
		if (driver->pe_images[i].type == IMAGE_FILE_EXECUTABLE_IMAGE) {
			entry = driver->pe_images[i].entry;
			drv_obj->start = driver->pe_images[i].entry;
			drv_obj->driver_size = driver->pe_images[i].size;
			DBGTRACE1("entry: %p, %p, drv_obj: %p",
				  entry, *entry, drv_obj);
			res = LIN2WIN2(entry, drv_obj, &drv_obj->name);
			ret |= res;
			DBGTRACE1("entry returns %08X", res);
			break;
		}

	if (ret) {
		ERROR("driver initialization failed: %08X", ret);
		RtlFreeUnicodeString(&drv_obj->name);
		/* this frees ndis_driver */
		free_custom_ext(drv_obj->drv_ext);
		kfree(drv_obj->drv_ext);
		kfree(drv_obj);
		TRACEEXIT1(return -EINVAL);
	}

	TRACEEXIT1(return 0);
}

/*
 * add driver to list of loaded driver but make sure this driver is
 * not loaded before.
 */
static int add_wrap_driver(struct wrap_driver *driver)
{
	KIRQL irql;
	struct wrap_driver *tmp;

	TRACEENTER1("%s", driver->name);
	irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(tmp, &wrap_drivers, list) {
		if (strcmp(tmp->name, driver->name) == 0) {
			kspin_unlock_irql(&loader_lock, irql);
			ERROR("cannot add duplicate driver");
			TRACEEXIT1(return -EBUSY);
		}
	}
	InsertTailList(&wrap_drivers, &driver->list);
	kspin_unlock_irql(&loader_lock, irql);

	TRACEEXIT1(return 0);
}

/* load a driver from userspace and initialize it */
static int load_user_space_driver(struct load_driver *load_driver)
{
	struct driver_object *drv_obj;
	struct ansi_string ansi_reg;
	struct wrap_driver *wrap_driver = NULL;
	int i;

	TRACEENTER1("");
	drv_obj = kmalloc(sizeof(*drv_obj), GFP_KERNEL);
	if (!drv_obj) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return -ENOMEM);
	}
	DBGTRACE1("drv_obj: %p", drv_obj);
	memset(drv_obj, 0, sizeof(*drv_obj));
	drv_obj->drv_ext = kmalloc(sizeof(*(drv_obj->drv_ext)), GFP_KERNEL);
	if (!drv_obj->drv_ext) {
		ERROR("couldn't allocate memory");
		kfree(drv_obj);
		TRACEEXIT1(return -ENOMEM);
	}
	memset(drv_obj->drv_ext, 0, sizeof(*(drv_obj->drv_ext)));
	drv_obj->drv_ext->add_device_func = NdisAddDevice;
	InitializeListHead(&drv_obj->drv_ext->custom_ext);
	DBGTRACE1("");
	if (IoAllocateDriverObjectExtension(drv_obj,
					    (void *)CE_NDIS_DRIVER_CLIENT_ID,
					    sizeof(*wrap_driver),
					    (void **)&wrap_driver) !=
	    STATUS_SUCCESS)
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	DBGTRACE1("driver: %p", wrap_driver);
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->major_func[i] = IopPassIrpDown;
	drv_obj->major_func[IRP_MJ_PNP] = NdisDispatchPnp;
	drv_obj->major_func[IRP_MJ_POWER] = NdisDispatchPower;
	drv_obj->major_func[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
		NdisDispatchDeviceControl;
	drv_obj->major_func[IRP_MJ_DEVICE_CONTROL] =
		NdisDispatchDeviceControl;

	memset(wrap_driver, 0, sizeof(*wrap_driver));
	wrap_driver->bustype = -1;
	wrap_driver->drv_obj = drv_obj;
	strncpy(wrap_driver->name, load_driver->name,
		sizeof(wrap_driver->name));
	ansi_reg.buf = "/tmp";
	ansi_reg.length = strlen(ansi_reg.buf);
	ansi_reg.max_length = ansi_reg.length + 1;
	if (RtlAnsiStringToUnicodeString(&drv_obj->name, &ansi_reg, 1) !=
	    STATUS_SUCCESS) {
		ERROR("couldn't initialize registry path");
		free_custom_ext(drv_obj->drv_ext);
		kfree(drv_obj->drv_ext);
		kfree(drv_obj);
		TRACEEXIT1(return -EINVAL);
	}
	DBGTRACE1("");
	if (load_sys_files(wrap_driver, load_driver) ||
	    load_bin_files(wrap_driver, load_driver) ||
	    load_settings(wrap_driver, load_driver) ||
	    start_wrap_driver(wrap_driver) ||
	    add_wrap_driver(wrap_driver)) {
		unload_wrap_driver(wrap_driver);
		TRACEEXIT1(return -EINVAL);
	} else {
		printk(KERN_INFO "%s: driver %s (%s) loaded\n",
		       DRIVER_NAME, wrap_driver->name, wrap_driver->version);
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
	wrap_pci_devices = NULL;
#if defined(CONFIG_USB)
	wrap_usb_devices = NULL;
#endif
	wrap_devices = NULL;
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
	num_wrap_devices = num_pci + num_usb;
	if (num_pci > 0) {
		wrap_pci_devices =
			kmalloc((num_pci + 1) * sizeof(struct pci_device_id),
				GFP_KERNEL);
		if (!wrap_pci_devices) {
			ERROR("couldn't allocate memory");
			goto err;
		}
		memset(wrap_pci_devices, 0,
		       (num_pci + 1) * sizeof(struct pci_device_id));
	}

#if defined(CONFIG_USB)
	if (num_usb > 0) {
		wrap_usb_devices =
			kmalloc((num_usb + 1) * sizeof(struct usb_device_id),
				GFP_KERNEL);
		if (!wrap_usb_devices) {
			ERROR("couldn't allocate memory");
			goto err;
		}
		memset(wrap_usb_devices, 0,
		       (num_usb + 1) * sizeof(struct usb_device_id));
	}
#endif

	wrap_devices = vmalloc(num_wrap_devices * sizeof(*wrap_devices));
	if (!wrap_devices) {
		ERROR("couldn't allocate memory");
		goto err;
	}

	memset(wrap_devices, 0, num_wrap_devices * sizeof(*wrap_devices));
	num_usb = num_pci = 0;
	for (i = 0; i < load_devices->count; i++) {
		struct load_device *device = &devices[i];
		struct wrap_device *wrap_device;

		wrap_device = &wrap_devices[num_pci + num_usb];

		InitializeListHead(&wrap_device->settings);
		memcpy(&wrap_device->conf_file_name, device->conf_file_name,
		       sizeof(wrap_device->conf_file_name));
		wrap_device->bus_type = device->bustype;

		wrap_device->vendor = device->vendor;
		wrap_device->device = device->device;
		wrap_device->subvendor = device->subvendor;
		wrap_device->subdevice = device->subdevice;

		if (device->bustype == NDIS_PCI_BUS) {
			wrap_pci_devices[num_pci].vendor = device->vendor;
			wrap_pci_devices[num_pci].device = device->device;
			if (device->subvendor == DEV_ANY_ID)
				wrap_pci_devices[num_pci].subvendor =
					PCI_ANY_ID;
			else
				wrap_pci_devices[num_pci].subvendor =
					device->subvendor;
			if (device->subdevice == DEV_ANY_ID)
				wrap_pci_devices[num_pci].subdevice =
					PCI_ANY_ID;
			else
				wrap_pci_devices[num_pci].subdevice =
					device->subdevice;
			wrap_pci_devices[num_pci].class = 0;
			wrap_pci_devices[num_pci].class_mask = 0;
			wrap_pci_devices[num_pci].driver_data =
				num_pci + num_usb;
			num_pci++;
			DBGTRACE1("pci device %d added", num_pci);
			DBGTRACE1("adding %04x:%04x:%04x:%04x to pci idtable",
				  device->vendor, device->device,
				  device->subvendor, device->subdevice);
#ifdef CONFIG_USB
		} else if (device->bustype == NDIS_USB_BUS) {
			wrap_usb_devices[num_usb].idVendor = device->vendor;
			wrap_usb_devices[num_usb].idProduct = device->device;
			wrap_usb_devices[num_usb].match_flags =
				USB_DEVICE_ID_MATCH_DEVICE;
			wrap_usb_devices[num_usb].driver_info =
				num_pci + num_usb;
			num_usb++;
			DBGTRACE1("usb device %d added", num_usb);
			DBGTRACE1("adding %04x:%04x to usb idtable",
				  device->vendor, device->device);
#endif
		} else {
			ERROR("bus type %d not supported", device->bustype);
		}
	}

	if (wrap_pci_devices) {
		memset(&wrap_pci_driver, 0, sizeof(wrap_pci_driver));
		wrap_pci_driver.name = DRIVER_NAME;
		wrap_pci_driver.id_table = wrap_pci_devices;
		wrap_pci_driver.probe = wrap_pnp_start_ndis_pci_device;
		wrap_pci_driver.remove =
			__devexit_p(wrap_pnp_remove_ndis_pci_device);
		wrap_pci_driver.suspend = wrap_pnp_suspend_ndis_pci;
		wrap_pci_driver.resume = wrap_pnp_resume_ndis_pci;
		res = pci_register_driver(&wrap_pci_driver);
		if (res < 0) {
			ERROR("couldn't register pci driver");
			goto err;
		}
	}
#ifdef CONFIG_USB
	if (wrap_usb_devices) {
		memset(&wrap_usb_driver, 0, sizeof(wrap_usb_driver));
		wrap_usb_driver.owner = THIS_MODULE;
		wrap_usb_driver.name = DRIVER_NAME;
		wrap_usb_driver.id_table = wrap_usb_devices;
		wrap_usb_driver.probe = wrap_pnp_start_ndis_usb_device;
		wrap_usb_driver.disconnect = wrap_pnp_remove_ndis_usb_device;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
		wrap_usb_driver.suspend = wrap_pnp_suspend_ndis_usb;
		wrap_usb_driver.resume = wrap_pnp_resume_ndis_usb;
#endif
		res = usb_register(&wrap_usb_driver);
		if (res < 0) {
			ERROR("couldn't register usb driver");
			goto err;
		}
	}
#endif

	vfree(devices);
	TRACEEXIT1(return 0);

err:
	if (wrap_devices)
		vfree(wrap_devices);
	wrap_devices = NULL;
#if defined(CONFIG_USB)
	if (wrap_usb_devices)
		kfree(wrap_usb_devices);
	wrap_usb_devices = NULL;
#endif
	if (wrap_pci_devices)
		kfree(wrap_pci_devices);
	wrap_pci_devices = NULL;
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
			res = load_user_space_driver(load_driver);
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
	.minor	= MISC_DYNAMIC_MINOR,
	.fops   = &wrapper_fops
};

int loader_init(void)
{
	int err;

	InitializeListHead(&wrap_drivers);
	kspin_lock_init(&loader_lock);
	if ((err = misc_register(&wrapper_misc)) < 0 ) {
		ERROR("couldn't register module (%d)", err);
		TRACEEXIT1(return err);
	}
	TRACEEXIT1(return 0);
}

void loader_exit(void)
{
	int i;
	struct nt_list *cur;

	TRACEENTER1("");
	misc_deregister(&wrapper_misc);

	for (i = 0; i < num_wrap_devices; i++)
		set_bit(HW_RMMOD, &wrap_devices[i].hw_status);
#ifdef CONFIG_USB
	if (wrap_usb_devices) {
		usb_deregister(&wrap_usb_driver);
		kfree(wrap_usb_devices);
		wrap_usb_devices = NULL;
	}
#endif
	if (wrap_pci_devices) {
		pci_unregister_driver(&wrap_pci_driver);
		kfree(wrap_pci_devices);
		wrap_pci_devices = NULL;
	}
	kspin_lock(&loader_lock);
	if (wrap_devices) {
		for (i = 0; i < num_wrap_devices; i++)
			unload_wrap_device(&wrap_devices[i]);

		vfree(wrap_devices);
		wrap_devices = NULL;
	}

	while ((cur = RemoveHeadList(&wrap_drivers))) {
		struct wrap_driver *driver;

		driver = container_of(cur, struct wrap_driver, list);
		unload_wrap_driver(driver);
	}
	kspin_unlock(&loader_lock);
	TRACEEXIT1(return);
}
