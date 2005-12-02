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

/*
  Network adapter: ClassGuid = {4d36e972-e325-11ce-bfc1-08002be10318}
  Network client: ClassGuid = {4d36e973-e325-11ce-bfc1-08002be10318}
  PCMCIA adapter: ClassGuid = {4d36e977-e325-11ce-bfc1-08002be10318}
  USB: ClassGuid = {36fc9e60-c465-11cf-8056-444553540000}
*/

/* the indices used here must match macros WRAP_NDIS_DEVICE etc. */
static struct guid class_guids[] = {
	/* Network */
	{0x4d36e972, 0xe325, 0x11ce, },
	/* USB WDM */
	{0x36fc9e60, 0xc465, 0x11cf, },
};

KSPIN_LOCK loader_lock;
struct wrap_device *wrap_devices;
static unsigned int num_wrap_devices;
struct nt_list wrap_drivers;
static struct pci_device_id *wrap_pci_devices;
static struct pci_driver wrap_pci_driver;
/* bin_file is used to load binary files */
static struct wrap_bin_file wrap_bin_file;
#if defined(CONFIG_USB)
static struct usb_device_id *wrap_usb_devices;
struct usb_driver wrap_usb_driver;
#endif

extern int debug;

int wrap_device_type(int data1)
{
	int i;
	for (i = 0; i < sizeof(class_guids) / sizeof(class_guids[0]); i++)
		if (data1 == class_guids[i].data1)
			return i;
	ERROR("unknown device: 0x%x\n", data1);
	return -1;
}

/* load driver for given device, if not already loaded */
struct wrap_driver *load_wrap_driver(struct wrap_device *wd)
{
	int err, found;
	struct wrap_driver *wrap_driver;
	KIRQL irql;

	TRACEENTER1("device: %04X:%04X:%04X:%04X", wd->vendor, wd->device,
		    wd->subvendor, wd->subdevice);
	found = 0;
	wrap_driver = NULL;
	irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(wrap_driver, &wrap_drivers, list) {
		if (strcmp(wrap_driver->name, wd->driver_name) == 0) {
			DBGTRACE1("driver %s already loaded",
				  wrap_driver->name);
			found = 1;
			break;
		}
	}
	kspin_unlock_irql(&loader_lock, irql);

	if (!found) {
		char *argv[] = {"loadndisdriver", WRAP_CMD_LOAD_DRIVER,
#if defined DEBUG && DEBUG >= 1
				"1",
#else
				"0",
#endif
				UTILS_VERSION, wd->driver_name,
				wd->conf_file_name, NULL};
		char *env[] = {NULL};

		DBGTRACE1("loading driver %s", wd->driver_name);
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
		DBGTRACE1("%s", wd->driver_name);
		irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
		nt_list_for_each_entry(wrap_driver, &wrap_drivers, list) {
			if (!strcmp(wrap_driver->name, wd->driver_name)) {
				wd->driver = wrap_driver;
				found = 1;
				break;
			}
		}
		kspin_unlock_irql(&loader_lock, irql);
		if (!found) {
			ERROR("couldn't load driver '%s'", wd->driver_name);
			TRACEEXIT1(return NULL);
		}
		DBGTRACE1("driver %s is loaded", wrap_driver->name);
	}

	irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
	InsertTailList(&wrap_driver->wrap_devices, &wd->list);
	kspin_unlock_irql(&loader_lock, irql);
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
	strncpy(driver->name, load_driver->name, MAX_DRIVER_NAME_LEN);
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

struct wrap_bin_file *get_bin_file(char *bin_file_name)
{
	int i = 0;
	struct wrap_driver *driver, *cur;
	KIRQL irql;

	driver = NULL;
	irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(cur, &wrap_drivers, list) {
		for (i = 0; i < cur->num_bin_files; i++)
			if (!stricmp(cur->bin_files[i].name, bin_file_name)) {
				driver = cur;
				break;
			}
	}
	kspin_unlock_irql(&loader_lock, irql);
	if (driver == NULL) {
		DBGTRACE1("coudln't find bin file '%s'", bin_file_name);
		return NULL;
	}
	
	if (!driver->bin_files[i].data) {
		char *argv[] = {"loadndisdriver", WRAP_CMD_LOAD_BIN_FILE,
#if defined DEBUG && DEBUG >= 1
				"1",
#else
				"0",
#endif
				UTILS_VERSION, driver->name,
				bin_file_name, NULL};
		char *env[] = {NULL};
		int err;

		DBGTRACE1("loading bin file %s/%s", driver->name,
			  bin_file_name);
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
		DBGTRACE2("bin file: %s/%s",
			  wrap_bin_file.driver_name, wrap_bin_file.name);
		if (stricmp(driver->bin_files[i].name, wrap_bin_file.name) ||
		    strcmp(driver->name, wrap_bin_file.driver_name)) {
			ERROR("invalid bin file: %s/%s",
			      wrap_bin_file.driver_name, wrap_bin_file.name);
			free_bin_file(&wrap_bin_file);
			TRACEEXIT2(return NULL);
		}
		memcpy(&driver->bin_files[i], &wrap_bin_file,
		       sizeof(wrap_bin_file));
	}
	TRACEEXIT2(return &(driver->bin_files[i]));
}

static int add_bin_file(struct load_driver_file *driver_file)
{
	memcpy(wrap_bin_file.name, driver_file->name,
	       sizeof(wrap_bin_file.name));
	memcpy(wrap_bin_file.driver_name, driver_file->driver_name,
	       sizeof(wrap_bin_file.driver_name));
	wrap_bin_file.size = driver_file->size;
	wrap_bin_file.data = vmalloc(wrap_bin_file.size);
	if (!wrap_bin_file.data) {
		ERROR("couldn't allocate memory");
		return -ENOMEM;
	}
	if (copy_from_user(wrap_bin_file.data, driver_file->data,
			   wrap_bin_file.size)) {
		ERROR("couldn't copy data");
		return -EINVAL;
	}
	return 0;
}

void free_bin_file(struct wrap_bin_file *bin_file)
{
	DBGTRACE2("unloading %s", bin_file->name);
	if (bin_file->data)
		vfree(bin_file->data);
	bin_file->data = NULL;
	bin_file->size = 0;
	TRACEEXIT2(return);
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
		memcpy(bin_file->driver_name, load_bin_file->driver_name,
		       MAX_DRIVER_NAME_LEN);
		DBGTRACE2("loaded bin file %s", bin_file->name);
		driver->num_bin_files++;
	}
	if (driver->num_bin_files < load_driver->nr_bin_files) {
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
		ULONG data1;

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
		DBGTRACE2("setting %s=%s", setting->name, setting->value);

		if (strcmp(setting->name, "driver_version") == 0)
			memcpy(wrap_driver->version, setting->value,
			       sizeof(wrap_driver->version));
		else if (strcmp(setting->name, "class_guid") == 0 &&
			   (sscanf(setting->value, "%x", &data1) == 1)) {
			int bus_type = WRAP_BUS_TYPE(wd->dev_bus_type);
			int dev_type = wrap_device_type(data1);
			DBGTRACE2("old: %x", wd->dev_bus_type);
			if (dev_type > 0)
				wd->dev_bus_type =
					WRAP_DEVICE_BUS_TYPE(dev_type,
							     bus_type);
			DBGTRACE2("data1: %x, dev type: %x, bus type: %x, "
				  "new: %x\n",
				  data1, dev_type, bus_type, wd->dev_bus_type);
		}
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
static void unload_wrap_device(struct wrap_device *wd)
{
	struct nt_list *cur;
	TRACEENTER1("unloading device %p (%04X:%04X:%04X:%04X), driver %s",
		    wd, wd->vendor, wd->device, wd->subvendor,
		    wd->subdevice, wd->driver_name);

	while ((cur = RemoveHeadList(&wd->settings))) {
		struct wrap_device_setting *setting;
		setting = container_of(cur, struct wrap_device_setting, list);
		kfree(setting);
	}
	InitializeListHead(&wd->list);
	TRACEEXIT1(return);
}

void unload_wrap_driver(struct wrap_driver *driver)
{
	int i;
	struct driver_object *drv_obj;
	struct nt_list *cur, *next;

	TRACEENTER1("unloading driver: %s (%p)", driver->name, driver);
	RemoveEntryList(&driver->list);
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
		if (driver->bin_files[i].data)
			vfree(driver->bin_files[i].data);
	}
	if (driver->bin_files)
		kfree(driver->bin_files);

	RtlFreeUnicodeString(&drv_obj->name);
	nt_list_for_each_safe(cur, next, &driver->wrap_devices) {
		struct wrap_device *wd;
		wd = container_of(cur, struct wrap_device, list);
		RemoveEntryList(&wd->list);
	}
	/* this frees driver */
	free_custom_extensions(drv_obj->drv_ext);
	kfree(drv_obj->drv_ext);
	DBGTRACE1("drv_obj: %p", drv_obj);
		
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
		free_custom_extensions(drv_obj->drv_ext);
		kfree(drv_obj->drv_ext);
		DBGTRACE1("drv_obj: %p", drv_obj);
		ObDereferenceObject(drv_obj);
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

	TRACEENTER1("name: %s", driver->name);
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

	TRACEENTER1("");
	drv_obj = allocate_object(sizeof(*drv_obj), OBJECT_TYPE_DRIVER,
				  load_driver->name);
	if (!drv_obj) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return -ENOMEM);
	}
	DBGTRACE1("drv_obj: %p", drv_obj);
	drv_obj->drv_ext = kmalloc(sizeof(*(drv_obj->drv_ext)), GFP_KERNEL);
	if (!drv_obj->drv_ext) {
		ERROR("couldn't allocate memory");
		kfree(drv_obj);
		TRACEEXIT1(return -ENOMEM);
	}
	memset(drv_obj->drv_ext, 0, sizeof(*(drv_obj->drv_ext)));
	InitializeListHead(&drv_obj->drv_ext->custom_ext);
	DBGTRACE1("");
	if (IoAllocateDriverObjectExtension(drv_obj,
					    (void *)CE_WRAP_DRIVER_CLIENT_ID,
					    sizeof(*wrap_driver),
					    (void **)&wrap_driver) !=
	    STATUS_SUCCESS)
		TRACEEXIT1(return -ENOMEM);
	DBGTRACE1("driver: %p", wrap_driver);
	memset(wrap_driver, 0, sizeof(*wrap_driver));
	InitializeListHead(&wrap_driver->list);
	InitializeListHead(&wrap_driver->wrap_devices);
	wrap_driver->drv_obj = drv_obj;
	ansi_reg.buf = "/tmp";
	ansi_reg.length = strlen(ansi_reg.buf);
	ansi_reg.max_length = ansi_reg.length + 1;
	if (RtlAnsiStringToUnicodeString(&drv_obj->name, &ansi_reg, TRUE) !=
	    STATUS_SUCCESS) {
		ERROR("couldn't initialize registry path");
		free_custom_extensions(drv_obj->drv_ext);
		kfree(drv_obj->drv_ext);
		DBGTRACE1("drv_obj: %p", drv_obj);
		ObDereferenceObject(drv_obj);
		TRACEEXIT1(return -EINVAL);
	}
	strncpy(wrap_driver->name, load_driver->name,
		sizeof(wrap_driver->name));
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
		if (wrap_is_pci_bus(devices[i].bus_type))
			num_pci++;
		else if (wrap_is_usb_bus(devices[i].bus_type))
			num_usb++;
		else
			WARNING("bus type %d (%d) for %s is not valid",
				devices[i].bus_type,
				WRAP_BUS_TYPE(devices[i].bus_type),
				devices[i].conf_file_name);
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
		struct wrap_device *wd;

		wd = &wrap_devices[num_pci + num_usb];
		InitializeListHead(&wd->list);
		InitializeListHead(&wd->settings);
		strncpy(wd->driver_name, device->driver_name,
			sizeof(wd->driver_name));
		memcpy(&wd->conf_file_name, device->conf_file_name,
		       sizeof(wd->conf_file_name));
		wd->dev_bus_type =
			WRAP_DEVICE_BUS_TYPE(0, device->bus_type);

		wd->vendor = device->vendor;
		wd->device = device->device;
		wd->subvendor = device->subvendor;
		wd->subdevice = device->subdevice;

		if (wrap_is_pci_bus(device->bus_type)) {
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
			DBGTRACE1("adding %04x:%04x:%04x:%04x (%s) to pci: %d",
				  device->vendor, device->device,
				  device->subvendor, device->subdevice,
				  device->driver_name, num_pci);
			num_pci++;
#ifdef CONFIG_USB
		} else if (wrap_is_usb_bus(device->bus_type)) {
			wrap_usb_devices[num_usb].idVendor = device->vendor;
			wrap_usb_devices[num_usb].idProduct = device->device;
			wrap_usb_devices[num_usb].match_flags =
				USB_DEVICE_ID_MATCH_DEVICE;
			wrap_usb_devices[num_usb].driver_info =
				num_pci + num_usb;
			DBGTRACE1("adding %04x:%04x (%s) to usb: %d",
				  device->vendor, device->device,
				  device->driver_name, num_usb);
			num_usb++;
#endif
		} else {
			ERROR("type %d not supported: %s",
			      device->bus_type, device->conf_file_name);
		}
	}

	if (wrap_pci_devices) {
		memset(&wrap_pci_driver, 0, sizeof(wrap_pci_driver));
		wrap_pci_driver.name = DRIVER_NAME;
		wrap_pci_driver.id_table = wrap_pci_devices;
		wrap_pci_driver.probe = wrap_pnp_start_pci_device;
		wrap_pci_driver.remove =
			__devexit_p(wrap_pnp_remove_pci_device);
		wrap_pci_driver.suspend = wrap_pnp_suspend_pci_device;
		wrap_pci_driver.resume = wrap_pnp_resume_pci_device;
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
		wrap_usb_driver.probe = wrap_pnp_start_usb_device;
		wrap_usb_driver.disconnect = wrap_pnp_remove_usb_device;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
		wrap_usb_driver.suspend = wrap_pnp_suspend_usb_device;
		wrap_usb_driver.resume = wrap_pnp_resume_usb_device;
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
	struct load_driver_file load_bin_file;
	int res;

	TRACEENTER1("cmd: %u", cmd);

	res = 0;
	switch (cmd) {
	case WRAP_IOCTL_REGISTER_DEVICES:
		DBGTRACE1("adding devices at %p", (void *)arg);
		res = copy_from_user(&devices, (void *)arg, sizeof(devices));
		if (!res)
			res = register_devices(&devices);
		break;
	case WRAP_IOCTL_LOAD_DRIVER:
		DBGTRACE1("loading driver at %p", (void *)arg);
		load_driver = vmalloc(sizeof(*load_driver));
		if (!load_driver)
			TRACEEXIT1(return -ENOMEM);
		res = copy_from_user(load_driver, (void *)arg,
				     sizeof(*load_driver));
		if (!res)
			res = load_user_space_driver(load_driver);
		vfree(load_driver);
		break;
	case WRAP_IOCTL_LOAD_BIN_FILE:
		res = copy_from_user(&load_bin_file, (void *)arg,
				     sizeof(load_bin_file));
		if (res)
			break;
		res = add_bin_file(&load_bin_file);
		break;
	default:
		ERROR("Unknown ioctl %u", cmd);
		res = -EINVAL;
		break;
	}
	TRACEEXIT1(return res);
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
	struct nt_list *cur, *next;

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

	nt_list_for_each_safe(cur, next, &wrap_drivers) {
		struct wrap_driver *driver;

		driver = container_of(cur, struct wrap_driver, list);
		unload_wrap_driver(driver);
	}
	kspin_unlock(&loader_lock);
	TRACEEXIT1(return);
}
