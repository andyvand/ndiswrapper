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
	/* Bluetooth */
	{0xe0cbf06c, 0xcd8b, 0x4647, },
	/* ivtcorporatino.com's bluetooth device claims this is
	 * bluetooth guid */
	{0xf12d3cf8, 0xb11d, 0x457e, },
};

struct semaphore loader_mutex;
static wait_queue_head_t loader_wq;
static int loader_done;

static struct nt_list wrap_devices;
static struct nt_list wrap_drivers;
static struct pci_device_id wrap_pci_device;
static struct pci_driver wrap_pci_driver;
/* bin_file is used to load binary files */
static struct wrap_bin_file wrap_bin_file;
#if defined(CONFIG_USB)
static struct usb_device_id wrap_usb_device;
struct usb_driver wrap_usb_driver;
#endif

int load_pe_images(struct pe_image[], int n);

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
	int ret;
	struct nt_list *cur;
	struct wrap_driver *wrap_driver;

	TRACEENTER1("device: %04X:%04X:%04X:%04X", wd->vendor, wd->device,
		    wd->subvendor, wd->subdevice);
	if (down_interruptible(&loader_mutex)) {
		WARNING("couldn't obtain loader_mutex");
		TRACEEXIT1(return NULL);
	}
	wrap_driver = NULL;
	nt_list_for_each(cur, &wrap_drivers) {
		wrap_driver = container_of(cur, struct wrap_driver, list);
		if (!strcmp(wrap_driver->name, wd->driver_name)) {
			DBGTRACE1("driver %s already loaded",
				  wrap_driver->name);
			break;
		} else
			wrap_driver = NULL;
	}
	up(&loader_mutex);

	if (!wrap_driver) {
		char *argv[] = {"loadndisdriver", WRAP_CMD_LOAD_DRIVER,
#if defined(DEBUG) && DEBUG >= 1
				"1",
#else
				"0",
#endif
				UTILS_VERSION, wd->driver_name,
				wd->conf_file_name, NULL};
		char *env[] = {NULL};

		DBGTRACE1("loading driver %s", wd->driver_name);
		if (down_interruptible(&loader_mutex)) {
			WARNING("couldn't obtain loader_mutex");
			TRACEEXIT1(return NULL);
		}
		loader_done = 0;
		ret = call_usermodehelper("/sbin/loadndisdriver", argv, env
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
					  , 1
#endif
			);
		if (ret) {
			up(&loader_mutex);
			ERROR("loadndiswrapper failed (%d); check system log "
			      "for messages from 'loadndisdriver'", ret);
			TRACEEXIT1(return NULL);
		}
		if (wait_event_interruptible(loader_wq, loader_done)) {
			up(&loader_mutex);
			TRACEEXIT1(return NULL);
		}
		DBGTRACE1("%s", wd->driver_name);
		wrap_driver = NULL;
		nt_list_for_each(cur, &wrap_drivers) {
			wrap_driver = container_of(cur, struct wrap_driver, list);
			if (!strcmp(wrap_driver->name, wd->driver_name)) {
				wd->driver = wrap_driver;
				break;
			} else
				wrap_driver = NULL;
		}
		up(&loader_mutex);
		if (wrap_driver)
			DBGTRACE1("driver %s is loaded", wrap_driver->name);
		else
			ERROR("couldn't load driver '%s'", wd->driver_name);
	}
	TRACEEXIT1(return wrap_driver);
}

/* load the driver files from userspace. */
static int load_sys_files(struct wrap_driver *driver,
			  struct load_driver *load_driver)
{
	int i, err;

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

	if (down_interruptible(&loader_mutex)) {
		WARNING("couldn't obtain loader_mutex");
		TRACEEXIT1(return NULL);
	}
	driver = NULL;
	nt_list_for_each_entry(cur, &wrap_drivers, list) {
		for (i = 0; i < cur->num_bin_files; i++)
			if (!stricmp(cur->bin_files[i].name, bin_file_name)) {
				driver = cur;
				break;
			}
	}
	up(&loader_mutex);
	if (driver == NULL) {
		DBGTRACE1("coudln't find bin file '%s'", bin_file_name);
		return NULL;
	}

	if (!driver->bin_files[i].data) {
		char *argv[] = {"loadndisdriver", WRAP_CMD_LOAD_BIN_FILE,
#if defined(DEBUG) && DEBUG >= 1
				"1",
#else
				"0",
#endif
				UTILS_VERSION, driver->name,
				bin_file_name, NULL};
		char *env[] = {NULL};
		int ret;

		DBGTRACE1("loading bin file %s/%s", driver->name,
			  bin_file_name);
		if (down_interruptible(&loader_mutex)) {
			WARNING("couldn't obtain loader_mutex");
			TRACEEXIT1(return NULL);
		}
		loader_done = 0;
		ret = call_usermodehelper("/sbin/loadndisdriver", argv, env
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
					  , 1
#endif
			);
		if (ret) {
			up(&loader_mutex);
			ERROR("loadndiswrapper failed (%d); check system log "
			      "for messages from 'loadndisdriver'", ret);
			TRACEEXIT1(return NULL);
		}
		if (wait_event_interruptible(loader_wq, loader_done)) {
			up(&loader_mutex);
			TRACEEXIT1(return NULL);
		}
		up(&loader_mutex);
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

/* load settnigs for a device. called with loader_mutex down */
static int load_settings(struct wrap_driver *wrap_driver,
			 struct load_driver *load_driver)
{
	int i, nr_settings;
	struct wrap_device *wd;
	struct nt_list *cur;

	TRACEENTER1("%p, %p", wrap_driver, load_driver);
	wd = NULL;
	nt_list_for_each(cur, &wrap_devices) {
		wd = container_of(cur, struct wrap_device, list);
		if (strcmp(wd->conf_file_name, load_driver->conf_file_name))
			wd = NULL;
		else
			break;
	}
	if (!wd) {
		ERROR("conf file %s not found", wd->conf_file_name);
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
			int bus_type = WRAP_BUS_TYPE(wd->bus_type);
			int dev_type = wrap_device_type(data1);
			DBGTRACE2("old: %x", wd->bus_type);
			if (dev_type > 0)
				wd->bus_type =
					WRAP_DEVICE_BUS_TYPE(dev_type, bus_type);
			DBGTRACE2("data1: %x, dev type: %x, bus type: %x, "
				  "new: %x\n", data1, dev_type, bus_type,
				  wd->bus_type);
		}
		InsertTailList(&wd->settings, &setting->list);
		nr_settings++;
	}
	/* it is not a fatal error if some settings couldn't be loaded */
	if (nr_settings > 0)
		TRACEEXIT1(return 0);
	else
		TRACEEXIT1(return -EINVAL);
}

void unload_wrap_device(struct wrap_device *wd)
{
	struct nt_list *cur;
	TRACEENTER1("unloading device %p (%04X:%04X:%04X:%04X), driver %s",
		    wd, wd->vendor, wd->device, wd->subvendor,
		    wd->subdevice, wd->driver_name);
	if (down_interruptible(&loader_mutex))
		WARNING("couldn't obtain loader_mutex");
	while ((cur = RemoveHeadList(&wd->settings))) {
		struct wrap_device_setting *setting;
		setting = container_of(cur, struct wrap_device_setting, list);
		kfree(setting);
	}
	RemoveEntryList(&wd->list);
	up(&loader_mutex);
	kfree(wd);
	TRACEEXIT1(return);
}

void unload_wrap_driver(struct wrap_driver *driver)
{
	int i;
	struct driver_object *drv_obj;

	TRACEENTER1("unloading driver: %s (%p)", driver->name, driver);
	DBGTRACE1("freeing %d images", driver->num_pe_images);
	if (down_interruptible(&loader_mutex))
		WARNING("couldn't obtain loader_mutex");
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
	RemoveEntryList(&driver->list);
	/* this frees driver */
	free_custom_extensions(drv_obj->drv_ext);
	kfree(drv_obj->drv_ext);
	up(&loader_mutex);
	DBGTRACE1("drv_obj: %p", drv_obj);

	TRACEEXIT1(return);
}

/* call the entry point of the driver */
static int start_wrap_driver(struct wrap_driver *driver)
{
	int i;
	NTSTATUS ret, res;
	struct driver_object *drv_obj;
	typeof(driver->pe_images[0].entry) entry;

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
 * not loaded before. called with loader_mutex down
 */
static int add_wrap_driver(struct wrap_driver *driver)
{
	struct wrap_driver *tmp;

	TRACEENTER1("name: %s", driver->name);
	nt_list_for_each_entry(tmp, &wrap_drivers, list) {
		if (strcmp(tmp->name, driver->name) == 0) {
			ERROR("cannot add duplicate driver");
			TRACEEXIT1(return -EBUSY);
		}
	}
	InsertHeadList(&wrap_drivers, &driver->list);
	TRACEEXIT1(return 0);
}

/* load a driver from userspace and initialize it. called with
 * loader_mutex down */
static int load_user_space_driver(struct load_driver *load_driver)
{
	struct driver_object *drv_obj;
	struct ansi_string ansi_reg;
	struct wrap_driver *wrap_driver = NULL;

	TRACEENTER1("%p", load_driver);
	drv_obj = allocate_object(sizeof(*drv_obj), OBJECT_TYPE_DRIVER, NULL);
	if (!drv_obj) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return -ENOMEM);
	}
	DBGTRACE1("drv_obj: %p", drv_obj);
	drv_obj->drv_ext = kmalloc(sizeof(*(drv_obj->drv_ext)), GFP_KERNEL);
	if (!drv_obj->drv_ext) {
		ERROR("couldn't allocate memory");
		ObDereferenceObject(drv_obj);
		TRACEEXIT1(return -ENOMEM);
	}
	memset(drv_obj->drv_ext, 0, sizeof(*(drv_obj->drv_ext)));
	InitializeListHead(&drv_obj->drv_ext->custom_ext);
	if (IoAllocateDriverObjectExtension(drv_obj,
					    (void *)WRAP_DRIVER_CLIENT_ID,
					    sizeof(*wrap_driver),
					    (void **)&wrap_driver) !=
	    STATUS_SUCCESS)
		TRACEEXIT1(return -ENOMEM);
	DBGTRACE1("driver: %p", wrap_driver);
	memset(wrap_driver, 0, sizeof(*wrap_driver));
	InitializeListHead(&wrap_driver->list);
	InitializeListHead(&wrap_driver->wrap_devices);
	wrap_driver->drv_obj = drv_obj;
	RtlInitAnsiString(&ansi_reg, "/tmp");
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

/* register drivers for pci and usb */
static void register_devices(void)
{
	int res;

	memset(&wrap_pci_device, 0, sizeof(wrap_pci_device));
	wrap_pci_device.vendor = PCI_ANY_ID;
	wrap_pci_device.device = PCI_ANY_ID;
	wrap_pci_device.subvendor = PCI_ANY_ID;
	wrap_pci_device.subdevice = PCI_ANY_ID;

	memset(&wrap_pci_driver, 0, sizeof(wrap_pci_driver));
	wrap_pci_driver.name = DRIVER_NAME;
	wrap_pci_driver.id_table = &wrap_pci_device;
	wrap_pci_driver.probe = wrap_pnp_start_pci_device;
	wrap_pci_driver.remove = __devexit_p(wrap_pnp_remove_pci_device);
	wrap_pci_driver.suspend = wrap_pnp_suspend_pci_device;
	wrap_pci_driver.resume = wrap_pnp_resume_pci_device;
	res = pci_register_driver(&wrap_pci_driver);
	if (res < 0) {
		ERROR("couldn't register pci driver: %d", res);
		wrap_pci_driver.name = NULL;
	}

#ifdef CONFIG_USB
	memset(&wrap_usb_device, 0, sizeof(wrap_usb_device));
	wrap_usb_device.driver_info = 1;

	memset(&wrap_usb_driver, 0, sizeof(wrap_usb_driver));
	wrap_usb_driver.name = DRIVER_NAME;
	wrap_usb_driver.id_table = &wrap_usb_device;
	wrap_usb_driver.probe = wrap_pnp_start_usb_device;
	wrap_usb_driver.disconnect = __devexit_p(wrap_pnp_remove_usb_device);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	wrap_usb_driver.suspend = wrap_pnp_suspend_usb_device;
	wrap_usb_driver.resume = wrap_pnp_resume_usb_device;
#endif
	res = usb_register(&wrap_usb_driver);
	if (res < 0) {
		ERROR("couldn't register usb driver: %d", res);
		wrap_usb_driver.name = NULL;
	}
#endif
	TRACEEXIT1(return);
}

static void unregister_devices(void)
{
	struct nt_list *cur, *next;

	if (down_interruptible(&loader_mutex))
		WARNING("couldn't obtain loader_mutex");
	nt_list_for_each_safe(cur, next, &wrap_devices) {
		struct wrap_device *wd;
		wd = container_of(cur, struct wrap_device, list);
		wd->surprise_removed = FALSE;
	}
	up(&loader_mutex);

	if (wrap_pci_driver.name)
		pci_unregister_driver(&wrap_pci_driver);
#ifdef CONFIG_USB
	if (wrap_usb_driver.name)
		usb_deregister(&wrap_usb_driver);
#endif
}

struct wrap_device *load_wrap_device(struct load_device *load_device)
{
	int ret;
	struct nt_list *cur;
	struct wrap_device *wd = NULL;
	char vendor[sizeof(int) + 1];
	char device[sizeof(int) + 1];
	char subvendor[sizeof(int) + 1];
	char subdevice[sizeof(int) + 1];

	TRACEENTER1("%04x, %04x, %04x, %04x", load_device->vendor,
		    load_device->device, load_device->subvendor,
		    load_device->subdevice);
	if (sprintf(vendor, "%04x", load_device->vendor) > 0 &&
	    sprintf(device, "%04x", load_device->device) > 0 &&
	    sprintf(subvendor, "%04x", load_device->subvendor) > 0 &&
	    sprintf(subdevice, "%04x", load_device->subdevice) > 0) {
		char *argv[] = {"loadndisdriver", WRAP_CMD_LOAD_DEVICE,
#if defined(DEBUG) && DEBUG >= 1
				"1",
#else
				"0",
#endif
				UTILS_VERSION, vendor, device,
				subvendor, subdevice, NULL};
		char *env[] = {NULL};
		DBGTRACE2("%s, %s, %s, %s", vendor, device,
			  subvendor, subdevice);
		if (down_interruptible(&loader_mutex)) {
			WARNING("couldn't obtain loader_mutex");
			TRACEEXIT1(return NULL);
		}
		loader_done = 0;
		ret = call_usermodehelper("/sbin/loadndisdriver", argv, env
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
					  , 1
#endif
			);
		if (ret) {
			up(&loader_mutex);
			DBGTRACE1("loadndiswrapper failed (%d); check system log "
				  "for messages from 'loadndisdriver'", ret);
			TRACEEXIT1(return NULL);
		}
		if (wait_event_interruptible(loader_wq, loader_done)) {
			DBGTRACE1("wait failed");
			up(&loader_mutex);
			TRACEEXIT1(return NULL);
		}
		wd = NULL;
		nt_list_for_each(cur, &wrap_devices) {
			wd = container_of(cur, struct wrap_device, list);
			DBGTRACE2("%p, %04x, %04x",
				  wd, wd->vendor, wd->device);
			if (wd->vendor == load_device->vendor &&
			    wd->device == load_device->device &&
			    wd->subvendor == load_device->subvendor &&
			    wd->subdevice == load_device->subdevice)
				break;
			else
				wd = NULL;
		}
		up(&loader_mutex);
	} else
		wd = NULL;
	TRACEEXIT1(return wd);
}

static int wrapper_ioctl(struct inode *inode, struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	struct load_driver *load_driver;
	struct load_device load_device;
	struct load_driver_file load_bin_file;
	int ret;

	TRACEENTER1("cmd: %u", cmd);

	ret = 0;
	switch (cmd) {
	case WRAP_IOCTL_LOAD_DEVICE:
		ret = copy_from_user(&load_device, (void *)arg,
				     sizeof(load_device));
		if (ret)
			break;
		DBGTRACE2("%04x, %04x, %04x, %04x", load_device.vendor,
			  load_device.device, load_device.subvendor,
			  load_device.subdevice);
		if (load_device.vendor) {
			struct wrap_device *wd;
			wd = kmalloc(sizeof(*wd), GFP_KERNEL);
			if (!wd) {
				ret = -ENOMEM;
				break;
			}
			memset(wd, 0, sizeof(*wd));
			InitializeListHead(&wd->settings);
			wd->bus_type = load_device.bus_type;
			wd->vendor = load_device.vendor;
			wd->device = load_device.device;
			wd->subvendor = load_device.subvendor;
			wd->subdevice = load_device.subdevice;
			memcpy(wd->conf_file_name, load_device.conf_file_name,
			       sizeof(wd->conf_file_name));
			memcpy(wd->driver_name, load_device.driver_name,
			       sizeof(wd->driver_name));
			/* loader_mutex is already down */
			InsertHeadList(&wrap_devices, &wd->list);
			ret = 0;
		} else
			ret = -EINVAL;
		break;
	case WRAP_IOCTL_LOAD_DRIVER:
		DBGTRACE1("loading driver at %p", (void *)arg);
		load_driver = vmalloc(sizeof(*load_driver));
		if (!load_driver) {
			ret = -ENOMEM;
			break;
		}
		ret = copy_from_user(load_driver, (void *)arg,
				     sizeof(*load_driver));
		if (!ret)
			ret = load_user_space_driver(load_driver);
		vfree(load_driver);
		break;
	case WRAP_IOCTL_LOAD_BIN_FILE:
		ret = copy_from_user(&load_bin_file, (void *)arg,
				     sizeof(load_bin_file));
		if (ret)
			break;
		ret = add_bin_file(&load_bin_file);
		break;
	default:
		ERROR("unknown ioctl %u", cmd);
		ret = -EINVAL;
		break;
	}
	loader_done = 1;
	wake_up(&loader_wq);
	TRACEEXIT1(return ret);
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
	InitializeListHead(&wrap_devices);
	init_MUTEX(&loader_mutex);
	init_waitqueue_head(&loader_wq);
	if ((err = misc_register(&wrapper_misc)) < 0 ) {
		ERROR("couldn't register module (%d)", err);
		unregister_devices();
		TRACEEXIT1(return err);
	}
	register_devices();
	TRACEEXIT1(return 0);
}

void loader_exit(void)
{
	TRACEENTER1("");
	misc_deregister(&wrapper_misc);
	unregister_devices();
	while (1) {
		struct nt_list *entry;
		struct wrap_driver *driver;
		if (down_interruptible(&loader_mutex))
			WARNING("couldn't obtain loader_mutex");
		entry = RemoveHeadList(&wrap_drivers);
		up(&loader_mutex);
		if (!entry)
			break;
		driver = container_of(entry, struct wrap_driver, list);
		DBGTRACE1("%p", driver);
		unload_wrap_driver(driver);
	}
	TRACEEXIT1(return);
}
