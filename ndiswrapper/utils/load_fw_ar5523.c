/* This program is provided under the following conditions
 *
 * Copyright (c) Laurent Goujon - 2005
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <usb.h>
#include <netinet/in.h>

struct {
	int vendor_id;
	int product_id;
} devices[] = {
	/* Netgear WG111U */
	{0x0846, 0x4301},
	/* Netgear WG111T */
	{0x1385, 0x4251},
	/* D-Link DWL-G132 */
	{0x2001, 0x3a03},
	{-1, -1},
};

#define BLOCK_SIZE	0x0800
#define BULK_TIMEOUT	5000
/* ar5523 has 3 endpoints: 0x01, 0x02 and 0x81 */
#define EP1		0x01
#define EP2		0x02
#define EP3		0x81

#define PROG_NAME "load_ar5523"
#define ERROR(fmt, ...) do {						\
		fprintf(stderr, "%s: %s(%d): " fmt "\n",		\
			PROG_NAME, __FUNCTION__, __LINE__ , ## __VA_ARGS__); \
	} while (0)
#define INFO(fmt, ...) do {						\
		fprintf(stdout, "%s: %s(%d): " fmt "\n",		\
			PROG_NAME, __FUNCTION__, __LINE__ , ## __VA_ARGS__); \
	} while (0)

struct cmd_t {
	unsigned int cmd_type;
	unsigned int size;
	unsigned int total_size;
	unsigned int remaining_size;
	char padding[496];
};

static int load_ar5523_fw(char *filename, struct usb_device *dev)
{
	int total_size, remaining_size, res, fd;
	struct cmd_t cmd;
	struct cmd_t answer;
	struct stat firmware_stat;
	char *buffer;
	usb_dev_handle *handle;
	ssize_t read_size;

	buffer = malloc(BLOCK_SIZE);
	if (!buffer) {
		ERROR("couldn't allocate memory");
		return -ENOMEM;
	}
	handle = usb_open(dev);
	if (!handle) {
		ERROR("couldn't open usb device");
		return -EINVAL;
	}
	memset(buffer, 0, BLOCK_SIZE);
	if (usb_set_configuration(handle, 1)) {
		ERROR("error when setting configuration: %s", usb_strerror());
		return -EINVAL;
	}

	if ((res = usb_claim_interface(handle, 0))) {
		if (res == EBUSY)
			ERROR("device is busy");
		if (res == ENOMEM)
			ERROR("couldn't allocate memory");
		ERROR("error when claiming interface: %s", usb_strerror());
		return -EINVAL;
	}

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		ERROR("couldn't open firmware file: %s", strerror(errno));
		return -EINVAL;
	}
	if (fstat(fd, &firmware_stat) == -1) {
		ERROR("error when opening firmware: %s", strerror(errno));
		return -EINVAL;
	}

	cmd.cmd_type = htonl(0x10);
	total_size = firmware_stat.st_size;
	remaining_size = total_size;
	cmd.total_size = htonl(total_size);

	while ((read_size = read(fd, buffer, BLOCK_SIZE)) > 0) {
		remaining_size -= read_size;
		cmd.size = htonl(read_size);
		cmd.remaining_size = htonl(remaining_size);

		res = usb_bulk_write(handle, EP1, (char *)&cmd, sizeof(cmd),
				     BULK_TIMEOUT);
		if (res < 0) {
			ERROR("error writing data: %s", usb_strerror());
			return res;
		}
		res = usb_bulk_write(handle, EP2, buffer, BLOCK_SIZE,
				     BULK_TIMEOUT);
		if (res < 0) {
			ERROR("error writing data: %s", usb_strerror());
			return res;
		}
		res = usb_bulk_read(handle, EP3, (char *)&answer,
				    sizeof(answer), BULK_TIMEOUT);
		if (res < 0) {
			ERROR("error reading data: %s", usb_strerror());
			return res;
		}
	}
	if (remaining_size > 0) {
		ERROR("couldn't load firmware completely - %d bytes left",
		      remaining_size);
		return -EINVAL;
	}
	usb_release_interface(handle, 0);
	usb_close(handle);
	free(buffer);
	return 0;
}

int main(int argc, char *argv[])
{
	struct usb_bus *busses, *bus;
	int max_devnum;
	char *fw_file, *base_name;
	
	if (argc < 2) {
		ERROR("usage: %s <firmware file> [<vendor ID> [<product ID>]]",
		      PROG_NAME);
		return -1;
	}
	fw_file = argv[1];
	base_name = strrchr(fw_file, '/');
	if (base_name)
		base_name++;
	else
		base_name = fw_file;
	if (strcmp(base_name, "ar5523.bin")) {
		ERROR("file %s may not be valid firmware file; "
		      "file name should end with \"ar5523.bin\"", fw_file);
		return -2;
	}
	max_devnum = (sizeof(devices) / sizeof(devices[0])) - 1;
	if (argc > 2)
		devices[max_devnum].vendor_id = strtol(argv[2], NULL, 0);
	if (argc > 3)
		devices[max_devnum].product_id = strtol(argv[3], NULL, 0);

	usb_init();
	usb_find_busses();
	usb_find_devices();

	busses = usb_get_busses();
	for (bus = busses; bus; bus = bus->next) {
		struct usb_device *dev;
		for (dev = bus->devices; dev; dev = dev->next) {
			int j;
			for (j = 0; j < max_devnum + 1; j++) {
				if (dev->descriptor.idVendor ==
				    devices[j].vendor_id &&
				    dev->descriptor.idProduct ==
				    devices[j].product_id) {
					INFO("loading firmware for device "
					     "0x%04X:0x%04X ... ",
					     devices[j].vendor_id,
					     devices[j].product_id);
					if (load_ar5523_fw(fw_file, dev)) {
						INFO("failed");
						return -EINVAL;
					} else {
						INFO("done");
						return 0;
					}
				}
			}
		}
	}
	ERROR("no valid device found");
	return -1;
}
