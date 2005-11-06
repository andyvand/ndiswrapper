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

#include "ntoskernel.h"
#include "ndis.h"
#include "wrapper.h"

driver_dispatch_t IopInvalidDeviceRequest;
driver_dispatch_t IopPassIrpDown;
driver_dispatch_t pdoDispatchInternalDeviceControl;
driver_dispatch_t pdoDispatchDeviceControl;
driver_dispatch_t pdoDispatchPnp;
driver_dispatch_t pdoDispatchPower;
driver_dispatch_t IopPassIrpDownAndWait;

NTSTATUS pnp_start_device(struct wrapper_dev *wd);
NTSTATUS pnp_remove_device(struct wrapper_dev *wd);
