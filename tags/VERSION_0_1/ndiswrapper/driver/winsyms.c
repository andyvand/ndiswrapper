/*
 *  Copyright (C) 2003 Pontus Fuchs
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
#include <linux/string.h>

/* Ndis */
void NdisInitializeWrapper(void);
void NdisTerminateWrapper(void);
void NdisMRegisterMiniport(void);
void NdisAllocateMemory(void);
void NdisAllocateMemoryWithTag(void);
void NdisFreeMemory(void);
void NdisWriteErrorLogEntry(void);
void NdisOpenConfiguration(void);
void NdisCloseConfiguration(void);
void NdisReadConfiguration(void);
void NdisWritePciSlotInformation(void);
void NdisWritePcmciaAttributeMemory(void);
void NdisFreeBuffer(void);
void NdisMFreeSharedMemory(void);
void NdisMAllocateSharedMemory(void);
void NdisAdjustBufferLength(void);
void NdisInitAnsiString(void);
void NdisMUnmapIoSpace(void);
void NdisFreeSpinLock(void);
void NdisMFreeMapRegisters(void);
void NdisFreeBufferPool(void);
void NdisFreePacketPool(void);
void NdisMDeregisterAdapterShutdownHandler(void);
void NdisMDeregisterInterrupt(void);
void NdisAcquireSpinLock(void);
void NdisReleaseSpinLock(void);
void NdisMSynchronizeWithInterrupt(void);
void NdisFreePacket(void);
void NdisAllocateBuffer(void);
void NdisAllocatePacket(void);
void NdisReadNetworkAddress(void);
void NdisOpenConfigurationKeyByName(void);
void NdisWriteConfiguration(void);
void NdisAnsiStringToUnicodeString(void);
void NdisSetTimer(void);
void NdisMSetPeriodicTimer(void);
void NdisMCancelTimer(void);
void NdisMMapIoSpace(void);
void NdisMQueryAdapterResources(void);
void NdisQueryBuffer(void);
void NDIS_BUFFER_TO_SPAN_PAGES(void);
void NdisQueryBufferOffset(void);
void NdisMInitializeTimer(void);
void NdisMRegisterInterrupt(void);
void NdisMRegisterAdapterShutdownHandler(void);
void NdisAllocateBufferPool(void);
void NdisAllocatePacketPool(void);
void NdisMAllocateMapRegisters(void);
void NdisAllocateSpinLock(void);
void NdisReadPciSlotInformation(void);
void NdisReadPcmciaAttributeMemory(void);
void NdisMGetDeviceProperty(void);
void NdisMSetAttributesEx(void);
void NdisIndicateStatus(void);
void NdisIndicateStatusComplete(void);
void NdisMIndicateReceivePacket(void);
void NdisMSendComplete(void);

void NdisMRegisterIoPortRange(void);
void NdisInterlockedDecrement(void);
void NdisGetCurrentSystemTime(void);
void NdisMDeregisterIoPortRange(void);
void NdisWaitEvent(void);
void NdisDprAcquireSpinLock(void);
void NdisDprReleaseSpinLock(void);
void NdisInterlockedIncrement(void);
void NdisSetEvent(void);
void NdisMInitializeScatterGatherDma(void);
void NdisSystemProcessorCount(void);
void NdisInitializeEvent(void);
void NdisMGetDmaAlignment(void);
void NdisUnicodeStringToAnsiString(void);

/* Cipe */
void DbgPrint(void);

/* HAL */
void KfAcquireSpinLock(void);
void KfReleaseSpinLock(void);
void KeStallExecutionProcessor(void);

/* ntoskern */
void InterlockedExchange(void);
void MmMapLockedPages(void);
void RtlAnsiStringToUnicodeString(void);
void RtlEqualUnicodeString(void);
void IoDeleteSymbolicLink(void);
void KeInitializeSpinLock(void);
void ExAllocatePoolWithTag(void);
void RtlUnicodeStringToAnsiString(void);
void IoCreateDevice(void);
void RtlFreeUnicodeString(void);
void IoDeleteDevice(void);
void IoCreateSymbolicLink(void);
void ExFreePool(void);
void RtlUnwind(void);
void IofCompleteRequest(void);
void IoReleaseCancelSpinLock(void);
void WRITE_REGISTER_UCHAR(void);
void WRITE_REGISTER_ULONG(void);
void WRITE_REGISTER_USHORT(void);
void my_strncpy(void);
void KeInitializeEvent(void);
void IoBuildSynchronousFsdRequest(void);
void IofCallDriver(void);
void KeWaitForSingleObject(void);
void my_sprintf(void);


struct winsym
{
	char *name;
	void *adr;
};
#define func(x, y) {x, &y}

static struct winsym syms[] = {

/* Ndis */
func("NdisWritePciSlotInformation"          , NdisWritePciSlotInformation),
func("NdisFreeMemory"                       , NdisFreeMemory),
func("NdisAllocateMemory"                   , NdisAllocateMemory),
func("NdisAllocateMemoryWithTag"            , NdisAllocateMemoryWithTag),
func("NdisWritePcmciaAttributeMemory"       , NdisWritePcmciaAttributeMemory),
func("NdisFreeBuffer"                       , NdisFreeBuffer),
func("NdisMFreeSharedMemory"                , NdisMFreeSharedMemory),
func("NdisMAllocateSharedMemory"            , NdisMAllocateSharedMemory),
func("NdisInitializeWrapper"                , NdisInitializeWrapper),
func("NdisAdjustBufferLength"               , NdisAdjustBufferLength),
func("NdisInitAnsiString"                   , NdisInitAnsiString),
func("NdisMUnmapIoSpace"                    , NdisMUnmapIoSpace),
func("NdisFreeSpinLock"                     , NdisFreeSpinLock),
func("NdisMFreeMapRegisters"                , NdisMFreeMapRegisters),
func("NdisFreeBufferPool"                   , NdisFreeBufferPool),
func("NdisFreePacketPool"                   , NdisFreePacketPool),
func("NdisMDeregisterAdapterShutdownHandler", NdisMDeregisterAdapterShutdownHandler),
func("NdisMDeregisterInterrupt"             , NdisMDeregisterInterrupt),
func("NdisAcquireSpinLock"                  , NdisAcquireSpinLock),
func("NdisReleaseSpinLock"                  , NdisReleaseSpinLock),
func("NdisMSynchronizeWithInterrupt"        , NdisMSynchronizeWithInterrupt),
func("NdisFreePacket"                       , NdisFreePacket),
func("NdisAllocateBuffer"                   , NdisAllocateBuffer),
func("NdisWriteErrorLogEntry"               , NdisWriteErrorLogEntry),
func("NdisAllocatePacket"                   , NdisAllocatePacket),
func("NdisReadConfiguration"                , NdisReadConfiguration),
func("NdisReadNetworkAddress"               , NdisReadNetworkAddress),
func("NdisCloseConfiguration"               , NdisCloseConfiguration),
func("NdisOpenConfigurationKeyByName"       , NdisOpenConfigurationKeyByName),
func("NdisWriteConfiguration"               , NdisWriteConfiguration),
func("NdisAnsiStringToUnicodeString"        , NdisAnsiStringToUnicodeString),
func("NdisOpenConfiguration"                , NdisOpenConfiguration),
func("NdisSetTimer"                         , NdisSetTimer),
func("NdisMSetPeriodicTimer"                , NdisMSetPeriodicTimer),
func("NdisMCancelTimer"                     , NdisMCancelTimer),
func("NdisMMapIoSpace"                      , NdisMMapIoSpace),
func("NdisMQueryAdapterResources"           , NdisMQueryAdapterResources),
func("NdisQueryBuffer"                      , NdisQueryBuffer),
func("NDIS_BUFFER_TO_SPAN_PAGES"            , NDIS_BUFFER_TO_SPAN_PAGES),
func("NdisQueryBufferOffset"                , NdisQueryBufferOffset),
func("NdisMInitializeTimer"                 , NdisMInitializeTimer),
func("NdisMRegisterInterrupt"               , NdisMRegisterInterrupt),
func("NdisMRegisterAdapterShutdownHandler"  , NdisMRegisterAdapterShutdownHandler),
func("NdisAllocateBufferPool"               , NdisAllocateBufferPool),
func("NdisAllocatePacketPool"               , NdisAllocatePacketPool),
func("NdisMAllocateMapRegisters"            , NdisMAllocateMapRegisters),
func("NdisAllocateSpinLock"                 , NdisAllocateSpinLock),
func("NdisReadPciSlotInformation"           , NdisReadPciSlotInformation),
func("NdisReadPcmciaAttributeMemory"        , NdisReadPcmciaAttributeMemory),
func("NdisMGetDeviceProperty"               , NdisMGetDeviceProperty),
func("NdisMSetAttributesEx"                 , NdisMSetAttributesEx),
func("NdisTerminateWrapper"                 , NdisTerminateWrapper),
func("NdisMRegisterMiniport"                , NdisMRegisterMiniport),


func("NdisMRegisterIoPortRange"             , NdisMRegisterIoPortRange),
func("NdisInterlockedDecrement"             , NdisInterlockedDecrement),
func("NdisGetCurrentSystemTime"             , NdisGetCurrentSystemTime),
func("NdisMDeregisterIoPortRange"           , NdisMDeregisterIoPortRange),
func("NdisWaitEvent"                        , NdisWaitEvent),
func("NdisDprAcquireSpinLock"               , NdisDprAcquireSpinLock),
func("NdisDprReleaseSpinLock"               , NdisDprReleaseSpinLock),
func("NdisInterlockedIncrement"             , NdisInterlockedIncrement),
func("NdisSetEvent"                         , NdisSetEvent),
func("NdisMInitializeScatterGatherDma"      , NdisMInitializeScatterGatherDma),
func("NdisSystemProcessorCount"             , NdisSystemProcessorCount),
func("NdisInitializeEvent"                  , NdisInitializeEvent),

func("NdisMGetDmaAlignment"                 , NdisMGetDmaAlignment),
func("NdisUnicodeStringToAnsiString"        , NdisUnicodeStringToAnsiString),

/* HAL */
func("KfAcquireSpinLock"                    , KfAcquireSpinLock),
func("KfReleaseSpinLock"                    , KfReleaseSpinLock),
func("KeStallExecutionProcessor"            , KeStallExecutionProcessor),

/* ntoskernel */
func("InterlockedExchange"                  , InterlockedExchange),
func("MmMapLockedPages"                     , MmMapLockedPages),
func("RtlAnsiStringToUnicodeString"         , RtlAnsiStringToUnicodeString),
func("RtlEqualUnicodeString"                , RtlEqualUnicodeString),
func("IoDeleteSymbolicLink"                 , IoDeleteSymbolicLink),
func("KeInitializeSpinLock"                 , KeInitializeSpinLock),
func("ExAllocatePoolWithTag"                , ExAllocatePoolWithTag),
func("RtlUnicodeStringToAnsiString"         , RtlUnicodeStringToAnsiString),
func("IoCreateDevice"                       , IoCreateDevice),
func("RtlFreeUnicodeString"                 , RtlFreeUnicodeString),
func("IoDeleteDevice"                       , IoDeleteDevice),
func("IoCreateSymbolicLink"                 , IoCreateSymbolicLink),
func("ExFreePool"                           , ExFreePool),
func("RtlUnwind"                            , RtlUnwind),
func("IofCompleteRequest"                   , IofCompleteRequest),
func("IoReleaseCancelSpinLock"              , IoReleaseCancelSpinLock),
func("WRITE_REGISTER_ULONG"                 , WRITE_REGISTER_ULONG),
func("WRITE_REGISTER_USHORT"                , WRITE_REGISTER_USHORT),
func("WRITE_REGISTER_UCHAR"                 , WRITE_REGISTER_UCHAR),
func("strncpy"                              , my_strncpy),
func("KeInitializeEvent"                    , KeInitializeEvent),
func("IoBuildSynchronousFsdRequest"         , IoBuildSynchronousFsdRequest),
func("IofCallDriver"                        , IofCallDriver),
func("KeWaitForSingleObject"                , KeWaitForSingleObject),
func("sprintf"                              , my_sprintf),


/* CIPE */
func("DbgPrint"          , DbgPrint),

{0, 0}
};


void *get_winsym(char *name)
{
	int i = 0;

	while(syms[i].name)
	{
		if(strcmp(syms[i].name, name)== 0)
		{
			return syms[i].adr;
		}

		i++;
	}
	return 0;
}
