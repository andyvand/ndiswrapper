#ifndef __KERNEL__
#include <string.h>
#endif

#include <linux/string.h>
#include "ndis.h"
#include "ndis_funcs.h"
#include "misc_funcs.h"

struct winsym
{
	char *name;
	void *adr;
};

#define func(x, y) {x, &y}
static struct winsym syms[] = {
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

//HAL
func("KfAcquireSpinLock"                    , KfAcquireSpinLock),
func("KfReleaseSpinLock"                    , KfReleaseSpinLock),
func("KeStallExecutionProcessor"            , KeStallExecutionProcessor),

//ntoskernel
func("InterlockedExchange"                  , InterlockedExchange),
func("MmMapLockedPages"                     , MmMapLockedPages),
func("RtlAnsiStringToUnicodeString"         , RtlAnsiStringToUnicodeString),
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
func("strncpy"                              , my_strncpy),
func("KeInitializeEvent"                    , KeInitializeEvent),
func("IoBuildSynchronousFsdRequest"         , IoBuildSynchronousFsdRequest),
func("IofCallDriver"                        , IofCallDriver),
func("KeWaitForSingleObject"                , KeWaitForSingleObject),
func("sprintf"                              , my_sprintf),

//CIPE
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
