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
void NdisMPciAssignResources(void);
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

void NdisResetEvent(void);
void NdisInitializeString(void);
void NdisMSleep(void);
void NdisUnchainBufferAtBack(void);
void NdisQueryBufferSafe(void);
void NdisGetFirstBufferFromPacketSafe(void);
void NdisUnchainBufferAtFront(void);
void NdisScheduleWorkItem(void);

void NdisMapFile(void);
void NdisCloseFile(void);
void NdisOpenFile(void);
void NdisGetSystemUpTime(void);
void NdisUnmapFile(void);
void NdisGetBufferPhysicalArraySize(void);

void NdisMSetAttributes(void);
void EthFilterDprIndicateReceiveComplete(void);
void EthFilterDprIndicateReceive(void);
//void NdisMSendComplete(void);
void NdisMStartBufferPhysicalMapping(void);
void NdisMCompleteBufferPhysicalMapping(void);

void NdisBufferVirtualAddress(void);
void NdisBufferLength(void);
void NdisAllocatePacketPoolEx(void);
void NdisPacketPoolUsage(void);

void IoIsWdmVersionAvailable(void);
void NdisMRegisterDevice(void);
void NdisMDeregisterDevice(void);
void NdisCancelTimer(void);
void NdisInitializeTimer(void);
void NdisMRemoveMiniport(void);

/* Cipe */
void DbgPrint(void);

/* HAL */
void KfAcquireSpinLock(void);
void KfReleaseSpinLock(void);
void KeStallExecutionProcessor(void);
void KeGetCurrentIrql(void);
void WRITE_PORT_ULONG(void);
void READ_PORT_ULONG(void);
void WRITE_PORT_USHORT(void);
void READ_PORT_USHORT(void);
void WRITE_PORT_UCHAR(void);
void READ_PORT_UCHAR(void);
void WRITE_PORT_BUFFER_USHORT(void);
void READ_PORT_BUFFER_USHORT(void);

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
void my_vsprintf(void);
void my_strlen(void);
void my_strncmp(void);
void my_strcmp(void);
void my_tolower(void);
void my_memcpy(void);
void my_strcpy(void);
void my_memset(void);
void my_memmove(void);
void my_srand(void);
void my_atoi(void);

void RtlCopyUnicodeString(void);

void RtlCompareMemory(void);
void _alldiv(void);
void _aulldiv(void);
void _allmul(void);
void _aullmul(void);
void _allrem(void);
void _aullrem(void);
void _allshr(void);
void _aullshr(void);
void _allshl(void);
void _aullshl(void);

void ExDeleteNPagedLookasideList(void);
void ExInitializeNPagedLookasideList(void);
void ExInterlockedPopEntrySList(void);
void ExInterlockedPushEntrySList(void);
void ExInterlockedAddLargeStatistic(void);
void MmMapIoSpace(void);
void MmUnmapIoSpace(void);
void KeInitializeTimer(void);
void KeInitializeDpc(void);
void KeSetTimerEx(void);
void KeCancelTimer(void);
void DbgBreakPoint(void);
void rand(void);

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
func("NdisMPciAssignResources"              , NdisMPciAssignResources),
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

func("NdisMapFile"			    , NdisMapFile),
func("NdisCloseFile"			    , NdisCloseFile),
func("NdisOpenFile"			    , NdisOpenFile),
func("NdisGetSystemUpTime"		    , NdisGetSystemUpTime),
func("NdisUnmapFile"			    , NdisUnmapFile),
func("NdisGetBufferPhysicalArraySize"	    , NdisGetBufferPhysicalArraySize),


func("NdisResetEvent"                       , NdisResetEvent),
func("NdisInitializeString"                 , NdisInitializeString),
func("NdisMSleep"                           , NdisMSleep),
func("NdisUnchainBufferAtBack"              , NdisUnchainBufferAtBack),
func("NdisQueryBufferSafe"                  , NdisQueryBufferSafe),
func("NdisGetFirstBufferFromPacketSafe"     , NdisGetFirstBufferFromPacketSafe),
func("NdisUnchainBufferAtFront"             , NdisUnchainBufferAtFront),
func("NdisScheduleWorkItem"                 , NdisScheduleWorkItem),
func("NdisMSetAttributes"                   , NdisMSetAttributes),
func("EthFilterDprIndicateReceiveComplete"  , EthFilterDprIndicateReceiveComplete),
func("EthFilterDprIndicateReceive"          , EthFilterDprIndicateReceive),
func("NdisMSendComplete"                    , NdisMSendComplete),
func("NdisMStartBufferPhysicalMapping"      , NdisMStartBufferPhysicalMapping),
func("NdisMCompleteBufferPhysicalMapping"   , NdisMCompleteBufferPhysicalMapping),

func("NdisBufferVirtualAddress"             , NdisBufferVirtualAddress),
func("NdisBufferLength"                     , NdisBufferLength),
func("NdisAllocatePacketPoolEx"             , NdisAllocatePacketPoolEx),
func("NdisPacketPoolUsage"                  , NdisPacketPoolUsage),
func("IoIsWdmVersionAvailable"              , IoIsWdmVersionAvailable),
func("NdisMRegisterDevice"                  , NdisMRegisterDevice),
func("NdisMDeregisterDevice"                , NdisMDeregisterDevice),
func("NdisCancelTimer"                      , NdisCancelTimer),
func("NdisInitializeTimer"                  , NdisInitializeTimer),
func("NdisMRemoveMiniport"                  , NdisMRemoveMiniport),


/* HAL */
func("KfAcquireSpinLock"                    , KfAcquireSpinLock),
func("KfReleaseSpinLock"                    , KfReleaseSpinLock),
func("KeStallExecutionProcessor"            , KeStallExecutionProcessor),
func("KeGetCurrentIrql"                     , KeGetCurrentIrql),

func("WRITE_PORT_ULONG"                     , WRITE_PORT_ULONG),
func("READ_PORT_ULONG"                      , READ_PORT_ULONG),
func("WRITE_PORT_USHORT"                    , WRITE_PORT_USHORT),
func("READ_PORT_USHORT"                     , READ_PORT_USHORT),
func("WRITE_PORT_UCHAR"                     , WRITE_PORT_UCHAR),
func("READ_PORT_UCHAR"                      , READ_PORT_UCHAR),
func("WRITE_PORT_BUFFER_USHORT"             , WRITE_PORT_BUFFER_USHORT),
func("READ_PORT_BUFFER_USHORT"              , READ_PORT_BUFFER_USHORT),

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
func("vsprintf"                             , my_vsprintf),
func("strlen"                               , my_strlen),
func("strncmp"                              , my_strncmp),
func("strcmp"                               , my_strcmp),
func("tolower"                              , my_tolower),
func("memcpy"                               , my_memcpy),
func("strcpy"                               , my_strcpy),
func("memset"                               , my_memset),
func("memmove"                              , my_memmove),
func("srand"                                , my_srand),
func("atoi"                                 , my_atoi),

func("RtlCopyUnicodeString"		    , RtlCopyUnicodeString),
func("RtlCompareMemory"                     , RtlCompareMemory),

func("_alldiv"                              , _alldiv),
func("_aulldiv"                             , _aulldiv),
func("_allmul"                              , _allmul),
func("_aullmul"                             , _aullmul),
func("_allrem"                              , _allrem),
func("_aullrem"                             , _aullrem),
func("_allshl"                              , _allshl),
func("_aullshl"                             , _aullshl),
func("_allshr"                              , _allshr),
func("_aullshr"                             , _aullshr),

func("ExDeleteNPagedLookasideList"          , ExDeleteNPagedLookasideList),
func("ExInitializeNPagedLookasideList"      , ExInitializeNPagedLookasideList),
func("ExInterlockedPopEntrySList"           , ExInterlockedPopEntrySList),
func("ExInterlockedPushEntrySList"          , ExInterlockedPushEntrySList),
func("ExInterlockedAddLargeStatistic"       , ExInterlockedAddLargeStatistic),
func("MmMapIoSpace"                         , MmMapIoSpace),
func("MmUnmapIoSpace"                       , MmUnmapIoSpace),
func("KeInitializeTimer"                    , KeInitializeTimer),
func("KeInitializeDpc"                      , KeInitializeDpc),
func("KeSetTimerEx"                         , KeSetTimerEx),
func("KeCancelTimer"                        , KeCancelTimer),
func("DbgBreakPoint"                        , DbgBreakPoint),
func("rand"                                 , rand),

/* CIPE */
func("DbgPrint"                             , DbgPrint),

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

