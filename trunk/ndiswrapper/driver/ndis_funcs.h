#ifndef NDIS_FUNC_H
#define NDIS_FUNC_H

#include "ndis.h"

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




#endif /* NDIS_FUNC_H */
