typedef void VOID;

typedef struct _NDIS_OBJECT_HEADER
{
    UCHAR   Type;
    UCHAR   Revision;
    USHORT  Size;
} NDIS_OBJECT_HEADER, *PNDIS_OBJECT_HEADER;

typedef struct
{
    union
    {
        PETH_FILTER             EthDB;
        PNULL_FILTER            NullDB;             // Default Filter
    };
    PTR_FILTER                  TrDB;

    void*                       YYYDB;

    void*                       XXXDB;
} FILTERDBS, *PFILTERDBS;

typedef void (*FILTER_PACKET_INDICATION_HANDLER)(NDIS_HANDLE Miniport, PPNDIS_PACKET PacketArray, UINT NumberOfPackets);

typedef void (*NDIS_M_SEND_COMPLETE_HANDLER)(
      NDIS_HANDLE             MiniportAdapterHandle,
      PNDIS_PACKET            Packet,
      NDIS_STATUS             Status
    );

typedef void (*NDIS_WM_SEND_COMPLETE_HANDLER)(
      NDIS_HANDLE             MiniportAdapterHandle,
      void*                   Packet,
      NDIS_STATUS             Status
    );

typedef void (*NDIS_M_TD_COMPLETE_HANDLER)(
      NDIS_HANDLE             MiniportAdapterHandle,
      PNDIS_PACKET            Packet,
      NDIS_STATUS             Status,
      UINT                    BytesTransferred
    );

typedef void (*NDIS_M_SEND_RESOURCES_HANDLER)(
      NDIS_HANDLE             MiniportAdapterHandle
    );

typedef void (*NDIS_M_STATUS_HANDLER)(
      NDIS_HANDLE             MiniportHandle,
      NDIS_STATUS             GeneralStatus,
      void*                   StatusBuffer,
      UINT                    StatusBufferSize
    );

typedef void (*NDIS_M_STS_COMPLETE_HANDLER)(
      NDIS_HANDLE             MiniportAdapterHandle
    );

typedef void (*NDIS_M_REQ_COMPLETE_HANDLER)(
      NDIS_HANDLE             MiniportAdapterHandle,
      NDIS_STATUS             Status
    );

typedef void (*NDIS_M_RESET_COMPLETE_HANDLER)(
      NDIS_HANDLE             MiniportAdapterHandle,
      NDIS_STATUS             Status,
      BOOLEAN                 AddressingReset
    );

typedef BOOLEAN (__fastcall *NDIS_M_START_SENDS)(
      PNDIS_MINIPORT_BLOCK    Miniport
    );

typedef
BOOLEAN
(*W_CHECK_FOR_HANG_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
void
(*W_DISABLE_INTERRUPT_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
void
(*W_ENABLE_INTERRUPT_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
void
(*W_HALT_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
void
(*W_HANDLE_INTERRUPT_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
NDIS_STATUS
(*W_INITIALIZE_HANDLER)(
     PNDIS_STATUS            OpenErrorStatus,
     PUINT                   SelectedMediumIndex,
       PNDIS_MEDIUM            MediumArray,
       UINT                    MediumArraySize,
       NDIS_HANDLE             MiniportAdapterContext,
       NDIS_HANDLE             WrapperConfigurationContext
    );

typedef
void
(*W_ISR_HANDLER)(
     PBOOLEAN                InterruptRecognized,
     PBOOLEAN                QueueMiniportHandleInterrupt,
       NDIS_HANDLE             MiniportAdapterContext
    );

typedef
NDIS_STATUS
(*W_QUERY_INFORMATION_HANDLER)(
       NDIS_HANDLE             MiniportAdapterContext,
       NDIS_OID                Oid,
       void*                   InformationBuffer,
       ULONG                   InformationBufferLength,
     PULONG                  BytesWritten,
     PULONG                  BytesNeeded
    );

typedef
NDIS_STATUS
(*W_RECONFIGURE_HANDLER)(
     PNDIS_STATUS            OpenErrorStatus,
       NDIS_HANDLE             MiniportAdapterContext,
       NDIS_HANDLE             WrapperConfigurationContext
    );

typedef
NDIS_STATUS
(*W_RESET_HANDLER)(
     PBOOLEAN                AddressingReset,
       NDIS_HANDLE             MiniportAdapterContext
    );

typedef
NDIS_STATUS
(*W_SEND_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      PNDIS_PACKET            Packet,
      UINT                    Flags
    );

typedef
NDIS_STATUS
(*WM_SEND_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      NDIS_HANDLE             NdisLinkHandle,
      PNDIS_WAN_PACKET        Packet
    );

typedef
NDIS_STATUS
(*W_SET_INFORMATION_HANDLER)(
       NDIS_HANDLE             MiniportAdapterContext,
       NDIS_OID                Oid,
       void*                   InformationBuffer,
       ULONG                   InformationBufferLength,
     PULONG                  BytesRead,
     PULONG                  BytesNeeded
    );

typedef
NDIS_STATUS
(*W_TRANSFER_DATA_HANDLER)(
     PNDIS_PACKET            Packet,
     PUINT                   BytesTransferred,
      NDIS_HANDLE             MiniportAdapterContext,
      NDIS_HANDLE             MiniportReceiveContext,
      UINT                    ByteOffset,
      UINT                    BytesToTransfer
    );

typedef
void
(*W_SEND_PACKETS_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      PPNDIS_PACKET           PacketArray,
      UINT                    NumberOfPackets
    );
typedef
void
(*ETH_RCV_INDICATE_HANDLER)(
      PETH_FILTER             Filter,
      NDIS_HANDLE             MacReceiveContext,
      PCHAR                   Address,
      void*                   HeaderBuffer,
      UINT                    HeaderBufferSize,
      void*                   LookaheadBuffer,
      UINT                    LookaheadBufferSize,
      UINT                    PacketSize
    );

typedef
void
(*ETH_RCV_COMPLETE_HANDLER)(
      PETH_FILTER             Filter
    );

typedef
void
(*TR_RCV_INDICATE_HANDLER)(
      PTR_FILTER              Filter,
      NDIS_HANDLE             MacReceiveContext,
      void*                   HeaderBuffer,
      UINT                    HeaderBufferSize,
      void*                   LookaheadBuffer,
      UINT                    LookaheadBufferSize,
      UINT                    PacketSize
    );

typedef
void
(*TR_RCV_COMPLETE_HANDLER)(
      PTR_FILTER              Filter
    );

typedef
void
(*WAN_RCV_HANDLER)(
     PNDIS_STATUS            Status,
      NDIS_HANDLE              MiniportAdapterHandle,
      NDIS_HANDLE              NdisLinkContext,
      PUCHAR                   Packet,
      ULONG                    PacketSize
    );

typedef
void
(*WAN_RCV_COMPLETE_HANDLER)(
     NDIS_HANDLE              MiniportAdapterHandle,
     NDIS_HANDLE              NdisLinkContext
    );

typedef struct _NDIS_MINIPORT_BLOCK
{
    NDIS_OBJECT_HEADER          Header;
    PNDIS_MINIPORT_BLOCK        NextMiniport;       // used by driver's MiniportQueue
    PNDIS_MINIPORT_BLOCK        BaseMiniport;
    NDIS_HANDLE                 MiniportAdapterContext; // context when calling mini-port functions
    UNICODE_STRING              Reserved4;
    void*                       Reserved10;
    NDIS_HANDLE                 OpenQueue;          // queue of opens for this mini-port
    REFERENCE                   ShortRef;           // contains spinlock for OpenQueue

    NDIS_HANDLE                 Reserved12;

    UCHAR                       Padding1;           // DO NOT REMOVE OR NDIS WILL BREAK!!!

    //
    // Synchronization stuff.
    //
    // The boolean is used to lock out several DPCs from running at the same time.
    //
    UCHAR                       LockAcquired;       // EXPOSED via macros. Do not move

    UCHAR                       PmodeOpens;         // Count of opens which turned on pmode/all_local

    //
    //  This is the processor number that the miniport's
    //  interrupt DPC and timers are running on.
    //
    //  Note: This field is no longer used
    //
    UCHAR                       Reserved23;

    KSPIN_LOCK                  Lock;

    PNDIS_REQUEST               MediaRequest;

    void*                       Interrupt;
    
    ULONG                       Flags;              // Flags to keep track of the miniport's state.
    ULONG                       PnPFlags;

    //
    // Send information
    //
    LIST_ENTRY                  PacketList;
    PNDIS_PACKET                FirstPendingPacket; // This is head of the queue of packets
                                                    // waiting to be sent to miniport.
    PNDIS_PACKET                ReturnPacketsQueue;

    //
    // Space used for temp. use during request processing
    //
    ULONG                       RequestBuffer;
    void*                       SetMCastBuffer;

    PNDIS_MINIPORT_BLOCK        PrimaryMiniport;
    void*                       Reserved11;

    //
    // context to pass to bus driver when reading or writing config space
    //
    void*                       BusDataContext;
    ULONG                       Reserved3;

    //
    // Resource information
    //
    PCM_RESOURCE_LIST           Resources;

    //
    // Watch-dog timer
    //
    NDIS_TIMER                  WakeUpDpcTimer;

    //
    // Needed for PnP. Upcased version. The buffer is allocated as part of the
    // NDIS_MINIPORT_BLOCK itself.
    //
    // Note:
    // the following two fields should be explicitly UNICODE_STRING because
    // under Win9x the NDIS_STRING is an ANSI_STRING
    //
    UNICODE_STRING              Reserved20;
    UNICODE_STRING              SymbolicLinkName;

    //
    // Check for hang stuff
    //
    ULONG                       CheckForHangSeconds;
    USHORT                      CFHangTicks;
    USHORT                      CFHangCurrentTick;

    //
    // Reset information
    //
    NDIS_STATUS                 ResetStatus;
    NDIS_HANDLE                 ResetOpen;

    //
    // Holds media specific information.
    //
    FILTERDBS                   FilterDbs;          // EXPOSED via macros. Do not move

    FILTER_PACKET_INDICATION_HANDLER PacketIndicateHandler;
    NDIS_M_SEND_COMPLETE_HANDLER    SendCompleteHandler;
    NDIS_M_SEND_RESOURCES_HANDLER   SendResourcesHandler;
    NDIS_M_RESET_COMPLETE_HANDLER   ResetCompleteHandler;

    NDIS_MEDIUM                 MediaType;

    //
    // contains mini-port information
    //
    ULONG                       BusNumber;
    NDIS_INTERFACE_TYPE         BusType;
    NDIS_INTERFACE_TYPE         AdapterType;

    PDEVICE_OBJECT              Reserved6;
    PDEVICE_OBJECT              Reserved7;
    PDEVICE_OBJECT              Reserved8;


    void*                       MiniportSGDmaBlock;

    //
    // List of registered address families. Valid for the call-manager, Null for the client
    //
    PNDIS_AF_LIST               CallMgrAfList;

    void*                       MiniportThread;
    void*                       SetInfoBuf;
    USHORT                      SetInfoBufLen;
    USHORT                      MaxSendPackets;

    //
    //  Status code that is returned from the fake handlers.
    //
    NDIS_STATUS                 FakeStatus;

    void*                       Reserved24;        // For the filter lock

    PUNICODE_STRING             Reserved9;

    void*                       Reserved21;

    UINT                        MacOptions;

    //
    // RequestInformation
    //
    PNDIS_REQUEST               PendingRequest;
    UINT                        MaximumLongAddresses;
    UINT                        MaximumShortAddresses;
    UINT                        CurrentLookahead;
    UINT                        MaximumLookahead;

    //
    //  For efficiency
    //
    ULONG_PTR                   Reserved1;
    W_DISABLE_INTERRUPT_HANDLER DisableInterruptHandler;
    W_ENABLE_INTERRUPT_HANDLER  EnableInterruptHandler;
    W_SEND_PACKETS_HANDLER      SendPacketsHandler;
    NDIS_M_START_SENDS          DeferredSendHandler;

    //
    // The following cannot be unionized.
    //
    ETH_RCV_INDICATE_HANDLER    EthRxIndicateHandler;   // EXPOSED via macros. Do not move
    TR_RCV_INDICATE_HANDLER     TrRxIndicateHandler;    // EXPOSED via macros. Do not move
    void*                       Reserved2;

    ETH_RCV_COMPLETE_HANDLER    EthRxCompleteHandler;   // EXPOSED via macros. Do not move
    TR_RCV_COMPLETE_HANDLER     TrRxCompleteHandler;    // EXPOSED via macros. Do not move
    void*                       Reserved22;

    NDIS_M_STATUS_HANDLER       StatusHandler;          // EXPOSED via macros. Do not move
    NDIS_M_STS_COMPLETE_HANDLER StatusCompleteHandler;  // EXPOSED via macros. Do not move
    NDIS_M_TD_COMPLETE_HANDLER  TDCompleteHandler;      // EXPOSED via macros. Do not move
    NDIS_M_REQ_COMPLETE_HANDLER QueryCompleteHandler;   // EXPOSED via macros. Do not move
    NDIS_M_REQ_COMPLETE_HANDLER SetCompleteHandler;     // EXPOSED via macros. Do not move

    NDIS_WM_SEND_COMPLETE_HANDLER WanSendCompleteHandler;// EXPOSED via macros. Do not move
    WAN_RCV_HANDLER             WanRcvHandler;          // EXPOSED via macros. Do not move
    WAN_RCV_COMPLETE_HANDLER    WanRcvCompleteHandler;  // EXPOSED via macros. Do not move

} NDIS_MINIPORT_BLOCK, *PNDIS_MINIPORT_BLOCK;


//
// Function types for NDIS_MINIPORT_CHARACTERISTICS
//


typedef
BOOLEAN
(*W_CHECK_FOR_HANG_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
VOID
(*W_DISABLE_INTERRUPT_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
VOID
(*W_ENABLE_INTERRUPT_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
VOID
(*W_HALT_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );

typedef
VOID
(*W_HANDLE_INTERRUPT_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext
    );


typedef
VOID
(*W_ISR_HANDLER)(
     PBOOLEAN                InterruptRecognized,
     PBOOLEAN                QueueMiniportHandleInterrupt,
       NDIS_HANDLE             MiniportAdapterContext
    );

typedef
NDIS_STATUS
(*W_QUERY_INFORMATION_HANDLER)(
       NDIS_HANDLE             MiniportAdapterContext,
       NDIS_OID                Oid,
       PVOID                   InformationBuffer,
       ULONG                   InformationBufferLength,
     PULONG                  BytesWritten,
     PULONG                  BytesNeeded
    );

typedef
NDIS_STATUS
(*W_RECONFIGURE_HANDLER)(
     PNDIS_STATUS            OpenErrorStatus,
       NDIS_HANDLE             MiniportAdapterContext,
       NDIS_HANDLE             WrapperConfigurationContext
    );

typedef
NDIS_STATUS
(*W_RESET_HANDLER)(
     PBOOLEAN                AddressingReset,
       NDIS_HANDLE             MiniportAdapterContext
    );

typedef
NDIS_STATUS
(*W_SEND_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      PNDIS_PACKET            Packet,
      UINT                    Flags
    );

typedef
NDIS_STATUS
(*WM_SEND_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      NDIS_HANDLE             NdisLinkHandle,
      PNDIS_WAN_PACKET        Packet
    );

typedef
NDIS_STATUS
(*W_SET_INFORMATION_HANDLER)(
       NDIS_HANDLE             MiniportAdapterContext,
       NDIS_OID                Oid,
       PVOID                   InformationBuffer,
       ULONG                   InformationBufferLength,
     PULONG                  BytesRead,
     PULONG                  BytesNeeded
    );

typedef
NDIS_STATUS
(*W_TRANSFER_DATA_HANDLER)(
     PNDIS_PACKET            Packet,
     PUINT                   BytesTransferred,
      NDIS_HANDLE             MiniportAdapterContext,
      NDIS_HANDLE             MiniportReceiveContext,
      UINT                    ByteOffset,
      UINT                    BytesToTransfer
    );

typedef
NDIS_STATUS
(*WM_TRANSFER_DATA_HANDLER)(
    VOID
    );

//
// Definition for shutdown handler
//

typedef
VOID
(*ADAPTER_SHUTDOWN_HANDLER) (
      PVOID ShutdownContext
    );

//
// Miniport extensions for NDIS 4.0
//
typedef
VOID
(*W_RETURN_PACKET_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      PNDIS_PACKET            Packet
    );

//
// NDIS 4.0 extension
//
typedef
VOID
(*W_SEND_PACKETS_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      PPNDIS_PACKET           PacketArray,
      UINT                    NumberOfPackets
    );

typedef
VOID
(*W_ALLOCATE_COMPLETE_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      PVOID                   VirtualAddress,
      PNDIS_PHYSICAL_ADDRESS  PhysicalAddress,
      ULONG                   Length,
      PVOID                   Context
    );

//
// W_CO_CREATE_VC_HANDLER is a synchronous call
//
typedef
NDIS_STATUS
(MINIPORT_CO_CREATE_VC)(
       NDIS_HANDLE             MiniportAdapterContext,
       NDIS_HANDLE             NdisVcHandle,
     PNDIS_HANDLE            MiniportVcContext
    );

typedef MINIPORT_CO_CREATE_VC (*W_CO_CREATE_VC_HANDLER);

typedef
NDIS_STATUS
(MINIPORT_CO_DELETE_VC)(
      NDIS_HANDLE             MiniportVcContext
    );

typedef MINIPORT_CO_DELETE_VC (*W_CO_DELETE_VC_HANDLER);

typedef
NDIS_STATUS
(MINIPORT_CO_ACTIVATE_VC)(
      NDIS_HANDLE             MiniportVcContext,
     PCO_CALL_PARAMETERS  CallParameters
    );

typedef MINIPORT_CO_ACTIVATE_VC (*W_CO_ACTIVATE_VC_HANDLER);

typedef
NDIS_STATUS
(MINIPORT_CO_DEACTIVATE_VC)(
      NDIS_HANDLE             MiniportVcContext
    );
typedef MINIPORT_CO_DEACTIVATE_VC (*W_CO_DEACTIVATE_VC_HANDLER);


typedef
VOID
(*W_CO_SEND_PACKETS_HANDLER)(
      NDIS_HANDLE             MiniportVcContext,
      PPNDIS_PACKET           PacketArray,
      UINT                    NumberOfPackets
    );

typedef
NDIS_STATUS
(*W_CO_REQUEST_HANDLER)(
          NDIS_HANDLE             MiniportAdapterContext,
          NDIS_HANDLE             MiniportVcContext  ,
     PNDIS_REQUEST        NdisRequest
    );


typedef struct _NDIS50_MINIPORT_CHARACTERISTICS
{   
    UCHAR                       MajorNdisVersion;
    UCHAR                       MinorNdisVersion;
    USHORT                      Filler;
    UINT                        Reserved;
    W_CHECK_FOR_HANG_HANDLER    CheckForHangHandler;
    W_DISABLE_INTERRUPT_HANDLER DisableInterruptHandler;
    W_ENABLE_INTERRUPT_HANDLER  EnableInterruptHandler;
    W_HALT_HANDLER              HaltHandler;
    W_HANDLE_INTERRUPT_HANDLER  HandleInterruptHandler;
    W_INITIALIZE_HANDLER        InitializeHandler;
    W_ISR_HANDLER               ISRHandler;
    W_QUERY_INFORMATION_HANDLER QueryInformationHandler;
    W_RECONFIGURE_HANDLER       ReconfigureHandler;
    W_RESET_HANDLER             ResetHandler;
    union
    {
        W_SEND_HANDLER          SendHandler;
        WM_SEND_HANDLER         WanSendHandler;
    };
    W_SET_INFORMATION_HANDLER   SetInformationHandler;
    union
    {
        W_TRANSFER_DATA_HANDLER TransferDataHandler;
        WM_TRANSFER_DATA_HANDLER WanTransferDataHandler;
    };

    //
    // Extensions for NDIS 4.0
    //
    W_RETURN_PACKET_HANDLER     ReturnPacketHandler;
    W_SEND_PACKETS_HANDLER      SendPacketsHandler;
    W_ALLOCATE_COMPLETE_HANDLER AllocateCompleteHandler;
    
    //
    // Extensions for NDIS 5.0
    //
    W_CO_CREATE_VC_HANDLER      CoCreateVcHandler;
    W_CO_DELETE_VC_HANDLER      CoDeleteVcHandler;
    W_CO_ACTIVATE_VC_HANDLER    CoActivateVcHandler;
    W_CO_DEACTIVATE_VC_HANDLER  CoDeactivateVcHandler;
    W_CO_SEND_PACKETS_HANDLER   CoSendPacketsHandler;
    W_CO_REQUEST_HANDLER        CoRequestHandler;
} NDIS50_MINIPORT_CHARACTERISTICS;


typedef VOID
(*W_CANCEL_SEND_PACKETS_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      PVOID                   CancelId
    );


typedef enum _NDIS_DEVICE_PNP_EVENT
{
    NdisDevicePnPEventQueryRemoved,
    NdisDevicePnPEventRemoved,
    NdisDevicePnPEventSurpriseRemoved,
    NdisDevicePnPEventQueryStopped,
    NdisDevicePnPEventStopped,
    NdisDevicePnPEventPowerProfileChanged,
    NdisDevicePnPEventMaximum
} NDIS_DEVICE_PNP_EVENT, *PNDIS_DEVICE_PNP_EVENT;

typedef VOID
(*W_PNP_EVENT_NOTIFY_HANDLER)(
      NDIS_HANDLE             MiniportAdapterContext,
      NDIS_DEVICE_PNP_EVENT   DevicePnPEvent,
      PVOID                   InformationBuffer,
      ULONG                   InformationBufferLength
    );

typedef VOID
(*W_MINIPORT_SHUTDOWN_HANDLER) (
      NDIS_HANDLE                     MiniportAdapterContext
    );


typedef struct _NDIS51_MINIPORT_CHARACTERISTICS
{
    NDIS50_MINIPORT_CHARACTERISTICS Ndis50Chars;
    //
    // Extensions for NDIS 5.1
    //
    W_CANCEL_SEND_PACKETS_HANDLER   CancelSendPacketsHandler;
    W_PNP_EVENT_NOTIFY_HANDLER      PnPEventNotifyHandler;
    W_MINIPORT_SHUTDOWN_HANDLER     AdapterShutdownHandler;
    PVOID                           Reserved1;
    PVOID                           Reserved2;
    PVOID                           Reserved3;
    PVOID                           Reserved4;
} NDIS51_MINIPORT_CHARACTERISTICS;

typedef struct _NDIS51_MINIPORT_CHARACTERISTICS NDIS_MINIPORT_CHARACTERISTICS;
typedef NDIS_MINIPORT_CHARACTERISTICS * PNDIS_MINIPORT_CHARACTERISTICS;

NDIS_STATUS
NdisMRegisterMiniport(
    NDIS_HANDLE                     NdisWrapperHandle,
    PNDIS_MINIPORT_CHARACTERISTICS  MiniportCharacteristics,
    UINT                            CharacteristicsLength
    );


typedef struct _NDIS40_PROTOCOL_CHARACTERISTICS
{
    UCHAR                           MajorNdisVersion;
    UCHAR                           MinorNdisVersion;
    USHORT                          Filler;
    union
    {
        UINT                        Reserved;
        UINT                        Flags;
    };
    OPEN_ADAPTER_COMPLETE_HANDLER   OpenAdapterCompleteHandler;
    CLOSE_ADAPTER_COMPLETE_HANDLER  CloseAdapterCompleteHandler;
    union
    {
        SEND_COMPLETE_HANDLER       SendCompleteHandler;
        WAN_SEND_COMPLETE_HANDLER   WanSendCompleteHandler;
    };
    union
    {
     TRANSFER_DATA_COMPLETE_HANDLER TransferDataCompleteHandler;
     WAN_TRANSFER_DATA_COMPLETE_HANDLER WanTransferDataCompleteHandler;
    };

    RESET_COMPLETE_HANDLER          ResetCompleteHandler;
    REQUEST_COMPLETE_HANDLER        RequestCompleteHandler;
    union
    {
        RECEIVE_HANDLER             ReceiveHandler;
        WAN_RECEIVE_HANDLER         WanReceiveHandler;
    };
    RECEIVE_COMPLETE_HANDLER        ReceiveCompleteHandler;
    STATUS_HANDLER                  StatusHandler;
    STATUS_COMPLETE_HANDLER         StatusCompleteHandler;
    NDIS_STRING                     Name;

    //
    // Start of NDIS 4.0 extensions.
    //
    RECEIVE_PACKET_HANDLER          ReceivePacketHandler;

    //
    // PnP protocol entry-points
    //
    BIND_HANDLER                    BindAdapterHandler;
    UNBIND_HANDLER                  UnbindAdapterHandler;
    PNP_EVENT_HANDLER               PnPEventHandler;
    UNLOAD_PROTOCOL_HANDLER         UnloadHandler;

} __NDIS40_PROTOCOL_CHARACTERISTICS;

typedef struct _NDIS50_PROTOCOL_CHARACTERISTICS
{
    __NDIS40_PROTOCOL_CHARACTERISTICS Ndis40Chars;
    //
    // Placeholders for protocol extensions for PnP/PM etc.
    //
    PVOID                           ReservedHandlers[4];

    //
    // Start of NDIS 5.0 extensions.
    //

    CO_SEND_COMPLETE_HANDLER        CoSendCompleteHandler;
    CO_STATUS_HANDLER               CoStatusHandler;
    CO_RECEIVE_PACKET_HANDLER       CoReceivePacketHandler;
    CO_AF_REGISTER_NOTIFY_HANDLER   CoAfRegisterNotifyHandler;
} __NDIS50_PROTOCOL_CHARACTERISTICS;

typedef __NDIS50_PROTOCOL_CHARACTERISTICS __NDIS_PROTOCOL_CHARACTERISTICS;

NDIS_STATUS
NdisIMRegisterLayeredMiniport(
     NDIS_HANDLE                     NdisWrapperHandle,
     PNDIS_MINIPORT_CHARACTERISTICS  MiniportCharacteristics,
     UINT                            CharacteristicsLength,
     PNDIS_HANDLE                    DriverHandle
    );

typedef
NTSTATUS
DRIVER_DISPATCH (
     struct _DEVICE_OBJECT *DeviceObject,
     struct _IRP *Irp
    );

typedef DRIVER_DISPATCH *PDRIVER_DISPATCH;

struct DispatchTable {
PDRIVER_DISPATCH IRP_MJ_CREATE;
PDRIVER_DISPATCH IRP_MJ_CREATE_NAMED_PIPE;
PDRIVER_DISPATCH IRP_MJ_CLOSE;
PDRIVER_DISPATCH IRP_MJ_READ;
PDRIVER_DISPATCH IRP_MJ_WRITE;
PDRIVER_DISPATCH IRP_MJ_QUERY_INFORMATION;
PDRIVER_DISPATCH IRP_MJ_SET_INFORMATION;
PDRIVER_DISPATCH IRP_MJ_QUERY_EA;
PDRIVER_DISPATCH IRP_MJ_SET_EA;
PDRIVER_DISPATCH IRP_MJ_FLUSH_BUFFERS;
PDRIVER_DISPATCH IRP_MJ_QUERY_VOLUME_INFORMATION;
PDRIVER_DISPATCH IRP_MJ_SET_VOLUME_INFORMATION;
PDRIVER_DISPATCH IRP_MJ_DIRECTORY_CONTROL;
PDRIVER_DISPATCH IRP_MJ_FILE_SYSTEM_CONTROL;
PDRIVER_DISPATCH IRP_MJ_DEVICE_CONTROL;
PDRIVER_DISPATCH IRP_MJ_INTERNAL_DEVICE_CONTROL;
PDRIVER_DISPATCH IRP_MJ_SHUTDOWN;
PDRIVER_DISPATCH IRP_MJ_LOCK_CONTROL;
PDRIVER_DISPATCH IRP_MJ_CLEANUP;
PDRIVER_DISPATCH IRP_MJ_CREATE_MAILSLOT;
PDRIVER_DISPATCH IRP_MJ_QUERY_SECURITY;
PDRIVER_DISPATCH IRP_MJ_SET_SECURITY;
PDRIVER_DISPATCH IRP_MJ_POWER;
PDRIVER_DISPATCH IRP_MJ_SYSTEM_CONTROL;
PDRIVER_DISPATCH IRP_MJ_DEVICE_CHANGE;
PDRIVER_DISPATCH IRP_MJ_QUERY_QUOTA;
PDRIVER_DISPATCH IRP_MJ_SET_QUOTA;
PDRIVER_DISPATCH IRP_MJ_PNP;
};

VOID
NdisRegisterProtocol(
       PNDIS_STATUS                      Status,
       PNDIS_HANDLE                      NdisProtocolHandle,
        __NDIS_PROTOCOL_CHARACTERISTICS*    ProtocolCharacteristics,
        UINT                              CharacteristicsLength
    );


typedef ULONG64 TRACEHANDLE, *PTRACEHANDLE;

typedef ULONGLONG REGHANDLE, *PREGHANDLE;

typedef
VOID
(*BIND_HANDLER)(
     PNDIS_STATUS            Status,
      NDIS_HANDLE             BindContext,
      PNDIS_STRING            DeviceName,
      PVOID                   SystemSpecific1,
      PVOID                   SystemSpecific2
    );

typedef struct _NDIS_MINIPORT_INTERRUPT
{
    PKINTERRUPT                 InterruptObject;
    KSPIN_LOCK                  DpcCountLock;
    PVOID                       Reserved;
    W_ISR_HANDLER               MiniportIsr;
    W_HANDLE_INTERRUPT_HANDLER  MiniportDpc;
    KDPC                        InterruptDpc;
    PNDIS_MINIPORT_BLOCK        Miniport;

    UCHAR                       DpcCount;
    BOOLEAN                     Filler1;

    //
    // This is used to tell when all the Dpcs for the adapter are completed.
    //

    KEVENT                      DpcsCompletedEvent;

    BOOLEAN                     SharedInterrupt;
    BOOLEAN                     IsrRequested;

} NDIS_MINIPORT_INTERRUPT, *PNDIS_MINIPORT_INTERRUPT;

NDIS_STATUS
NdisMRegisterInterrupt(
     PNDIS_MINIPORT_INTERRUPT Interrupt,
      NDIS_HANDLE             MiniportAdapterHandle,
      UINT                    InterruptVector,
      UINT                    InterruptLevel,
      BOOLEAN                 RequestIsr,
      BOOLEAN                 SharedInterrupt,
      NDIS_INTERRUPT_MODE     InterruptMode
    );

typedef
NDIS_STATUS
(*RECEIVE_HANDLER)(
      NDIS_HANDLE             ProtocolBindingContext,
      NDIS_HANDLE             MacReceiveContext,
      PVOID                   HeaderBuffer,
      UINT                    HeaderBufferSize,
      PVOID                   LookAheadBuffer,
      UINT                    LookaheadBufferSize,
      UINT                    PacketSize
    );

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef SINGLE_LIST_ENTRY SLIST_ENTRY, *PSLIST_ENTRY;

typedef union _SLIST_HEADER {
    ULONGLONG Alignment;
    struct {
        SLIST_ENTRY Next;
        WORD   Depth;
        WORD   Sequence;
    } DUMMYSTRUCTNAME;
} SLIST_HEADER, *PSLIST_HEADER;

PSLIST_ENTRY
InterlockedPushEntrySList (
     PSLIST_HEADER ListHead,
     PSLIST_ENTRY ListEntry
    );

typedef struct _NDIS_PACKET_OOB_DATA
{
    union
    {
        ULONGLONG   TimeToSend;
        ULONGLONG   TimeSent;
    };
    ULONGLONG       TimeReceived;
    UINT            HeaderSize;
    UINT            SizeMediaSpecificInfo;
    PVOID           MediaSpecificInformation;

    NDIS_STATUS     Status;
} NDIS_PACKET_OOB_DATA, *PNDIS_PACKET_OOB_DATA;

enum IRP_MJ {
IRP_MJ_CREATE =                   0x00,
IRP_MJ_CREATE_NAMED_PIPE =        0x04,
IRP_MJ_CLOSE =                    0x08,
IRP_MJ_READ =                     0x0c,
IRP_MJ_WRITE =                    0x10,
IRP_MJ_QUERY_INFORMATION =        0x14,
IRP_MJ_SET_INFORMATION =          0x18,
IRP_MJ_QUERY_EA =                 0x1c,
IRP_MJ_SET_EA =                   0x20,
IRP_MJ_FLUSH_BUFFERS =            0x24,
IRP_MJ_QUERY_VOLUME_INFORMATION = 0x28,
IRP_MJ_SET_VOLUME_INFORMATION =   0x2c,
IRP_MJ_DIRECTORY_CONTROL =        0x30,
IRP_MJ_FILE_SYSTEM_CONTROL =      0x34,
IRP_MJ_DEVICE_CONTROL =           0x38,
IRP_MJ_INTERNAL_DEVICE_CONTROL =  0x3c,
IRP_MJ_SHUTDOWN =                 0x40,
IRP_MJ_LOCK_CONTROL =             0x44,
IRP_MJ_CLEANUP =                  0x48,
IRP_MJ_CREATE_MAILSLOT =          0x4c,
IRP_MJ_QUERY_SECURITY =           0x50,
IRP_MJ_SET_SECURITY =             0x54,
IRP_MJ_POWER =                    0x58,
IRP_MJ_SYSTEM_CONTROL =           0x5c,
IRP_MJ_DEVICE_CHANGE =            0x60,
IRP_MJ_QUERY_QUOTA =              0x64,
IRP_MJ_SET_QUOTA =                0x68,
IRP_MJ_PNP =                      0x6c,
IRP_MJ_PNP_POWER =                0x6c,
IRP_MJ_MAXIMUM_FUNCTION =         0x6c
};