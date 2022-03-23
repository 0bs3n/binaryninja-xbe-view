import struct
import sys

def get_cstr(buf):
    cursor = 0
    while buf[cursor] != 0:
        cursor += 1
    return buf[:cursor]

def u32(b):
    return struct.unpack("<I", b)[0]

class XbeKernelThunkExport:
    def __init__(self):
        # https://xboxdevwiki.net/Kernel#Kernel_exports
        self.thunk_exports = {
            1:   'AvGetSavedDataAddress',
            2:   'AvSendTVEncoderOption',
            3:   'AvSetDisplayMode',
            4:   'AvSetSavedDataAddress',
            5:   'DbgBreakPoint',
            6:   'DbgBreakPointWithStatus',
            7:   'DbgLoadImageSymbols',
            8:   'DbgPrint',
            9:   'HalReadSMCTrayState',
            10:  'DbgPrompt',
            11:  'DbgUnLoadImageSymbols',
            12:  'ExAcquireReadWriteLockExclusive',
            13:  'ExAcquireReadWriteLockShared',
            14:  'ExAllocatePool',
            15:  'ExAllocatePoolWithTag',
            16:  'ExEventObjectType',
            17:  'ExFreePool',
            18:  'ExInitializeReadWriteLock',
            19:  'ExInterlockedAddLargeInteger',
            20:  'ExInterlockedAddLargeStatistic',
            21:  'ExInterlockedCompareExchange64',
            22:  'ExMutantObjectType',
            23:  'ExQueryPoolBlockSize',
            24:  'ExQueryNonVolatileSetting',
            25:  'ExReadWriteRefurbInfo',
            26:  'ExRaiseException',
            27:  'ExRaiseStatus',
            28:  'ExReleaseReadWriteLock',
            29:  'ExSaveNonVolatileSetting',
            30:  'ExSemaphoreObjectType',
            31:  'ExTimerObjectType',
            32:  'ExfInterlockedInsertHeadList',
            33:  'ExfInterlockedInsertTailList',
            34:  'ExfInterlockedRemoveHeadList',
            35:  'FscGetCacheSize',
            36:  'FscInvalidateIdleBlocks',
            37:  'FscSetCacheSize',
            38:  'HalClearSoftwareInterrupt',
            39:  'HalDisableSystemInterrupt',
            40:  'HalDiskCachePartitionCount',
            41:  'HalDiskModelNumber',
            42:  'HalDiskSerialNumber',
            43:  'HalEnableSystemInterrupt',
            44:  'HalGetInterruptVector',
            45:  'HalReadSMBusValue',
            46:  'HalReadWritePCISpace',
            47:  'HalRegisterShutdownNotification',
            48:  'HalRequestSoftwareInterrupt',
            49:  'HalReturnToFirmware',
            50:  'HalWriteSMBusValue',
            51:  'InterlockedCompareExchange',
            52:  'InterlockedDecrement',
            53:  'InterlockedIncrement',
            54:  'InterlockedExchange',
            55:  'InterlockedExchangeAdd',
            56:  'InterlockedFlushSList',
            57:  'InterlockedPopEntrySList',
            58:  'InterlockedPushEntrySList',
            59:  'IoAllocateIrp',
            60:  'IoBuildAsynchronousFsdRequest',
            61:  'IoBuildDeviceIoControlRequest',
            62:  'IoBuildSynchronousFsdRequest',
            63:  'IoCheckShareAccess',
            64:  'IoCompletionObjectType',
            65:  'IoCreateDevice',
            66:  'IoCreateFile',
            67:  'IoCreateSymbolicLink',
            68:  'IoDeleteDevice',
            69:  'IoDeleteSymbolicLink',
            70:  'IoDeviceObjectType',
            71:  'IoFileObjectType',
            72:  'IoFreeIrp',
            73:  'IoInitializeIrp',
            74:  'IoInvalidDeviceRequest',
            75:  'IoQueryFileInformation',
            76:  'IoQueryVolumeInformation',
            77:  'IoQueueThreadIrp',
            78:  'IoRemoveShareAccess',
            79:  'IoSetIoCompletion',
            80:  'IoSetShareAccess',
            81:  'IoStartNextPacket',
            82:  'IoStartNextPacketByKey',
            83:  'IoStartPacket',
            84:  'IoSynchronousDeviceIoControlRequest',
            85:  'IoSynchronousFsdRequest',
            86:  'IofCallDriver',
            87:  'IofCompleteRequest',
            88:  'KdDebuggerEnabled',
            89:  'KdDebuggerNotPresent',
            90:  'IoDismountVolume',
            91:  'IoDismountVolumeByName',
            92:  'KeAlertResumeThread',
            93:  'KeAlertThread',
            94:  'KeBoostPriorityThread',
            95:  'KeBugCheck',
            96:  'KeBugCheckEx',
            97:  'KeCancelTimer',
            98:  'KeConnectInterrupt',
            99:  'KeDelayExecutionThread',
            100: 'KeDisconnectInterrupt',
            101: 'KeEnterCriticalRegion',
            102: 'MmGlobalData',
            103: 'KeGetCurrentIrql',
            104: 'KeGetCurrentThread',
            105: 'KeInitializeApc',
            106: 'KeInitializeDeviceQueue',
            107: 'KeInitializeDpc',
            108: 'KeInitializeEvent',
            109: 'KeInitializeInterrupt',
            110: 'KeInitializeMutant',
            111: 'KeInitializeQueue',
            112: 'KeInitializeSemaphore',
            113: 'KeInitializeTimerEx',
            114: 'KeInsertByKeyDeviceQueue',
            115: 'KeInsertDeviceQueue',
            116: 'KeInsertHeadQueue',
            117: 'KeInsertQueue',
            118: 'KeInsertQueueApc',
            119: 'KeInsertQueueDpc',
            120: 'KeInterruptTime',
            121: 'KeIsExecutingDpc',
            122: 'KeLeaveCriticalRegion',
            123: 'KePulseEvent',
            124: 'KeQueryBasePriorityThread',
            125: 'KeQueryInterruptTime',
            126: 'KeQueryPerformanceCounter',
            127: 'KeQueryPerformanceFrequency',
            128: 'KeQuerySystemTime',
            129: 'KeRaiseIrqlToDpcLevel',
            130: 'KeRaiseIrqlToSynchLevel',
            131: 'KeReleaseMutant',
            132: 'KeReleaseSemaphore',
            133: 'KeRemoveByKeyDeviceQueue',
            134: 'KeRemoveDeviceQueue',
            135: 'KeRemoveEntryDeviceQueue',
            136: 'KeRemoveQueue',
            137: 'KeRemoveQueueDpc',
            138: 'KeResetEvent',
            139: 'KeRestoreFloatingPointState',
            140: 'KeResumeThread',
            141: 'KeRundownQueue',
            142: 'KeSaveFloatingPointState',
            143: 'KeSetBasePriorityThread',
            144: 'KeSetDisableBoostThread',
            145: 'KeSetEvent',
            146: 'KeSetEventBoostPriority',
            147: 'KeSetPriorityProcess',
            148: 'KeSetPriorityThread',
            149: 'KeSetTimer',
            150: 'KeSetTimerEx',
            151: 'KeStallExecutionProcessor',
            152: 'KeSuspendThread',
            153: 'KeSynchronizeExecution',
            154: 'KeSystemTime',
            155: 'KeTestAlertThread',
            156: 'KeTickCount',
            157: 'KeTimeIncrement',
            158: 'KeWaitForMultipleObjects',
            159: 'KeWaitForSingleObject',
            160: 'KfRaiseIrql',
            161: 'KfLowerIrql',
            162: 'KiBugCheckData',
            163: 'KiUnlockDispatcherDatabase',
            164: 'LaunchDataPage',
            165: 'MmAllocateContiguousMemory',
            166: 'MmAllocateContiguousMemoryEx',
            167: 'MmAllocateSystemMemory',
            168: 'MmClaimGpuInstanceMemory',
            169: 'MmCreateKernelStack',
            170: 'MmDeleteKernelStack',
            171: 'MmFreeContiguousMemory',
            172: 'MmFreeSystemMemory',
            173: 'MmGetPhysicalAddress',
            174: 'MmIsAddressValid',
            175: 'MmLockUnlockBufferPages',
            176: 'MmLockUnlockPhysicalPage',
            177: 'MmMapIoSpace',
            178: 'MmPersistContiguousMemory',
            179: 'MmQueryAddressProtect',
            180: 'MmQueryAllocationSize',
            181: 'MmQueryStatistics',
            182: 'MmSetAddressProtect',
            183: 'MmUnmapIoSpace',
            184: 'NtAllocateVirtualMemory',
            185: 'NtCancelTimer',
            186: 'NtClearEvent',
            187: 'NtClose',
            188: 'NtCreateDirectoryObject',
            189: 'NtCreateEvent',
            190: 'NtCreateFile',
            191: 'NtCreateIoCompletion',
            192: 'NtCreateMutant',
            193: 'NtCreateSemaphore',
            194: 'NtCreateTimer',
            195: 'NtDeleteFile',
            196: 'NtDeviceIoControlFile',
            197: 'NtDuplicateObject',
            198: 'NtFlushBuffersFile',
            199: 'NtFreeVirtualMemory',
            200: 'NtFsControlFile',
            201: 'NtOpenDirectoryObject',
            202: 'NtOpenFile',
            203: 'NtOpenSymbolicLinkObject',
            204: 'NtProtectVirtualMemory',
            205: 'NtPulseEvent',
            206: 'NtQueueApcThread',
            207: 'NtQueryDirectoryFile',
            208: 'NtQueryDirectoryObject',
            209: 'NtQueryEvent',
            210: 'NtQueryFullAttributesFile',
            211: 'NtQueryInformationFile',
            212: 'NtQueryIoCompletion',
            213: 'NtQueryMutant',
            214: 'NtQuerySemaphore',
            215: 'NtQuerySymbolicLinkObject',
            216: 'NtQueryTimer',
            217: 'NtQueryVirtualMemory',
            218: 'NtQueryVolumeInformationFile',
            219: 'NtReadFile',
            220: 'NtReadFileScatter',
            221: 'NtReleaseMutant',
            222: 'NtReleaseSemaphore',
            223: 'NtRemoveIoCompletion',
            224: 'NtResumeThread',
            225: 'NtSetEvent',
            226: 'NtSetInformationFile',
            227: 'NtSetIoCompletion',
            228: 'NtSetSystemTime',
            229: 'NtSetTimerEx',
            230: 'NtSignalAndWaitForSingleObjectEx',
            231: 'NtSuspendThread',
            232: 'NtUserIoApcDispatcher',
            233: 'NtWaitForSingleObject',
            234: 'NtWaitForSingleObjectEx',
            235: 'NtWaitForMultipleObjectsEx',
            236: 'NtWriteFile',
            237: 'NtWriteFileGather',
            238: 'NtYieldExecution',
            239: 'ObCreateObject',
            240: 'ObDirectoryObjectType',
            241: 'ObInsertObject',
            242: 'ObMakeTemporaryObject',
            243: 'ObOpenObjectByName',
            244: 'ObOpenObjectByPointer',
            245: 'ObpObjectHandleTable',
            246: 'ObReferenceObjectByHandle',
            247: 'ObReferenceObjectByName',
            248: 'ObReferenceObjectByPointer',
            249: 'ObSymbolicLinkObjectType',
            250: 'ObfDereferenceObject',
            251: 'ObfReferenceObject',
            252: 'PhyGetLinkState',
            253: 'PhyInitialize',
            254: 'PsCreateSystemThread',
            255: 'PsCreateSystemThreadEx',
            256: 'PsQueryStatistics',
            257: 'PsSetCreateThreadNotifyRoutine',
            258: 'PsTerminateSystemThread',
            259: 'PsThreadObjectType',
            260: 'RtlAnsiStringToUnicodeString',
            261: 'RtlAppendStringToString',
            262: 'RtlAppendUnicodeStringToString',
            263: 'RtlAppendUnicodeToString',
            264: 'RtlAssert',
            265: 'RtlCaptureContext',
            266: 'RtlCaptureStackBackTrace',
            267: 'RtlCharToInteger',
            268: 'RtlCompareMemory',
            269: 'RtlCompareMemoryUlong',
            270: 'RtlCompareString',
            271: 'RtlCompareUnicodeString',
            272: 'RtlCopyString',
            273: 'RtlCopyUnicodeString',
            274: 'RtlCreateUnicodeString',
            275: 'RtlDowncaseUnicodeChar',
            276: 'RtlDowncaseUnicodeString',
            277: 'RtlEnterCriticalSection',
            278: 'RtlEnterCriticalSectionAndRegion',
            279: 'RtlEqualString',
            280: 'RtlEqualUnicodeString',
            281: 'RtlExtendedIntegerMultiply',
            282: 'RtlExtendedLargeIntegerDivide',
            283: 'RtlExtendedMagicDivide',
            284: 'RtlFillMemory',
            285: 'RtlFillMemoryUlong',
            286: 'RtlFreeAnsiString',
            287: 'RtlFreeUnicodeString',
            288: 'RtlGetCallersAddress',
            289: 'RtlInitAnsiString',
            290: 'RtlInitUnicodeString',
            291: 'RtlInitializeCriticalSection',
            292: 'RtlIntegerToChar',
            293: 'RtlIntegerToUnicodeString',
            294: 'RtlLeaveCriticalSection',
            295: 'RtlLeaveCriticalSectionAndRegion',
            296: 'RtlLowerChar',
            297: 'RtlMapGenericMask',
            298: 'RtlMoveMemory',
            299: 'RtlMultiByteToUnicodeN',
            300: 'RtlMultiByteToUnicodeSize',
            301: 'RtlNtStatusToDosError',
            302: 'RtlRaiseException',
            303: 'RtlRaiseStatus',
            304: 'RtlTimeFieldsToTime',
            305: 'RtlTimeToTimeFields',
            306: 'RtlTryEnterCriticalSection',
            307: 'RtlUlongByteSwap',
            308: 'RtlUnicodeStringToAnsiString',
            309: 'RtlUnicodeStringToInteger',
            310: 'RtlUnicodeToMultiByteN',
            311: 'RtlUnicodeToMultiByteSize',
            312: 'RtlUnwind',
            313: 'RtlUpcaseUnicodeChar',
            314: 'RtlUpcaseUnicodeString',
            315: 'RtlUpcaseUnicodeToMultiByteN',
            316: 'RtlUpperChar',
            317: 'RtlUpperString',
            318: 'RtlUshortByteSwap',
            319: 'RtlWalkFrameChain',
            320: 'RtlZeroMemory',
            321: 'XboxEEPROMKey',
            322: 'XboxHardwareInfo',
            323: 'XboxHDKey',
            324: 'XboxKrnlVersion',
            325: 'XboxSignatureKey',
            326: 'XeImageFileName',
            327: 'XeLoadSection',
            328: 'XeUnloadSection',
            329: 'READ_PORT_BUFFER_UCHAR',
            330: 'READ_PORT_BUFFER_USHORT',
            331: 'READ_PORT_BUFFER_ULONG',
            332: 'WRITE_PORT_BUFFER_UCHAR',
            333: 'WRITE_PORT_BUFFER_USHORT',
            334: 'WRITE_PORT_BUFFER_ULONG',
            335: 'XcSHAInit',
            336: 'XcSHAUpdate',
            337: 'XcSHAFinal',
            338: 'XcRC4Key',
            339: 'XcRC4Crypt',
            340: 'XcHMAC',
            341: 'XcPKEncPublic',
            342: 'XcPKDecPrivate',
            343: 'XcPKGetKeyLen',
            344: 'XcVerifyPKCS1Signature',
            345: 'XcModExp',
            346: 'XcDESKeyParity',
            347: 'XcKeyTable',
            348: 'XcBlockCrypt',
            349: 'XcBlockCryptCBC',
            350: 'XcCryptService',
            351: 'XcUpdateCrypto',
            352: 'RtlRip',
            353: 'XboxLANKey',
            354: 'XboxAlternateSignatureKeys',
            355: 'XePublicKeyData',
            356: 'HalBootSMCVideoMode',
            357: 'IdexChannelObject',
            358: 'HalIsResetOrShutdownPending',
            359: 'IoMarkIrpMustComplete',
            360: 'HalInitiateShutdown',
            361: 'RtlSnprintf',
            362: 'RtlSprintf',
            363: 'RtlVsnprintf',
            364: 'RtlVsprintf',
            365: 'HalEnableSecureTrayEject',
            366: 'HalWriteSMCScratchRegister',
            374: 'MmDbgAllocateMemory',
            375: 'MmDbgFreeMemory',
            376: 'MmDbgQueryAvailablePages',
            377: 'MmDbgReleaseAddress',
            378: 'MmDbgWriteCheck',
            }

    def resolve(self, addr):
        return self.thunk_exports[addr - 0x80000000]


class SectionFlags:
    def __init__(self, flagword):
        self.writable = flagword & 1
        self.preload  = flagword & 2
        self.executable = flagword & 4
        self.inserted_file = flagword & 8
        self.head_page_read_only = flagword & 0x10
        self.tail_page_read_only = flagword & 0x20

class SectionHeader:
    def __init__(self, data):
        self.flags = SectionFlags(u32(data[0:4]))
        self.m_virtual_addr = u32(data[4:8])
        self.m_virtual_size = u32(data[8:0xc])
        self.m_raw_addr     = u32(data[0xc:0x10])
        self.m_sizeof_raw   = u32(data[0x10:0x14])
        self.m_section_name_addr = u32(data[0x14:0x18])
        self.m_section_reference_count = u32(data[0x18:0x1c])
        self.m_head_shared_ref_count_addr = u32(data[0x1c:0x20])
        self.m_tail_shared_ref_count_addr = u32(data[0x20:0x24])
        self.name = None

    def __repr__(self):
        return f"Virtual Address: {self.m_virtual_addr:#x}\n"+\
               f"Virtual Size: {self.m_virtual_size:#x}\n"+\
            f"File Offset: {self.m_raw_addr:#x}\n"+\
            f"File Size: {self.m_sizeof_raw:#x}\n"+\
            f"Section Name Address: {self.m_section_name_addr:#x}\n"+\
            f"Section Ref Count: {self.m_section_reference_count:#x}\n"+\
            f"Head Shared Ref Count Address: {self.m_head_shared_ref_count_addr:#x}\n"+\
            f"Tail Shared Ref Count Address: {self.m_tail_shared_ref_count_addr:#x}\n"

class XbeFile:
    def __init__(self, data):
        self.data = data
        self.magic = data[0:4]
        self.base_address =         u32(data[0x104:0x108])

        self.all_headers_size =     u32(data[0x108:0x10c])
        self.image_size =           u32(data[0x10c:0x110])
        self.image_header_size =    u32(data[0x110:0x114])
        self.num_sections =         u32(data[0x11c:0x120])
        self.section_headers_addr = u32(data[0x120:0x124])
        self.init_flags =           u32(data[0x124:0x128])
        self.ciphered_entry =       u32(data[0x128:0x12c])
        self.stack_size =           u32(data[0x130:0x134])
        # ignoring original PE_* values here, stop ignoring if things don't work
        self.debug_pathname_addr =  u32(data[0x14c:0x150])
        self.debug_filename_addr =  u32(data[0x150:0x154])
        self.debug_utf16_filename_addr = u32(data[0x154:0x158])
        self.cipher_kernel_image_thunk_addr = u32(data[0x158:0x15c])
        self.nonkernel_import_dir_addr = u32(data[0x15c:0x160])
        self.num_libversions = u32(data[0x160:0x164])
        self.libversions_addr = u32(data[0x164:0x168])
        self.kernel_libversions_addr = u32(data[0x168:0x16c])
        self.xapi_libversion_addr = u32(data[0x16c:0x170])
        self.sections = []

        SECTION_HEADER_SIZE = 0x38
        for i in range(0, self.num_sections * SECTION_HEADER_SIZE, SECTION_HEADER_SIZE):
            print("data start:", data[0:4])
            curr_section_header = self.section_headers_addr + i
            print(f"current_header_addr: {curr_section_header:#x}")
            section_hdr = SectionHeader(self.get_data_range(curr_section_header, curr_section_header + SECTION_HEADER_SIZE))
            section_hdr.name = get_cstr(self.get_data_range(section_hdr.m_section_name_addr, end = None))
            print(section_hdr)
            self.sections.append(section_hdr)

        self.entry = None
        self.kernel_thunk_addr = None
        self.decode_addrs() # see function implementation
        self.get_kernel_thunk_table()

    def get_data_range(self, start, end):
        if end is None:
            return self.data[start - self.base_address:]
        elif start is None:
            return self.data[:end - self.base_address]
        return self.data[start - self.base_address:end - self.base_address]

    def decode_addrs(self):
        entry_debug_key = 0x94859D4B
        entry_retail_key = 0xA8FC57AB

        thunk_debug_key = 0xEFB1F152
        thunk_retail_key = 0x5B6D40B6

        debug_entry = self.ciphered_entry ^ entry_debug_key
        retail_entry = self.ciphered_entry ^ entry_retail_key

        text_sec = self.get_section_by_name(b".text")
        if retail_entry > text_sec.m_virtual_addr and retail_entry < (text_sec.m_virtual_addr + text_sec.m_virtual_size):
            self.entry = retail_entry
            self.kernel_thunk_addr = self.cipher_kernel_image_thunk_addr ^ thunk_retail_key
        elif debug_entry > text_sec.m_virtual_addr and debug_entry < (text_sec.m_virtual_addr + text_sec.m_virtual_size):
            self.entry = debug_entry
            self.kernel_thunk_addr = self.cipher_kernel_image_thunk_addr ^ thunk_debug_key

    def get_section_by_name(self, section_name):
        for section in self.sections:
            cand_section_name = get_cstr(self.get_data_range(section.m_section_name_addr, end = None))
            print(cand_section_name)
            print(f"section name addr: {section.m_section_name_addr:#x}")
            print(f"section name addr + len: {section.m_section_name_addr + len(section_name):#x}")
            if section_name == cand_section_name:
                return section
        return None

    def get_kernel_thunk_table(self):
        print("thunk_addr: 0x%x" % self.kernel_thunk_addr)
        thunk_table = {}
        i = 0

        # kernel thunk table appears to be at the start of .rdata
        # due to walking it before mapping everything, we will just
        # use the raw address of the .rdata section
        # not sure if this workaround will bite us in the end...
        addr = self.get_section_by_name(b'.rdata').m_raw_addr

        while (True):
            thunk_data = u32(self.data[addr + i:addr  + i + 4])
            if thunk_data == 0: # end of thunk table
                break

            thunk_table[XbeKernelThunkExport().resolve(thunk_data)] = self.kernel_thunk_addr + i
            i = i+4
        self.kernel_thunk_table = thunk_table