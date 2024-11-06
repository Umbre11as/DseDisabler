#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
#include <ntifs.h>
#include <ntstrsafe.h>
#include <CaveHook.h>

#define Log(format, ...) DbgPrintEx(0, 0, format, __VA_ARGS__)

extern "C" {
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation, // not implemented
        SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
        SystemModuleInformation, // q: RTL_PROCESS_MODULES
        SystemLocksInformation, // q: RTL_PROCESS_LOCKS
        SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
        SystemPagedPoolInformation, // not implemented
        SystemNonPagedPoolInformation, // not implemented
        SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
        SystemVdmBopInformation, // not implemented // 20
        SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemLoadGdiDriverInformation, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation, // s (kernel-mode only)
        SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
        SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
        SystemObsolete0, // not implemented
        SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeperation, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
        SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
        SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
        SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
        SystemSessionCreate, // not implemented
        SystemSessionDetach, // not implemented
        SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
        SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
        SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend, // s (kernel-mode only)
        SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
        SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
        SystemComPlusPackage, // q; s: ULONG
        SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
        SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation, // q: ULONG
        SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
        SystemObjectSecurityMode, // q: ULONG // 70
        SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
        SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
        SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemWow64SharedInformationObsolete, // not implemented
        SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
        SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
        SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
        SystemVerifierTriageInformation, // not implemented
        SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
        SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
        SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
        SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx, // not implemented
        SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
        SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
        SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
        SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
        SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
        SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
        SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
        SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
        SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
        SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
        SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
        SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
        SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
        SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
        SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
        SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
        SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
        SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
        SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
        SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
        SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
        SystemBadPageInformation, // SYSTEM_BAD_PAGE_INFORMATION
        SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
        SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
        SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
        SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
        SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
        SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
        SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
        SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
        SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
        SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
        SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
        SystemCriticalProcessErrorLogInformation,
        SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
        SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
        SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation, // 150
        SystemSoftRebootInformation, // q: ULONG
        SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
        SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
        SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
        SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
        SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
        SystemCodeIntegrityPolicyInformation, // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
        SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
        SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
        SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
        SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
        SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
        SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
        SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
        SystemInterruptSteeringInformation, // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
        SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
        SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
        SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
        SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
        SystemControlFlowTransition, // (Warbird/Encrypt/Decrypt/Execute)
        SystemKernelDebuggingAllowed, // s: ULONG
        SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
        SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
        SystemIntegrityQuotaInformation,
        SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
        SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
        SystemSecureDumpEncryptionInformation,
        SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
        SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
        SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
        SystemFirmwareBootPerformanceInformation,
        SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
        SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
        SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
        SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
        SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
        SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
        SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
        SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
        SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
        SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
        SystemCodeIntegritySyntheticCacheInformation,
        SystemFeatureConfigurationInformation, // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
        SystemFeatureConfigurationSectionInformation, // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
        SystemFeatureUsageSubscriptionInformation, // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
        SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
        SystemSpacesBootInformation, // since 20H2
        SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
        SystemWheaIpmiHardwareInformation,
        SystemDifSetRuleClassInformation, // SYSTEM_DIF_VOLATILE_INFORMATION
        SystemDifClearRuleClassInformation,
        SystemDifApplyPluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
        SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
        SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
        SystemBuildVersionInformation, // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
        SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege)
        SystemCodeIntegrityAddDynamicStore,
        SystemCodeIntegrityClearDynamicStores,
        SystemDifPoolTrackingInformation,
        SystemPoolZeroingInformation, // q: SYSTEM_POOL_ZEROING_INFORMATION
        SystemDpcWatchdogInformation, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
        SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
        SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
        SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
        SystemXfgCheckFailureInformation, // q: SYSTEM_XFG_FAILURE_INFORMATION
        SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
        SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
        SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
        SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
        SystemSecureKernelDebuggerInformation,
        SystemOriginalImageFeatureInformation, // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
        SystemMemoryNumaInformation, // SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT
        SystemMemoryNumaPerformanceInformation, // SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUTSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
        SystemCodeIntegritySignedPoliciesFullInformation,
        SystemSecureSecretsInformation,
        SystemTrustedAppsRuntimeInformation, // SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
        SystemBadPageInformationEx, // SYSTEM_BAD_PAGE_INFORMATION
        SystemResourceDeadlockTimeout, // ULONG
        SystemBreakOnContextUnwindFailureInformation, // ULONG (requires SeDebugPrivilege)
        SystemOslRamdiskInformation, // SYSTEM_OSL_RAMDISK_INFORMATION
        MaxSystemInfoClass
    } SYSTEM_INFORMATION_CLASS;

    enum _LDR_DLL_LOAD_REASON {
        LoadReasonStaticDependency = 0,
        LoadReasonStaticForwarderDependency = 1,
        LoadReasonDynamicForwarderDependency = 2,
        LoadReasonDelayloadDependency = 3,
        LoadReasonDynamicLoad = 4,
        LoadReasonAsImageLoad = 5,
        LoadReasonAsDataLoad = 6,
        LoadReasonEnclavePrimary = 7,
        LoadReasonEnclaveDependency = 8,
        LoadReasonPatchImage = 9,
        LoadReasonUnknown = -1
    };

    enum _LDR_HOT_PATCH_STATE {
        LdrHotPatchBaseImage = 0,
        LdrHotPatchNotApplied = 1,
        LdrHotPatchAppliedReverse = 2,
        LdrHotPatchAppliedForward = 3,
        LdrHotPatchFailedToPatch = 4,
        LdrHotPatchStateMax = 5
    };

    typedef struct _LDR_DATA_TABLE_ENTRY {
        struct _LIST_ENTRY InLoadOrderLinks; //0x0
        struct _LIST_ENTRY InMemoryOrderLinks; //0x10
        struct _LIST_ENTRY InInitializationOrderLinks; //0x20
        VOID *DllBase; //0x30
        VOID *EntryPoint; //0x38
        ULONG SizeOfImage; //0x40
        struct _UNICODE_STRING FullDllName; //0x48
        struct _UNICODE_STRING BaseDllName; //0x58
        union {
            UCHAR FlagGroup[4]; //0x68
            ULONG Flags; //0x68
            struct {
                ULONG PackagedBinary: 1; //0x68
                ULONG MarkedForRemoval: 1; //0x68
                ULONG ImageDll: 1; //0x68
                ULONG LoadNotificationsSent: 1; //0x68
                ULONG TelemetryEntryProcessed: 1; //0x68
                ULONG ProcessStaticImport: 1; //0x68
                ULONG InLegacyLists: 1; //0x68
                ULONG InIndexes: 1; //0x68
                ULONG ShimDll: 1; //0x68
                ULONG InExceptionTable: 1; //0x68
                ULONG ReservedFlags1: 2; //0x68
                ULONG LoadInProgress: 1; //0x68
                ULONG LoadConfigProcessed: 1; //0x68
                ULONG EntryProcessed: 1; //0x68
                ULONG ProtectDelayLoad: 1; //0x68
                ULONG ReservedFlags3: 2; //0x68
                ULONG DontCallForThreads: 1; //0x68
                ULONG ProcessAttachCalled: 1; //0x68
                ULONG ProcessAttachFailed: 1; //0x68
                ULONG CorDeferredValidate: 1; //0x68
                ULONG CorImage: 1; //0x68
                ULONG DontRelocate: 1; //0x68
                ULONG CorILOnly: 1; //0x68
                ULONG ChpeImage: 1; //0x68
                ULONG ChpeEmulatorImage: 1; //0x68
                ULONG ReservedFlags5: 1; //0x68
                ULONG Redirected: 1; //0x68
                ULONG ReservedFlags6: 2; //0x68
                ULONG CompatDatabaseProcessed: 1; //0x68
            };
        };
        USHORT ObsoleteLoadCount; //0x6c
        USHORT TlsIndex; //0x6e
        struct _LIST_ENTRY HashLinks; //0x70
        ULONG TimeDateStamp; //0x80
        struct _ACTIVATION_CONTEXT *EntryPointActivationContext; //0x88
        VOID *Lock; //0x90
        struct _LDR_DDAG_NODE *DdagNode; //0x98
        struct _LIST_ENTRY NodeModuleLink; //0xa0
        struct _LDRP_LOAD_CONTEXT *LoadContext; //0xb0
        VOID *ParentDllBase; //0xb8
        VOID *SwitchBackContext; //0xc0
        struct _RTL_BALANCED_NODE BaseAddressIndexNode; //0xc8
        struct _RTL_BALANCED_NODE MappingInfoIndexNode; //0xe0
        ULONGLONG OriginalBase; //0xf8
        union _LARGE_INTEGER LoadTime; //0x100
        ULONG BaseNameHashValue; //0x108
        enum _LDR_DLL_LOAD_REASON LoadReason; //0x10c
        ULONG ImplicitPathOptions; //0x110
        ULONG ReferenceCount; //0x114
        ULONG DependentLoadFlags; //0x118
        UCHAR SigningLevel; //0x11c
        ULONG CheckSum; //0x120
        VOID *ActivePatchImageBase; //0x128
        enum _LDR_HOT_PATCH_STATE HotPatchState; //0x130
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef NTSTATUS(*DRIVER_ENTRYPOINT)(PDRIVER_OBJECT, PUNICODE_STRING);

extern "C" {
    NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(
            IN PVOID ImageBase,
            IN PCCH RoutineName
    );

    NTSTATUS NTAPI ZwQuerySystemInformation(
            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IN OUT PVOID SystemInformation,
            IN ULONG SystemInformationLength,
            OUT OPTIONAL PULONG ReturnLength
    );
}

struct Request {
    ULONGLONG Offset;
    int NewValue;
};

static PVOID gCIBase = nullptr;

void CommunicationDetour(PVOID buffer, SIZE_T size, ULONGLONG cookie) {
    if (ExGetPreviousMode() == UserMode && cookie == 0xABCCC2F && buffer && size > 0) {
        auto request = reinterpret_cast<Request*>(buffer);
        memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONGLONG>(gCIBase) + request->Offset), &request->NewValue, sizeof(request->NewValue));

        int newV = 0;
        memcpy(&newV, reinterpret_cast<PVOID>(reinterpret_cast<ULONGLONG>(gCIBase) + request->Offset), sizeof(newV));
        Log("g_CiOptions: %p, new value: %d\n", reinterpret_cast<ULONGLONG>(gCIBase) + request->Offset, newV);
    }
}

PVOID GetSystemModuleBase(IN PCSTR path) {
    ULONG size = 0;
    ZwQuerySystemInformation(SystemModuleInformation, nullptr, size, &size);
    if (size <= 0)
        return nullptr;

    auto processModules = reinterpret_cast<PRTL_PROCESS_MODULES>(ExAllocatePool(NonPagedPool, size));
    ZwQuerySystemInformation(SystemModuleInformation, processModules, size, &size);
    if (!processModules)
        return nullptr;

    RTL_PROCESS_MODULE_INFORMATION moduleInformation;
    for (ULONG i = 0; i < processModules->NumberOfModules; i++) {
        moduleInformation = processModules->Modules[i];
        if (strcmp(moduleInformation.FullPathName, path) == 0) {
            ExFreePool(processModules);
            return moduleInformation.ImageBase;
        }
    }

    ExFreePool(processModules);
    return nullptr;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmicrosoft-cast"
NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"PsLoadedModuleList");
    auto moduleList = reinterpret_cast<PLIST_ENTRY>(MmGetSystemRoutineAddress(&functionName));
    if (!moduleList)
        return STATUS_INVALID_ADDRESS;

    UNICODE_STRING ciDllName;
    RtlInitUnicodeString(&ciDllName, L"CI.dll");

    for (PLIST_ENTRY link = moduleList; link != moduleList->Blink; link = link->Flink) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (entry && RtlCompareUnicodeString(&ciDllName, &entry->BaseDllName, TRUE) == 0) {
            gCIBase = entry->DllBase;
            break;
        }
    }
    if (!gCIBase)
        return STATUS_NOT_FOUND;

    PVOID ntoskrnlBase = GetSystemModuleBase(R"(\SystemRoot\system32\ntoskrnl.exe)");
    if (!ntoskrnlBase)
        return STATUS_INVALID_ADDRESS;

    PVOID function = RtlFindExportedRoutineByName(ntoskrnlBase, "NtCompareSigningLevels");
    if (!function)
        return STATUS_NOT_FOUND;

    CaveHook(reinterpret_cast<ULONGLONG>(function), CommunicationDetour, nullptr);
    return STATUS_SUCCESS;
}
#pragma clang diagnostic pop

#pragma clang diagnostic pop