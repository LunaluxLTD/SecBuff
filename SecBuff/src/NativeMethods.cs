/*
@author: atailh4n
NativeMethods.cs (c) 2026
@description: Native OS methods and it's generic representation methods.
Totally internal.
@created:  2026-03-23T16:21:56.122Z
Modified: !date!
*/

using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;

namespace SecBuff;

/// <summary>
/// Native OS methods and it's generic representation methods.
/// Totally internal.
/// </summary>
[SuppressMessage("ReSharper", "InconsistentNaming")]
[SuppressMessage("ReSharper", "IdentifierTypo")]
internal static partial class NativeMethods
{
    private static bool AllowPagefileOverride { get; } =
        Environment.GetEnvironmentVariable("SECBUFF_ALLOW_PAGEFILE") == "1";

    public static readonly nuint OSPageSize = (nuint)Environment.SystemPageSize;
    public static readonly bool IsWindows = OperatingSystem.IsWindows();
    private static bool _warnedAuditResult;

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("psapi.dll", EntryPoint = "GetPerformanceInfo", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool NT_GetPerformanceInfo(out NT_PERFORMANCE_INFORMATION pPerformanceInformation, int size);

    [StructLayout(LayoutKind.Sequential)]
    private struct NT_PERFORMANCE_INFORMATION
    {
        public uint cb;
        public nuint CommitTotal;
        public nuint CommitLimit;
        public nuint CommitPeak;
        public nuint PhysicalTotal;
        public nuint PhysicalAvailable;
        public nuint SystemCache;
        public nuint KernelTotal;
        public nuint KernelPaged;
        public nuint KernelNonpaged;
        public nuint PageSize;
        public uint HandleCount;
        public uint ProcessCount;
        public uint ThreadCount;
    }

    private static bool IsPagefileEnabled()
    {
        var info = new NT_PERFORMANCE_INFORMATION
        {
            cb = (uint)Marshal.SizeOf<NT_PERFORMANCE_INFORMATION>()
        };
        if (!NT_GetPerformanceInfo(out info, (int)info.cb)) throw new Win32Exception();
        return info.CommitLimit > info.PhysicalTotal;
    }

    // Check if we are in Windows.
    private static void AuditWindowsEnvironment()
    {
        if (!IsWindows && !_warnedAuditResult) return;

        // 1. Report it kindly.
        Trace.TraceWarning(
            "[SecBuff.Audit] Operating on Windows environment. " +
            "Due to legacy architectural constraints in the NT Kernel (VAD management), " +
            "deterministic memory locking cannot be guaranteed when combined with page-level protection. " +
            "Use of this library on Windows is considered sub-optimal for high-security assurance. " +
            "POSIX systems such as Linux, BSD or MacOS strongly recommended due to their " +
            "predictable virtual memory patterns unlike Windows.");

        // 2. PageFile control (skip testing)
        if (Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_TEST") != "1" && IsPagefileEnabled() && !AllowPagefileOverride)
        {
            throw new SecurityException(
                "[SecBuff.Audit] CRITICAL: System swap (PageFile) is active. " +
                "The Windows Memory Manager may silently drop VirtualLock status during " +
                "protection transitions (PAGE_NOACCESS), potentially leaking sensitive data to disk. " +
                "To maintain zero-swap integrity, PageFile MUST be disabled at the OS level. " +
                "Lunalux.SecBuff cannot continue to work on this system. " +
                "If you want to bypass this and get responsibility, pass SECBUFF_ALLOW_PAGEFILE=1 to " +
                "your environment values.");
        }

        Trace.TraceWarning("[SecBuff.Audit] Running with PageFile enabled due to SECBUFF_ALLOW_PAGEFILE override. " +
                       "Zero-swap integrity is NOT guaranteed.");

        _warnedAuditResult = true;
    }

    static NativeMethods()
    {
        AuditWindowsEnvironment();
    }

    // --- Windows (kernel32.dll) ---
    [StructLayout(LayoutKind.Sequential)]
    public struct NT_MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "VirtualLock", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool NT_VirtualLock(IntPtr lpAddress, nuint dwSize);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "VirtualUnlock", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool NT_VirtualUnlock(IntPtr lpAddress, nuint dwSize);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "VirtualProtect", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool NT_VirtualProtect(IntPtr lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "VirtualQuery", SetLastError = true)]
    private static partial nuint NT_VirtualQuery(IntPtr lpAddress, out NT_MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    // --- POSIX (libc) ---
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "mlock", SetLastError = true)]
    private static partial int POSIX_mlock(IntPtr addr, nuint len);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "munlock", SetLastError = true)]
    private static partial int POSIX_munlock(IntPtr addr, nuint len);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "mprotect", SetLastError = true)]
    private static partial int POSIX_mprotect(IntPtr addr, nuint len, int prot);

    public static uint NT_GetCurrentProtection(IntPtr addr)
    {
        var result = NT_VirtualQuery(addr, out var mbi, (UIntPtr)Marshal.SizeOf<NT_MEMORY_BASIC_INFORMATION>());
        return result == UIntPtr.Zero ? throw new Win32Exception(Marshal.GetLastWin32Error()) : mbi.Protect;
    }

    public static bool LockMemory(IntPtr addr, nuint len)
    {
        if (IsWindows)
            return NT_VirtualLock(addr, len);
        return POSIX_mlock(addr, len) == 0;
    }

    public static bool UnlockMemory(IntPtr addr, nuint len)
    {
        if (IsWindows)
            return NT_VirtualUnlock(addr, len);
        return POSIX_munlock(addr, len) == 0;
    }

    public static bool ProtectMemory(IntPtr addr, nuint len, int prot)
    {
        if (IsWindows)
            return NT_VirtualProtect(addr, len, (uint)prot, out _);
        return POSIX_mprotect(addr, len, prot) == 0;
    }
}