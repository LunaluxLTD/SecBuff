/*
@author: atailh4n
NativeMethods.cs (c) 2026
@description: Native OS methods and it's generic representation methods.
Totally internal.
@created:  2026-03-23
Modified: 2026-04-29
*/

using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;
using static SecBuff.FilePermissions;

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
        if (!NT_GetPerformanceInfo(out info, (int)info.cb)) throw new Win32Exception("Couldn't get memory info, SecBuff cannot continue.");
        return info.CommitLimit > info.PhysicalTotal;
    }

    // Check if we are in Windows.
    private static void AuditWindowsEnvironment()
    {
        if (!IsWindows) return;
        if (_warnedAuditResult) return;

        // 1. Report it kindly.
        Trace.TraceWarning(
            "[SecBuff.Audit] Operating on Windows environment. " +
            "Due to legacy architectural constraints in the NT Kernel (VAD management), " +
            "deterministic memory locking cannot be guaranteed when combined with page-level protection. " +
            "Use of this library on Windows is considered sub-optimal for high-security assurance. " +
            "POSIX systems such as Linux, BSD or MacOS strongly recommended due to their " +
            "predictable virtual memory patterns unlike Windows.");

        // 2. PageFile control (skip testing)
        if (Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_TEST") != "1" && IsPagefileEnabled())
        {
            if (!AllowPagefileOverride)
                throw new SecurityException(
                    "[SecBuff.Audit] CRITICAL: System swap (PageFile) is active. " +
                    "The Windows Memory Manager may silently drop VirtualLock status during " +
                    "protection transitions (PAGE_NOACCESS), potentially leaking sensitive data to disk. " +
                    "To maintain zero-swap integrity, PageFile MUST be disabled at the OS level. " +
                    "Lunalux.SecBuff cannot continue to work on this system. " +
                    "If you want to bypass this and get responsibility, pass SECBUFF_ALLOW_PAGEFILE=1 to " +
                    "your environment values.");
            
            Trace.TraceWarning("[SecBuff.Audit] Running with PageFile enabled due to SECBUFF_ALLOW_PAGEFILE override. " +
                               "Zero-swap integrity is NOT guaranteed.");
        }

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

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr NT_CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "ReadFile", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool NT_ReadFile(
        IntPtr hFile,
        void* lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "WriteFile", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool NT_WriteFile(
        IntPtr hFile,
        void* lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool NT_CloseHandle(IntPtr hObject);
    
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
    
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int POSIX_open(string pathname, int flags, int mode);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "read", SetLastError = true)]
    private static unsafe partial nint POSIX_read(int fd, void* buf, nuint count);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "write", SetLastError = true)]
    private static unsafe partial nint POSIX_write(int fd, void* buf, nuint count);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int POSIX_close(int fd);

    public static uint NT_GetCurrentProtection(IntPtr addr)
    {
        var result = NT_VirtualQuery(addr, out var mbi, (UIntPtr)Marshal.SizeOf<NT_MEMORY_BASIC_INFORMATION>());
        return result == UIntPtr.Zero ? throw new Win32Exception(Marshal.GetLastWin32Error()) : mbi.Protect;
    }

#region Native Memory Operations

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

#endregion

#region Native File System
    public static unsafe void ReadFileExact(string path, Span<byte> buffer)
    {
        if (IsWindows)
        {
            var handle = NT_CreateFile(path, NT_GENERIC_READ, 0, IntPtr.Zero, NT_OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception($"[SecBuff] NT CreateFileW failed: {Marshal.GetLastWin32Error()}");
    
            try
            {
                fixed (byte* ptr = buffer)
                {
                    if (!NT_ReadFile(handle, ptr, (uint)buffer.Length, out var read, IntPtr.Zero))
                        throw new IOException($"[SecBuff] NT ReadFile failed: {Marshal.GetLastWin32Error()}");
                    
                    if (read != buffer.Length)
                        throw new EndOfStreamException("Unexpected EOF.");
                }
            }
            finally
            {
                if (!NT_CloseHandle(handle))
                    Trace.TraceWarning($"[SecBuff] NT CloseHandle failed: {Marshal.GetLastWin32Error()}");
            }
            return;
        }
        
        var fd = POSIX_open(path, POSIX_O_RDONLY, 0);
        if (fd < 0)
        {
            var errno = Marshal.GetLastPInvokeError();

            throw errno switch
            {
                2  => new FileNotFoundException(null, path), // ENOENT
                13 => new UnauthorizedAccessException(),    // EACCES
                _  => new IOException($"POSIX open failed (errno={errno})")
            };
        }
    
        try
        {
            fixed (byte* buf = buffer)
            {
                var read = POSIX_read(fd, buf, (nuint)buffer.Length);
                if (read != buffer.Length)
                    throw new EndOfStreamException("Unexpected EOF.");
            }
        }
        finally
        {
            if (POSIX_close(fd) != 0)
                Trace.TraceWarning($"[SecBuff] POSIX close() failed: {Marshal.GetLastPInvokeError()}");
        }
    }
    
    public static unsafe void WriteFileExact(string path, ReadOnlySpan<byte> buffer)
    {
        if (IsWindows)
        {
            var handle = NT_CreateFile(path, NT_GENERIC_WRITE, 0, IntPtr.Zero, NT_CREATE_ALWAYS, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error());
    
            try
            {
                fixed (byte* ptr = buffer)
                {
                    if (!NT_WriteFile(handle, ptr, (uint)buffer.Length, out var written, IntPtr.Zero) || written != buffer.Length)
                        throw new IOException("[SecBuff] NT_Write failed.");
                }
            }
            finally
            {
                if (!NT_CloseHandle(handle))
                    Trace.TraceWarning($"[SecBuff] NT_CloseHandle failed: {Marshal.GetLastWin32Error()}");
            }
            return;
        }

        var fd = POSIX_open(path, POSIX_O_WRONLY | POSIX_O_CREAT | POSIX_O_TRUNC, 0x1A4); // 0644
        if (fd < 0)
            throw new IOException($"[SecBuff] POSIX open() failed: ${Marshal.GetLastPInvokeError()}");
    
        try
        {
            fixed (byte* buf = buffer)
            {
                var written = POSIX_write(fd, buf, (nuint)buffer.Length);
                if (written != buffer.Length)
                    throw new IOException($"[SecBuff] POSIX write() failed: ${Marshal.GetLastPInvokeError()}");
            }
        }
        finally
        {
            if (POSIX_close(fd) != 0)
                Trace.TraceWarning($"[SecBuff] POSIX close() failed: {Marshal.GetLastPInvokeError()}");
        }
    }
#endregion
}