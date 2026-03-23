/*
 * Author: atailh4n
 * File: NativeMethodsTests.cs
 * Copyright (c) 2026
 * Description: Tests for NativeMethods' LockMemory, UnlockMemory, ProtectMemory.
 * Created: 2026-03-23
 * Modified: !date!
 */

using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Xunit;
using static SecBuff.NativeMethods;

namespace SecBuff.Tests;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public sealed unsafe class NativeMethodsTests
{
    // Helper method
    private static byte* AllocAligned(out nuint size)
    {
        size = OSPageSize;
        return (byte*)NativeMemory.AlignedAlloc(size, OSPageSize);
    }
    // -------------------------------------------------------------------------
    // LockMemory
    // -------------------------------------------------------------------------
    [Fact]
    public void LockMemory_ValidPageAlignedAddress_ReturnsTrue()
    {
        var ptr = AllocAligned(out var size);
        try
        {
            var result = LockMemory((IntPtr)ptr, size);

            // mlock may fail in low ulimit environments, do not skip, warn instead
            // CI may require root or CAP_IPC_LOCK privileges
            if (!result)
                Assert.Fail($"mlock/VirtualLock failed. OS error: {Marshal.GetLastPInvokeError()}. " +
                            "Check ulimit -l or process privileges.");
        }
        finally
        {
            UnlockMemory((IntPtr)ptr, size);
            NativeMemory.AlignedFree(ptr);
        }
    }

    [Fact]
    public void LockMemory_ThenUnlock_BothSucceed()
    {
        var ptr = AllocAligned(out var size);
        try
        {
            var locked = LockMemory((IntPtr)ptr, size);
            var unlocked = UnlockMemory((IntPtr)ptr, size);

            Assert.True(locked, "LockMemory failed");
            Assert.True(unlocked, "UnlockMemory failed");
        }
        finally
        {
            NativeMemory.AlignedFree(ptr);
        }
    }

    [Fact]
    public void LockMemory_AlreadyLocked_DoesNotThrow()
    {
        // Kernel is typically idempotent, double lock should not throw
        var ptr = AllocAligned(out var size);
        try
        {
            LockMemory((IntPtr)ptr, size);
            var result = LockMemory((IntPtr)ptr, size); // second call
            Assert.True(result, "Double lock should succeed silently. Not reference counted.");
            // Result is OS-dependent, but it should not throw
            UnlockMemory((IntPtr)ptr, size);
        }
        finally
        {
            NativeMemory.AlignedFree(ptr);
        }
    }

    // -------------------------------------------------------------------------
    // UnlockMemory
    // -------------------------------------------------------------------------

    [Fact]
    public void UnlockMemory_WithoutPriorLock_ReturnsFalseOrTrue()
    {
        // On POSIX, unlocking a non-locked region may return ENOMEM
        // On Windows, VirtualUnlock may fail
        // Both outcomes are acceptable, the important part is no crash
        var ptr = AllocAligned(out var size);
        try
        {
            _ = UnlockMemory((IntPtr)ptr, size);
            // No exception = pass
        }
        finally
        {
            NativeMemory.AlignedFree(ptr);
        }
    }

    // -------------------------------------------------------------------------
    // ProtectMemory
    // -------------------------------------------------------------------------
    [Fact]
    public void ProtectMemory_PAGE_READWRITE_ReturnsTrue()
    {
        if (!IsWindows) return;
        var ptr = AllocAligned(out var size);
        try
        {
            LockMemory((IntPtr)ptr, size);

            const int PAGE_READWRITE = 0x04;
            var result = ProtectMemory((IntPtr)ptr, size, PAGE_READWRITE);
            Assert.True(result, $"VirtualProtect failed. OS error: {Marshal.GetLastPInvokeError()}");
        }
        finally
        {
            UnlockMemory((IntPtr)ptr, size);
            NativeMemory.AlignedFree(ptr);
        }
    }

    [Fact]
    public void ProtectMemory_PAGE_NOACCESS_ReturnsTrue()
    {
        if (!IsWindows) return;
        var ptr = AllocAligned(out var size);
        try
        {
            LockMemory((IntPtr)ptr, size);

            const int PAGE_NOACCESS = 0x01;
            const int PAGE_READWRITE = 0x04;

            var result = ProtectMemory((IntPtr)ptr, size, PAGE_NOACCESS);
            Assert.True(result);

            // Restore protection before free
            ProtectMemory((IntPtr)ptr, size, PAGE_READWRITE);
        }
        finally
        {
            UnlockMemory((IntPtr)ptr, size);
            NativeMemory.AlignedFree(ptr);
        }
    }

    [Fact]
    public void ProtectMemory_PROT_NONE_ReturnsTrue()
    {
        if (IsWindows) return;
        var ptr = AllocAligned(out var size);
        try
        {
            LockMemory((IntPtr)ptr, size);

            const int PROT_NONE = 0x0;
            var result = ProtectMemory((IntPtr)ptr, size, PROT_NONE);
            Assert.True(result, $"mprotect PROT_NONE failed. OS error: {Marshal.GetLastPInvokeError()}");

            // Restore protection before free
            const int PROT_READ_WRITE = 0x1 | 0x2;
            ProtectMemory((IntPtr)ptr, size, PROT_READ_WRITE);
        }
        finally
        {
            UnlockMemory((IntPtr)ptr, size);
            NativeMemory.AlignedFree(ptr);
        }
    }

    [Fact]
    public void ProtectMemory_PROT_READ_ReturnsTrue()
    {
        if (IsWindows) return;
        var ptr = AllocAligned(out var size);
        try
        {
            LockMemory((IntPtr)ptr, size);

            const int PROT_READ = 0x1;
            var result = ProtectMemory((IntPtr)ptr, size, PROT_READ);
            Assert.True(result);

            const int PROT_READ_WRITE = 0x1 | 0x2;
            ProtectMemory((IntPtr)ptr, size, PROT_READ_WRITE);
        }
        finally
        {
            UnlockMemory((IntPtr)ptr, size);
            NativeMemory.AlignedFree(ptr);
        }
    }

    [Fact]
    public void ProtectMemory_UnalignedAddress_ReturnsFalse()
    {
        if (IsWindows) return;
        var ptr = AllocAligned(out var size);
        try
        {
            LockMemory((IntPtr)ptr, size);

            // Intentionally misalign by 1 byte, expect mprotect EINVAL
            var misaligned = (IntPtr)(ptr + 1);
            const int PROT_READ = 0x1;
            var result = ProtectMemory(misaligned, size, PROT_READ);

            Assert.False(result, "mprotect should fail on unaligned address");
        }
        finally
        {
            UnlockMemory((IntPtr)ptr, size);
            NativeMemory.AlignedFree(ptr);
        }
    }

    // -------------------------------------------------------------------------
    // Platform smoke test
    // -------------------------------------------------------------------------

    [Fact]
    public void LockUnlockProtect_FullCycle_NoExceptions()
    {
        // Simulates the full sequence used in SecureBuffer constructor
        var ptr = AllocAligned(out var size);
        try
        {
            var locked = LockMemory((IntPtr)ptr, size);
            Assert.SkipUnless(locked,
                $"LockMemory failed (LastError: {Marshal.GetLastWin32Error()}); unprivileged environment.");

            var readWrite = IsWindows ? 0x04 : (0x1 | 0x2);
            var noAccess = IsWindows ? 0x01 : 0x0;

            Assert.True(ProtectMemory((IntPtr)ptr, size, readWrite), "ProtectMemory RW failed");

            // Write some data
            ptr[0] = 0xDE;
            ptr[1] = 0xAD;

            // Lock dismissed at RIGHT here. Unlock removed.
            Assert.True(ProtectMemory((IntPtr)ptr, size, noAccess), "ProtectMemory NoAccess failed");
            Assert.True(ProtectMemory((IntPtr)ptr, size, readWrite), "ProtectMemory RW restore failed");
        }
        finally
        {
            NativeMemory.AlignedFree(ptr);
        }
    }
}