/*
@author: atailh4n
SecureBuffer.cs (c) 2026
@description: Provides a secure, fixed-address memory buffer that is protected from being swapped to disk
@created:  2026-03-23
Modified: 2026-04-29
*/

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SecBuff.Interfaces;
using static System.Runtime.InteropServices.NativeMemory;
using static SecBuff.NativeMethods;
using static SecBuff.PageStates;

namespace SecBuff;

/// <summary>
/// Provides a secure, fixed-address memory buffer that is protected from being swapped to disk 
/// and optionally guarded by OS-level memory protection (NX/RO/RW).
/// </summary>
/// <remarks>
/// This class ensures that sensitive data is kept in RAM using <c>mlock</c> (POSIX) or <c>VirtualLock</c> (Windows).
/// If <c>useMprotect</c> is enabled, the memory is set to <c>PROT_NONE</c> when not in use, 
/// preventing unauthorized read/write access even within the same process.
/// </remarks>
[SuppressMessage("ReSharper", "IdentifierTypo")]
[SuppressMessage("ReSharper", "InconsistentNaming")]
public sealed unsafe class SecureBuffer : ISecureBuffer
{
    private readonly byte* _pointer;
    private nint _pointerHandle;
    private readonly int _length;
    private readonly nuint _allocationSize;
    private readonly bool _useMprotect;
    private readonly ReaderWriterLockSlim? _protectionLock;

    private int _state;
    private const int DisposedFlag = unchecked((int)0x80000000);
    
    /// <summary>
    /// Check for if this instance uses <c>mprotect</c> or <c>VirtualProtect</c>
    /// </summary>
    public bool UsesMprotect => _useMprotect;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBuffer"/> class.
    /// </summary>
    /// <param name="length">The size of the buffer in bytes.</param>
    /// <param name="useMprotect">
    /// If <see langword="true"/>, enables page-level protection. Memory will be aligned to system page size 
    /// and access will be restricted when no leases are active.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if length is less than or equal to zero.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the OS fails to lock or protect the memory region.</exception>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public SecureBuffer(int length, bool useMprotect = false)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

        _length = length;
        _useMprotect = useMprotect;
        
        _allocationSize = ((nuint)length + OSPageSize - 1) & ~(OSPageSize - 1);
        _pointer = (byte*)AlignedAlloc(_allocationSize, OSPageSize);
        _pointerHandle = (nint)_pointer;

        try
        {
            // Lock memory in RAM to prevent swapping to disk
            if (!LockMemory((IntPtr)_pointer, _allocationSize))
                throw new InvalidOperationException(
                    $"Failed to lock memory. OS Error: {Marshal.GetLastPInvokeError()}");

            if (_useMprotect)
            {
                // Set initial protection to RW so we can zero it and prepare for first use
                if (!ProtectMemory((IntPtr)_pointer, _allocationSize, IsWindows ? NT_PAGE_READWRITE : (POSIX_PROT_READ | POSIX_PROT_WRITE)))
                    throw new InvalidOperationException(
                        $"Failed to set memory protection. OS Error: {Marshal.GetLastPInvokeError()}");

                _protectionLock = new ReaderWriterLockSlim();
            }
        }
        catch
        {
            AlignedFree(_pointer);
            throw;
        }
        CryptographicOperations.ZeroMemory(new Span<byte>(_pointer, _length));
    }

    /// <summary>
    /// Helper method for platform
    /// specific memory protecting flags. 
    /// </summary>
    private static int GetProtectionFlag(bool write)
    {
        if (IsWindows)
            return write ? NT_PAGE_READWRITE : NT_PAGE_READONLY;
        return write ? (POSIX_PROT_READ | POSIX_PROT_WRITE) : POSIX_PROT_READ;
    }

    /// <summary>
    /// Transitions the memory state to <c>PROT_NONE</c>, disabling all access.
    /// Use this after the initial data write to ensure the buffer is unreachable until explicitly acquired.
    /// </summary>
    /// <remarks>This only has an effect if <c>useMprotect</c> was set to <see langword="true"/> during construction.</remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the buffer has already been disposed.</exception>
    public void Seal()
    {
        if (!_useMprotect) return;

        Debug.Assert(_protectionLock != null, nameof(_protectionLock) + " != null");
        _protectionLock.EnterWriteLock();
        try
        {
            var current = Volatile.Read(ref _state);

            if ((current & DisposedFlag) == 0)
            {
                if (current == 0)
                {
                    ProtectMemory((IntPtr)_pointer, _allocationSize, IsWindows ? NT_PAGE_NOACCESS : POSIX_PROT_NONE);
                }
            }
            else
            {
                throw new ObjectDisposedException(nameof(SecureBuffer));
            }
        }
        finally
        {
            _protectionLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Acquires a synchronous lease for accessing the secured memory.
    /// </summary>
    /// <param name="requestWrite">If <see langword="true"/>, requests write access (RW); otherwise, requests read-only access (RO).</param>
    /// <returns>A <see cref="SecureLease"/> that must be disposed to release access. Modern <c>using var</c> recommended for auto disposal.</returns>
    /// <remarks>
    /// If <c>useMprotect</c> is enabled, this method will transition the memory page protections. 
    /// Multiple readers can coexist, but a writer requires exclusive access.
    /// </remarks>
    public SecureLease Acquire(bool requestWrite = false)
    {
        if (_useMprotect)
        {
            Debug.Assert(_protectionLock != null, nameof(_protectionLock) + " != null");
            if (!requestWrite)
            {
                _protectionLock.EnterReadLock();
            }
            else
            {
                _protectionLock.EnterWriteLock();
            }

            try
            {
                var current = Volatile.Read(ref _state);
                ObjectDisposedException.ThrowIf((current & DisposedFlag) != 0, nameof(SecureBuffer));

                var protection = GetProtectionFlag(requestWrite);
                if (!ProtectMemory((IntPtr)_pointer, _allocationSize, protection))
                    throw new InvalidOperationException("Failed to transition memory protection state.");
                Interlocked.Increment(ref _state);

                return new SecureLease(this, _pointer, _length);
            }
            finally
            {
                if (!requestWrite)
                {
                    _protectionLock.ExitReadLock();
                }
                else
                {
                    _protectionLock.ExitWriteLock();
                }
            }
        }

        // Lock-free path for buffers without OS-level page protection
        while (true)
        {
            var current = Volatile.Read(ref _state);
            if ((current & DisposedFlag) == 0)
            {
                if (Interlocked.CompareExchange(ref _state, current + 1, current) == current)
                    return new SecureLease(this, _pointer, _length);
            }
            else
            {
                throw new ObjectDisposedException(nameof(SecureBuffer));
            }
        }
    }

    /// <summary>
    /// Acquires an asynchronous lease for accessing the secured memory.
    /// </summary>
    /// <param name="requestWrite">If <see langword="true"/>, requests write access (RW); otherwise, requests read-only access (RO).</param>
    /// <returns>A <see cref="SecureAsyncLease"/> which, unlike <see cref="SecureLease"/>, is not a ref-struct and can be used across await boundaries.</returns>
    public SecureAsyncLease AcquireAsync(bool requestWrite = false)
    {
        if (_useMprotect)
        {
            Debug.Assert(_protectionLock != null, nameof(_protectionLock) + " != null");
            if (!requestWrite)
            {
                _protectionLock.EnterReadLock();
            }
            else
            {
                _protectionLock.EnterWriteLock();
            }
            try
            {
                var current = Volatile.Read(ref _state);
                ObjectDisposedException.ThrowIf((current & DisposedFlag) != 0, nameof(SecureBuffer));

                var protection = GetProtectionFlag(requestWrite);
                if (!ProtectMemory((IntPtr)_pointer, _allocationSize, protection))
                    throw new InvalidOperationException("Failed to transition memory protection state.");
                Interlocked.Increment(ref _state);

                return new SecureAsyncLease(this, _pointer, _length);
            }
            finally
            {
                if (!requestWrite)
                {
                    _protectionLock.ExitReadLock();
                }
                else
                {
                    _protectionLock.ExitWriteLock();
                }
            }
        }

        while (true)
        {
            var current = Volatile.Read(ref _state);
            if ((current & DisposedFlag) == 0)
            {
                if (Interlocked.CompareExchange(ref _state, current + 1, current) == current)
                    return new SecureAsyncLease(this, _pointer, _length);
            }
            else throw new ObjectDisposedException(nameof(SecureBuffer));
        }
    }

    /// <summary>
    /// Internal method to decrement the reference counter and restore memory protections 
    /// if the active lease count reaches zero.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void Release()
    {
        if (_useMprotect)
        {
            Debug.Assert(_protectionLock != null, nameof(_protectionLock) + " != null");
            _protectionLock.EnterWriteLock();
            try
            {
                var newState = Interlocked.Decrement(ref _state);
                if (newState == DisposedFlag)
                {
                    ZeroAndFree();
                }
                else if ((newState & ~DisposedFlag) == 0)
                {
                    ProtectMemory((IntPtr)_pointer, _allocationSize, IsWindows ? NT_PAGE_NOACCESS : POSIX_PROT_NONE);
                }
            }
            finally
            {
                _protectionLock.ExitWriteLock();
            }
        }
        else
        {
            var newState = Interlocked.Decrement(ref _state);
            if (newState == DisposedFlag) ZeroAndFree();
        }
    }

    /// <summary>
    /// Releases all resources, zeros the memory using <see cref="CryptographicOperations.ZeroMemory"/>, 
    /// and unlocks the memory region from RAM.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    public void Dispose()
    {
        if (_useMprotect)
        {
            Debug.Assert(_protectionLock != null, nameof(_protectionLock) + " != null");

            _protectionLock.EnterWriteLock();
            try
            {
                var current = Volatile.Read(ref _state);
                if ((current & DisposedFlag) != 0) return;

                _state = current | DisposedFlag;

                if (current == 0)
                {
                    ZeroAndFree();
                }
            }
            finally
            {
                _protectionLock.ExitWriteLock();
            }
            _protectionLock?.Dispose();
            GC.SuppressFinalize(this);
        }
        else
        {
            while (true)
            {
                var current = Volatile.Read(ref _state);
                if ((current & DisposedFlag) != 0) return;

                var newState = current | DisposedFlag;
                if (Interlocked.CompareExchange(ref _state, newState, current) != current) continue;

                if (current == 0)
                {
                    ZeroAndFree();
                }
                
                GC.SuppressFinalize(this);
                break;
            }
        }
    }

    /// <summary>
    /// Finalizer for <see cref="SecureBuffer"/> to ensure memory is zeroed and freed if not disposed manually.
    /// </summary>
    ~SecureBuffer()
    {
        var oldState = Interlocked.Exchange(ref _state, DisposedFlag);
        if ((oldState & DisposedFlag) == 0) ZeroAndFree();
    }

    /// <summary>
    /// Securely zeros the buffer and releases native memory handles.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    private void ZeroAndFree()
    {
        var raw = Interlocked.Exchange(ref _pointerHandle, 0);
        if (raw == 0) return;

        var ptr = (byte*)raw;

        // Windows requires this:
        // "All pages in the specified region must be committed. Memory protected with PAGE_NOACCESS cannot be locked."
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock#remarks
        if (_useMprotect || IsWindows)
            ProtectMemory((IntPtr)ptr, _allocationSize, IsWindows ? NT_PAGE_READWRITE : (POSIX_PROT_READ | POSIX_PROT_WRITE));
        
        CryptographicOperations.ZeroMemory(new Span<byte>(ptr, (int)_allocationSize));
        
        UnlockMemory((IntPtr)ptr, _allocationSize);
        AlignedFree(ptr);
    }
}