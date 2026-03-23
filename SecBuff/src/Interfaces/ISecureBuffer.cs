/*
@author: atailh4n
ISecureBuffer.cs (c) 2026
@description: Provides a secure, fixed-address memory buffer that is protected from being swapped to disk 
and optionally guarded by OS-level memory protection (NX/RO/RW)
@created:  2026-03-23T16:25:51.396Z
Modified: !date!
*/

using System.Runtime.CompilerServices;

namespace SecBuff.Interfaces;

/// <summary>
/// Provides a secure, fixed-address memory buffer that is protected from being swapped to disk 
/// and optionally guarded by OS-level memory protection (NX/RO/RW).
/// </summary>
/// <remarks>
/// This class ensures that sensitive data is kept in RAM using <c>mlock</c> (POSIX) or <c>VirtualLock</c> (Windows).
/// If <c>useMprotect</c> is enabled, the memory is set to <c>PROT_NONE</c> when not in use, 
/// preventing unauthorized read/write access even within the same process.
/// </remarks>
public interface ISecureBuffer : IDisposable
{
    /// <summary>
    /// Transitions the memory state to <c>PROT_NONE</c>, disabling all access.
    /// Use this after the initial data write to ensure the buffer is unreachable until explicitly acquired.
    /// </summary>
    /// <remarks>This only has an effect if <c>useMprotect</c> was set to <see langword="true"/> during construction.</remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the buffer has already been disposed.</exception>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    void Seal();

    /// <summary>
    /// Acquires a synchronous lease for accessing the secured memory.
    /// </summary>
    /// <param name="requestWrite">If <see langword="true"/>, requests write access (RW); otherwise, requests read-only access (RO).</param>
    /// <returns>A <see cref="SecureLease"/> that must be disposed to release access. Modern <c>using var</c> recommended for auto disposal.</returns>
    /// <remarks>
    /// If <c>useMprotect</c> is enabled, this method will transition the memory page protections. 
    /// Multiple readers can coexist, but a writer requires exclusive access.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    SecureLease Acquire(bool requestWrite = false);

    /// <summary>
    /// Acquires an asynchronous lease for accessing the secured memory.
    /// </summary>
    /// <param name="requestWrite">If <see langword="true"/>, requests write access (RW); otherwise, requests read-only access (RO).</param>
    /// <returns>A <see cref="SecureAsyncLease"/> which, unlike <see cref="SecureLease"/>, is not a ref-struct and can be used across await boundaries.</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    SecureAsyncLease AcquireAsync(bool requestWrite = false);
}