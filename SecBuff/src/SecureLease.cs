/*
@author: atailh4n
SecureLease.cs (c) 2026
@description: A stack-only, thread-local lease to safely access the <see cref="SecureBuffer"/> memory.
@created:  2026-03-23
Modified: 2026-04-29
*/

using System.Runtime.CompilerServices;

namespace SecBuff;

/// <summary>
/// A stack-only, thread-local lease to safely access the <see cref="SecureBuffer"/> memory.
/// Using a 'ref struct' ensures that the lease cannot be moved to the managed heap, 
/// preventing accidental memory leaks or asynchronous capture of sensitive data.
/// </summary>
public unsafe ref struct SecureLease
{
    private SecureBuffer? _buffer;
    private readonly byte* _pointer;
    private readonly int _length;

    /// <summary>
    /// Gets a <see cref="Span{T}"/> over the secured memory. 
    /// Throws <see cref="ObjectDisposedException"/> if the lease has been disposed.
    /// </summary>
    public Span<byte> Span
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _buffer == null ? throw new ObjectDisposedException(nameof(SecureLease)) : new Span<byte>(_pointer, _length);
    }

    /// <summary>
    /// Gets the raw pointer to the secured memory. 
    /// Danger: Use with extreme caution. Ensure the lease is not disposed while using the pointer.
    /// </summary>
    public byte* RawPtr
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _buffer == null ? throw new ObjectDisposedException(nameof(SecureLease)) : _pointer;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal SecureLease(SecureBuffer buffer, byte* pointer, int length)
    {
        _buffer = buffer;
        _pointer = pointer;
        _length = length;
    }

    /// <summary>
    /// Releases the access lease back to the <see cref="SecureBuffer"/>. 
    /// If this was the last active lease, the buffer may return to its protected state (e.g., PROT_NONE).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Dispose()
    {
        var b = _buffer;
        if (b == null) return;
        _buffer = null; // Prevent double-release from the same lease instance
        b.Release();
    }
}