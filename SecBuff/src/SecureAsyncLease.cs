/*
@author: atailh4n
SecureAsyncLease.cs (c) 2026
@description: A struct-based lease designed for asynchronous contexts.
@created:  2026-03-23T16:21:56.122Z
Modified: !date!
*/

using System.Runtime.CompilerServices;
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace SecBuff;

/// <summary>
/// A struct-based lease designed for asynchronous contexts.
/// Unlike <see cref="SecureLease"/>, this is not a 'ref struct', allowing it 
/// to be captured by async state machines across await boundaries.
/// </summary>
/// <remarks>
/// <b>Warning:</b> Ensure the <see cref="Span"/> or <see cref="RawPtr"/> is not used after 
/// the lease is disposed, especially when passing data between threads.
/// </remarks>
public unsafe struct SecureAsyncLease : IDisposable, IEquatable<SecureAsyncLease>
{
    public bool Equals(SecureAsyncLease other) => false;
    public override bool Equals(object? obj) => false;
    public override int GetHashCode() => RuntimeHelpers.GetHashCode(this);
    public static bool operator ==(SecureAsyncLease? left, SecureAsyncLease? right) => false;
    public static bool operator !=(SecureAsyncLease? left, SecureAsyncLease? right) => true;
    
    private SecureBuffer? _buffer;
    private readonly byte* _pointer;
    private readonly int _length;

    /// <summary>
    /// Gets a <see cref="Span{T}"/> over the secured memory.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the lease is already disposed.</exception>
    public Span<byte> Span
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _buffer == null ? throw new ObjectDisposedException(nameof(SecureAsyncLease)) : new Span<byte>(_pointer, _length);
    }

    /// <summary>
    /// Gets the raw pointer to the secured memory.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the lease is already disposed.</exception>
    public byte* RawPtr
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _buffer == null ? throw new ObjectDisposedException(nameof(SecureAsyncLease)) : _pointer;
    }

    internal SecureAsyncLease(SecureBuffer buffer, byte* pointer, int length)
    {
        _buffer = buffer;
        _pointer = pointer;
        _length = length;
    }

    /// <summary>
    /// Releases the access lease back to the <see cref="SecureBuffer"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Dispose()
    {
        var b = _buffer;
        if (b == null) return;

        _buffer = null; // Prevent double-release
        b.Release();
    }
}