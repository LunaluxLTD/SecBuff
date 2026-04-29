/*
@author: atailh4n
ISecretManager.cs (c) 2026
@description: An ISO 27001 aligned secure vault for storing sensitive data in RAM.
Utilizes OS-level memory locking (mlock/VirtualLock) to prevent swapping to disk 
and memory protection (mprotect/VirtualProtect) for granular access control
@created:  2026-03-23T16:25:51.396Z
Modified: !date!
*/

using System.Runtime.CompilerServices;

namespace SecBuff.Interfaces;

/// <summary>
/// An ISO 27001 aligned secure vault for storing sensitive data in RAM.
/// Utilizes OS-level memory locking (mlock/VirtualLock) to prevent swapping to disk 
/// and memory protection (mprotect/VirtualProtect) for granular access control.
/// </summary>
/// <typeparam name="TKey">The type of the key used to identify secrets (e.g., string or enum).</typeparam>
public interface ISecretManager<TKey> : IDisposable where TKey : notnull
{
    /// <summary>
    /// Adds a new secret to the vault or updates an existing one.
    /// </summary>
    /// <param name="key">The unique identifier for the secret.</param>
    /// <param name="value">The raw byte data of the secret to be secured.</param>
    /// <param name="useMprotect">If <see langword="true"/>, enables OS-level page protection (RO/RW/NONE) for this secret.</param>
    /// <param name="useEncryption">If <see cref="SecureKeyFile"/> is set, uses AES-256-GCM encryption.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the vault has been disposed.</exception>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    void SetSecret(TKey key, ReadOnlySpan<byte> value, bool useMprotect = false, bool useEncryption = false);

    /// <summary>
    /// Safely accesses a secret by providing a <see cref="ReadOnlySpan{T}"/> to the specified callback.
    /// The memory is automatically transitioned back to a protected state once the callback returns.
    /// </summary>
    /// <param name="key">The identifier of the secret to access.</param>
    /// <param name="action">The logic to execute while the secret is accessible in memory.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the <see cref="SecretManager{TKey}"/> already disposed.</exception>
    /// <exception cref="KeyNotFoundException">Thrown if the secret does not exist in the vault.</exception>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    void AccessSecret(TKey key, SecretManager<TKey>.SecretAccessor action);

    /// <summary>
    /// Safely accesses a secret and returns a value derived from it.
    /// </summary>
    /// <typeparam name="TResult">The type of the data to return from the callback.</typeparam>
    /// <param name="key">The identifier of the secret to access.</param>
    /// <param name="action">The logic to execute while the secret is accessible in memory.</param>
    /// <returns>The result returned by the <paramref name="action"/>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the <see cref="SecretManager{TKey}"/> already disposed.</exception>
    /// <exception cref="KeyNotFoundException">Thrown if the secret does not exist in the vault.</exception>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    TResult AccessSecret<TResult>(TKey key, SecretManager<TKey>.SecretAccessor<TResult> action);

    /// <summary>
    /// Manually revokes a secret from the vault, zeroing its memory and releasing OS handles.
    /// </summary>
    /// <param name="key">The key of the secret to remove.</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    void RevokeSecret(TKey key);

    /// <summary>
    /// Retrieves the underlying <see cref="SecureBuffer"/> for a given key. 
    /// Use this for advanced scenarios where manual lease management is required.
    /// </summary>
    /// <param name="key">The key of the secret.</param>
    /// <returns>The <see cref="SecureBuffer"/> instance associated with the key.</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    ISecureBuffer GetBuffer(TKey key);
}