/*
@author: atailh4n
SecretManager.cs (c) 2026
@description: An ISO 27001 aligned secure vault for storing sensitive data in RAM.
@created:  2026-03-23
Modified: 2026-04-29
*/

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecBuff.Interfaces;

namespace SecBuff;

/// <summary>
/// An ISO 27001 aligned secure vault for storing sensitive data in RAM.
/// Utilizes OS-level memory locking (mlock/VirtualLock) to prevent swapping to disk 
/// and memory protection (mprotect/VirtualProtect) for granular access control.
/// </summary>
/// <typeparam name="TKey">The type of the key used to identify secrets (e.g., string or enum).</typeparam>
public sealed partial class SecretManager<TKey>(ILogger<SecretManager<TKey>> logger, SecureKeyFile? keyFile = null) : ISecretManager<TKey>
    where TKey : notnull
{
    private readonly Dictionary<TKey, SecretEntry> _secrets = new();
    private readonly ReaderWriterLockSlim _rwLock = new(LockRecursionPolicy.NoRecursion);
    private int _disposed;
    
    // It will access at Acquire method.
    // ReSharper disable once NotAccessedPositionalProperty.Global
    internal record SecretEntry(SecureBuffer Buffer, bool IsEncrypted);

    /// <summary>
    /// Adds a new secret to the vault or updates an existing one.
    /// </summary>
    /// <param name="key">The unique identifier for the secret.</param>
    /// <param name="value">The raw byte data of the secret to be secured.</param>
    /// <param name="useMprotect">If <see langword="true"/>, enables OS-level page protection (RO/RW/NONE) for this secret.</param>
    /// <param name="useEncryption">If <see cref="SecureKeyFile"/> is set, uses AES-256-GCM encryption.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the vault has been disposed.</exception>
    public void SetSecret(TKey key, ReadOnlySpan<byte> value, bool useMprotect = false, bool useEncryption = false)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);

        if (useEncryption && keyFile is null)
            throw new InvalidOperationException(
                "useEncryption is true but no SecureKeyFile was provided to SecretManager.");

        _rwLock.EnterWriteLock();
        try
        {
            LogSecretGetRequest(key.ToString() ?? "Unknown");
            if (_secrets.TryGetValue(key, out var existing))
                existing.Buffer.Dispose();
            
            SecureBuffer? buffer = null;
            
            if (useEncryption && keyFile is not null)
            {
                const int nonceSize = 12;
                const int tagSize   = 16;
                var totalSize = nonceSize + tagSize + value.Length;
                try
                {
                    buffer = new SecureBuffer(totalSize, useMprotect);
                    using var lease = buffer.Acquire(requestWrite: true);

                    var nonce      = lease.Span[..nonceSize];
                    var tag        = lease.Span[nonceSize..(nonceSize + tagSize)];
                    var ciphertext = lease.Span[(nonceSize + tagSize)..];

                    RandomNumberGenerator.Fill(nonce);

                    Span<byte> aesKey = stackalloc byte[32];
                    try
                    {
                        keyFile.DeriveKey(aesKey, salt: nonce, info: "SecBuff.AES256GCM"u8);
                        using var aes = new AesGcm(aesKey, tagSize);
                        aes.Encrypt(nonce, value, ciphertext, tag);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(aesKey);
                    }

                    _secrets[key] = new SecretEntry(buffer, IsEncrypted: true);
                    buffer = null; // ownership transferred
                }
                finally
                {
                    buffer?.Dispose();
                }
                return;
            }
            
            try
            {
                buffer = new SecureBuffer(value.Length, useMprotect);
                using var lease = buffer.Acquire(requestWrite: true);
                value.CopyTo(lease.Span);
                _secrets[key] = new SecretEntry(buffer, IsEncrypted: false);
                buffer = null; // ownership transferred
            }
            finally
            {
                buffer?.Dispose();
            }

            LogSecretKeySetSucceed(key.ToString() ?? "Unknown");
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }
    /// <summary>
    /// Represents a method that receives a secure <see cref="ReadOnlySpan{T}"/> of bytes.
    /// Required because <see cref="Span{T}"/> types cannot be used as generic arguments in standard Actions.
    /// </summary>
    /// <param name="span">The secure, memory-locked span.</param>
    public delegate void SecretAccessor(ReadOnlySpan<byte> span);

    /// <summary>
    /// Represents a method that receives a secure <see cref="ReadOnlySpan{T}"/> of bytes and returns a result.
    /// </summary>
    /// <typeparam name="TResult">The type of the result to return.</typeparam>
    /// <param name="span">The secure, memory-locked span.</param>
    public delegate TResult SecretAccessor<out TResult>(ReadOnlySpan<byte> span);
    
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    private void AccessEntryCore(SecretEntry entry, SecretAccessor action)
    {
        if (entry.IsEncrypted)
        {
            const int nonceSize = 12;
            const int tagSize   = 16;

            using var cipherLease = entry.Buffer.Acquire(requestWrite: false);

            ReadOnlySpan<byte> nonce      = cipherLease.Span[..nonceSize];
            ReadOnlySpan<byte> tag        = cipherLease.Span[nonceSize..(nonceSize + tagSize)];
            ReadOnlySpan<byte> ciphertext = cipherLease.Span[(nonceSize + tagSize)..];

            SecureBuffer? plaintext = null;
            try
            {
                plaintext = new SecureBuffer(ciphertext.Length, entry.Buffer.UsesMprotect);
                using var plainLease = plaintext.Acquire(requestWrite: true);

                Span<byte> aesKey = stackalloc byte[32];
                try
                {
                    keyFile!.DeriveKey(aesKey, salt: nonce, info: "SecBuff.AES256GCM"u8);
                    using var aes = new AesGcm(aesKey, tagSize);
                    aes.Decrypt(nonce, ciphertext, tag, plainLease.Span);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(aesKey);
                }

                action(plainLease.Span);
            }
            finally
            {
                plaintext?.Dispose();
            }
        }
        else
        {
            using var lease = entry.Buffer.Acquire(requestWrite: false);
            action(lease.Span);
        }
    }

    /// <summary>
    /// Safely accesses a secret by providing a <see cref="ReadOnlySpan{T}"/> to the specified callback.
    /// The memory is automatically transitioned back to a protected state once the callback returns.
    /// </summary>
    /// <param name="key">The identifier of the secret to access.</param>
    /// <param name="action">The logic to execute while the secret is accessible in memory.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the <see cref="SecretManager{TKey}"/> already disposed.</exception>
    /// <exception cref="KeyNotFoundException">Thrown if the secret does not exist in the vault.</exception>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    public void AccessSecret(TKey key, SecretAccessor action)
    {
        _rwLock.EnterReadLock();
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
            LogSecretGetRequest(key.ToString() ?? "Unknown");

            if (!_secrets.TryGetValue(key, out var entry))
                throw new KeyNotFoundException($"Key '{key}' was not found.");

            ArgumentNullException.ThrowIfNull(action);
            AccessEntryCore(entry, action);
        }
        finally
        {
            LogSecretGetSuccess(key.ToString() ?? "Unknown");
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Safely accesses a secret and returns a value derived from it.
    /// </summary>
    /// <typeparam name="TResult">The type of the data to return from the callback.</typeparam>
    /// <param name="key">The identifier of the secret to access.</param>
    /// <param name="action">The logic to execute while the secret is accessible in memory.</param>
    /// <returns>The result returned by the <paramref name="action"/>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the <see cref="SecretManager{TKey}"/> already disposed.</exception>
    /// <exception cref="KeyNotFoundException">Thrown if the secret does not exist in the vault.</exception>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    public TResult AccessSecret<TResult>(TKey key, SecretAccessor<TResult> action)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
        _rwLock.EnterReadLock();
        try
        {
            if (!_secrets.TryGetValue(key, out var entry))
                throw new KeyNotFoundException($"Key '{key.ToString()}' was not found.");

            ArgumentNullException.ThrowIfNull(action);

            TResult? result = default;
            AccessEntryCore(entry, span => result = action(span));
            return result!;
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Manually revokes a secret from the vault, zeroing its memory and releasing OS handles.
    /// </summary>
    /// <param name="key">The key of the secret to remove.</param>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    public void RevokeSecret(TKey key)
    {
        _rwLock.EnterWriteLock();
        try
        {
            if (!_secrets.TryGetValue(key, out var entry)) return;
            entry.Buffer.Dispose();
            _secrets.Remove(key);
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Retrieves the underlying <see cref="SecureBuffer"/> for a given key. 
    /// Use this for advanced scenarios where manual lease management is required.
    /// </summary>
    /// <param name="key">The key of the secret.</param>
    /// <returns>The <see cref="SecureBuffer"/> instance associated with the key.</returns>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    public ISecureBuffer GetBuffer(TKey key)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);

        _rwLock.EnterReadLock();
        try
        {
            return _secrets.TryGetValue(key, out var entry) ? entry.Buffer : throw new KeyNotFoundException($"Key '{key}' was not found.");
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Disposes the vault, securely clearing and freeing all stored secrets and releasing synchronization primitives.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        _rwLock.EnterWriteLock();
        try
        {
            foreach (var entry in _secrets.Values)
            {
                entry.Buffer.Dispose();
            }

            _secrets.Clear();
        }
        finally
        {
            _rwLock.ExitWriteLock();
            _rwLock.Dispose();
        }
    }

    [LoggerMessage(LogLevel.Debug, "{KeyName} key set requested")]
    partial void LogSecretKeySetRequest(string keyName);

    [LoggerMessage(LogLevel.Debug, "{KeyName} key set succeed")]
    partial void LogSecretKeySetSucceed(string keyName);

    [LoggerMessage(LogLevel.Debug, "{KeyName} key get requested")]
    partial void LogSecretGetRequest(string keyName);

    [LoggerMessage(LogLevel.Debug, "{KeyName} key get succeed")]
    partial void LogSecretGetSuccess(string keyName);
}