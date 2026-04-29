/*
@author: atailh4n
SecureKeyFile.cs (c) 2026
@description: Key file system for deriving key.
@created:  2026-03-23
Modified: 2026-04-29
*/

using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SecBuff;

/// <summary>
/// Represents a <c>.sbkf</c> (SecBuff Key File) containing 256-bit entropy
/// used as key material for AES-256-GCM encryption meant to use on NT systems and
/// supports cross-platform encrypting.
/// The keyfile is intended to reside on a physically separate medium (e.g. USB)
/// to provide a possession-based security boundary.
/// </summary>
public sealed class SecureKeyFile : IDisposable
{
    private const int KeySizeBytes = 32;
    private const byte Version = 1;

    private static ReadOnlySpan<byte> Magic => "SBKF"u8;

    private readonly SecureBuffer _keyMaterial;
    private int _disposed;

    private SecureKeyFile(SecureBuffer keyMaterial)
    {
        _keyMaterial = keyMaterial;
    }

    /// <inheritdoc />
    ~SecureKeyFile()
    {
        DisposeInternal();
    }
    
    /// <summary>
    /// <remarks>Done for .NET 8.0 backwards compability.</remarks>
    /// </summary>
    internal delegate void KeyMaterialAccessor(ReadOnlySpan<byte> keyMaterial);
    
    /// <summary>
    /// Gets a <see cref="KeyMaterialAccessor"/> as parameter. Accesses key material.
    /// <remarks><see cref="KeyMaterialAccessor"/> is a <see langword="delegate"/> type for backwards comapbility for .NET 8.0</remarks>
    /// </summary>
    /// <param name="action"><see cref="KeyMaterialAccessor"/> to access.</param>
    /// <exception cref="ObjectDisposedException">If <see langword="this"/> disposed.</exception>
    internal void AccessKeyMaterial(KeyMaterialAccessor action)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
        using var lease = _keyMaterial.Acquire();
        action(lease.Span);
    }
    
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    internal void DeriveKey(Span<byte> destination, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
        using var lease = _keyMaterial.Acquire(false);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, lease.Span, destination, salt, info);
    }

    /// <summary>
    /// Loads a <c>.sbkf</c> keyfile from the given path directly into
    /// protected memory. Never produces a managed string of key material.
    /// <param name="path">Path to the file.</param>
    /// <returns>
    /// A <see cref="SecureKeyFile"/> instance.
    /// </returns>
    /// <exception cref="InvalidDataException"> Either empty file, wrong file length or wrong magic</exception>
    /// <exception cref="NotSupportedException">If <see cref="Version"/> is wrong.</exception>
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static SecureKeyFile Load(string path)
    {
        using SecureBuffer keyFileBuffer = new(Magic.Length + 1 + KeySizeBytes, true);
        using var keyFileLease = keyFileBuffer.Acquire(true);
        
        try
        {
            NativeMethods.ReadFileExact(path, keyFileLease.Span);
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidDataException("Invalid key file size.", ex);
        } 

        if (keyFileLease.Span.IsEmpty)
            throw new InvalidDataException("Invalid .sbkf file: empty file.");
        
        if (keyFileLease.Span.Length != Magic.Length + 1 + KeySizeBytes)
            throw new InvalidDataException("Invalid .sbkf file: invalid .sbkf file.");

        if (!keyFileLease.Span[..Magic.Length].SequenceEqual(Magic))
            throw new InvalidDataException("Invalid .sbkf file: bad magic.");

        if (keyFileLease.Span[Magic.Length] != Version)
            throw new NotSupportedException($"Unsupported .sbkf version: {keyFileLease.Span[Magic.Length]}.");

        SecureBuffer? key = null;
        
        try
        {
            key = new SecureBuffer(KeySizeBytes, true);
            using var keyLease = key.Acquire(true);

            if (!keyFileLease.Span.Slice(Magic.Length + 1, KeySizeBytes).TryCopyTo(keyLease.Span))
                throw new InvalidOperationException("Cannot copy keyfile to secure memory. Aborted.");

            var result = new SecureKeyFile(key);
            key = null; // ownership transferred
            return result;
        }
        finally
        {
            key?.Dispose();
        }
    }

    /// <summary>
    /// Generates a new <c>.sbkf</c> keyfile at the given path.
    /// <param name="path">Path to the file.</param>
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void Generate(string path)
    {
        Span<byte> key = stackalloc byte[KeySizeBytes];
        RandomNumberGenerator.Fill(key);
        
        Span<byte> file = stackalloc byte[Magic.Length + 1 + KeySizeBytes];
        Magic.CopyTo(file);
        file[Magic.Length] = Version;
        key.CopyTo(file[(Magic.Length + 1)..]);

        using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            fs.Write(file);

        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(file);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        DisposeInternal();
        GC.SuppressFinalize(this);
    }

    private void DisposeInternal()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        _keyMaterial.Dispose();
    }
}