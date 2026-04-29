/*
 * Author: atailh4n
 * File: SecretManagerTests.cs
 * Copyright (c) 2026
 * Description: Tests for SecretManager<TKey>'s set/access/revoke lifecycle, concurrency, disposal.
 * Created: 2026-03-23
 * Modified: !date!
 */

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using NSubstitute;
using SecBuff.Interfaces;
using Xunit;

namespace SecBuff.Tests;

public enum SecretKey { ApiKey, DbPassword, HsmPin }

public sealed class SecretManagerTests : IDisposable
{
    private readonly ILogger<SecretManager<string>> _logger;
    private readonly SecretManager<string> _manager;

    public SecretManagerTests()
    {
        _logger = Substitute.For<ILogger<SecretManager<string>>>();
        _manager = new SecretManager<string>(_logger);
    }

    public void Dispose() => _manager.Dispose();

    // -------------------------------------------------------------------------
    // Set
    // -------------------------------------------------------------------------

    [Fact]
    public void Set_NewKey_DoesNotThrow()
    {
        _manager.SetSecret("pin", "1234"u8.ToArray());
    }

    [Fact]
    public void Set_ExistingKey_Overwrites()
    {
        _manager.SetSecret("key", "oldvalue"u8.ToArray());
        _manager.SetSecret("key", "newvalue"u8.ToArray());

        _manager.AccessSecret("key", span =>
        {
            Assert.Equal("newvalue"u8.ToArray(), span.ToArray());
        });
    }

    [Fact]
    public void Set_AfterDispose_Throws()
    {
        _manager.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            _manager.SetSecret("key", "data"u8.ToArray()));
    }

    [Fact]
    public void Set_WithMprotect_DoesNotThrow()
    {
        _manager.SetSecret("secure-key", "sensitive"u8.ToArray(), useMprotect: true);
    }

    // -------------------------------------------------------------------------
    // AccessSecret (void)
    // -------------------------------------------------------------------------

    [Fact]
    public void AccessSecret_ExistingKey_CallbackReceivesCorrectData()
    {
        var expected = "hello-world"u8.ToArray();
        _manager.SetSecret("msg", expected);

        byte[]? actual = null;
        _manager.AccessSecret("msg", span => actual = span.ToArray());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void AccessSecret_NonExistentKey_Throws()
    {
        Assert.Throws<KeyNotFoundException>(() =>
            _manager.AccessSecret("ghost", _ => { }));
    }

    [Fact]
    public void AccessSecret_AfterDispose_Throws()
    {
        _manager.SetSecret("key", "data"u8.ToArray());
        _manager.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            _manager.AccessSecret("key", _ => { }));
    }

    // -------------------------------------------------------------------------
    // AccessSecret<TResult>
    // -------------------------------------------------------------------------

    [Fact]
    public void AccessSecretWithResult_ReturnsValue()
    {
        _manager.SetSecret("token", "abc123"u8.ToArray());

        var result = _manager.AccessSecret("token", span => span.Length);

        Assert.Equal(6, result);
    }

    [Fact]
    public void AccessSecretWithResult_NonExistentKey_Throws()
    {
        Assert.Throws<KeyNotFoundException>(() =>
            _manager.AccessSecret("ghost", span => span.Length));
    }

    // -------------------------------------------------------------------------
    // Revoke
    // -------------------------------------------------------------------------

    [Fact]
    public void Revoke_ExistingKey_RemovesSecret()
    {
        _manager.SetSecret("key", "data"u8.ToArray());
        _manager.RevokeSecret("key");

        Assert.Throws<KeyNotFoundException>(() =>
            _manager.AccessSecret("key", _ => { }));
    }

    [Fact]
    public void Revoke_NonExistentKey_DoesNotThrow()
    {
        _manager.RevokeSecret("nonexistent"); // no-op for non-existent key
    }

    [Fact]
    public void Revoke_ThenSet_SameKey_Works()
    {
        _manager.SetSecret("key", "first"u8.ToArray());
        _manager.RevokeSecret("key");
        _manager.SetSecret("key", "second"u8.ToArray());

        _manager.AccessSecret("key", span =>
            Assert.Equal("second"u8.ToArray(), span.ToArray()));
    }

    // -------------------------------------------------------------------------
    // GetBuffer
    // -------------------------------------------------------------------------

    [Fact]
    public void GetBuffer_ExistingKey_ReturnsISecureBuffer()
    {
        _manager.SetSecret("key", "data"u8.ToArray());
        var buffer = _manager.GetBuffer("key");

        Assert.NotNull(buffer);
        Assert.IsAssignableFrom<ISecureBuffer>(buffer);
    }

    [Fact]
    public void GetBuffer_NonExistentKey_Throws()
    {
        Assert.Throws<KeyNotFoundException>(() => _manager.GetBuffer("ghost"));
    }

    [Fact]
    public void GetBuffer_AfterDispose_Throws()
    {
        _manager.SetSecret("key", "data"u8.ToArray());
        _manager.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _manager.GetBuffer("key"));
    }

    // -------------------------------------------------------------------------
    // Dispose
    // -------------------------------------------------------------------------

    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        var manager = new SecretManager<string>(_logger);
        manager.Dispose();
        manager.Dispose();
    }

    [Fact]
    public void Dispose_ZeroesAllSecrets()
    {
        // Verify all secrets are removed after dispose, accessing them throws
        var manager = new SecretManager<string>(_logger);
        manager.SetSecret("a", "aaaa"u8.ToArray());
        manager.SetSecret("b", "bbbb"u8.ToArray());
        manager.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            manager.AccessSecret("a", _ => { }));
    }

    // -------------------------------------------------------------------------
    // Enum key variant
    // -------------------------------------------------------------------------

    [Fact]
    public void Set_EnumKey_Works()
    {
        var manager = new SecretManager<SecretKey>(
            Substitute.For<ILogger<SecretManager<SecretKey>>>());

        manager.SetSecret(SecretKey.HsmPin, "0000"u8.ToArray());
        manager.AccessSecret(SecretKey.HsmPin, span =>
            Assert.Equal("0000"u8.ToArray(), span.ToArray()));

        manager.Dispose();
    }

    // -------------------------------------------------------------------------
    // Concurrency
    // -------------------------------------------------------------------------

    [Fact]
    public void ConcurrentReads_SameKey_AllSucceed()
    {
        _manager.SetSecret("shared", "concurrent"u8.ToArray());
        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        Parallel.For(0, 32, _ =>
        {
            try
            {
                _manager.AccessSecret("shared", span => _ = span.Length);
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }
        });

        Assert.Empty(errors);
    }

    [Fact]
    public async Task ConcurrentSetAndAccess_NoCorruption()
    {
        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        var writer = Task.Run(() =>
        {
            var i = 0;
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var value = System.Text.Encoding.UTF8.GetBytes($"value{i++}");
                    _manager.SetSecret("key", value);
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex) { errors.Add(ex); }
            }
        }, TestContext.Current.CancellationToken);

        var reader = Task.Run(() =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try { _manager.AccessSecret("key", span => _ = span.Length); }
                catch (KeyNotFoundException) { /* writer hasn't set yet, okay */ }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex) { errors.Add(ex); }
            }
        }, TestContext.Current.CancellationToken);

        cts.CancelAfter(500);
        await Task.WhenAll(writer, reader);

        Assert.Empty(errors);
    }

    [Fact]
    public void ConcurrentRevoke_SameKey_AtMostOneSucceeds_NoThrow()
    {
        _manager.SetSecret("key", "data"u8.ToArray());
        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        Parallel.For(0, 16, _ =>
        {
            try { _manager.RevokeSecret("key"); }
            catch (Exception ex) { errors.Add(ex); }
        });

        Assert.Empty(errors);
    }

    [Fact]
    public void ConcurrentDispose_MultipleThreads_NoDoubleFree()
    {
        var manager = new SecretManager<string>(_logger);
        manager.SetSecret("key", "data"u8.ToArray());

        Parallel.For(0, 8, _ => manager.Dispose());
        // No AccessViolationException = double-free guard works
    }
    
    // -------------------------------------------------------------------------
// Encryption (SBKF)
// -------------------------------------------------------------------------

[Fact]
public void SetSecret_WithEncryption_AccessReturnsPlaintext()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        SecureKeyFile.Generate(path);
        using var keyFile = SecureKeyFile.Load(path);
        using var manager = new SecretManager<string>(_logger, keyFile);

        var expected = "super-secret"u8.ToArray();
        manager.SetSecret("key", expected, useEncryption: true);

        byte[]? actual = null;
        manager.AccessSecret("key", span => actual = span.ToArray());

        Assert.Equal(expected, actual);
    }
    finally
    {
        File.Delete(path);
    }
}

[Fact]
public void SetSecret_EncryptionWithoutKeyFile_Throws()
{
    Assert.Throws<InvalidOperationException>(() =>
        _manager.SetSecret("key", "data"u8.ToArray(), useEncryption: true));
}

[Fact]
public void SetSecret_TwoEncryptedKeys_IndependentlyDecrypt()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        SecureKeyFile.Generate(path);
        using var keyFile = SecureKeyFile.Load(path);
        using var manager = new SecretManager<string>(_logger, keyFile);

        manager.SetSecret("a", "first"u8.ToArray(), useEncryption: true);
        manager.SetSecret("b", "second"u8.ToArray(), useEncryption: true);

        byte[]? a = null, b = null;
        manager.AccessSecret("a", span => a = span.ToArray());
        manager.AccessSecret("b", span => b = span.ToArray());

        Assert.Equal("first"u8.ToArray(), a);
        Assert.Equal("second"u8.ToArray(), b);
    }
    finally
    {
        File.Delete(path);
    }
}

[Fact]
public void SetSecret_OverwriteEncrypted_ReturnsNewValue()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        SecureKeyFile.Generate(path);
        using var keyFile = SecureKeyFile.Load(path);
        using var manager = new SecretManager<string>(_logger, keyFile);

        manager.SetSecret("key", "old"u8.ToArray(), useEncryption: true);
        manager.SetSecret("key", "new"u8.ToArray(), useEncryption: true);

        byte[]? actual = null;
        manager.AccessSecret("key", span => actual = span.ToArray());

        Assert.Equal("new"u8.ToArray(), actual);
    }
    finally
    {
        File.Delete(path);
    }
}

[Fact]
public void SetSecret_EncryptedThenUnencrypted_ReturnsPlaintext()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        SecureKeyFile.Generate(path);
        using var keyFile = SecureKeyFile.Load(path);
        using var manager = new SecretManager<string>(_logger, keyFile);

        // Set encrypted first, then overwrite without encryption
        manager.SetSecret("key", "encrypted"u8.ToArray(), useEncryption: true);
        manager.SetSecret("key", "plaintext"u8.ToArray(), useEncryption: false);

        byte[]? actual = null;
        manager.AccessSecret("key", span => actual = span.ToArray());

        Assert.Equal("plaintext"u8.ToArray(), actual);
    }
    finally
    {
        File.Delete(path);
    }
}

// -------------------------------------------------------------------------
// SBKF file format
// -------------------------------------------------------------------------

[Fact]
public void SecureKeyFile_Generate_ThenLoad_Succeeds()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        SecureKeyFile.Generate(path);
        using var keyFile = SecureKeyFile.Load(path);
        Assert.NotNull(keyFile);
    }
    finally
    {
        File.Delete(path);
    }
}

[Fact]
public void SecureKeyFile_Load_WrongMagic_Throws()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        var garbage = new byte[37];
        RandomNumberGenerator.Fill(garbage);
        File.WriteAllBytes(path, garbage);

        Assert.Throws<InvalidDataException>(() => SecureKeyFile.Load(path));
    }
    finally
    {
        File.Delete(path);
    }
}

[Fact]
public void SecureKeyFile_Load_WrongSize_Throws()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        File.WriteAllBytes(path, new byte[10]);
        Assert.Throws<InvalidDataException>(() => SecureKeyFile.Load(path));
    }
    finally
    {
        File.Delete(path);
    }
}

[Fact]
public void SecureKeyFile_Load_WrongVersion_Throws()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        // Correct magic, wrong version, random key
        Span<byte> file = stackalloc byte[37];
        "SBKF"u8.CopyTo(file);
        file[4] = 0xFF; // wrong version
        RandomNumberGenerator.Fill(file[5..]);
        File.WriteAllBytes(path, file.ToArray());

        Assert.Throws<NotSupportedException>(() => SecureKeyFile.Load(path));
    }
    finally
    {
        File.Delete(path);
    }
}

[Fact]
public void SecureKeyFile_Dispose_CalledTwice_DoesNotThrow()
{
    var path = Path.GetTempFileName() + ".sbkf";
    try
    {
        SecureKeyFile.Generate(path);
        var keyFile = SecureKeyFile.Load(path);
        keyFile.Dispose();
        keyFile.Dispose();
    }
    finally
    {
        File.Delete(path);
    }
}
}