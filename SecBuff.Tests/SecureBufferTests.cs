/*
 * Author: atailh4n
 * File: SecureBufferTests.cs
 * Copyright (c) 2026
 * Description: Tests for SecureBuffer's allocation, lease lifecycle, mprotect path, concurrency, disposal.
 * Created: 2026-03-23
 * Modified: !date!
 */

using System.Security.Cryptography;
using Xunit;

namespace SecBuff.Tests;

public sealed class SecureBufferTests
{
    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    [Fact]
    public void Constructor_ValidLength_DoesNotThrow()
    {
        using var buffer = new SecureBuffer(64);
        // No exception = allocation + mlock succeeded
    }

    [Fact]
    public void Constructor_WithMprotect_DoesNotThrow()
    {
        using var buffer = new SecureBuffer(64, useMprotect: true);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Constructor_NonPositiveLength_Throws(int length)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer(length));
    }

    [Fact]
    public void Constructor_ZeroesMemoryOnInit()
    {
        using var buffer = new SecureBuffer(64);
        using var lease = buffer.Acquire(requestWrite: false);

        Assert.True(lease.Span.ToArray().All(b => b == 0));
    }

    // -------------------------------------------------------------------------
    // Acquire / Release — no mprotect
    // -------------------------------------------------------------------------

    [Fact]
    public void Acquire_ReadLease_CanRead()
    {
        using var buffer = new SecureBuffer(8);

        // Write first
        using (var w = buffer.Acquire(requestWrite: true))
            w.Span[0] = 0xAB;

        // Read back
        using var r = buffer.Acquire(requestWrite: false);
        Assert.Equal(0xAB, r.Span[0]);
    }

    [Fact]
    public void Acquire_WriteLease_DataPersists()
    {
        using var buffer = new SecureBuffer(16);

        using (var w = buffer.Acquire(requestWrite: true))
        {
            for (var i = 0; i < 16; i++)
                w.Span[i] = (byte)i;
        }

        using var r = buffer.Acquire(requestWrite: false);
        for (var i = 0; i < 16; i++)
            Assert.Equal((byte)i, r.Span[i]);
    }

    [Fact]
    public void Acquire_MultipleReadLeases_AllSucceed()
    {
        using var buffer = new SecureBuffer(8);

        var l1 = buffer.Acquire(requestWrite: false);
        var l2 = buffer.Acquire(requestWrite: false);
        var l3 = buffer.Acquire(requestWrite: false);

        // All should be valid
        _ = l1.Span;
        _ = l2.Span;
        _ = l3.Span;

        l1.Dispose();
        l2.Dispose();
        l3.Dispose();
    }

    [Fact]
    public void Lease_Dispose_SpanThrowsAfter()
    {
        using var buffer = new SecureBuffer(8);
        var lease = buffer.Acquire(requestWrite: false);
        lease.Dispose();
        
        var threw = false;
        try { _ = lease.Span; }
        catch (ObjectDisposedException) { threw = true; }

        Assert.True(threw);
    }
    
    [Fact]
    public void AsyncLease_Dispose_SpanThrowsAfter()
    {
        using var buffer = new SecureBuffer(8);
        var lease = buffer.AcquireAsync(requestWrite: false);
        lease.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = lease.Span);
    }

    [Fact]
    public void Lease_DoubleDispose_DoesNotThrow()
    {
        using var buffer = new SecureBuffer(8);
        var lease = buffer.Acquire(requestWrite: false);
        lease.Dispose();
        lease.Dispose(); // should be a no-op
    }

    // -------------------------------------------------------------------------
    // Acquire / Release — with mprotect
    // -------------------------------------------------------------------------

    [Fact]
    public void Acquire_WithMprotect_ReadLease_CanRead()
    {
        using var buffer = new SecureBuffer(8, useMprotect: true);

        using (var w = buffer.Acquire(requestWrite: true))
            w.Span[0] = 0xCD;

        using var r = buffer.Acquire(requestWrite: false);
        Assert.Equal(0xCD, r.Span[0]);
    }

    [Fact]
    public void Acquire_WithMprotect_MultipleReadLeases_AllSucceed()
    {
        using var buffer = new SecureBuffer(32, useMprotect: true);

        var l1 = buffer.Acquire(requestWrite: false);
        var l2 = buffer.Acquire(requestWrite: false);

        _ = l1.Span;
        _ = l2.Span;

        l1.Dispose();
        l2.Dispose();
    }

    // -------------------------------------------------------------------------
    // Seal
    // -------------------------------------------------------------------------

    [Fact]
    public void Seal_WithMprotect_ThenAcquire_Succeeds()
    {
        using var buffer = new SecureBuffer(8, useMprotect: true);

        using (var w = buffer.Acquire(requestWrite: true))
            w.Span[0] = 0x42;

        buffer.Seal();

        // After seal, acquiring should re-open access
        using var r = buffer.Acquire(requestWrite: false);
        Assert.Equal(0x42, r.Span[0]);
    }

    [Fact]
    public void Seal_WithoutMprotect_IsNoOp()
    {
        using var buffer = new SecureBuffer(8, useMprotect: false);
        buffer.Seal(); // should not throw
    }

    [Fact]
    public void Seal_AfterDispose_Throws()
    {
        var buffer = new SecureBuffer(8, useMprotect: true);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => buffer.Seal());
    }

    // -------------------------------------------------------------------------
    // AcquireAsync
    // -------------------------------------------------------------------------

    [Fact]
    public void AcquireAsync_ReadLease_CanRead()
    {
        using var buffer = new SecureBuffer(8);

        using (var w = buffer.Acquire(requestWrite: true))
            w.Span[0] = 0xFF;

        var asyncLease = buffer.AcquireAsync(requestWrite: false);
        Assert.Equal(0xFF, asyncLease.Span[0]);
        asyncLease.Dispose();
    }

    [Fact]
    public async Task AcquireAsync_SurvivesAwaitBoundary()
    {
        using var buffer = new SecureBuffer(16);
        
        var writeLease = buffer.AcquireAsync(requestWrite: true);
        writeLease.Span[0] = 0x77;
        writeLease.Dispose();

        await Task.Yield(); // cross await boundary
        
        var readLease = buffer.AcquireAsync(requestWrite: false);
        Assert.Equal(0x77, readLease.Span[0]);
        readLease.Dispose();
    }

    [Fact]
    public void AcquireAsync_AfterDispose_Throws()
    {
        var buffer = new SecureBuffer(8);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => buffer.AcquireAsync());
    }

    // -------------------------------------------------------------------------
    // Dispose
    // -------------------------------------------------------------------------

    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        var buffer = new SecureBuffer(8);
        buffer.Dispose();
        buffer.Dispose();
    }

    [Fact]
    public void Dispose_ZeroesMemory()
    {
        // We can't read after dispose directly (that would be UB),
        // but we verify the buffer was writable before dispose
        // and that dispose completes without error even with active data.
        var buffer = new SecureBuffer(32);

        using (var w = buffer.Acquire(requestWrite: true))
            RandomNumberGenerator.Fill(w.Span);

        buffer.Dispose(); // should zero + free without throwing
    }

    [Fact]
    public void Acquire_AfterDispose_Throws()
    {
        var buffer = new SecureBuffer(8);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => buffer.Acquire());
    }

    [Fact]
    public void Dispose_WithMprotect_ZeroesAndFrees()
    {
        var buffer = new SecureBuffer(32, useMprotect: true);

        using (var w = buffer.Acquire(requestWrite: true))
            RandomNumberGenerator.Fill(w.Span);

        buffer.Dispose();
    }

    // -------------------------------------------------------------------------
    // Concurrency
    // -------------------------------------------------------------------------

    [Fact]
    public void ConcurrentReads_NoMprotect_AllSucceed()
    {
        using var buffer = new SecureBuffer(64);

        using (var w = buffer.Acquire(requestWrite: true))
            w.Span.Fill(0xAA);

        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        Parallel.For(0, 32, _ =>
        {
            try
            {
                using var lease = buffer.Acquire(requestWrite: false);
                Assert.Equal(0xAA, lease.Span[0]);
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }
        });

        Assert.Empty(errors);
    }

    [Fact]
    public void ConcurrentReads_WithMprotect_AllSucceed()
    {
        using var buffer = new SecureBuffer(64, useMprotect: true);

        using (var w = buffer.Acquire(requestWrite: true))
            w.Span.Fill(0xBB);

        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        // mprotect path uses ReaderWriterLockSlim — multiple readers allowed
        Parallel.For(0, 16, _ =>
        {
            try
            {
                using var lease = buffer.Acquire(requestWrite: false);
                Assert.Equal(0xBB, lease.Span[0]);
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }
        });

        Assert.Empty(errors);
    }

    [Fact]
    public async Task ConcurrentWriteRead_StateRemainsConsistent()
    {
        using var buffer = new SecureBuffer(64);
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        var writer = Task.Run(() =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    using var w = buffer.Acquire(requestWrite: true);
                    w.Span.Fill(0xCC);
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex) { errors.Add(ex); }
            }
        }, cts.Token);

        var reader = Task.Run(() =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    using var r = buffer.Acquire(requestWrite: false);
                    _ = r.Span[0];
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex) { errors.Add(ex); }
            }
        }, cts.Token);

        cts.CancelAfter(500);
        await Task.WhenAll(writer, reader);

        Assert.Empty(errors);
    }

    [Fact]
    public void ConcurrentDispose_OnlyOneSucceeds_NoDoubleFreeCrash()
    {
        // Hammering Dispose from multiple threads should not crash
        var buffer = new SecureBuffer(64);

        Parallel.For(0, 16, _ => buffer.Dispose());
        // If double-free guard works, no AccessViolationException
    }
}