/*
 * Author: atailh4n
 * File: SecureConsoleTests.cs
 * Copyright (c) 2026
 * Description: Tests for SecureConsole, stdin mock via Console.SetIn, SecureBuffer output validation.
 * We mocking stdin with Console.SetIn. Every test injects it's own TextReader,
 * at teardown, stdin resets.
 * Created: 2026-03-23
 * Modified: !date!
 */

using System.Text;
using NSubstitute;
using SecBuff.Interfaces;
using Xunit;

namespace SecBuff.Tests;

public sealed class SecureConsoleTests : IDisposable
{
    private readonly TextReader _originalIn;
    private readonly TextWriter _originalOut;
    
    private static SecureConsole CreateConsole(params ConsoleKeyInfo[] keys)
    {
        var keyReader = Substitute.For<IKeyReader>();
        var queue = new Queue<ConsoleKeyInfo>(keys);
        keyReader.ReadKey(true).Returns(_ => queue.Dequeue());
        return new SecureConsole(keyReader);
    }

    public SecureConsoleTests()
    {
        _originalIn  = Console.In;
        _originalOut = Console.Out;

        // Suppress prompt output during tests
        Console.SetOut(TextWriter.Null);
    }

    public void Dispose()
    {
        Console.SetIn(_originalIn);
        Console.SetOut(_originalOut);
    }

    // Helper: Inject a sequence of ConsoleKeyInfo into stdin
    // StringReader does not work with Console.ReadKey, because ReadKey reads stdin directly.
    // Therefore, we use a thin wrapper that intercepts the ConsoleKeyInfo stream.
    private static void SetStdinKeys(params ConsoleKeyInfo[] keys)
    {
        // Console.ReadKey reads directly from stdin, not from Console.In.
        // The reliable way to mock this in tests:
        // write the characters into a StringReader and inject it via Console.SetIn.
        // With ReadKey intercept:true, it reads from Console.In (.NET implementation).
        var sb = new StringBuilder();
        foreach (var k in keys)
            if (k.KeyChar != '\0')
                sb.Append(k.KeyChar);

        Console.SetIn(new StringReader(sb.ToString()));
    }

    // -------------------------------------------------------------------------
    // Basic reading
    // -------------------------------------------------------------------------

    [Fact]
    public void ReadSecret_SimpleInput_ReturnsCorrectBytes()
    {
        var console = CreateConsole(
            new ConsoleKeyInfo('p', ConsoleKey.P, false, false, false),
            new ConsoleKeyInfo('i', ConsoleKey.I, false, false, false),
            new ConsoleKeyInfo('n', ConsoleKey.N, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );

        using var buffer = console.ReadSecret("PIN");
        using var lease  = buffer.AcquireAsync(requestWrite: false);

        var result = Encoding.UTF8.GetString(lease.Span);
        Assert.Equal("pin", result);
    }

    [Fact]
    public void ReadSecret_ReturnsSecureBuffer_NotNull()
    {
        var console = CreateConsole(
            new ConsoleKeyInfo('x', ConsoleKey.X, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );

        using var buffer = console.ReadSecret("Test");
        Assert.NotNull(buffer);
    }

    [Fact]
    public void ReadSecret_EmptyInput_ReturnsZeroLengthBuffer()
    {
        SetStdinKeys(
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );
        
        var console = CreateConsole(
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );
        
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            console.ReadSecret("Test"));
    }

    // -------------------------------------------------------------------------
    // Backspace
    // -------------------------------------------------------------------------

    [Fact]
    public void ReadSecret_Backspace_RemovesLastChar()
    {
        var console = CreateConsole(
            new ConsoleKeyInfo('a', ConsoleKey.A, false, false, false),
            new ConsoleKeyInfo('b', ConsoleKey.B, false, false, false),
            new ConsoleKeyInfo('\b', ConsoleKey.Backspace, false, false, false), // backspace 'b'
            new ConsoleKeyInfo('c', ConsoleKey.C, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false) // enter
        );

        using var buffer = console.ReadSecret("Test");
        var lease = buffer.AcquireAsync(requestWrite: false);
        var result = Encoding.UTF8.GetString(lease.Span);
        lease.Dispose();

        Assert.Equal("ac", result);
    }

    [Fact]
    public void ReadSecret_BackspaceOnEmpty_DoesNotThrow()
    {
        var console = CreateConsole(
            new ConsoleKeyInfo('\b', ConsoleKey.Backspace, false, false, false),
            new ConsoleKeyInfo('\b', ConsoleKey.Backspace, false, false, false),
            new ConsoleKeyInfo('z', ConsoleKey.Z, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );

        using var buffer = console.ReadSecret("Test");
        var lease = buffer.AcquireAsync(requestWrite: false);
        var result = Encoding.UTF8.GetString(lease.Span);
        lease.Dispose();

        Assert.Equal("z", result);
    }

    [Fact]
    public void ReadSecret_AllBackspaced_ThenRetype_Correct()
    {
        var console = CreateConsole(
            new ConsoleKeyInfo('a', ConsoleKey.A, false, false, false),
            new ConsoleKeyInfo('\b', ConsoleKey.Backspace, false, false, false),
            new ConsoleKeyInfo('b', ConsoleKey.B, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );
        
        

        using var buffer = console.ReadSecret("Test");
        var lease = buffer.AcquireAsync(requestWrite: false);
        var result = Encoding.UTF8.GetString(lease.Span);
        lease.Dispose();

        Assert.Equal("b", result);
    }

    // -------------------------------------------------------------------------
    // maxLength
    // -------------------------------------------------------------------------

    [Fact]
    public void ReadSecret_ExceedsMaxLength_TruncatesAtMax()
    {
        const int max = 4;

        var console = CreateConsole(
            new ConsoleKeyInfo('a', ConsoleKey.A, false, false, false),
            new ConsoleKeyInfo('b', ConsoleKey.B, false, false, false),
            new ConsoleKeyInfo('c', ConsoleKey.C, false, false, false),
            new ConsoleKeyInfo('d', ConsoleKey.D, false, false, false),
            new ConsoleKeyInfo('e', ConsoleKey.E, false, false, false), // must be dropped
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );

        using var buffer = console.ReadSecret("Test", maxLength: max);
        var lease = buffer.AcquireAsync(requestWrite: false);
        var result = Encoding.UTF8.GetString(lease.Span);
        lease.Dispose();

        Assert.Equal("abcd", result);
        Assert.Equal(max, Encoding.UTF8.GetByteCount(result));
    }

    [Fact]
    public void ReadSecret_ExactlyMaxLength_Accepted()
    {
        const int max = 3;

        var console = CreateConsole(
            new ConsoleKeyInfo('x', ConsoleKey.X, false, false, false),
            new ConsoleKeyInfo('y', ConsoleKey.Y, false, false, false),
            new ConsoleKeyInfo('z', ConsoleKey.Z, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );

        using var buffer = console.ReadSecret("Test", maxLength: max);
        var lease = buffer.AcquireAsync(requestWrite: false);
        var result = Encoding.UTF8.GetString(lease.Span);
        lease.Dispose();

        Assert.Equal("xyz", result);
    }

    // -------------------------------------------------------------------------
    // mprotect flag
    // -------------------------------------------------------------------------

    [Fact]
    public void ReadSecret_WithMprotect_ReturnsProtectedBuffer()
    {
        var console = CreateConsole(
            new ConsoleKeyInfo('s', ConsoleKey.S, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );

        using var buffer = console.ReadSecret("Test", useMprotect: true);

        // after Acquire method data must still be accessible
        var lease = buffer.AcquireAsync(requestWrite: false);
        var result = Encoding.UTF8.GetString(lease.Span);
        lease.Dispose();

        Assert.Equal("s", result);
    }

    // -------------------------------------------------------------------------
    // Memory protect - Indirect checks
    // -------------------------------------------------------------------------

    [Fact]
    public void ReadSecret_ReturnedBuffer_IsDisposable()
    {
        var console = CreateConsole(
            new ConsoleKeyInfo('k', ConsoleKey.K, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );

        var buffer = console.ReadSecret("Test");
        buffer.Dispose(); // throw etmemeli
    }

    [Fact]
    public void ReadSecret_MultipleCallsSequentially_EachIndependent()
    {
        // 1st
        var console = CreateConsole(
            new ConsoleKeyInfo('1', ConsoleKey.D1, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );
        using var buf1 = console.ReadSecret("First");

        // 2nd
        console = CreateConsole(
            new ConsoleKeyInfo('2', ConsoleKey.D2, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        );
        using var buf2 = console.ReadSecret("Second");

        var l1 = buf1.AcquireAsync(requestWrite: false);
        var l2 = buf2.AcquireAsync(requestWrite: false);

        Assert.NotEqual(l1.Span.ToArray(), l2.Span.ToArray());

        l1.Dispose();
        l2.Dispose();
    }
}