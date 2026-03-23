/*
@author: atailh4n
SecureConsole.cs (c) 2026
@description: Provides secure interaction methods for the console, ensuring sensitive input
@created:  2026-03-23T16:21:56.122Z
Modified: !date!
*/

using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SecBuff.Interfaces;

namespace SecBuff;

/// <summary>
/// Provides secure interaction methods for the console, ensuring sensitive input 
/// never touches the managed heap as a <see cref="string"/>.
/// </summary>
public sealed class SecureConsole(IKeyReader? keyReader = null) : ISecureConsole
{
    private readonly IKeyReader _keyReader = keyReader ?? new ConsoleKeyReader();

    /// <summary>
    /// Reads a secret from the standard input (stdin) character by character without echoing the actual characters.
    /// The input is captured directly into a secure stack-allocated buffer and then moved to a <see cref="SecureBuffer"/>.
    /// </summary>
    /// <param name="prompt">The message to display to the user before reading input.</param>
    /// <param name="maxLength">The maximum allowed length for the secret input (default is 256).</param>
    /// <param name="useMprotect">If <see langword="true"/>, the resulting <see cref="SecureBuffer"/> will use OS-level page protection.</param>
    /// <returns>A <see cref="SecureBuffer"/> containing the UTF-8 encoded secret.</returns>
    /// <remarks>
    /// This method is backspace-tolerant and provides visual feedback using asterisks (*). 
    /// It uses <c>stackalloc</c> and <see cref="CryptographicOperations.ZeroMemory"/> to ensure 
    /// transient data is wiped immediately after processing.
    /// </remarks>
    [SuppressMessage("ReSharper", "RedundantAssignment")]
    [SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters")]
    public ISecureBuffer ReadSecret(string prompt, int maxLength = 256, bool useMprotect = false)
    {
        Console.Write($"{prompt} (Max {maxLength} chars): ");

        // Use stackalloc to keep temporary data off the managed heap
        Span<byte> staging = stackalloc byte[maxLength];
        Span<byte> encoded = stackalloc byte[4]; // Buffer for UTF-8 character encoding
        var currentLength = 0;

        try
        {
            while (true)
            {
                // Intercept: true prevents the character from being printed to the console
                var key = _keyReader.ReadKey(true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (currentLength > 0)
                    {
                        staging[--currentLength] = 0;
                        Console.Write("\b \b"); // Erase the asterisk from console
                    }
                    continue;
                }

                if (currentLength >= maxLength) continue;

                var source = key.KeyChar;
                // Encode the char directly into the staging buffer
                var written = Encoding.UTF8.GetBytes(
                    MemoryMarshal.CreateReadOnlySpan(ref source, 1),
                    encoded);

                for (var i = 0; i < written && currentLength < maxLength; i++)
                {
                    staging[currentLength++] = encoded[i];
                    Console.Write("*"); // Visual mask
                }

                written = 0; // Reset for safety, GC hint at this point.
            }

            // Create the permanent secure storage
            var buffer = new SecureBuffer(currentLength, useMprotect);

            using var lease = buffer.Acquire(requestWrite: true);
            staging[..currentLength].CopyTo(lease.Span);

            return buffer;
        }
        finally
        {
            // Zero out the stack buffers IMMEDIATELY to prevent memory leakage
            CryptographicOperations.ZeroMemory(staging);
            CryptographicOperations.ZeroMemory(encoded);
        }
    }
}