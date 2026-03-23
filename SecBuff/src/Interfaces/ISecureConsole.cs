/*
@author: atailh4n
ISecureConsole.cs (c) 2026
@description: Provides secure interaction methods for the console, ensuring sensitive input 
never touches the managed heap as a <see cref="string"/>.
@created:  2026-03-23T16:25:51.396Z
Modified: !date!
*/

using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SecBuff.Interfaces;

/// <summary>
/// Provides secure interaction methods for the console, ensuring sensitive input 
/// never touches the managed heap as a <see cref="string"/>.
/// </summary>
public interface ISecureConsole
{
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
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    ISecureBuffer ReadSecret(string prompt, int maxLength = 256, bool useMprotect = false);
}