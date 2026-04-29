/*
@author: atailh4n
ConsoleKeyReader.cs (c) 2026
@description: Default implementation of IKeyReader using the system console.
@created: 2026-03-23
Modified: 2026-04-29
*/

using SecBuff.Interfaces;

namespace SecBuff;

/// <summary>
/// Default implementation of <see cref="IKeyReader"/> that reads input from the system console.
/// Intended for use in production scenarios.
/// </summary>
public sealed class ConsoleKeyReader : IKeyReader
{
    /// <summary>
    /// Reads a key from standard input using <see cref="Console.ReadKey(bool)"/>.
    /// </summary>
    /// <param name="intercept">
    /// If true, the pressed key is not displayed in the console; otherwise, it is shown.
    /// </param>
    /// <returns>
    /// A <see cref="ConsoleKeyInfo"/> representing the key that was pressed.
    /// </returns>
    public ConsoleKeyInfo ReadKey(bool intercept) => Console.ReadKey(intercept);
}