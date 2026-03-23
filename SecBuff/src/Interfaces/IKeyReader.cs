/*
 * Author: atailh4n
 * File: ISecretManager.cs
 * Copyright (c) 2026
 * Description: Interface for reading key input.
 * Created: 2026-03-23
 * Modified: !date!
 */

namespace SecBuff.Interfaces;

/// <summary>
/// Provides an abstraction for reading key input, typically from standard input.
/// </summary>
public interface IKeyReader
{
    /// <summary>
    /// Reads a key from the input stream.
    /// </summary>
    /// <param name="intercept">
    /// If true, the pressed key is not displayed in the console.
    /// </param>
    /// <returns>
    /// A <see cref="ConsoleKeyInfo"/> representing the key that was pressed.
    /// </returns>
    ConsoleKeyInfo ReadKey(bool intercept);
}