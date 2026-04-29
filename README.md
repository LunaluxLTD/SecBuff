# SecBuff (Lunalux.SecBuff)

_Hardened Memory Management for .NET, Time-bound memory exposure model. Aligned with ISO/IEC 27001 practices._

![GitHub License](https://img.shields.io/github/license/LunaluxLTD/SecBuff?style=for-the-badge)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/LunaluxLTD/SecBuff/pipeline.yml?style=for-the-badge)
![NuGet Version](https://img.shields.io/nuget/v/Lunalux.SecBuff?style=for-the-badge)
![NuGet Downloads](https://img.shields.io/nuget/dt/Lunalux.SecBuff?style=for-the-badge)
[![CodeFactor](https://www.codefactor.io/repository/github/lunaluxltd/secbuff/badge?style=for-the-badge)](https://www.codefactor.io/repository/github/lunaluxltd/secbuff)

## Overview

**SecBuff** implements a time-bound memory exposure model for sensitive data in .NET, provides best-effort protection for sensitive data in user-space memory; such as API keys, passwords, and cryptographic material.

By default, .NET types such as `string` and `byte[]` are managed by the garbage collector, which introduces several security concerns:

- Sensitive data **may be duplicated in memory** due to garbage collector relocation.
- Memory pages **may be swapped to disk**, potentially exposing secrets in plaintext.
- Process memory dumps **may reveal sensitive data without restriction**.

**SecBuff** mitigates these risks by operating outside the managed heap and leveraging operating system–level memory protection mechanisms. Guarantees depend on the underlying operating system.

The library is designed to support secure memory handling practices aligned with standards such as **ISO/IEC 27001**, reduces the likelihood of sensitive data being persisted outside physical memory, subject to OS guarantees.

## Key Features

**Memory Locking**\
**Prevents sensitive data** from being swapped to disk:

- Windows: `VirtualLock`
- POSIX systems: `mlock`

**Memory Protection**\
**Restricts access to protected memory** regions when not in use.

- Windows: `VirtualProtect`
- POSIX systems: `mprotect`

**Deterministic Zeroing**\
**Ensures sensitive data is securely wiped** from memory after use via `CryptographicOperations`.

**Controlled Access Model**\
Secrets are **only accessible within explicitly defined scopes** and remain inaccessible otherwise.

**Async Compatibility**\
Supports safe usage across `async` / `await` boundaries. Due to .NET runtime constraints, strict stack-only guarantees (`ref struct`) cannot be preserved across async boundaries. **SecBuff** provides `AcquireAsync` as a controlled alternative.

## Threat Model

**Protects against:**

- Accidental memory exposure
- Managed heap inspection
- Basic memory dumps

**Does NOT protect against:**

- Kernel-level attackers
- Full system compromise
- Cold boot attacks
- DMA attacks
- CPU caches and processor registers may temporarily retain sensitive data. Due to .NET runtime constraints, **SecBuff cannot explicitly clear these transient copies**.

## Quick Start

1. **Secure Input**\
   Read sensitive input directly into protected memory **without creating intermediate managed** `string`**s**:

   ```cs
   using SecBuff;
   using ISecureBuffer password = 
       SecureConsole.ReadSecret("Enter admin password", useMprotect: true);
   ```
  
2. **Secret Management**\
   Store and access secrets using a controlled access pattern:

   ```cs
   var vault = new SecretManager<string>(logger);
   
   // Store a secret - System.Text.Encoding is not recommended due to GC can copy these strings.
   vault.Set("ApiKey", Encoding.UTF8.GetBytes("super-secret-key"), useMprotect: true);
   
   // Access the secret
   vault.AccessSecret("ApiKey", span =>
   {
       MyApiClient.Initialize(span);
   });
   ```

   Memory is only readable and writable within the access delegate and is **protected immediately** afterward through reference-counted access control.
  
3. **Encrypted Key Files (.sbkf)**  
   Persist and reuse cryptographic keys securely across application runs:

   ```cs
   // Generate or load a key file
   var keyFile = SecureKeyFile.Load("master.sbkf");
   
   // Initialize vault with encryption support
   var vault = new SecretManager<string>(logger, keyFile);
   
   // Store encrypted secret
   vault.SetSecret("ApiKey", "super-secret-key"u8.ToArray(), useEncryption: true);
   
   // Access (automatically decrypted in a protected buffer)
   vault.AccessSecret("ApiKey", span =>
   {
       MyApiClient.Initialize(span);
   });
   ```

   - Uses AES-256-GCM for authenticated encryption.
   - Keys are derived via SecureKeyFile.DeriveKey.
   - Plaintext exists only in protected memory and only during access scope.
   - Encrypted secrets remain protected even if memory is compromised.

## Technical Details

| Feature        | Windows                                                                       | POSIX Systems             |
| -------------- | ----------------------------------------------------------------------------- | ------------------------- |
| Memory Locking | `VirtualLock` (Non-deterministic\*)                                           | `mlock`                   |_
| Protection     | `VirtualProtect`                                                              | `mprotect`                |
| Alignment      | Page-aligned                                                                  | Page-aligned              |
| Zeroing        | `CryptographicOperations`                                                     | `CryptographicOperations` |
| Swap Defense   | Requires PageFile Disabled or `SECBUFF_ALLOW_PAGEFILE=1` environment variable | MCL_FUTURE / `mlock`      |

> [!CAUTION]
> **Windows Memory Integrity Problem:**\
> \
> Due to legacy architectural constraints in the Windows NT Kernel,
> VirtualLock may be silently dropped by the Memory Manager
> when page protections are transitioned (e.g., to `PAGE_NOACCESS`).
> This is a [documented limitation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock#remarks) of the Windows memory API.
> Windows does not provide a strict guarantee that locked pages remain
> resident under all conditions, especially when protection states are modified.
> To guarantee zero-swap integrity on Windows, System PageFile must be disabled.
> SecBuff will perform an environment audit and throw a `SecurityException`
> if an insecure configuration is detected.
> By enabling `SECBUFF_ALLOW_PAGEFILE=1`, you explicitly accept that secrets may be paged to disk.

**No Managed Strings**\
Sensitive data is **never stored as managed type**. All APIs operate on `Span<byte>` or unmanaged memory.

**Scoped Access**\
Secrets are exposed **only within controlled execution scopes** (e.g., `using` blocks).

**Deterministic Cleanup**\
Memory is **explicitly cleared on disposal**. Finalizers act as a fallback if `Dispose` is not invoked.

**Stack-Constrained Access**\
`ref struct` patterns are used where appropriate to prevent unintended heap allocation or capture, but for async operations it is not possible due to .NET's structure, which **SecBuff** has AcquireAsync for this spesific case.

## Contributing

**SecBuff** is developed by LunaluxLTD (Ata İlhan Köktürk).

Contributions are welcome. For security-related issues, please use a responsible disclosure process via a.kokturk@lunalux.com.tr. General improvements and discussions can be submitted via pull requests or issues.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
