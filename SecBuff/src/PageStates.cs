/*
@author: atailh4n
PageStates.cs (c) 2026
@description: Native memory page states table.
Totally internal.
@created:  2026-03-23
Modified: 2026-04-29
*/

namespace SecBuff;

internal static class PageStates
{
    // Windows
    public const int NT_PAGE_NOACCESS = 0x01;
    public const int NT_PAGE_READONLY = 0x02;
    public const int NT_PAGE_READWRITE = 0x04;
    
    // POSIX
    public const int POSIX_PROT_NONE = 0x0;
    public const int POSIX_PROT_READ = 0x1;
    public const int POSIX_PROT_WRITE = 0x2;
}