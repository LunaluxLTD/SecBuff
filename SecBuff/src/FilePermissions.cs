/*
@author: atailh4n
FilePermissions.cs (c) 2026
@description: Native file permissions table
@created:  2026-04-29
Modified: !date!
*/

namespace SecBuff;

internal static class FilePermissions
{
    // Windows
    public const uint NT_GENERIC_WRITE = 0x40000000;
    public const uint NT_GENERIC_READ = 0x80000000;
    public const uint NT_CREATE_ALWAYS = 2;
    public const uint NT_OPEN_EXISTING = 3;

    // POSIX
    public const int POSIX_O_RDONLY = 0;
    public const int POSIX_O_WRONLY = 1;
    public const int POSIX_O_RDWR   = 2;

    // macOS and BSD share the same values, differ from Linux
    public static int POSIX_O_CREAT => (OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD()) ? 0x200 : 0x40;
    public static int POSIX_O_TRUNC => (OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD()) ? 0x400 : 0x200;
}