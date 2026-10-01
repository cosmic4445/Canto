using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Canto.Shell;

[SupportedOSPlatform("windows")]
public static class ContextMenu
{
    private const string LockKey = @"Software\Classes\Directory\shell\CantoLock";
    private const string UnlockKey = @"Software\Classes\Directory\shell\CantoUnlock";

    public static bool IsInstalled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(LockKey);
        return key is not null;
    }

    public static void Install(string cantoExePath)
    {
        string full = Path.GetFullPath(cantoExePath);
        if (!File.Exists(full))
        {
            throw new FileNotFoundException("canto executable not found", full);
        }

        Register(LockKey, "Lock with Canto", full, "lock");
        Register(UnlockKey, "Unlock with Canto", full, "unlock");
    }

    public static void Uninstall()
    {
        Registry.CurrentUser.DeleteSubKeyTree(LockKey, false);
        Registry.CurrentUser.DeleteSubKeyTree(UnlockKey, false);
    }

    private static void Register(string path, string label, string exe, string verb)
    {
        using var key = Registry.CurrentUser.CreateSubKey(path);
        key.SetValue("MUIVerb", label);
        key.SetValue("Icon", $"\"{exe}\",0");
        using var command = key.CreateSubKey("command");
        command.SetValue(string.Empty, $"\"{exe}\" {verb} \"%1\"");
    }
}
