// ref: https://powertoe.wordpress.com/2015/04/27/invoking-the-getdiskspaceinformation-method-of-the-iofflinefilescache-com-interface-with-c-and-powershell/
// mirror: https://web.archive.org/web/20170723171715/https://powertoe.wordpress.com/2015/04/27/invoking-the-getdiskspaceinformation-method-of-the-iofflinefilescache-com-interface-with-c-and-powershell/
using System;
using System.Runtime.InteropServices;
 
public class offlinecache {
    public static ulong[] GetOfflineCache() {
        ulong pcbVolumeTotal=0, pcbLimit=0, pcbUsed=0, pcbUnpinnedLimit=0, pcbUnpinnedUsed=0;
        Guid ID = new Guid("48C6BE7C-3871-43cc-B46F-1449A1BB2FF3");
        Type idtype = Type.GetTypeFromCLSID(ID);
        IOfflineFilesCache obj = (IOfflineFilesCache) Activator.CreateInstance(idtype, true);
        int i = obj.GetDiskSpaceInformation(ref pcbVolumeTotal, ref pcbLimit, ref pcbUsed, ref pcbUnpinnedLimit, ref pcbUnpinnedUsed);
        ulong[] output = new ulong[5];
        output[0] = pcbVolumeTotal;
        output[1] = pcbLimit;
        output[2] = pcbUsed;
        output[3] = pcbUnpinnedLimit;
        output[4] = pcbUnpinnedUsed;
        return output;
    }
 
    [ComImport]
    [Guid("855D6203-7914-48B9-8D40-4C56F5ACFFC5"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IOfflineFilesCache
    {
        [PreserveSig()]
        int Synchronize();
 
        [PreserveSig()]
        int DeleteItems();
 
        [PreserveSig()]
        int DeleteItemsForUser();
 
        [PreserveSig()]
        int Pin();
 
        [PreserveSig()]
        int UnPin();
 
        [PreserveSig()]
        int GetEncryptionStatus();
 
        [PreserveSig()]
        int Encrypt();
 
        [PreserveSig()]
        int FindItem();
 
        [PreserveSig()]
        int FindItemEx();
 
        [PreserveSig()]
        int RenameItem();
 
        [PreserveSig()]
        int GetLocation();
 
        [PreserveSig()]
        int GetDiskSpaceInformation(ref ulong pcbVolumeTotal, ref ulong pcbLimit, ref ulong pcbUsed, ref ulong pcbUnpinnedLimit, ref ulong pcbUnpinnedUsed);
 
        [PreserveSig()]
        int SetDiskSpaceLimits();
 
        [PreserveSig()]
        int ProcessAdminPinPolicy();
 
        [PreserveSig()]
        int GetSettingObject();
 
        [PreserveSig()]
        int EnumSettiingObjects();
 
        [PreserveSig()]
        int IsPathCacheable();
    }
}