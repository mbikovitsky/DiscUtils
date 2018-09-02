using System;
using System.Runtime.InteropServices;

namespace SecurityTests
{
    internal static class Win32Native
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateWellKnownSid(int wellKnownSidType, byte[] domainSid, [Out] byte[] resultSid, ref uint resultSidSize);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertStringSidToSid(string stringSid, out IntPtr resultSid);

        [DllImport("advapi32.dll")]
        public static extern uint GetLengthSid(byte[] sid);

        [DllImport("advapi32.dll")]
        public static extern uint GetLengthSid(IntPtr sid);

        [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptor",
            CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertStringSdToSd(string stringSd,
                                                      uint stringSdRevision,
                                                      out IntPtr resultSd,
                                                      out uint resultSdSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr handle);
    }
}
