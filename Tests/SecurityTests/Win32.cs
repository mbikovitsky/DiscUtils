using System;
using System.Linq;
using System.Runtime.InteropServices;
using DiscUtils.Security.Principal;

namespace SecurityTests
{
    internal static class Win32
    {
        public static byte[] CreateWellKnownSid(WellKnownSidType wellKnownSidType, SecurityIdentifier domainSid)
        {
            byte[] domainSidBinaryForm = null;
            if (null != domainSid)
            {
                domainSidBinaryForm = new byte[domainSid.BinaryLength];
                domainSid.GetBinaryForm(domainSidBinaryForm, 0);
            }

            uint resultSidSize = (uint)SecurityIdentifier.MaxBinaryLength;
            byte[] resultSid = new byte[resultSidSize];

            if (!Win32Native.CreateWellKnownSid((int)wellKnownSidType, domainSidBinaryForm, resultSid, ref resultSidSize))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            return resultSid.Take((int)Win32Native.GetLengthSid(resultSid)).ToArray();
        }

        public static byte[] ConvertStringSidToSid(string stringSid)
        {
            IntPtr rawBuffer = IntPtr.Zero;
            byte[] result;

            try
            {
                if (!Win32Native.ConvertStringSidToSid(stringSid, out rawBuffer))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }

                result = new byte[Win32Native.GetLengthSid(rawBuffer)];

                Marshal.Copy(rawBuffer, result, 0, result.Length);
            }
            finally
            {
                if (rawBuffer != IntPtr.Zero)
                {
                    Win32Native.LocalFree(rawBuffer);
                }
            }

            return result;
        }

        public static byte[] ConvertStringSdToSd(string stringSd)
        {
            IntPtr rawBuffer = IntPtr.Zero;
            byte[] result;

            try
            {
                if (!Win32Native.ConvertStringSdToSd(stringSd, 1, out rawBuffer, out uint rawBufferSize))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }

                result = new byte[rawBufferSize];

                Marshal.Copy(rawBuffer, result, 0, (int)rawBufferSize);
            }
            finally
            {
                if (rawBuffer != IntPtr.Zero)
                {
                    Win32Native.LocalFree(rawBuffer);
                }
            }

            return result;
        }
    }
}
