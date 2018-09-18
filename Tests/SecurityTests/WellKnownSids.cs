using System;
using System.Collections.Generic;
using System.Linq;
using DiscUtils.Security.Principal;
using Xunit;

namespace SecurityTests
{
    public class WellKnownSids
    {
        private static readonly IReadOnlyList<string> _wellKnownSddl = new[]
        {
            "AN",
            "AO",
            "AU",
            "BA",
            "BG",
            "BO",
            "BU",
            "CA",
            "CD",
            "CG",
            "CO",
            "DA",
            "DC",
            "DD",
            "DG",
            "DU",
            "EA",
            "ED",
            "HI",
            "IU",
            "LA",
            "LG",
            "LS",
            "LW",
            "ME",
            "MU",
            "NO",
            "NS",
            "NU",
            "PA",
            "PO",
            "PS",
            "PU",
            "RC",
            "RD",
            "RE",
            "RO",
            "RS",
            "RU",
            "SA",
            "SI",
            "SO",
            "SU",
            "SY",
            "WD"
        };

        [Theory]
        [MemberData(nameof(WellKnownSidTypesTheoryParams))]
        public void SecurityIdentifier_WellKnownSidTypeConvertedOrNotImplemented(WellKnownSidType wellKnownSidType)
        {
            byte[] correctSid = Win32.CreateWellKnownSid(wellKnownSidType, null);

            SecurityIdentifier sid;
            try
            {
                sid = new SecurityIdentifier(wellKnownSidType, null);
            }
            catch (NotImplementedException)
            {
                return;
            }

            Assert.Equal(correctSid, sid.GetBinaryForm());
        }

        [Theory]
        [MemberData(nameof(WellKnownSddlTheoryParams))]
        public void SecurityIdentifier_WellKnownSDDLConvertedOrNotImplemented(string sddl)
        {
            byte[] correctSid = Win32.ConvertStringSidToSid(sddl);

            SecurityIdentifier sid;
            try
            {
                sid = new SecurityIdentifier(sddl);
            }
            catch (NotImplementedException)
            {
                return;
            }

            Assert.Equal(correctSid, sid.GetBinaryForm());
        }

        public static IEnumerable<object[]> WellKnownSidTypesTheoryParams
        {
            get
            {
                foreach (WellKnownSidType wellKnownSidType in Enum.GetValues(typeof(WellKnownSidType)).Cast<WellKnownSidType>())
                {
                    try
                    {
                        Win32.CreateWellKnownSid(wellKnownSidType, null);
                    }
                    catch
                    {
                        continue;
                    }

                    yield return new object[] { wellKnownSidType };
                }
            }
        }

        public static IEnumerable<object[]> WellKnownSddlTheoryParams
        {
            get
            {
                foreach (string sddl in _wellKnownSddl)
                {
                    try
                    {
                        Win32.ConvertStringSidToSid(sddl);
                    }
                    catch
                    {
                        continue;
                    }

                    yield return new object[] { sddl };
                }
            }
        }
    }
}
