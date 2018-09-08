using DiscUtils.Security.AccessControl;
using Xunit;

namespace SecurityTests
{
    public class Sddl
    {
        private const SecurityInfos _allSecurityInfos = SecurityInfos.Owner | SecurityInfos.Group | SecurityInfos.DiscretionaryAcl | SecurityInfos.SystemAcl;

        private const string _sddl = @"O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)";

        [Theory]
        [InlineData(_sddl)]
        public void RawSecurityDescriptor_CorrectSDDLOutput(string stringSd)
        {
            byte[] binaryForm = Win32.ConvertStringSdToSd(stringSd);

            RawSecurityDescriptor securityDescriptor = new RawSecurityDescriptor(binaryForm, 0);

            Assert.Equal(
                NormalizeSddl(stringSd, _allSecurityInfos),
                NormalizeSddl(securityDescriptor.GetSddlForm(AccessControlSections.All), _allSecurityInfos));
        }

        [Theory]
        [InlineData(_sddl)]
        public void RawSecurityDescriptor_CorrectSDDLParser(string stringSd)
        {
            RawSecurityDescriptor securityDescriptor = new RawSecurityDescriptor(stringSd);

            byte[] binaryForm = new byte[securityDescriptor.BinaryLength];
            securityDescriptor.GetBinaryForm(binaryForm, 0);

            Assert.Equal(
                NormalizeSddl(stringSd, _allSecurityInfos),
                Win32.ConvertSdToStringSd(binaryForm, _allSecurityInfos));
        }

        private static string NormalizeSddl(string sddl, SecurityInfos securityInfos)
        {
            return Win32.ConvertSdToStringSd(Win32.ConvertStringSdToSd(sddl), securityInfos);
        }
    }
}
