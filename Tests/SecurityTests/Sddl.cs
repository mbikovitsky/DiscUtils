using DiscUtils.Security.AccessControl;
using Xunit;

namespace SecurityTests
{
    public class Sddl
    {
        [Theory]
        [InlineData("O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;CIOIIO;0x10000000;;;S-1-3-0)(A;CIOIIO;0x10000000;;;S-1-5-18)(A;;0x1301bf;;;S-1-5-18)(A;CIOIIO;0x10000000;;;S-1-5-32-544)(A;;0x1301bf;;;S-1-5-32-544)(A;CIOIIO;0xa0000000;;;S-1-5-32-545)(A;;0x1200a9;;;S-1-5-32-545)(A;CIIO;0x10000000;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;S-1-15-2-1)(A;CIOIIO;0xa0000000;;;S-1-15-2-1)(A;;0x1200a9;;;S-1-15-2-2)(A;CIOIIO;0xa0000000;;;S-1-15-2-2)")]
        public void RawSecurityDescriptor_CorrectSDDLOutput(string stringSd)
        {
            byte[] binaryForm = Win32.ConvertStringSdToSd(stringSd);

            RawSecurityDescriptor securityDescriptor = new RawSecurityDescriptor(binaryForm, 0);

            Assert.Equal(stringSd, securityDescriptor.GetSddlForm(AccessControlSections.All));
        }
    }
}
