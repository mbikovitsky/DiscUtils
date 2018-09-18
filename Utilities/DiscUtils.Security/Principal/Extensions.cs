namespace DiscUtils.Security.Principal
{
    public static class Extensions
    {
        public static byte[] GetBinaryForm(this SecurityIdentifier sid)
        {
            byte[] binaryForm = new byte[sid.BinaryLength];
            sid.GetBinaryForm(binaryForm, 0);
            return binaryForm;
        }
    }
}
