using System;
using System.Diagnostics;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public abstract class GenericSecurityDescriptor
    {
        #region Protected Members

        //
        // Pictorially the structure of a security descriptor is as follows:
        //
        //       3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
        //       1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
        //      +---------------------------------------------------------------+
        //      |            Control            |Reserved1 (SBZ)|   Revision    |
        //      +---------------------------------------------------------------+
        //      |                            Owner                              |
        //      +---------------------------------------------------------------+
        //      |                            Group                              |
        //      +---------------------------------------------------------------+
        //      |                            Sacl                               |
        //      +---------------------------------------------------------------+
        //      |                            Dacl                               |
        //      +---------------------------------------------------------------+
        //

        internal const int HeaderLength = 20;
        internal const int OwnerFoundAt = 4;
        internal const int GroupFoundAt = 8;
        internal const int SaclFoundAt = 12;
        internal const int DaclFoundAt = 16;

        #endregion

        #region Private Methods

        //
        // Stores an integer in big-endian format into an array at a given offset
        //

        private static void MarshalInt(byte[] binaryForm, int offset, int number)
        {
            binaryForm[offset + 0] = (byte)(number >> 0);
            binaryForm[offset + 1] = (byte)(number >> 8);
            binaryForm[offset + 2] = (byte)(number >> 16);
            binaryForm[offset + 3] = (byte)(number >> 24);
        }

        //
        // Retrieves an integer stored in big-endian format at a given offset in an array
        //

        internal static int UnmarshalInt(byte[] binaryForm, int offset)
        {
            return (int)(
                (binaryForm[offset + 0] << 0) +
                (binaryForm[offset + 1] << 8) +
                (binaryForm[offset + 2] << 16) +
                (binaryForm[offset + 3] << 24));
        }

        #endregion

        #region Constructors

        protected GenericSecurityDescriptor()
        { }

        #endregion

        #region Protected Properties

        //
        // Marshaling logic requires calling into the derived
        // class to obtain pointers to SACL and DACL
        //

        internal abstract GenericAcl GenericSacl { get; }
        internal abstract GenericAcl GenericDacl { get; }
        private bool IsCraftedAefaDacl
        {
            get
            {
                return (GenericDacl is DiscretionaryAcl) && (GenericDacl as DiscretionaryAcl).EveryOneFullAccessForNullDacl;
            }
        }

        #endregion

        #region Public Properties

        public static bool IsSddlConversionSupported()
        {
            return true; // SDDL to binary conversions are supported on Windows 2000 and higher
        }

        public static byte Revision
        {
            get { return 1; }
        }

        //
        // Allows retrieving and setting the control bits for this security descriptor
        //

        public abstract ControlFlags ControlFlags { get; }

        //
        // Allows retrieving and setting the owner SID for this security descriptor
        //

        public abstract SecurityIdentifier Owner { get; set; }

        //
        // Allows retrieving and setting the group SID for this security descriptor
        //

        public abstract SecurityIdentifier Group { get; set; }

        //
        // Retrieves the length of the binary representation
        // of the security descriptor
        //

        public int BinaryLength
        {
            get
            {
                int result = HeaderLength;

                if (Owner != null)
                {
                    result += Owner.BinaryLength;
                }

                if (Group != null)
                {
                    result += Group.BinaryLength;
                }

                if ((ControlFlags & ControlFlags.SystemAclPresent) != 0 &&
                    GenericSacl != null)
                {
                    result += GenericSacl.BinaryLength;
                }

                if ((ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0 &&
                    GenericDacl != null && !IsCraftedAefaDacl)
                {
                    result += GenericDacl.BinaryLength;
                }

                return result;
            }
        }

        #endregion

        #region Public Methods

        //
        // Converts the security descriptor to its SDDL form
        //

        public string GetSddlForm(AccessControlSections includeSections)
        {
            throw new NotImplementedException();
        }

        //
        // Converts the security descriptor to its binary form
        //

        public void GetBinaryForm(byte[] binaryForm, int offset)
        {
            if (binaryForm == null)
            {
                throw new ArgumentNullException(nameof(binaryForm));
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset),
                    "Non-negative number required.");
            }

            if (binaryForm.Length - offset < BinaryLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "Destination array is not long enough to copy all the required data. Check array length and offset.");
            }

            //
            // the offset will grow as we go for each additional field (owner, group,
            // acl, etc) being written. But for each of such fields, we must use the
            // original offset as passed in, not the growing offset
            //

            int originalOffset = offset;

            //
            // Populate the header
            //

            int length = BinaryLength;

            byte rmControl =
                ((this is RawSecurityDescriptor) &&
                 ((ControlFlags & ControlFlags.RMControlValid) != 0)) ? ((this as RawSecurityDescriptor).ResourceManagerControl) : (byte)0;

            // if the DACL is our internally crafted NULL replacement, then let us turn off this control
            int materializedControlFlags = (int)ControlFlags;
            if (IsCraftedAefaDacl)
            {
                unchecked { materializedControlFlags &= ~((int)ControlFlags.DiscretionaryAclPresent); }
            }

            binaryForm[offset + 0] = Revision;
            binaryForm[offset + 1] = rmControl;
            binaryForm[offset + 2] = unchecked((byte)((int)materializedControlFlags >> 0));
            binaryForm[offset + 3] = (byte)((int)materializedControlFlags >> 8);

            //
            // Compute offsets at which owner, group, SACL and DACL are stored
            //

            int ownerOffset, groupOffset, saclOffset, daclOffset;

            ownerOffset = offset + OwnerFoundAt;
            groupOffset = offset + GroupFoundAt;
            saclOffset = offset + SaclFoundAt;
            daclOffset = offset + DaclFoundAt;

            offset += HeaderLength;

            //
            // Marhsal the Owner SID into place
            //

            if (Owner != null)
            {
                MarshalInt(binaryForm, ownerOffset, offset - originalOffset);
                Owner.GetBinaryForm(binaryForm, offset);
                offset += Owner.BinaryLength;
            }
            else
            {
                //
                // If Owner SID is null, store 0 in the offset field
                //

                MarshalInt(binaryForm, ownerOffset, 0);
            }

            //
            // Marshal the Group SID into place
            //

            if (Group != null)
            {
                MarshalInt(binaryForm, groupOffset, offset - originalOffset);
                Group.GetBinaryForm(binaryForm, offset);
                offset += Group.BinaryLength;
            }
            else
            {
                //
                // If Group SID is null, store 0 in the offset field
                //

                MarshalInt(binaryForm, groupOffset, 0);
            }

            //
            // Marshal the SACL into place, if present
            //

            if ((ControlFlags & ControlFlags.SystemAclPresent) != 0 &&
                GenericSacl != null)
            {
                MarshalInt(binaryForm, saclOffset, offset - originalOffset);
                GenericSacl.GetBinaryForm(binaryForm, offset);
                offset += GenericSacl.BinaryLength;
            }
            else
            {
                //
                // If SACL is null or not present, store 0 in the offset field
                //

                MarshalInt(binaryForm, saclOffset, 0);
            }

            //
            // Marshal the DACL into place, if present
            //

            if ((ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0 &&
                GenericDacl != null && !IsCraftedAefaDacl)
            {
                MarshalInt(binaryForm, daclOffset, offset - originalOffset);
                GenericDacl.GetBinaryForm(binaryForm, offset);
                offset += GenericDacl.BinaryLength;
            }
            else
            {
                //
                // If DACL is null or not present, store 0 in the offset field
                //

                MarshalInt(binaryForm, daclOffset, 0);
            }
        }
        #endregion
    }
}
