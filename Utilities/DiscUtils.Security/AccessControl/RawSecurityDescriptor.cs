using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public sealed class RawSecurityDescriptor : GenericSecurityDescriptor
    {
        #region Private Members

        private SecurityIdentifier _owner;
        private SecurityIdentifier _group;
        private ControlFlags _flags;
        private RawAcl _sacl;
        private RawAcl _dacl;
        private byte _rmControl; // the not-so-reserved SBZ1 field

        private static readonly IReadOnlyDictionary<string, ControlFlags> _daclFlagsMap = new Dictionary<string, ControlFlags>
        {
            { "P", ControlFlags.DiscretionaryAclProtected },
            { "AR", ControlFlags.DiscretionaryAclAutoInheritRequired },
            { "AI", ControlFlags.DiscretionaryAclAutoInherited }
        };

        private static readonly IReadOnlyDictionary<string, ControlFlags> _saclFlagsMap = new Dictionary<string, ControlFlags>
        {
            { "P", ControlFlags.SystemAclProtected },
            { "AR", ControlFlags.SystemAclAutoInheritRequired },
            { "AI", ControlFlags.SystemAclAutoInherited }
        };

        #endregion

        #region Protected Properties

        internal override GenericAcl GenericSacl
        {
            get { return _sacl; }
        }

        internal override GenericAcl GenericDacl
        {
            get { return _dacl; }
        }

        #endregion

        #region Private methods

        private void CreateFromParts(ControlFlags flags, SecurityIdentifier owner, SecurityIdentifier group, RawAcl systemAcl, RawAcl discretionaryAcl)
        {
            SetFlags(flags);
            Owner = owner;
            Group = group;
            SystemAcl = systemAcl;
            DiscretionaryAcl = discretionaryAcl;
            ResourceManagerControl = 0;
        }

        private static Tuple<ControlFlags, RawAcl> ParseAclSddl(string sddl)
        {
            Match match = Regex.Match(sddl, "^(?<prefix>D|S):(?<flags>P|AR|AI|NO_ACCESS_CONTROL)*(?<acl>.*)$");
            if (!match.Success)
            {
                throw new ArgumentException("The SDDL form of a security descriptor object is invalid.", nameof(sddl));
            }

            bool isDacl = match.Groups["prefix"].Value == "D";

            string[] flagStrings = match.Groups["flags"]
                                        .Captures
                                        .Cast<Capture>()
                                        .Select(capture => capture.Value)
                                        .ToArray();

            string aclString = match.Groups["acl"].Value;
            bool aclSpecified = !string.IsNullOrEmpty(aclString);

            if (!aclSpecified && !flagStrings.Contains("NO_ACCESS_CONTROL"))
            {
                throw new ArgumentException("The SDDL form of a security descriptor object is invalid.", nameof(sddl));
            }

            IReadOnlyDictionary<string, ControlFlags> map = isDacl ? _daclFlagsMap : _saclFlagsMap;

            ControlFlags flags = flagStrings
                                 .Where(flagString => map.ContainsKey(flagString))
                                 .Select(flagString => map[flagString])
                                 .Aggregate(ControlFlags.None, (accumulated, currentFlag) => accumulated | currentFlag);

            RawAcl acl = null;
            if (aclSpecified)
            {
                acl = new RawAcl(aclString);
                flags |= isDacl ? ControlFlags.DiscretionaryAclPresent : ControlFlags.SystemAclPresent;
            }

            return new Tuple<ControlFlags, RawAcl>(flags, acl);
        }

        #endregion

        #region Constructors

        //
        // Creates a security descriptor explicitly
        //

        public RawSecurityDescriptor(ControlFlags flags, SecurityIdentifier owner, SecurityIdentifier group, RawAcl systemAcl, RawAcl discretionaryAcl)
            : base()
        {
            CreateFromParts(flags, owner, group, systemAcl, discretionaryAcl);
        }

        //
        // Creates a security descriptor from an SDDL string
        //

        public RawSecurityDescriptor(string sddlForm)
        {
            if (sddlForm == null)
            {
                throw new ArgumentNullException(nameof(sddlForm));
            }

            Match match = Regex.Match(sddlForm, "^(?:O:(?<owner>.+?)|)(?:G:(?<group>.+?)|)(?<dacl>D:.+?|)(?<sacl>S:.+?|)$");
            if (!match.Success)
            {
                throw new ArgumentException("The SDDL form of a security descriptor object is invalid.", nameof(sddlForm));
            }

            string ownerString = match.Groups["owner"].Value;
            SecurityIdentifier owner = string.IsNullOrEmpty(ownerString) ? null : new SecurityIdentifier(ownerString);

            string groupString = match.Groups["group"].Value;
            SecurityIdentifier group = string.IsNullOrEmpty(groupString) ? null : new SecurityIdentifier(groupString);

            ControlFlags daclFlags = ControlFlags.None;
            RawAcl dacl = null;
            string daclString = match.Groups["dacl"].Value;
            if (daclString != "")
            {
                var tuple = ParseAclSddl(daclString);
                daclFlags = tuple.Item1;
                dacl = tuple.Item2;
            }

            ControlFlags saclFlags = ControlFlags.None;
            RawAcl sacl = null;
            string saclString = match.Groups["sacl"].Value;
            if (saclString != "")
            {
                var tuple = ParseAclSddl(saclString);
                saclFlags = tuple.Item1;
                sacl = tuple.Item2;
            }

            CreateFromParts(daclFlags | saclFlags, owner, group, sacl, dacl);
        }

        //
        // Creates a security descriptor from its binary representation
        // Important: the representation must be in self-relative format
        //

        public RawSecurityDescriptor(byte[] binaryForm, int offset)
            : base()
        {
            //
            // The array passed in must be valid
            //

            if (binaryForm == null)
            {
                throw new ArgumentNullException(nameof(binaryForm));
            }

            if (offset < 0)
            {
                //
                // Offset must not be negative
                //

                throw new ArgumentOutOfRangeException(nameof(offset),
                    "Non-negative number required.");
            }

            //
            // At least make sure the header is in place
            //

            if (binaryForm.Length - offset < HeaderLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "Destination array is not long enough to copy all the required data. Check array length and offset.");
            }

            //
            // We only understand revision-1 security descriptors
            //

            if (binaryForm[offset + 0] != Revision)
            {
                throw new ArgumentOutOfRangeException(nameof(binaryForm),
                    "Security descriptor with revision other than '1' are not legal.");
            }


            ControlFlags flags;
            SecurityIdentifier owner, group;
            RawAcl sacl, dacl;
            byte rmControl;

            //
            // Extract the ResourceManagerControl field
            //

            rmControl = binaryForm[offset + 1];

            //
            // Extract the control flags
            //

            flags = (ControlFlags)((binaryForm[offset + 2] << 0) + (binaryForm[offset + 3] << 8));

            //
            // Make sure that the input is in self-relative format
            //

            if ((flags & ControlFlags.SelfRelative) == 0)
            {
                throw new ArgumentException(
                    "Security descriptor must be in the self-relative form.",
                    nameof(binaryForm));
            }

            //
            // Extract the owner SID
            //

            int ownerOffset = UnmarshalInt(binaryForm, offset + OwnerFoundAt);

            if (ownerOffset != 0)
            {
                owner = new SecurityIdentifier(binaryForm, offset + ownerOffset);
            }
            else
            {
                owner = null;
            }

            //
            // Extract the group SID
            //

            int groupOffset = UnmarshalInt(binaryForm, offset + GroupFoundAt);

            if (groupOffset != 0)
            {
                group = new SecurityIdentifier(binaryForm, offset + groupOffset);
            }
            else
            {
                group = null;
            }

            //
            // Extract the SACL
            //

            int saclOffset = UnmarshalInt(binaryForm, offset + SaclFoundAt);

            if (((flags & ControlFlags.SystemAclPresent) != 0) &&
                saclOffset != 0)
            {
                sacl = new RawAcl(binaryForm, offset + saclOffset);
            }
            else
            {
                sacl = null;
            }

            //
            // Extract the DACL
            //

            int daclOffset = UnmarshalInt(binaryForm, offset + DaclFoundAt);

            if (((flags & ControlFlags.DiscretionaryAclPresent) != 0) &&
                daclOffset != 0)
            {
                dacl = new RawAcl(binaryForm, offset + daclOffset);
            }
            else
            {
                dacl = null;
            }

            //
            // Create the resulting security descriptor
            //

            CreateFromParts(flags, owner, group, sacl, dacl);

            //
            // In the offchance that the flags indicate that the rmControl
            // field is meaningful, remember what was there.
            //

            if ((flags & ControlFlags.RMControlValid) != 0)
            {
                ResourceManagerControl = rmControl;
            }
        }

        #endregion

        #region Public Properties

        //
        // Allows retrieving the control bits for this security descriptor
        // Important: Special checks must be applied when setting flags and not
        // all flags can be set (for instance, we only deal with self-relative
        // security descriptors), thus flags can be set through other methods.
        //

        public override ControlFlags ControlFlags
        {
            get
            {
                return _flags;
            }
        }

        //
        // Allows retrieving and setting the owner SID for this security descriptor
        //

        public override SecurityIdentifier Owner
        {
            get
            {
                return _owner;
            }

            set
            {
                _owner = value;
            }
        }

        //
        // Allows retrieving and setting the group SID for this security descriptor
        //

        public override SecurityIdentifier Group
        {
            get
            {
                return _group;
            }

            set
            {
                _group = value;
            }
        }

        //
        // Allows retrieving and setting the SACL for this security descriptor
        //

        public RawAcl SystemAcl
        {
            get
            {
                return _sacl;
            }

            set
            {
                _sacl = value;
            }
        }

        //
        // Allows retrieving and setting the DACL for this security descriptor
        //

        public RawAcl DiscretionaryAcl
        {
            get
            {
                return _dacl;
            }

            set
            {
                _dacl = value;
            }
        }

        //
        // CORNER CASE (LEGACY)
        // The ostensibly "reserved" field in the Security Descriptor header
        // can in fact be used by obscure resource managers which in this
        // case must set the RMControlValid flag.
        //

        public byte ResourceManagerControl
        {
            get
            {
                return _rmControl;
            }

            set
            {
                _rmControl = value;
            }
        }


        #endregion

        #region Public Methods

        public void SetFlags(ControlFlags flags)
        {
            //
            // We can not deal with non-self-relative descriptors
            // so just forget about it
            //

            _flags = (flags | ControlFlags.SelfRelative);
        }
        #endregion
    }
}
