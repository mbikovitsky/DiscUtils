using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DiscUtils.Security.Principal
{
    //
    // This class implements revision 1 SIDs
    // NOTE: The SecurityIdentifier class is immutable and must remain this way
    //
    public sealed class SecurityIdentifier : IdentityReference, IComparable<SecurityIdentifier>
    {
        #region Public Constants

        //
        // Identifier authority must be at most six bytes long
        //

        internal static readonly long MaxIdentifierAuthority = 0xFFFFFFFFFFFF;

        //
        // Maximum number of subauthorities in a SID
        //

        internal static readonly byte MaxSubAuthorities = 15;

        //
        // Minimum length of a binary representation of a SID
        //

        public static readonly int MinBinaryLength = 1 + 1 + 6; // Revision (1) + subauth count (1) + identifier authority (6)

        //
        // Maximum length of a binary representation of a SID
        //

        public static readonly int MaxBinaryLength = 1 + 1 + 6 + MaxSubAuthorities * 4; // 4 bytes for each subauth

        #endregion

        #region Private Members

        //
        // Immutable properties of a SID
        //

        private IdentifierAuthority _identifierAuthority;
        private int[] _subAuthorities;
        private byte[] _binaryForm;

        //
        // Computed attributes of a SID
        //

        private string _sddlForm = null;

        private static readonly IReadOnlyDictionary<string, WellKnownSidType> _wellKnownSddlConstants = new Dictionary<string, WellKnownSidType>
        {
            { "AC", (WellKnownSidType)84 },
            { "AN", WellKnownSidType.AnonymousSid },
            { "AO", WellKnownSidType.BuiltinAccountOperatorsSid },
            { "AU", WellKnownSidType.AuthenticatedUserSid },
            { "BA", WellKnownSidType.BuiltinAdministratorsSid },
            { "BG", WellKnownSidType.BuiltinGuestsSid },
            { "BO", WellKnownSidType.BuiltinBackupOperatorsSid },
            { "BU", WellKnownSidType.BuiltinUsersSid },
            { "CD", (WellKnownSidType)78 },
            { "CG",  WellKnownSidType.CreatorGroupSid },
            { "CO", WellKnownSidType.CreatorOwnerSid },
            { "ED", WellKnownSidType.EnterpriseControllersSid },
            { "HI", (WellKnownSidType)68 },
            { "IU", WellKnownSidType.InteractiveSid },
            { "LS", WellKnownSidType.LocalServiceSid },
            { "LW", (WellKnownSidType)66 },
            { "ME", (WellKnownSidType)67 },
            { "MU", WellKnownSidType.BuiltinPerformanceMonitoringUsersSid },
            { "NO", WellKnownSidType.BuiltinNetworkConfigurationOperatorsSid },
            { "NS", WellKnownSidType.NetworkServiceSid },
            { "NU", WellKnownSidType.NetworkSid },
            { "PO", WellKnownSidType.BuiltinPrintOperatorsSid },
            { "PS", WellKnownSidType.SelfSid },
            { "PU", WellKnownSidType.BuiltinPowerUsersSid },
            { "RC", WellKnownSidType.RestrictedCodeSid },
            { "RD", WellKnownSidType.BuiltinRemoteDesktopUsersSid },
            { "RE", WellKnownSidType.BuiltinReplicatorSid },
            { "RU", WellKnownSidType.BuiltinPreWindows2000CompatibleAccessSid },
            { "SI", (WellKnownSidType)69 },
            { "SO", WellKnownSidType.BuiltinSystemOperatorsSid },
            { "SU", WellKnownSidType.ServiceSid },
            { "SY", WellKnownSidType.LocalSystemSid },
            { "WD", WellKnownSidType.WorldSid }
        };

        private static readonly IReadOnlyDictionary<WellKnownSidType, Tuple<IdentifierAuthority, IReadOnlyList<int>>> _wellKnownSidPartsMap = new Dictionary<WellKnownSidType, Tuple<IdentifierAuthority, IReadOnlyList<int>>>
        {
            // WinLowLabelSid
            {
                (WellKnownSidType)66,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>((IdentifierAuthority)16, new[] { 0x1000 })
            },

            // WinMediumLabelSid
            {
                (WellKnownSidType)67,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>((IdentifierAuthority)16, new[] { 0x2000 })
            },

            // WinHighLabelSid
            {
                (WellKnownSidType)68,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>((IdentifierAuthority)16, new[] { 0x3000 })
            },

            // WinSystemLabelSid
            {
                (WellKnownSidType)69,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>((IdentifierAuthority)16, new[] { 0x4000 })
            },

            // WinBuiltinCertSvcDComAccessGroup
            {
                (WellKnownSidType)78,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 574 })
            },

            // WinBuiltinAnyPackageSid
            {
                (WellKnownSidType)84,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>((IdentifierAuthority)15, new[] { 2, 1 })
            },

            {
                WellKnownSidType.AnonymousSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 7 })
            },

            {
                WellKnownSidType.BuiltinAccountOperatorsSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 548 })
            },

            {
                WellKnownSidType.AuthenticatedUserSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 11 })
            },

            {
                WellKnownSidType.BuiltinAdministratorsSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 544 })
            },

            {
                WellKnownSidType.BuiltinGuestsSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 546 })
            },

            {
                WellKnownSidType.BuiltinBackupOperatorsSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 551 })
            },

            {
                WellKnownSidType.BuiltinUsersSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 545 })
            },

            {
                WellKnownSidType.CreatorGroupSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.CreatorAuthority, new[] { 1 })
            },

            {
                WellKnownSidType.CreatorOwnerSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.CreatorAuthority, new[] { 0 })
            },

            {
                WellKnownSidType.EnterpriseControllersSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 9 })
            },

            {
                WellKnownSidType.InteractiveSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 4 })
            },

            {
                WellKnownSidType.LocalServiceSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 19 })
            },

            {
                WellKnownSidType.BuiltinPerformanceMonitoringUsersSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 558 })
            },

            {
                WellKnownSidType.BuiltinNetworkConfigurationOperatorsSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 556 })
            },

            {
                WellKnownSidType.NetworkServiceSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 20 })
            },

            {
                WellKnownSidType.NetworkSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 2 })
            },

            {
                WellKnownSidType.BuiltinPrintOperatorsSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 550 })
            },

            {
                WellKnownSidType.SelfSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 10 })
            },

            {
                WellKnownSidType.BuiltinPowerUsersSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 547 })
            },

            {
                WellKnownSidType.RestrictedCodeSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 12 })
            },

            {
                WellKnownSidType.BuiltinRemoteDesktopUsersSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 555 })
            },

            {
                WellKnownSidType.BuiltinReplicatorSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 552 })
            },

            {
                WellKnownSidType.BuiltinPreWindows2000CompatibleAccessSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 554 })
            },

            {
                WellKnownSidType.BuiltinSystemOperatorsSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 32, 549 })
            },

            {
                WellKnownSidType.ServiceSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 6 })
            },

            {
                WellKnownSidType.LocalSystemSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.NTAuthority, new[] { 18 })
            },

            {
                WellKnownSidType.WorldSid,
                new Tuple<IdentifierAuthority, IReadOnlyList<int>>(IdentifierAuthority.WorldAuthority, new[] { 0 })
            },
        };

        #endregion

        #region Constructors

        //
        // Shared constructor logic
        // NOTE: subauthorities are really unsigned integers, but due to CLS
        //       lack of support for unsigned integers the caller must perform
        //       the typecast
        //

        private void CreateFromParts(IdentifierAuthority identifierAuthority, int[] subAuthorities)
        {
            if (subAuthorities == null)
            {
                throw new ArgumentNullException(nameof(subAuthorities));
            }

            //
            // Check the number of subauthorities passed in 
            //

            if (subAuthorities.Length > MaxSubAuthorities)
            {
                throw new ArgumentOutOfRangeException(
                    "subAuthorities.Length",
                    subAuthorities.Length,
                    $"The number of sub-authorities must not exceed {MaxSubAuthorities}.");
            }

            //
            // Identifier authority is at most 6 bytes long
            //

            if (identifierAuthority < 0 ||
                (long)identifierAuthority > MaxIdentifierAuthority)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(identifierAuthority),
                    identifierAuthority,
                    "The size of the identifier authority must not exceed 6 bytes.");
            }

            //
            // Create a local copy of the data passed in
            //

            _identifierAuthority = identifierAuthority;
            _subAuthorities = new int[subAuthorities.Length];
            subAuthorities.CopyTo(_subAuthorities, 0);

            //
            // Compute and store the binary form
            //
            // typedef struct _SID {
            //     UCHAR Revision;
            //     UCHAR SubAuthorityCount;
            //     SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            //     ULONG SubAuthority[ANYSIZE_ARRAY]
            // } SID, *PISID;
            //

            byte i;
            _binaryForm = new byte[1 + 1 + 6 + 4 * this.SubAuthorityCount];

            //
            // First two bytes contain revision and subauthority count
            //

            _binaryForm[0] = Revision;
            _binaryForm[1] = (byte)this.SubAuthorityCount;

            //
            // Identifier authority takes up 6 bytes
            //

            for (i = 0; i < 6; i++)
            {
                _binaryForm[2 + i] = (byte)((((ulong)_identifierAuthority) >> ((5 - i) * 8)) & 0xFF);
            }

            //
            // Subauthorities go last, preserving big-endian representation
            //

            for (i = 0; i < this.SubAuthorityCount; i++)
            {
                byte shift;
                for (shift = 0; shift < 4; shift += 1)
                {
                    _binaryForm[8 + 4 * i + shift] = unchecked((byte)(((ulong)_subAuthorities[i]) >> (shift * 8)));
                }
            }
        }

        private void CreateFromBinaryForm(byte[] binaryForm, int offset)
        {
            //
            // Give us something to work with
            //

            if (binaryForm == null)
            {
                throw new ArgumentNullException(nameof(binaryForm));
            }

            //
            // Negative offsets are not allowed
            //

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(offset),
                    offset,
                    "Non-negative number required.");
            }

            //
            // At least a minimum-size SID should fit in the buffer
            //

            if (binaryForm.Length - offset < SecurityIdentifier.MinBinaryLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "Destination array is not long enough to copy all the required data. Check array length and offset.");
            }

            IdentifierAuthority Authority;
            int[] SubAuthorities;

            //
            // Extract the elements of a SID
            //

            if (binaryForm[offset] != Revision)
            {
                //
                // Revision is incorrect
                //

                throw new ArgumentException(
                    "SIDs with revision other than '1' are not supported.",
                    nameof(binaryForm));
            }

            //
            // Insist on the correct number of subauthorities
            //

            if (binaryForm[offset + 1] > MaxSubAuthorities)
            {
                throw new ArgumentException(
                    $"The number of sub-authorities must not exceed {MaxSubAuthorities}.",
                    nameof(binaryForm));
            }

            //
            // Make sure the buffer is big enough
            //

            int Length = 1 + 1 + 6 + 4 * binaryForm[offset + 1];

            if (binaryForm.Length - offset < Length)
            {
                throw new ArgumentException(
                    "Destination array is not long enough to copy all the required data. Check array length and offset.",
                    nameof(binaryForm));
            }

            Authority =
                (IdentifierAuthority)(
                (((long)binaryForm[offset + 2]) << 40) +
                (((long)binaryForm[offset + 3]) << 32) +
                (((long)binaryForm[offset + 4]) << 24) +
                (((long)binaryForm[offset + 5]) << 16) +
                (((long)binaryForm[offset + 6]) << 8) +
                (((long)binaryForm[offset + 7])));

            SubAuthorities = new int[binaryForm[offset + 1]];

            //
            // Subauthorities are represented in big-endian format
            //

            for (byte i = 0; i < binaryForm[offset + 1]; i++)
            {
                unchecked
                {
                    SubAuthorities[i] =
                        (int)(
                        (((uint)binaryForm[offset + 8 + 4 * i + 0]) << 0) +
                        (((uint)binaryForm[offset + 8 + 4 * i + 1]) << 8) +
                        (((uint)binaryForm[offset + 8 + 4 * i + 2]) << 16) +
                        (((uint)binaryForm[offset + 8 + 4 * i + 3]) << 24));
                }
            }

            CreateFromParts(Authority, SubAuthorities);

            return;
        }

        private void CreateFromWellKnownSidType(WellKnownSidType sidType, SecurityIdentifier domainSid)
        {
            if (!_wellKnownSidPartsMap.TryGetValue(sidType, out Tuple<IdentifierAuthority, IReadOnlyList<int>> parts))
            {
                throw new NotImplementedException();
            }

            CreateFromParts(parts.Item1, parts.Item2.ToArray());
        }

        //
        // Constructs a SecurityIdentifier object from its string representation
        // Returns 'null' if string passed in is not a valid SID
        // NOTE: although there is a P/Invoke call involved in the implementation of this method,
        //       there is no security risk involved, so no security demand is being made.
        //


        public SecurityIdentifier(string sddlForm)
        {
            //
            // Give us something to work with
            //

            if (sddlForm == null)
            {
                throw new ArgumentNullException(nameof(sddlForm));
            }

            if (_wellKnownSddlConstants.TryGetValue(sddlForm, out WellKnownSidType wellKnownSidType))
            {
                CreateFromWellKnownSidType(wellKnownSidType, null);
                return;
            }

            string[] components = sddlForm.Split('-');

            if (components.Length < 3)
            {
                throw new ArgumentOutOfRangeException(nameof(sddlForm), sddlForm,
                    "Not enough components in SDDL string.");
            }

            if (components[0] != "S")
            {
                throw new ArgumentException($"Invalid SDDL prefix '{components[0]}'.", nameof(sddlForm));
            }

            byte revision = byte.Parse(components[1]);
            if (revision != Revision)
            {
                throw new ArgumentException($"Invalid revision '{revision}'.", nameof(sddlForm));
            }

            IdentifierAuthority authority = (IdentifierAuthority)long.Parse(components[2]);
            if (authority < 0 ||
                (long)authority > MaxIdentifierAuthority)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(sddlForm),
                    sddlForm,
                    "The size of the identifier authority must not exceed 6 bytes.");
            }

            int[] subAuthorities = components.Skip(3).Select(int.Parse).ToArray();
            if (subAuthorities.Length > MaxSubAuthorities)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(sddlForm),
                    sddlForm,
                    $"The number of sub-authorities must not exceed {MaxSubAuthorities}.");
            }

            CreateFromParts(authority, subAuthorities);
        }

        //
        // Constructs a SecurityIdentifier object from its binary representation
        //

        public SecurityIdentifier(byte[] binaryForm, int offset)
        {
            CreateFromBinaryForm(binaryForm, offset);
        }

        //
        // Constructs a well-known SID
        // The 'domainSid' parameter is optional and only used
        // by the well-known types that require it
        // NOTE: although there is a P/Invoke call involved in the implementation of this constructor,
        //       there is no security risk involved, so no security demand is being made.
        //


        public SecurityIdentifier(WellKnownSidType sidType, SecurityIdentifier domainSid)
        {
            //
            // sidType must not be equal to LogonIdsSid
            //

            if (sidType == WellKnownSidType.LogonIdsSid)
            {
                throw new ArgumentException("Well-known SIDs of type LogonIdsSid cannot be created.", nameof(sidType));
            }

            //
            // sidType should not exceed the max defined value
            //

            if ((sidType < WellKnownSidType.NullSid) || (sidType > WellKnownSidType.WinCapabilityRemovableStorageSid))
            {
                throw new ArgumentException("Value was invalid.", nameof(sidType));
            }

            CreateFromWellKnownSidType(sidType, domainSid);
        }

        internal SecurityIdentifier(SecurityIdentifier domainSid, uint rid)
        {
            int i;
            int[] SubAuthorities = new int[domainSid.SubAuthorityCount + 1];

            for (i = 0; i < domainSid.SubAuthorityCount; i++)
            {
                SubAuthorities[i] = domainSid.GetSubAuthority(i);
            }

            SubAuthorities[i] = (int)rid;

            CreateFromParts(domainSid.IdentifierAuthority, SubAuthorities);
        }

        internal SecurityIdentifier(IdentifierAuthority identifierAuthority, int[] subAuthorities)
        {
            CreateFromParts(identifierAuthority, subAuthorities);
        }

        #endregion

        #region Static Properties

        //
        // Revision is always '1'
        //

        internal static byte Revision
        {
            get
            {
                return 1;
            }
        }

        #endregion

        #region Non-static Properties

        //
        // This is for internal consumption only, hence it is marked 'internal'
        // Making this call public would require a deep copy of the data to
        // prevent the caller from messing with the internal representation.
        //

        internal byte[] BinaryForm
        {
            get
            {
                return _binaryForm;
            }
        }

        internal IdentifierAuthority IdentifierAuthority
        {
            get
            {
                return _identifierAuthority;
            }
        }

        internal int SubAuthorityCount
        {
            get
            {
                return _subAuthorities.Length;
            }
        }

        public int BinaryLength
        {
            get
            {
                return _binaryForm.Length;
            }
        }

        #endregion

        #region Inherited properties and methods

        public override bool Equals(object o)
        {
            return (this == o as SecurityIdentifier); // invokes operator==
        }

        public bool Equals(SecurityIdentifier sid)
        {
            return (this == sid); // invokes operator==
        }

        public override int GetHashCode()
        {
            int hashCode = ((long)this.IdentifierAuthority).GetHashCode();
            for (int i = 0; i < SubAuthorityCount; i++)
            {
                hashCode ^= this.GetSubAuthority(i);
            }
            return hashCode;
        }

        public override string ToString()
        {
            if (_sddlForm == null)
            {
                StringBuilder result = new StringBuilder();

                //
                // Typecasting of _IdentifierAuthority to a long below is important, since
                // otherwise you would see this: "S-1-NTAuthority-32-544"
                //

                result.Append("S-1-").Append((long)_identifierAuthority);

                for (int i = 0; i < SubAuthorityCount; i++)
                {
                    result.Append('-').Append((uint)(_subAuthorities[i]));
                }

                _sddlForm = result.ToString();
            }

            return _sddlForm;
        }

        public override string Value
        {
            get
            {
                return ToString().ToUpperInvariant();
            }
        }

        internal static bool IsValidTargetTypeStatic(Type targetType)
        {
            return targetType == typeof(SecurityIdentifier);
        }

        public override bool IsValidTargetType(Type targetType)
        {
            return IsValidTargetTypeStatic(targetType);
        }


        public override IdentityReference Translate(Type targetType)
        {
            if (targetType == null)
            {
                throw new ArgumentNullException(nameof(targetType));
            }

            if (targetType == typeof(SecurityIdentifier))
            {
                return this; // assumes SecurityIdentifier objects are immutable
            }

            throw new ArgumentException("The targetType parameter must be of IdentityReference type.", nameof(targetType));
        }

        #endregion

        #region Operators

        public static bool operator ==(SecurityIdentifier left, SecurityIdentifier right)
        {
            object l = left;
            object r = right;

            if (l == r)
            {
                return true;
            }
            else if (l == null || r == null)
            {
                return false;
            }
            else
            {
                return (left.CompareTo(right) == 0);
            }
        }

        public static bool operator !=(SecurityIdentifier left, SecurityIdentifier right)
        {
            return !(left == right);
        }

        #endregion

        #region IComparable implementation

        public int CompareTo(SecurityIdentifier sid)
        {
            if (sid == null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            if (this.IdentifierAuthority < sid.IdentifierAuthority)
            {
                return -1;
            }

            if (this.IdentifierAuthority > sid.IdentifierAuthority)
            {
                return 1;
            }

            if (this.SubAuthorityCount < sid.SubAuthorityCount)
            {
                return -1;
            }

            if (this.SubAuthorityCount > sid.SubAuthorityCount)
            {
                return 1;
            }

            for (int i = 0; i < this.SubAuthorityCount; i++)
            {
                int diff = this.GetSubAuthority(i) - sid.GetSubAuthority(i);

                if (diff != 0)
                {
                    return diff;
                }
            }

            return 0;
        }

        #endregion

        #region Public Methods

        internal int GetSubAuthority(int index)
        {
            return _subAuthorities[index];
        }

        public void GetBinaryForm(byte[] binaryForm, int offset)
        {
            _binaryForm.CopyTo(binaryForm, offset);
        }

        #endregion
    }
}
