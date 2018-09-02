using System;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public abstract class AuthorizationRule
    {
        #region Private Members

        private readonly IdentityReference _identity;
        private readonly int _accessMask;
        private readonly bool _isInherited;
        private readonly InheritanceFlags _inheritanceFlags;
        private readonly PropagationFlags _propagationFlags;

        #endregion

        #region Constructors

        protected internal AuthorizationRule(
            IdentityReference identity,
            int accessMask,
            bool isInherited,
            InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (accessMask == 0)
            {
                throw new ArgumentException(
                    SR.Argument_ArgumentZero,
nameof(accessMask));
            }

            if (inheritanceFlags < InheritanceFlags.None || inheritanceFlags > (InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit))
            {
                throw new ArgumentOutOfRangeException(
nameof(inheritanceFlags),
                    SR.Format(SR.Argument_InvalidEnumValue, inheritanceFlags, "InheritanceFlags"));
            }

            if (propagationFlags < PropagationFlags.None || propagationFlags > (PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly))
            {
                throw new ArgumentOutOfRangeException(
nameof(propagationFlags),
                    SR.Format(SR.Argument_InvalidEnumValue, inheritanceFlags, "PropagationFlags"));
            }

            if (identity.IsValidTargetType(typeof(SecurityIdentifier)) == false)
            {
                throw new ArgumentException(
                    SR.Arg_MustBeIdentityReferenceType,
nameof(identity));
            }

            _identity = identity;
            _accessMask = accessMask;
            _isInherited = isInherited;
            _inheritanceFlags = inheritanceFlags;

            if (inheritanceFlags != 0)
            {
                _propagationFlags = propagationFlags;
            }
            else
            {
                _propagationFlags = 0;
            }
        }

        #endregion

        #region Properties

        public IdentityReference IdentityReference
        {
            get { return _identity; }
        }

        protected internal int AccessMask
        {
            get { return _accessMask; }
        }

        public bool IsInherited
        {
            get { return _isInherited; }
        }

        public InheritanceFlags InheritanceFlags
        {
            get { return _inheritanceFlags; }
        }

        public PropagationFlags PropagationFlags
        {
            get { return _propagationFlags; }
        }

        #endregion
    }
}
