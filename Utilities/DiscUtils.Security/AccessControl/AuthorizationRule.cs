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
                    "Argument cannot be zero.",
                    nameof(accessMask));
            }

            if (inheritanceFlags < InheritanceFlags.None || inheritanceFlags > (InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(inheritanceFlags),
                    $"The value '{inheritanceFlags}' is not valid for this usage of the type {InheritanceFlags}.");
            }

            if (propagationFlags < PropagationFlags.None || propagationFlags > (PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(propagationFlags),
                    $"The value '{propagationFlags}' is not valid for this usage of the type {PropagationFlags}.");
            }

            if (identity.IsValidTargetType(typeof(SecurityIdentifier)) == false)
            {
                throw new ArgumentException(
                    "Type must be an IdentityReference, such as NTAccount or SecurityIdentifier.",
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
