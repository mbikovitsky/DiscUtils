using System;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public abstract class ObjectAccessRule : AccessRule
    {
        #region Private Members

        private readonly Guid _objectType;
        private readonly Guid _inheritedObjectType;
        private readonly ObjectAceFlags _objectFlags = ObjectAceFlags.None;

        #endregion

        #region Constructors

        protected ObjectAccessRule(IdentityReference identity, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, Guid objectType, Guid inheritedObjectType, AccessControlType type)
            : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, type)
        {
            if ((!objectType.Equals(Guid.Empty)) && ((accessMask & ObjectAce.AccessMaskWithObjectType) != 0))
            {
                _objectType = objectType;
                _objectFlags |= ObjectAceFlags.ObjectAceTypePresent;
            }
            else
            {
                _objectType = Guid.Empty;
            }

            if ((!inheritedObjectType.Equals(Guid.Empty)) && ((inheritanceFlags & InheritanceFlags.ContainerInherit) != 0))
            {
                _inheritedObjectType = inheritedObjectType;
                _objectFlags |= ObjectAceFlags.InheritedObjectAceTypePresent;
            }
            else
            {
                _inheritedObjectType = Guid.Empty;
            }
        }

        #endregion

        #region Properties

        public Guid ObjectType
        {
            get { return _objectType; }
        }

        public Guid InheritedObjectType
        {
            get { return _inheritedObjectType; }
        }

        public ObjectAceFlags ObjectFlags
        {
            get { return _objectFlags; }
        }

        #endregion
    }
}
