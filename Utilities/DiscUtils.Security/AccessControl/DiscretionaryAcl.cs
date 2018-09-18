using System;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public sealed class DiscretionaryAcl : CommonAcl
    {
        #region
        private static SecurityIdentifier _sidEveryone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        private bool everyOneFullAccessForNullDacl = false;
        #endregion

        #region Constructors

        //
        // Creates an emtpy ACL
        //

        public DiscretionaryAcl(bool isContainer, bool isDS, int capacity)
            : this(isContainer, isDS, isDS ? AclRevisionDS : AclRevision, capacity)
        {
        }

        public DiscretionaryAcl(bool isContainer, bool isDS, byte revision, int capacity)
            : base(isContainer, isDS, revision, capacity)
        {
        }

        //
        // Creates an ACL from a given raw ACL
        // after canonicalizing it
        //

        public DiscretionaryAcl(bool isContainer, bool isDS, RawAcl rawAcl)
            : this(isContainer, isDS, rawAcl, false)
        {
        }

        //
        // Internal version - if 'trusted' is true,
        // takes ownership of the given raw ACL
        //

        internal DiscretionaryAcl(bool isContainer, bool isDS, RawAcl rawAcl, bool trusted)
            : base(isContainer, isDS, rawAcl == null ? new RawAcl(isDS ? AclRevisionDS : AclRevision, 0) : rawAcl, trusted, true)
        {
        }

        #endregion

        #region Public Methods

        public void AddAccess(AccessControlType accessType, SecurityIdentifier sid, int accessMask, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags)
        {
            CheckAccessType(accessType);
            CheckFlags(inheritanceFlags, propagationFlags);
            everyOneFullAccessForNullDacl = false;
            AddQualifiedAce(sid, accessType == AccessControlType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, accessMask, GenericAce.AceFlagsFromInheritanceFlags(inheritanceFlags, propagationFlags), ObjectAceFlags.None, Guid.Empty, Guid.Empty);
        }

        public void SetAccess(AccessControlType accessType, SecurityIdentifier sid, int accessMask, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags)
        {
            CheckAccessType(accessType);
            CheckFlags(inheritanceFlags, propagationFlags);
            everyOneFullAccessForNullDacl = false;
            SetQualifiedAce(sid, accessType == AccessControlType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, accessMask, GenericAce.AceFlagsFromInheritanceFlags(inheritanceFlags, propagationFlags), ObjectAceFlags.None, Guid.Empty, Guid.Empty);
        }

        public bool RemoveAccess(AccessControlType accessType, SecurityIdentifier sid, int accessMask, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags)
        {
            CheckAccessType(accessType);
            everyOneFullAccessForNullDacl = false;
            return RemoveQualifiedAces(sid, accessType == AccessControlType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, accessMask, GenericAce.AceFlagsFromInheritanceFlags(inheritanceFlags, propagationFlags), false, ObjectAceFlags.None, Guid.Empty, Guid.Empty);
        }

        public void RemoveAccessSpecific(AccessControlType accessType, SecurityIdentifier sid, int accessMask, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags)
        {
            CheckAccessType(accessType);
            everyOneFullAccessForNullDacl = false;
            RemoveQualifiedAcesSpecific(sid, accessType == AccessControlType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, accessMask, GenericAce.AceFlagsFromInheritanceFlags(inheritanceFlags, propagationFlags), ObjectAceFlags.None, Guid.Empty, Guid.Empty);
        }

        public void AddAccess(AccessControlType accessType, SecurityIdentifier sid, ObjectAccessRule rule)
        {
            AddAccess(accessType, sid, rule.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, rule.ObjectFlags, rule.ObjectType, rule.InheritedObjectType);
        }

        public void AddAccess(AccessControlType accessType, SecurityIdentifier sid, int accessMask, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, ObjectAceFlags objectFlags, Guid objectType, Guid inheritedObjectType)
        {
            //
            // This is valid only for DS Acls 
            //
            if (!IsDS)
            {
                throw new InvalidOperationException(
                    "Adding ACEs with Object Flags and Object GUIDs is only valid for directory-object ACLs.");
            }

            CheckAccessType(accessType);
            CheckFlags(inheritanceFlags, propagationFlags);
            everyOneFullAccessForNullDacl = false;
            AddQualifiedAce(sid, accessType == AccessControlType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, accessMask, GenericAce.AceFlagsFromInheritanceFlags(inheritanceFlags, propagationFlags), objectFlags, objectType, inheritedObjectType);
        }

        public void SetAccess(AccessControlType accessType, SecurityIdentifier sid, ObjectAccessRule rule)
        {
            SetAccess(accessType, sid, rule.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, rule.ObjectFlags, rule.ObjectType, rule.InheritedObjectType);
        }

        public void SetAccess(AccessControlType accessType, SecurityIdentifier sid, int accessMask, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, ObjectAceFlags objectFlags, Guid objectType, Guid inheritedObjectType)
        {
            //
            // This is valid only for DS Acls 
            //
            if (!IsDS)
            {
                throw new InvalidOperationException(
                    "Adding ACEs with Object Flags and Object GUIDs is only valid for directory-object ACLs.");
            }

            CheckAccessType(accessType);
            CheckFlags(inheritanceFlags, propagationFlags);
            everyOneFullAccessForNullDacl = false;
            SetQualifiedAce(sid, accessType == AccessControlType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, accessMask, GenericAce.AceFlagsFromInheritanceFlags(inheritanceFlags, propagationFlags), objectFlags, objectType, inheritedObjectType);
        }

        public bool RemoveAccess(AccessControlType accessType, SecurityIdentifier sid, ObjectAccessRule rule)
        {
            return RemoveAccess(accessType, sid, rule.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, rule.ObjectFlags, rule.ObjectType, rule.InheritedObjectType);
        }

        public bool RemoveAccess(AccessControlType accessType, SecurityIdentifier sid, int accessMask, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, ObjectAceFlags objectFlags, Guid objectType, Guid inheritedObjectType)
        {
            //
            // This is valid only for DS Acls 
            //
            if (!IsDS)
            {
                throw new InvalidOperationException(
                    "Adding ACEs with Object Flags and Object GUIDs is only valid for directory-object ACLs.");
            }

            CheckAccessType(accessType);
            everyOneFullAccessForNullDacl = false;
            return RemoveQualifiedAces(sid, accessType == AccessControlType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, accessMask, GenericAce.AceFlagsFromInheritanceFlags(inheritanceFlags, propagationFlags), false, objectFlags, objectType, inheritedObjectType);
        }

        public void RemoveAccessSpecific(AccessControlType accessType, SecurityIdentifier sid, ObjectAccessRule rule)
        {
            RemoveAccessSpecific(accessType, sid, rule.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, rule.ObjectFlags, rule.ObjectType, rule.InheritedObjectType);
        }

        public void RemoveAccessSpecific(AccessControlType accessType, SecurityIdentifier sid, int accessMask, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, ObjectAceFlags objectFlags, Guid objectType, Guid inheritedObjectType)
        {
            //
            // This is valid only for DS Acls 
            //
            if (!IsDS)
            {
                throw new InvalidOperationException(
                    "Adding ACEs with Object Flags and Object GUIDs is only valid for directory-object ACLs.");
            }

            CheckAccessType(accessType);
            everyOneFullAccessForNullDacl = false;
            RemoveQualifiedAcesSpecific(sid, accessType == AccessControlType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, accessMask, GenericAce.AceFlagsFromInheritanceFlags(inheritanceFlags, propagationFlags), objectFlags, objectType, inheritedObjectType);
        }

        #endregion

        #region internals and privates

        //
        // DACL's "allow everyone full access may be created to replace a null DACL because managed 
        // access control does not want to leave null DACLs around. But we need to remember this MACL
        // created ACE when the DACL is modified, we can remove it to match the same native semantics of
        // a null DACL.
        //         
        internal bool EveryOneFullAccessForNullDacl
        {
            get { return everyOneFullAccessForNullDacl; }
            set { everyOneFullAccessForNullDacl = value; }
        }

        //
        // As soon as you tried successfully to modified the ACL, the internally created allow every one full access ACL is materialized
        // because in native world, a NULL dacl can't be operated on.
        //
        internal override void OnAclModificationTried()
        {
            everyOneFullAccessForNullDacl = false;
        }

        /// <summary>
        /// This static method will create an "allow everyone full control" single ACE DACL.
        /// </summary>
        /// <param name="isDS">whether it is a DS DACL</param>
        /// <param name="isContainer">whether it is a container</param>
        /// <returns>The single ACE DACL</returns>
        /// Note: This method is created to get the best behavior for using "allow everyone full access"
        /// single ACE DACL to replace null DACL from CommonSecurityObject. 
        internal static DiscretionaryAcl CreateAllowEveryoneFullAccess(bool isDS, bool isContainer)
        {
            DiscretionaryAcl dcl = new DiscretionaryAcl(isContainer, isDS, 1);
            dcl.AddAccess(
                AccessControlType.Allow,
                _sidEveryone,
                -1,
                isContainer ? (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) : InheritanceFlags.None,
                PropagationFlags.None);

            dcl.everyOneFullAccessForNullDacl = true;
            return dcl;
        }
        #endregion
    }
}
