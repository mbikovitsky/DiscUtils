using System;

namespace DiscUtils.Security.AccessControl
{
    /// <summary>
    /// Predefined ACE types.
    /// Anything else is considered user-defined.
    /// </summary>
    public enum AceType : byte
    {
        AccessAllowed = 0x00,
        AccessDenied = 0x01,
        SystemAudit = 0x02,
        SystemAlarm = 0x03,
        AccessAllowedCompound = 0x04,
        AccessAllowedObject = 0x05,
        AccessDeniedObject = 0x06,
        SystemAuditObject = 0x07,
        SystemAlarmObject = 0x08,
        AccessAllowedCallback = 0x09,
        AccessDeniedCallback = 0x0A,
        AccessAllowedCallbackObject = 0x0B,
        AccessDeniedCallbackObject = 0x0C,
        SystemAuditCallback = 0x0D,
        SystemAlarmCallback = 0x0E,
        SystemAuditCallbackObject = 0x0F,
        SystemAlarmCallbackObject = 0x10,
        MaxDefinedAceType = SystemAlarmCallbackObject,
    }

    /// <summary>
    /// Predefined ACE flags.
    /// The inheritance and auditing flags are stored in the
    /// same field - this is to follow Windows ACE design.
    /// </summary>
    [Flags]
    public enum AceFlags : byte
    {
        None = 0x00,
        ObjectInherit = 0x01,
        ContainerInherit = 0x02,
        NoPropagateInherit = 0x04,
        InheritOnly = 0x08,
        Inherited = 0x10,
        SuccessfulAccess = 0x40,
        FailedAccess = 0x80,

        InheritanceFlags = ObjectInherit | ContainerInherit | NoPropagateInherit | InheritOnly,
        AuditFlags = SuccessfulAccess | FailedAccess,
    }

    [Flags]
    public enum AuditFlags
    {
        None = 0x00,
        Success = 0x01,
        Failure = 0x02,
    }

    [Flags]
    public enum InheritanceFlags
    {
        None = 0x00,
        ContainerInherit = 0x01,
        ObjectInherit = 0x02,
    }

    [Flags]
    public enum PropagationFlags
    {
        None = 0x00,
        NoPropagateInherit = 0x01,
        InheritOnly = 0x02,
    }

    //
    // Qualified ACEs are always one of:
    //     - AccessAllowed
    //     - AccessDenied
    //     - SystemAudit
    //     - SystemAlarm
    // and may optionally support callback data
    //


    public enum AceQualifier
    {
        AccessAllowed = 0x0,
        AccessDenied = 0x1,
        SystemAudit = 0x2,
        SystemAlarm = 0x3,
    }

    [Flags]
    public enum ObjectAceFlags
    {
        None = 0x00,
        ObjectAceTypePresent = 0x01,
        InheritedObjectAceTypePresent = 0x02,
    }

    public enum CompoundAceType
    {
        Impersonation = 0x01,
    }

    public enum AccessControlType
    {
        Allow = 0,
        Deny = 1,
    }

    [Flags]
    public enum ControlFlags
    {
        None = 0x0000,
        OwnerDefaulted = 0x0001, // set by RM only
        GroupDefaulted = 0x0002, // set by RM only
        DiscretionaryAclPresent = 0x0004, // set by RM or user, 'off' means DACL is null
        DiscretionaryAclDefaulted = 0x0008, // set by RM only
        SystemAclPresent = 0x0010, // same as DiscretionaryAclPresent
        SystemAclDefaulted = 0x0020, // sams as DiscretionaryAclDefaulted
        DiscretionaryAclUntrusted = 0x0040, // ignore this one
        ServerSecurity = 0x0080, // ignore this one
        DiscretionaryAclAutoInheritRequired = 0x0100, // ignore this one
        SystemAclAutoInheritRequired = 0x0200, // ignore this one
        DiscretionaryAclAutoInherited = 0x0400, // set by RM only
        SystemAclAutoInherited = 0x0800, // set by RM only
        DiscretionaryAclProtected = 0x1000, // when set, RM will stop inheriting
        SystemAclProtected = 0x2000, // when set, RM will stop inheriting
        RMControlValid = 0x4000, // the reserved 8 bits have some meaning
        SelfRelative = 0x8000, // must always be on
    }

    [Flags]
    public enum AccessControlSections
    {
        None = 0,
        Audit = 0x1,
        Access = 0x2,
        Owner = 0x4,
        Group = 0x8,
        All = 0xF
    }

    [Flags]
    public enum SecurityInfos
    {
        Owner = 0x00000001,
        Group = 0x00000002,
        DiscretionaryAcl = 0x00000004,
        SystemAcl = 0x00000008,
    }
}
