using System;

namespace DiscUtils.Security.AccessControl
{
    //
    // Predefined ACE types
    // Anything else is considered user-defined
    //


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

    //
    // Predefined ACE flags
    // The inheritance and auditing flags are stored in the
    // same field - this is to follow Windows ACE design
    //

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
}
