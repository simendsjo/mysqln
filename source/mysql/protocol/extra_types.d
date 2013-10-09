/++
This module includes types related to the MySQL protocol, or helper types to
mitigate mismatch between MySQL and D types.

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.protocol.extra_types;

import std.variant;
import std.exception;

import mysql.common;

/++
Length Coded Integer Value

Also called Length Coded Binary

See_Also: http://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
+/
struct LCI
{
    /// True if the LCI contains a null value
    bool isNull;

    /++
    True if the packet that created this LCI didn't have enough bytes to
    store a value of the size specified. More bytes have to be fetched from
    the server
    +/
    bool isIncomplete;

    /++
    Number of bytes needed to store the value (Extracted from the LCI
    header. The header byte is not included)
    +/
    ubyte numBytes;

    /// Number of bytes total used for this LCI
    @property ubyte totalBytes() pure const nothrow
    {
        return cast(ubyte)(numBytes <= 1 ? 1 : numBytes+1);
    }

    /// The decoded value. This is always 0 if isNull or isIncomplete is set.
    ulong value;

    pure const nothrow invariant()
    {
        if(isIncomplete)
        {
            assert(!isNull);
            assert(value == 0);
            assert(numBytes > 0);
        }
        else if(isNull)
        {
            assert(!isIncomplete);
            assert(value == 0);
            assert(numBytes == 0);
        }
        else
        {
            assert(!isNull);
            assert(!isIncomplete);
            assert(numBytes > 0);
        }
    }
}

/++
Represents a value from MySQL
+/
struct SQLValue
{
    /// True if this is a null value
    bool isNull;

    /// True if not enough data is available to conclude the type
    bool isIncomplete;

    /// The value
    Variant _value;

    /// Returns the value
    @property inout(Variant) value()() inout
    {
        enforceEx!MYX(!isIncomplete, "SQL value not complete");
        return _value;
    }

    /// Set the value
    @property void value(T)(T value)
    {
        enforceEx!MYX(!isNull, "Cannot set SQL Value - it has been marked as null");
        enforceEx!MYX(!isIncomplete, "SQL value not complete");
        _value = value;
    }

    pure const nothrow invariant()
    {
        isNull && assert(!isIncomplete);
        isNull && assert(!_value.hasValue);
        isIncomplete && assert(!isNull);
    }
}

/++
TIMESTAMP

Timestamps are normally not dealt with directly as MySQL default them to update
to the current time whenever something happens on the table.

The format is YYYYMMDDHHMMSS
+/
struct Timestamp
{
    ulong rep;
}

/++
Time difference.
+/
struct TimeDiff
{
    bool negative;
    int days;
    ubyte hours, minutes, seconds;
}


/++
Length Coded String.

See_Also: LCI
+/
struct LCS
{
    // dummy struct just to tell what value we are using
    // we don't need to store anything here as the result is always a string
}
