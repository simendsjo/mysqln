/++
Utilities for working with the MySQL Binary interface.

This includes:
$(UL
    $(LI convertion routines between MySQL values (Text and Binary))
    $(LI Helpers for dealing with byte arrays)
)

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/binary-protocol-value.html, Binary Protocol Value)

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.protocol.packet_helpers;

import std.variant;
import std.datetime;
import std.exception;
import std.conv;
import std.string;
import std.array;
import std.traits;

import mysql.common;
import mysql.protocol.constants;
import mysql.protocol.extra_types;

/// enum of the SQLSign of T
template sqlSignOf(T)
{
    static if(is(T == bool) || is(T == Date) || is(T == TimeOfDay) ||
              is(T == DateTime) || is(T == Timestamp) || isArray!T)
    {
        enum sqlSignOf = SQLSign.SIGNED;
    }
    else static if(isNumeric!T)
    {
        enum sqlSignOf = isUnsigned!T ? SQLSign.UNSIGNED : SQLSign.SIGNED;
    }
    else
        static assert(0, "Cannot figure out sign");
}

/// enum of the SQLType of T
template sqlTypeOf(T)
{
    static if(is(T == bool) || is(T == ubyte) || is(T == byte))
        enum sqlTypeOf = SQLType.TINY;
    else static if(is(T == short) || is(T == ushort))
        enum sqlTypeOf = SQLType.SHORT;
    else static if(is(T == int) || is(T == uint))
        enum sqlTypeOf = SQLType.INT;
    else static if(is(T == long) || is(T == ulong))
        enum sqlTypeOf = SQLType.LONGLONG;
    else static if(is(T == float))
        enum sqlTypeOf = SQLType.FLOAT;
    else static if(is(T == double))
        enum sqlTypeOf = SQLType.DOUBLE;
    else static if(is(T == Date))
        enum sqlTypeOf = SQLType.DATE;
    else static if(is(T == TimeOfDay))
        enum sqlTypeOf = SQLType.TIME;
    else static if(is(T == DateTime))
        enum sqlTypeOf = SQLType.DATETIME;
    else static if(is(T == Timestamp))
        enum sqlTypeOf = SQLType.TIMESTAMP;
    else static if(is(T == string)) // TODO: handle other string types
        enum sqlTypeOf = SQLType.VARCHAR;
    else static if(is(T == byte[]) || is(T == ubyte[]))
        enum sqlTypeOf = SQLType.TINYBLOB;
    else static if(is(T == typeof(null)))
        static assert(0, "Null is not a supported type");
    else
        static assert(0, "Unsupported D type");
}

/// Returns true if packet has enough bytes to store a value of T
@property bool hasEnoughBytes(T, ubyte N=T.sizeof)(in ubyte[] packet) pure nothrow
in
{
    static assert(T.sizeof >= N, T.stringof~" not large enough to store "~to!string(N)~" bytes");
}
body
{
    return packet.length >= N;
}

/++
Skips over n items, advances the array, and return the newly advanced array
to allow method chaining
+/
T[] skip(T)(ref T[] array, size_t n) pure nothrow
in
{
    assert(n <= array.length);
}
body
{
    array = array[n..$];
    return array;
}

/// Convert a Timestamp to DateTime
DateTime toDateTime(Timestamp value) pure
{
    auto x = value.rep;
    int second = cast(int) (x%100);
    x /= 100;
    int minute = cast(int) (x%100);
    x /= 100;
    int hour   = cast(int) (x%100);
    x /= 100;
    int day    = cast(int) (x%100);
    x /= 100;
    int month  = cast(int) (x%100);
    x /= 100;
    int year   = cast(int) (x%10000);

    return DateTime(year, month, day, hour, minute, second);
}


/++
Decodes MySQL value into a D value.

If the parameter is of type ubyte[], it is expected to be in MySQL Binary
Protocol value format.

If it's string, it's expected to be in MySQL Text Protocol value format.

If no template specialization is found for the Text protocol, std.conv.to is
used.

Params:
    value = MySQL value

Returns: A populated or default initialized D value
+/
T decode(T : TimeDiff)(in ubyte[] value) pure
{
    mypenforce(value.length, "Supplied byte array is zero length");
    TimeDiff td;
    uint l = value[0];
    mypenforce(l == 0 || l == 5 || l == 8 || l == 12, "Bad Time length in binary row.");
    if (l >= 5)
    {
        td.negative = (value[1]  != 0);
        td.days     = (value[5] << 24) + (value[4] << 16) + (value[3] << 8) + value[2];
    }
    if (l >= 8)
    {
        td.hours    = value[6];
        td.minutes  = value[7];
        td.seconds  = value[8];
    }
    // Note that the fractional seconds part is not stored by MySQL
    return td;
}

/// ditto
T decode(T : TimeDiff)(string value) pure
{
    TimeDiff td;
    int t = parse!int(value);
    if (t < 0)
    {
        td.negative = true;
        t = -t;
    }
    td.hours    = t%24;
    td.days     = t/24;
    munch(s, ":");
    td.minutes  = parse!ubyte(s);
    munch(s, ":");
    td.seconds  = parse!ubyte(s);
    return td;
}

/// ditto
T decode(T : Date)(in ubyte[] value) pure
{
    mypenforce(value.length, "Supplied byte array is zero length");
    if (value[0] == 0)
        return Date(0,0,0);

    mypenforce(value[0] >= 4, "Binary date representation is too short");
    int year    = (value[2]  << 8) + value[1];
    int month   = cast(int) value[3];
    int day     = cast(int) value[4];
    return Date(year, month, day);
}

/// ditto
T decode(T : Date)(string value)
{
    int year = parse!(ushort)(value);
    munch(value, "-");
    int month = parse!(ubyte)(value);
    munch(value, "-");
    int day = parse!(ubyte)(value);
    return Date(year, month, day);
}


/// ditto
T decode(T : TimeOfDay)(string value)
{
    TimeOfDay tod;
    tod.hour = parse!int(value);
    mypenforce(tod.hour <= 24 && tod.hour >= 0,
            "Time column value is in time difference form");
    munch(value, ":");
    tod.minute = parse!ubyte(value);
    munch(value, ":");
    tod.second = parse!ubyte(value);
    return tod;
}

/// ditto
T decode(T : TimeOfDay)(in ubyte[] value) pure
{
    mypenforce(value.length, "Supplied byte array is zero length");
    uint l = value[0];
    mypenforce(l == 0 || l == 5 || l == 8 || l == 12, "Bad Time length in binary row.");
    mypenforce(l >= 8, "Time column value is not in a time-of-day format");

    TimeOfDay tod;
    tod.hour    = value[6];
    tod.minute  = value[7];
    tod.second  = value[8];
    return tod;
}

/// ditto
T decode(T : DateTime)(in ubyte[] value) pure
{
    mypenforce(a.length, "Supplied byte array is zero length");
    if (value[0] == 0)
        return DateTime();

    mypenforce(value[0] >= 4, "Supplied ubyte[] is not long enough");
    int year    = (value[2] << 8) + value[1];
    int month   =  value[3];
    int day     =  value[4];
    DateTime dt;
    if (value[0] == 4)
    {
        dt = DateTime(year, month, day);
    }
    else
    {
        mypenforce(value[0] >= 7, "Supplied ubyte[] is not long enough");
        int hour    = value[5];
        int minute  = value[6];
        int second  = value[7];
        dt = DateTime(year, month, day, hour, minute, second);
    }
    return dt;
}

/// ditto
T decode(T : DateTime)(string value)
{
    int year = parse!(ushort)(value);
    munch(value, "-");
    int month = parse!(ubyte)(value);
    munch(value, "-");
    int day = parse!(ubyte)(value);
    munch(value, " ");
    int hour = parse!(ubyte)(value);
    munch(value, ":");
    int minute = parse!(ubyte)(value);
    munch(value, ":");
    int second = parse!(ubyte)(value);
    return DateTime(year, month, day, hour, minute, second);
}

/// ditto
T decode(T:ulong)(in ubyte[] value, size_t n) pure nothrow
{
    switch(n)
    {
        case 8: return value.decode!(T, 8)();
        case 4: return value.decode!(T, 4)();
        case 3: return value.decode!(T, 3)();
        case 2: return value.decode!(T, 2)();
        case 1: return value.decode!(T, 1)();
        default: assert(0);
    }
}

/// ditto
T decode(T, ubyte N=T.sizeof)(in ubyte[] value) pure nothrow
if(isIntegral!T)
in
{
    static assert(N == 1 || N == 2 || N == 3 || N == 4 || N == 8, "Cannot decode integral value. Invalid size: "~N.stringof);
    static assert(T.sizeof >= N, T.stringof~" not large enough to store "~to!string(N)~" bytes");
    assert(value.hasEnoughBytes!(T,N), "packet not long enough to contain all bytes needed for "~T.stringof);
}
body
{
    T decoded = 0;
    static if(N == 8) // 64 bit
    {
        decoded |= cast(T)(value[7]) << (8*7);
        decoded |= cast(T)(value[6]) << (8*6);
        decoded |= cast(T)(value[5]) << (8*5);
        decoded |= cast(T)(value[4]) << (8*4);
    }
    static if(N >= 4) // 32 bit
    {
        decoded |= cast(T)(value[3]) << (8*3);
    }
    static if(N >= 3) // 24 bit
    {
        decoded |= cast(T)(value[2]) << (8*2);
    }
    static if(N >= 2) // 16 bit
    {
        decoded |= cast(T)(value[1]) << (8*1);
    }
    static if(N >= 1) // 8 bit
    {
        decoded |= cast(T)(value[0]) << (8*0);
    }
    return decoded;
}

/// ditto
T decode(T, ubyte N=T.sizeof)(in ubyte[] value) pure nothrow
if(isFloatingPoint!T)
in
{
    static assert((is(T == float) && N == float.sizeof)
            || is(T == double) && N == double.sizeof);
}
body
{
    T result = 0;
    (cast(ubyte*)&result)[0..T.sizeof] = value[0..T.sizeof];
    return result;
}

/// ditto
T decode(T:LCI)(in ubyte[] value) pure nothrow
in
{
    assert(value.length >= 1, "packet has to include at least the LCI length byte");
}
body
{
    auto lci = value.decodeLCIHeader();
    if(lci.isNull || lci.isIncomplete)
        return lci;
    assert(value.length >= lci.totalBytes);
    lci.value = value.decode!ulong(lci.numBytes);
    return lci;
}

/// ditto
T decode(T)(in string value)
{
    return value.to!T();
}

/++
Convert D value to a MySQL Binary Protocol encoded value

Params: value = D value

Returns: MySQL Binary Protocol encoded equivalent of value
+/
ubyte[] encode(in bool value) pure nothrow
{
    return [value ? 0x01 : 0x00];
}

/// ditto
ubyte[] encode(in TimeOfDay value) pure nothrow
{
    ubyte[] rv;
    if (value == TimeOfDay.init)
    {
        rv.length = 1;
        rv[0] = 0;
    }
    else
    {
        rv.length = 9;
        rv[0] = 8;
        rv[6] = value.hour;
        rv[7] = value.minute;
        rv[8] = value.second;
    }
    return rv;
}

/// ditto
ubyte[] encode(in Date value) pure nothrow
{
    ubyte[] rv;
    if (value.year < 0)
    {
        rv.length = 1;
        rv[0] = 0;
    }
    else
    {
        rv.length = 5;
        rv[0] = 4;
        rv[1] = cast(ubyte) ( value.year       & 0xff);
        rv[2] = cast(ubyte) ((value.year >> 8) & 0xff);
        rv[3] = cast(ubyte)   value.month;
        rv[4] = cast(ubyte)   value.day;
    }
    return rv;
}

/// ditto
ubyte[] encode(in DateTime value) pure nothrow
{
    uint len = 1;
    if (value.year || value.month || value.day) len = 5;
    if (value.hour || value.minute|| value.second) len = 8;
    ubyte[] rv;
    rv.length = len;
    rv[0] =  cast(ubyte)(rv.length - 1); // num bytes
    if(len >= 5)
    {
        rv[1] = cast(ubyte) ( value.year       & 0xff);
        rv[2] = cast(ubyte) ((value.year >> 8) & 0xff);
        rv[3] = cast(ubyte)   value.month;
        rv[4] = cast(ubyte)   value.day;
    }
    if(len == 8)
    {
        rv[5] = cast(ubyte) value.hour;
        rv[6] = cast(ubyte) value.minute;
        rv[7] = cast(ubyte) value.second;
    }
    return rv;
}

/++
Encodes a D type, and stores the result in dest

See_Also: encode
+/
void encodeInto(T)(in T[] source, ubyte[] dest) pure nothrow
in
{
    assert(dest.length >= source.length);
}
body
{
    dest[0..source.length] = source[];
}
unittest
{
    ubyte[] src = [0, 1, 1, 0];
    ubyte[] dst = [0, 0, 0, 0];
    src.encodeInto(dst[0..$]);
    assert(dst == [0, 1, 1, 0]);
}

/// ditto
void encodeInto(T)(in T source, ubyte[] dest) pure nothrow
if(isFloatingPoint!T)
{
    static if(T.sizeof == 4)
        encodeInto(*cast(int*)&source, dest);
    else static if(T.sizeof == 8)
        encodeInto(*cast(long*)&source, dest);
    else
        static assert(0, T.stringof~" not supported");
}

/// ditto
void encodeInto(T, bool IsInt24 = false)(in T source, ubyte[] array) pure nothrow
if(isIntegral!T)
in
{
    static if(IsInt24)
        assert(array.length >= 3);
    else
        assert(array.length >= T.sizeof, "Not enough space to unpack "~T.stringof);
}
body
{
    static if(T.sizeof >= 1)
    {
        array[0] = cast(ubyte) (source >> 8*0) & 0xff;
    }
    static if(T.sizeof >= 2)
    {
        array[1] = cast(ubyte) (source >> 8*1) & 0xff;
    }
    static if(!IsInt24)
    {
        static if(T.sizeof >= 4)
        {
            array[2] = cast(ubyte) (source >> 8*2) & 0xff;
            array[3] = cast(ubyte) (source >> 8*3) & 0xff;
        }
        static if(T.sizeof >= 8)
        {
            array[4] = cast(ubyte) (source >> 8*4) & 0xff;
            array[5] = cast(ubyte) (source >> 8*5) & 0xff;
            array[6] = cast(ubyte) (source >> 8*6) & 0xff;
            array[7] = cast(ubyte) (source >> 8*7) & 0xff;
        }
    }
    else
    {
        array[2] = cast(ubyte) (source >> 8*2) & 0xff;
    }
}

/++
Encodes T into a MySQL Binary Protocol value, stores it into dest, and then
skippes over the added bytes in dest.

NOTE:
    If source already is an array, it is assumed to already be in MySQL Binary
    Protocol format, and will just be copied over.

See_Also: encode, encodeInto and skip

Params:
    source  = D value to convert
    IsInt24 = true if source should be converted to a MySQL 24-bit int
    dest    = destination for the converted value
+/
void encodeIntoAndSkip(T)(in T[] source, ref ubyte[] dest) pure nothrow
{
    source.encodeInto(dest);
    dest.skip(source.length);
}

/// ditto
void encodeIntoAndSkip(T, bool IsInt24 = false)(in T source, ref ubyte[] dest) pure nothrow
{
    source.encodeInto(dest);
    dest.skip(source.sizeof);
}

/// DOCUMENT ME!!!!
ubyte[] encodeLength(size_t l, out size_t offset) pure nothrow
out(result)
{
    assert(result.length >= 1);
}
body
{
    ubyte[] t;
    if (!l)
    {
        t.length = 1;
        t[0] = 0;
    }
    else if (l <= 250)
    {
        t.length = 1+l;
        t[0] = cast(ubyte) l;
        offset = 1;
    }
    else if (l <= 0xffff) // 16-bit
    {
        t.length = 3+l;
        t[0] = 252;
        encodeInto(cast(ushort)l, t[1..3]);
        offset = 3;
    }
    else if (l < 0xffffff) // 24-bit
    {
        t.length = 4+l;
        t[0] = 253;
        encodeInto!(uint, true)(cast(uint)l, t[1..4]);
        offset = 4;
    }
    else // 64-bit
    {
        ulong u = cast(ulong) l;
        t.length = 9+l;
        t[0] = 254;
        u.encodeInto(t[1..9]);
        offset = 9;
    }
    return t;
}

/++
Converts an array of D values into a LCS

See_Also: LCS, encode
+/
ubyte[] encodeLCS(T)(in T[] value) pure nothrow
{
    size_t offset;
    ubyte[] len = encodeLength(value.length, offset);
    if (len[0])
        len[offset..$] = (cast(ubyte[])value)[0..$];
    return len;
}

/++
Get bytes out of a packet, convert them to T, and skip the bytes fetched.
+/
T consume(T)(MySQLSocket conn) pure {
    ubyte[T.sizeof] buffer;
    conn.read(buffer);
    ubyte[] rng = buffer;
    return consume!T(rng);
}

/// ditto
T consume(T:string, ubyte N=T.sizeof)(ref ubyte[] packet) pure
{
    return packet.consume!string(N);
}

/// ditto
T consume(T:string)(ref ubyte[] packet, size_t N) pure
in
{
    assert(packet.length >= N);
}
body
{
    return cast(string)packet.consume(N);
}

/// ditto
ubyte[] consume()(ref ubyte[] packet, size_t N) pure nothrow
in
{
    assert(packet.length >= N);
}
body
{
    auto result = packet[0..N];
    packet = packet[N..$];
    return result;
}

/// ditto
T consume(T)(ref ubyte[] packet, int n) pure nothrow
if(isIntegral!T)
{
    switch(n)
    {
        case 8: return packet.consume!(T, 8)();
        case 4: return packet.consume!(T, 4)();
        case 3: return packet.consume!(T, 3)();
        case 2: return packet.consume!(T, 2)();
        case 1: return packet.consume!(T, 1)();
        default: assert(0);
    }
}

/// ditto
T consume(T:TimeOfDay, ubyte N=T.sizeof)(ref ubyte[] packet) pure
in
{
    static assert(N == T.sizeof);
}
body
{
    mypenforce(packet.length, "Supplied byte array is zero length");
    uint length = packet.front;
    mypenforce(length == 0 || length == 5 || length == 8 || length == 12, "Bad Time length in binary row.");
    mypenforce(length >= 8, "Time column value is not in a time-of-day format");

    packet.popFront(); // length
    auto bytes = packet.consume(length);

    // TODO: What are the fields in between!?! Blank Date?
    TimeOfDay tod;
    tod.hour    = bytes[5];
    tod.minute  = bytes[6];
    tod.second  = bytes[7];
    return tod;
}

/// ditto
T consume(T:Date, ubyte N=T.sizeof)(ref ubyte[] packet) pure
in
{
    static assert(N == T.sizeof);
}
body
{
    return decode!Date(packet.consume(5));
}

/// ditto
T consume(T:DateTime, ubyte N=T.sizeof)(ref ubyte[] packet) pure
in
{
    assert(packet.length);
    assert(N == T.sizeof);
}
body
{
    auto numBytes = packet.consume!ubyte();
    if(numBytes == 0)
        return DateTime();

    mypenforce(numBytes >= 4, "Supplied packet is not large enough to store DateTime");

    int year    = packet.consume!ushort();
    int month   = packet.consume!ubyte();
    int day     = packet.consume!ubyte();
    int hour    = 0;
    int minute  = 0;
    int second  = 0;
    if(numBytes > 4)
    {
        mypenforce(numBytes >= 7, "Supplied packet is not large enough to store a DateTime with TimeOfDay");
        hour    = packet.consume!ubyte();
        minute  = packet.consume!ubyte();
        second  = packet.consume!ubyte();
    }
    return DateTime(year, month, day, hour, minute, second);
}

/// ditto
T consume(T:bool, ubyte N=T.sizeof)(ref ubyte[] packet) pure nothrow
{
    static assert(N == 1);
    return packet.consume!ubyte() == 1;
}

/// ditto
T consume(T, ubyte N=T.sizeof)(ref ubyte[] packet) pure nothrow
if(isIntegral!T)
in
{
    static assert(N == 1 || N == 2 || N == 3 || N == 4 || N == 8, "Cannot consume integral value. Invalid size: "~N.stringof);
    static assert(T.sizeof >= N, T.stringof~" not large enough to store "~to!string(N)~" bytes");
    assert(packet.hasEnoughBytes!(T,N), "packet not long enough to contain all bytes needed for "~T.stringof);
}
body
{
    // The uncommented line triggers a template deduction error,
    // so we need to store a temporary first
    // could the problem be method chaining?
    //return packet.consume(N).decode!(T, N)();
    auto bytes = packet.consume(N);
    return bytes.decode!(T, N)();
}

/// ditto
T consume(T, ubyte N=T.sizeof)(ref ubyte[] packet) pure nothrow
if(isFloatingPoint!T)
in
{
    static assert((is(T == float) && N == float.sizeof)
            || is(T == double) && N == double.sizeof);
}
body
{
    return packet.consume(T.sizeof).decode!T();
}

/// ditto
string consume(T:LCS)(ref ubyte[] packet) pure
in
{
    assert(packet.length >= 1, "LCS packet needs to store at least the LCI header");
}
body
{
    auto lci = packet.consumeIfComplete!LCI();
    assert(!lci.isIncomplete);
    if(lci.isNull)
        return null;
    mypenforce(lci.value <= uint.max, "Protocol Length Coded String is too long");
    return cast(string)packet.consume(cast(size_t)lci.value).idup;
}

/++
Consume if complete. DOCUMENT BETTER!
+/
SQLValue consumeBinaryValueIfComplete(T, int N=T.sizeof)(ref ubyte[] packet, bool unsigned)
{
    SQLValue result;
    result.isIncomplete = packet.length < N;
    // isNull should have been handled by the caller as the binary format uses a null bitmap,
    // and we don't have access to that information at this point
    assert(!result.isNull);
    if(!result.isIncomplete)
    {
        // only integral types is unsigned
        static if(isIntegral!T)
        {
            if(unsigned)
                result.value = packet.consume!(Unsigned!T)();
            else
                result.value = packet.consume!(Signed!T)();
        }
        else
        {
            // TODO: DateTime values etc might be incomplete!
            result.value = packet.consume!(T, N)();
        }
    }
    return result;
}

/// ditto
SQLValue consumeNonBinaryValueIfComplete(T)(ref ubyte[] packet, bool unsigned)
{
    SQLValue result;
    auto lci = packet.decode!LCI();
    result.isIncomplete = lci.isIncomplete || packet.length < (lci.value+lci.totalBytes);
    result.isNull = lci.isNull;
    if(!result.isIncomplete)
    {
        // The packet has all the data we need, so we'll remove the LCI
        // and convert the data
        packet.skip(lci.totalBytes);
        assert(packet.length >= lci.value);
        auto value = cast(string) packet.consume(cast(size_t)lci.value);

        if(!result.isNull)
        {
            assert(!result.isIncomplete);
            assert(!result.isNull);
            static if(isIntegral!T)
            {
                if(unsigned)
                    result.value = to!(Unsigned!T)(value);
                else
                    result.value = to!(Signed!T)(value);
            }
            else
            {
                static if(isArray!T)
                {
                    // to!() crashes when trying to convert empty strings
                    // to arrays, so we have this hack to just store any
                    // empty array in those cases
                    if(!value.length)
                        result.value = T.init;
                    else
                        result.value = cast(T)value.dup;

                }
                else
                {
                    // TODO: DateTime values etc might be incomplete!
                    result.value = value.decode!T();
                }
            }
        }
    }
    return result;
}

/// ditto
SQLValue consumeIfComplete(T, int N=T.sizeof)(ref ubyte[] packet, bool binary, bool unsigned)
{
    return binary
        ? packet.consumeBinaryValueIfComplete!(T, N)(unsigned)
        : packet.consumeNonBinaryValueIfComplete!T(unsigned);
}

/// ditto
SQLValue consumeIfComplete()(ref ubyte[] packet, SQLType sqlType, bool binary, bool unsigned)
{
    switch(sqlType)
    {
        default: assert(false, "Unsupported SQL type "~to!string(sqlType));
        case SQLType.NULL:
            SQLValue result;
            result.isIncomplete = false;
            result.isNull = true;
            return result;
        case SQLType.BIT:
            return packet.consumeIfComplete!bool(binary, unsigned);
        case SQLType.TINY:
            return packet.consumeIfComplete!byte(binary, unsigned);
        case SQLType.SHORT:
            return packet.consumeIfComplete!short(binary, unsigned);
        case SQLType.INT24:
            return packet.consumeIfComplete!(int, 3)(binary, unsigned);
        case SQLType.INT:
            return packet.consumeIfComplete!int(binary, unsigned);
        case SQLType.LONGLONG:
            return packet.consumeIfComplete!long(binary, unsigned);
        case SQLType.FLOAT:
            return packet.consumeIfComplete!float(binary, unsigned);
        case SQLType.DOUBLE:
            return packet.consumeIfComplete!double(binary, unsigned);
        case SQLType.TIMESTAMP:
            return packet.consumeIfComplete!DateTime(binary, unsigned);
        case SQLType.TIME:
            return packet.consumeIfComplete!TimeOfDay(binary, unsigned);
        case SQLType.YEAR:
            return packet.consumeIfComplete!ushort(binary, unsigned);
        case SQLType.DATE:
            return packet.consumeIfComplete!Date(binary, unsigned);
        case SQLType.DATETIME:
            return packet.consumeIfComplete!DateTime(binary, unsigned);
        case SQLType.VARCHAR:
        case SQLType.ENUM:
        case SQLType.SET:
        case SQLType.VARSTRING:
        case SQLType.STRING:
            return packet.consumeIfComplete!string(false, unsigned);
        case SQLType.TINYBLOB:
        case SQLType.MEDIUMBLOB:
        case SQLType.BLOB:
        case SQLType.LONGBLOB:

            // TODO: This line should work. Why doesn't it?
            //return packet.consumeIfComplete!(ubyte[])(binary, unsigned);

            auto lci = packet.consumeIfComplete!LCI();
            assert(!lci.isIncomplete);
            SQLValue result;
            result.isIncomplete = false;
            result.isNull = lci.isNull;
            if(result.isNull)
            {
                // TODO: consumeIfComplete!LCI should be adjusted to do
                //       this itself, but not until I'm certain that nothing
                //       is reliant on the current behavior.
                packet.popFront(); // LCI length
            }
            else
                result.value = packet.consume(cast(size_t)lci.value);
            return result;
    }
}

/// ditto
T consumeIfComplete(T:LCI)(ref ubyte[] packet) pure nothrow
in
{
    assert(packet.length >= 1, "packet has to include at least the LCI length byte");
}
body
{
    auto lci = packet.decodeLCIHeader();
    if(lci.isNull || lci.isIncomplete)
        return lci;

    if(lci.numBytes > 1)
    {
        // We know it's complete, so we have to start consuming the LCI
        // Single byte values doesn't have a length
        packet.popFront(); // LCI length
    }

    assert(packet.length >= lci.numBytes);

    lci.value = packet.consume!ulong(lci.numBytes);
    return lci;
}

/++
Extract number of bytes used for this LCI

Returns the number of bytes required to store this LCI

See_Also: http://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger

Returns: 0 if it's a null value, or number of bytes in other cases
+/
byte getNumLCIBytes(in ubyte lciHeader) pure nothrow
{
    switch(lciHeader)
    {
        case 251: return 0; // null
        case 0: .. case 250: return 1; // 8-bit
        case 252: return 2;  // 16-bit
        case 253: return 3;  // 24-bit
        case 254: return 8;  // 64-bit

        case 255:
        default:
            assert(0);
    }
    assert(0);
}

/// Decodes an LCI header
LCI decodeLCIHeader(in ubyte[] packet) pure nothrow
in
{
    assert(packet.length >= 1, "packet has to include at least the LCI length byte");
}
body
{
    LCI lci;
    lci.numBytes = getNumLCIBytes(packet.front);
    if(lci.numBytes == 0)
    {
        lci.isNull = true;
        return lci;
    }

    assert(!lci.isNull);
    lci.isIncomplete = (lci.numBytes > 1) && (packet.length-1 < lci.numBytes); // -1 for LCI length as we haven't popped it off yet
    if(lci.isIncomplete)
    {
        // Not enough bytes to store data. We don't remove any data, and expect
        // the caller to check isIncomplete and take action to fetch more data
        // and call this method at a later time
        return lci;
    }

    assert(!lci.isIncomplete);
    return lci;
}

/++
Parse Length Coded Integer.

See_Also: http://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
+/
ulong parseLCI(ref ubyte[] ubp, out bool nullFlag) pure nothrow
{
    nullFlag = false;
    ulong t;
    byte numLCIBytes = getNumLCIBytes(ubp[0]);
    switch (numLCIBytes)
    {
        case 0: // Null - only for Row Data Packet
            nullFlag = true;
            t = 0;
            break;
        case 8: // 64-bit
            t |= ubp[8];
            t <<= 8;
            t |= ubp[7];
            t <<= 8;
            t |= ubp[6];
            t <<= 8;
            t |= ubp[5];
            t <<= 8;
            t |= ubp[4];
            t <<= 8;
            ubp.skip(5);
            goto case;
        case 3: // 24-bit
            t |= ubp[3];
            t <<= 8;
            t |= ubp[2];
            t <<= 8;
            t |= ubp[1];
            ubp.skip(3);
            goto case;
        case 2: // 16-bit
            t |= ubp[2];
            t <<= 8;
            t |= ubp[1];
            ubp.skip(2);
            break;
        case 1: // 8-bit
            t = cast(ulong)ubp[0];
            break;
        default:
            assert(0);
    }
    ubp.skip(1);
    return t;
}

/// ditto
ulong parseLCI(ref ubyte[] ubp) pure nothrow
{
    bool isNull;
    return parseLCI(ubp, isNull);
}

/++
Set packet length and number. It's important that the length of packet has
already been set to the final state as its length is used
+/
void setPacketHeader(ref ubyte[] packet, ubyte packetNumber) pure nothrow
in
{
    // packet should include header, and possibly data
    assert(packet.length >= 4);
}
body
{
    auto dataLength = packet.length - 4; // don't include header in calculated size
    assert(dataLength <= uint.max);
    packet.setPacketHeader(packetNumber, cast(uint)dataLength);
}

/// ditto
void setPacketHeader(ref ubyte[] packet, ubyte packetNumber, uint dataLength) pure nothrow
in
{
    // packet should include header
    assert(packet.length >= 4);
    // Length is always a 24-bit int
    assert(dataLength <= 0xffff_ffff_ffff);
}
body
{
    dataLength.encodeInto!(uint, true)(packet);
    packet[3] = packetNumber;
}

/// Converts a D value to a MySQL Binary Protocol value
ubyte[] toMySQLBinaryValue(T)(ref T value) pure
{
    static if(is(T == bool))
    {
        return [value ? 0x01 : 0x00];
    }
    else static if(is(T == Timestamp))
    {
        return value.toDateTime().encode();
    }
    else static if(is(T == Date))
    {
        return value.encode();
    }
    else static if(is(T == DateTime))
    {
        return value.encode();
    }
    else static if(is(T == TimeOfDay))
    {
        return value.encode();
    }
    else static if(isArray!T)
    {
        return value.encodeLCS();
    }
    else
    {
        ubyte[] data = new ubyte[T.sizeof];
        value.encodeInto(data);
//            debug writeln("toSqlValue ", value, " = ", data);
        return data;
    }
}

/++
Converts an MySQL Text Protocol value to a D value and stores it in a Variant.
If the SQL value is null, an uninitialized Variant is returned.
+/
Variant fromSQLTextValue(string value, SQLType type, size_t length, bool unsigned)
{
    if(value is null)
    {
        Variant v;
        return v;
    }

    final switch(type)
    {
        case SQLType.TINY:
            // Assume boolean
            if(length == 1)
            {
                if(value == "1" || value == "true")
                    return Variant(true);
                else if(value == "0" || value == "false")
                    return Variant(false);
                assert(0);
            }
            else if(unsigned)
                return Variant(value.to!ubyte());
            else
                return Variant(value.to!byte());
            assert(0);
        case SQLType.SHORT:
            if(unsigned)
                return Variant(value.to!ushort());
            else
                return Variant(value.to!short());
        case SQLType.INT:
            if(unsigned)
                return Variant(value.to!uint());
            else
                return Variant(value.to!int());
        case SQLType.BIT: // FIXME: Implement bitfield
        case SQLType.LONGLONG:
            if(unsigned)
                return Variant(value.to!ulong);
            else
                return Variant(value.to!long);
        case SQLType.FLOAT:
            return Variant(value.to!float());
        // FIXME: Implement fixed point DECIMAL type
        case SQLType.DECIMAL:
        case SQLType.NEWDECIMAL:
        case SQLType.DOUBLE:
            return Variant(value.to!double());
        case SQLType.NULL:
            return Variant(null);
        case SQLType.TIMESTAMP:
            auto year   = value[0..4];
            auto month  = value[5..7];
            auto day    = value[8..10];
            auto hour   = value[11..13];
            auto minute = value[14..16];
            auto second = value[17..19];
            auto dtm    = DateTime(
                    year.to!int,
                    month.to!int,
                    day.to!int,
                    hour.to!int,
                    minute.to!int,
                    second.to!int);
            return Variant(dtm);
        case SQLType.INT24:
            if(unsigned)
                return Variant(value.to!uint());
            else
                return Variant(value.to!int());
        case SQLType.DATE:
            return Variant(value.decode!Date());
        case SQLType.TIME:
            auto hour   = value[0..2];
            auto minute = value[3..5];
            auto second = value[6..$];
            auto tm = TimeOfDay(hour.to!int, minute.to!int, second.to!int);
            return Variant(tm);
        case SQLType.DATETIME:
            return Variant(value.decode!DateTime());
        case SQLType.YEAR:
            return Variant(value.to!int);
        case SQLType.NEWDATE:
            return Variant(value.decode!Date());
        case SQLType.VARSTRING:
        case SQLType.STRING:
        case SQLType.VARCHAR:
            return Variant(value);
        case SQLType.TINYBLOB:
        case SQLType.MEDIUMBLOB:
        case SQLType.BLOB:
        case SQLType.LONGBLOB:
            return Variant(cast(ubyte[])value);
        // FIXME: All the below is wrong!!!
        case SQLType.ENUM:
            return Variant(value);
        case SQLType.SET:
            return Variant(value);
        case SQLType.GEOMETRY:
            return Variant(value);
        case SQLType.INFER_FROM_D_TYPE:
            assert(0);
    }
    assert(0);
}
