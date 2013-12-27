/++
Parsing and building packets for the MySQL binary interface.

The types in this file does not work directly on a connection. They expect to
get enough data in their constructor.

NOTE:
    There are several responses from the server that cannot be fully parsed
    without requesting more data from the connection. These responses are
    partly located here, and partly in mysql.protocol.commands.

See_Also:
http://dev.mysql.com/doc/internals/en/client-server-protocol.html
mysql.protocol.packet_helpers

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.protocol.packets;

import std.datetime;
import std.variant;
import std.array;
import std.exception;
import std.string;
import std.algorithm;
import std.typecons;
import std.traits;
debug import std.stdio;

import mysql.common;
import mysql.protocol.constants;
import mysql.protocol.extra_types;
public import mysql.protocol.packet_helpers;

/++
Thrown if we encounter an unexpected packet or byte stream in some server
result.
+/
class MySQLIllegalPacketException : MySQLProtocolException
{
    ubyte[] packet;

    this(ubyte[] packet, string msg, string file = __FILE__, size_t line = __LINE__)
    {
        super(msg, file, line);
        this.packet = packet;
    }
}

/++
Throw if we got an OKPacket we didn't expect
+/
class MySQLOKPacketException : MySQLIllegalPacketException
{
    OKPacket okPacket;

    this(OKPacket okPacket, string msg, string file = __FILE__, size_t line = __LINE__)
    {
        super(okPacket.packet, msg, file, line);
        this.okPacket = okPacket;
    }
}

/++
Throw if we got an EOFPacket we didn't expect
+/
class MySQLEOFPacketException : MySQLIllegalPacketException
{
    EOFPacket eofPacket;

    this(EOFPacket eofPacket, string msg, string file = __FILE__, size_t line = __LINE__)
    {
        super(eofPacket.packet, msg, file, line);
        this.eofPacket = eofPacket;
    }
}

/++
Throw if we got an ErrorPacket we didn't expect
+/
class MySQLErrorPacketException : MySQLIllegalPacketException
{
    ErrorPacket errorPacket;

    this(ErrorPacket errorPacket, string msg = "", string file = __FILE__, size_t line = __LINE__)
    {
        super(errorPacket.packet, msg.length ? msg : errorPacket.errorMessage, file, line);
        this.errorPacket = errorPacket;
    }
}

/++
Throw if we got an unknown packet
+/
class MySQLUnknownPacketException : MySQLIllegalPacketException
{
    this(ubyte[] packet, string msg, string file = __FILE__, size_t line = __LINE__)
    {
        super(packet, msg, file, line);
    }
}

/++
Throws an exception if packet is not an OKPacket
+/
void enforceOK(ubyte[] packet, string msg = "", string file = __FILE__, uint line = __LINE__)
{
    if(packet.isErrorPacket)
    {
        throw new MySQLErrorPacketException(ErrorPacket(packet),
                msg ? msg : "Expected OK packet, got Error", file, line);
    }
    else if(packet.isEOFPacket)
    {
        throw new MySQLEOFPacketException(EOFPacket(packet),
                msg ? msg : "Expected OK packet, got EOF", file, line);
    }
    else if(!packet.isOKPacket)
    {
        throw new MySQLUnknownPacketException(packet,
                msg ? msg : "Expected OK packet, got unknown", file, line);
    }
}

/++
Throws an exception if packet is not an EOFPacket
+/
void enforceEOF(ubyte[] packet, string msg = "", string file = __FILE__, uint line = __LINE__)
{
    if(packet.isErrorPacket)
    {
        throw new MySQLErrorPacketException(ErrorPacket(packet),
                msg ? msg : "Expected EOF packet, got Error", file, line);
    }
    else if(packet.isOKPacket)
    {
        throw new MySQLOKPacketException(OKPacket(packet),
                msg ? msg : "Expected EOF packet, got OK", file, line);
    }
    else if(!packet.isEOFPacket)
    {
        throw new MySQLUnknownPacketException(packet,
                msg ? msg : "Expected EOF packet, got unknown", file, line);
    }
}

/++
Marker for generic packet type
+/
enum ResultPacketMarker : ubyte
{
    /++
    See_Also: ErrorPacket
    +/
    error   = 0xff,

    /++
    See_Also: OKPacket
    +/
    ok      = 0x00,

    /++
    See_Also: EOFPacket
    +/
    eof     = 0xfe,
}

/++
True if the packet starts with the EOF packet marker

Note that the same marker is used for 8 byte LCI
+/
bool isEOFPacket(in ubyte[] packet) pure nothrow
in
{
    assert(!packet.empty);
}
body
{
    return packet.front == ResultPacketMarker.eof && packet.length < 9;
}

/++
True if the packet starts with the OK packet marker
+/
bool isOKPacket(in ubyte[] packet) pure nothrow
{
    return packet.front == ResultPacketMarker.ok;
}

/++
True if the packet starts with the Error packet marker
+/
bool isErrorPacket(in ubyte[] packet) pure nothrow
{
    return packet.front == ResultPacketMarker.error;
}

/++
Successful completion of a command

See_Also: http://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-OK_Packet
+/
struct OKPacket
{
public:
    @property
    {
        /// The underlying raw packet
        ubyte[] packet() pure nothrow { return _packet; }

        /// Number of rows affected
        ulong affectedRows() pure const nothrow { return _affectedRows; }

        /// Last insert-id generated
        ulong lastInsertId() pure const nothrow { return _lastInsertId; }

        /// Server status
        ServerStatus serverStatus() pure const nothrow { return _serverStatus; }

        /// Number of warnings
        ushort warnings() pure const nothrow { return _warnings; }

        /// Human readably info about the query
        string info() pure const nothrow { return _info; }
    }

    /// Parse from a packet
    this(ubyte[] packet)
    in
    {
        assert(packet.front == ResultPacketMarker.ok);
    }
    body
    {
        _packet = packet;
        packet.popFront(); // skip marker/field code

        auto lci = packet.consumeIfComplete!LCI();
        assert(!lci.isNull);
        assert(!lci.isIncomplete);
        _affectedRows = lci.value;

        lci = packet.consumeIfComplete!LCI();
        assert(!lci.isNull);
        assert(!lci.isIncomplete);
        _lastInsertId = lci.value;

        _serverStatus = cast(ServerStatus)packet.consume!short();

        _warnings = packet.consume!short();
        _info = cast(string)packet.idup;
    }

private:
    ubyte[] _packet;
    ulong _affectedRows;
    ulong _lastInsertId;
    ServerStatus _serverStatus;
    ushort _warnings;
    string _info;
}

/++
An Error packet. This is used to signal an error in a request to the server.

See_Also: http://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-ERR_Packet
+/
struct ErrorPacket
{
public:
    @property
    {
        /// The underlying raw packet
        ubyte[] packet() pure nothrow { return _packet; }

        /// The internal MySQL error code
        ushort errorCode() pure const nothrow { return _errorCode; }

        /// Current sql state
        string sqlState() pure nothrow { return _sqlState; }

        /// Human readable error message
        string errorMessage() pure nothrow { return _errorMessage; }
    }

    /// Construct from a raw packet
    this(ubyte[] packet)
    in
    {
        assert(packet.front == ResultPacketMarker.error);
    }
    body
    {
        _packet = packet;
        packet.popFront(); // skip marker/field code

        _errorCode = packet.consume!ushort();

        assert(packet.front == cast(ubyte) '#'); // Protocol 4.1
        packet.popFront();

        _sqlState = (cast(string)packet[0 .. 5])[];
        packet.skip(5);

        _errorMessage = cast(string)packet.idup;
    }

private:
    ubyte[] _packet;
    ushort _errorCode;
    string _sqlState;
    string _errorMessage;
}

/++
EOF packet sent from the server. This usually signals and of a part of a server
response.

An EOF packet is also called "Last Data Packet" or "End Packet".

IMPLEMENTATION_NOTE:
    The EOF packet may appear in places where a Protocol::LengthEncodedInteger
    may appear. You have to check the packet length is less then 9 to make sure
    it is a EOF packet.

See_Also:
http://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-EOF_Packet
isEOFPacket
+/
struct EOFPacket
{
public:
    @property
    {
        /// The underlying raw packet
        ubyte[] packet() pure nothrow { return _packet; }

        /// Warning count
        ushort warnings() pure const nothrow { return _warnings; }

        /// Server status
        ServerStatus serverStatus() pure const nothrow { return _serverStatus; }
    }

    /// Construct an EOFPacket struct from the raw data packet
    this(ubyte[] packet)
    in
    {
        assert(packet.isEOFPacket());
        assert(packet.length == 5);
    }
    body
    {
        _packet = packet;
        packet.popFront(); // eof marker
        _warnings     = packet.consume!short();
        _serverStatus = cast(ServerStatus)packet.consume!short();
    }

private:
    ubyte[] _packet;
    ushort _warnings;
    ServerStatus _serverStatus;
}

/++
Initial server response when connecting to the server.

See_also: http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV10
+/
struct HandshakePacket
{
public:
    @property
    {
        /// Protocol version
        ubyte protocolVersion() const pure nothrow { return _protocolVersion; }

        /// Human readable server version
        string serverVersion() const pure nothrow { return _serverVersion; }

        /// Connection id
        uint connectionId() const pure nothrow { return _connectionId; }

        /// Server capabilities
        CapabilityFlags serverCapabilities() const pure nothrow { return _serverCapabilities; }

        /++
        Default server character set
        See_Also: http://dev.mysql.com/doc/internals/en/character-set.html
        +/
        ubyte characterSet() const pure nothrow { return _characterSet; }

        /++
        Server status

        See_also: http://dev.mysql.com/doc/internals/en/status-flags.html#packet-Protocol::StatusFlags
        +/
        ushort serverStatus() const pure nothrow { return _serverStatus; }

        /++
        Auth buffer required to log in
        +/
        ubyte[] authBuf() pure nothrow { return _authBuf; }
    }

    /// Construct from a raw packet
    this(ubyte[] packet)
    {
        consumeServerPreInfo(packet);
        consumeScrambleBuf(packet);
        consumeServerInfo(packet);
        consumeAuthBuf(packet);
    }

private:
    ubyte       _protocolVersion;
    string      _serverVersion;
    uint        _connectionId;
    CapabilityFlags _serverCapabilities;
    ubyte       _characterSet;
    ushort      _serverStatus;
    ubyte[]     _authBuf;

    void consumeServerPreInfo(ref ubyte[] packet) pure
    {
        _protocolVersion = packet.consume!ubyte();

        _serverVersion = packet.consume!string(packet.countUntil(0));
        packet.skip(1); // \0 terminated _serverVersion

        _connectionId = packet.consume!uint();
    }

    void consumeScrambleBuf(ref ubyte[] packet) pure
    {
        _authBuf.length = 255;
        _authBuf[0..8] = packet.consume(8)[]; // scramble_buff
        mypenforce(packet.consume!ubyte() == 0,
                "filler should always be 0");
    }

    void consumeServerInfo(ref ubyte[] packet) pure
    {
        // lower bytes
        _serverCapabilities = cast(CapabilityFlags)packet.consume!ushort();
        _characterSet = packet.consume!ubyte();
        _serverStatus = packet.consume!ushort();
        // server_capabilities (upper bytes)
        _serverCapabilities += cast(CapabilityFlags)(packet.consume!ushort() << 16);
         // Assumed to be set since v4.1.1, according to spec
        _serverCapabilities |= CapabilityFlags.LONG_PASSWORD;

        mypenforce(_serverCapabilities & CapabilityFlags.PROTOCOL_41,
                "Server doesn't support protocol v4.1");
        mypenforce(_serverCapabilities & CapabilityFlags.SECURE_CONNECTION,
                "Server doesn't support protocol v4.1 connection");
    }

    void consumeAuthBuf(ref ubyte[] packet) pure
    {
        packet.skip(1); // this byte supposed to be scramble length, but is actually zero
        packet.skip(10); // filler of \0

        // rest of the scramble
        auto len = packet.countUntil(0);
        mypenforce(len >= 12,
                "second part of scramble buffer should be at least 12 bytes");
        mypenforce(_authBuf.length > 8+len);
        _authBuf[8..8+len] = packet.consume(len)[];
        _authBuf.length = 8+len; // cut to correct size
        mypenforce(packet.consume!ubyte() == 0,
                "Excepted \\0 terminating scramble buf");
    }
}

/++
Response from the client to an initial HandshakePacket.

This will send the username, password and more to complete the connection.

See_Also: http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
+/
struct HandshakeResponsePacket
{
public:
    /// The underlying raw packet
    @property ubyte[] packet() pure nothrow { return _packet;}

    /++
    Params:
        username = username
        password = user password
        database = default database
        cCaps    = Client capabilities
        authBuf  = Scramblebuf sent from the server in the initial HandshakePacket
    +/
    this(in string username, in string password, in string database,
            in CapabilityFlags cCaps, in ubyte[] authBuf)
    {
        buildAuthPacket(username, database, cCaps, makeToken(password, authBuf));
    }

private:
    ubyte[] _packet;

    static ubyte[] makeToken(in string password, in ubyte[] authBuf) pure
    {
        import std.digest.sha;
        auto pass1 = sha1Of(cast(const(ubyte)[])password);
        auto pass2 = sha1Of(pass1);

        SHA1 sha1;
        sha1.start();
        sha1.put(authBuf);
        sha1.put(pass2);
        auto result = sha1.finish();
        foreach (size_t i; 0..20)
            result[i] = result[i] ^ pass1[i];
        return result.dup;
    }

    void buildAuthPacket(in string username, in string database,
            in CapabilityFlags cCaps, in ubyte[] token) pure nothrow
    in
    {
        assert(token.length == 20);
    }
    body
    {
        _packet.reserve(4/*header*/ + 4 + 4 + 1 + 23 + username.length+1
                + token.length+1 + database.length+1);
         // create room for the beginning headers that we set rather than
         // append
        _packet.length = 4 + 4 + 4;

        // NOTE: we'll set the header last when we know the size

        // Set the default capabilities required by the client
        cCaps.encodeInto(_packet[4..8]);

        // Request a conventional maximum packet length.
        1.encodeInto(_packet[8..12]);

        _packet ~= 33; // Set UTF-8 as default charSet

        // There's a statutory block of zero bytes here - fill them in.
        foreach(i; 0 .. 23)
            _packet ~= 0;

        // Add the user name as a null terminated string
        foreach(i; 0 .. username.length)
            _packet ~= username[i];
        _packet ~= 0; // \0

        // Add our calculated authentication token as a length prefixed string.
        assert(token.length <= ubyte.max);
        _packet ~= cast(ubyte)token.length;
        foreach(i; 0 .. token.length)
            _packet ~= token[i];

        if(database.length)
        {
            foreach(i; 0 .. database.length)
                _packet ~= database[i];
            _packet ~= 0; // \0
        }
    }
}

/++
Column definition packet

This describes information of a column in a TextResultSet or BinaryResultSet

See_Also: http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition41
+/
struct ColumnDefinition
{
public:
    @property
    {
        /// Schema name (Database name)
        string schema() pure const nothrow { return _schema; }

        /++
        Virtual table name for column as string - this could be an alias as in
        'from tablename as foo'
        +/
        string table() pure const nothrow { return _table; }

        /// Physical table name
        string originalTable() pure const nothrow { return _originalTable; }

        /// Virtual column name
        string name() pure const nothrow { return _name; }

        /// Physical column name
        string originalName() pure const nothrow { return _originalName; }

        /// Column character set
        ushort charSet() pure const nothrow { return _charSet; }

        /// Maximum length of field
        uint length() pure const nothrow { return _length; }

        /++
        The type of the column hopefully (but not always) corresponding to enum
        SQLType. Only the low byte currently used
        +/
        SQLType type() pure const nothrow { return _type; }

        /// Column flags - unsigned, binary, null and so on
        FieldFlags flags() pure const nothrow { return _flags; }

        /// Precision for floating point values
        ubyte scale() pure const nothrow { return _scale; }

        /++
        If this was constructed with a COM_FIELD_LIST command, this will
        include the default values
        +/
        string defaultValues() pure nothrow { return _defaultValues; }

        /// NotNull from flags
        bool notNull() pure const nothrow { return (_flags & FieldFlags.NOT_NULL) != 0; }

        /// Unsigned from flags
        bool unsigned() pure const nothrow { return (_flags & FieldFlags.UNSIGNED) != 0; }

        /// Binary from flags
        bool binary() pure const nothrow { return (_flags & FieldFlags.BINARY) != 0; }

        /// Is-enum from flags
        bool isenum() pure const nothrow { return (_flags & FieldFlags.ENUM) != 0; }

        /// Is-set (a SET column that is) from flags
        bool isset() pure const nothrow { return (_flags & FieldFlags.SET) != 0; }
    }

    /// Construct from a raw packet.
    this(ubyte[] packet)
    in
    {
        assert(packet.length);
    }
    out
    {
        assert(!packet.length);
    }
    body
    {
        const catalog = packet.consume!(string, 4);
        // FIXME: catalog is always "def", even when I'm looking at it here
        //        For some reason though, this assertion fails in dmd head (pre 2.064)
//        assert(catalog == "def");

        _schema         = packet.consume!LCS();
        _table          = packet.consume!LCS();
        _originalTable  = packet.consume!LCS();
        _name           = packet.consume!LCS();
        _originalName   = packet.consume!LCS();

        mypenforce(packet.length >= 13, "Malformed field specification packet");
        packet.popFront(); // one byte filler here
        _charSet    = packet.consume!short();
        _length     = packet.consume!int();
        _type       = cast(SQLType)packet.consume!ubyte();
        _flags      = cast(FieldFlags)packet.consume!short();
        _scale      = packet.consume!ubyte();
        packet.skip(2); // two byte filler

        // Command is COM_FIELD_LIST
        if(packet.length)
        {
            auto lci = packet.consumeIfComplete!LCI();
            assert(!lci.isNull);
            assert(!lci.isIncomplete);
            _defaultValues = cast(string)packet.consume(cast(size_t)lci.value);
        }
    }

private:
    string   _schema;
    string   _table;
    string   _originalTable;
    string   _name;
    string   _originalName;
    ushort   _charSet;
    uint     _length;
    SQLType  _type;
    FieldFlags _flags;
    ubyte    _scale;
    string    _defaultValues;
}

/++
Partial ResultSet packet.

This only include the first packet information needed to fetch the rest of the
packets.
+/
struct ResultSet
{
public:
    /// Number of columns in the result
    @property long columnCount() pure const nothrow { return _columnCount; }

    /// Construct from a raw packet
    this(ubyte[] packet)
    {
        auto lci = packet.consumeIfComplete!LCI();
        assert(!lci.isNull);
        assert(!lci.isIncomplete);
        _columnCount = lci.value;
    }

private:
    long _columnCount;
}

/++
Result from a ComStmtPrepare (prepare)

Note that this does not read columns or parameters.

See_Also: http://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
+/
struct StmtPrepareOK
{
public:
    @property
    {
        /// Statement id
        int statementId() pure const nothrow { return _statementId; }

        /// Number of warnings
        short numWarnings() pure const nothrow { return _numWarnings; }

        /// Number of parameters in the request
        short numParams() pure const nothrow { return _numParams; }

        /// Number of columns in the resultset
        short numColumns() pure const nothrow { return _numColumns; }
    }

    /// Construct from a raw packet
    this(ubyte[] packet)
    in
    {
        assert(packet.front == ResultPacketMarker.ok);
    }
    body
    {
        packet.popFront(); // Magic marker
        _statementId     = packet.consume!int;
        assert(_statementId != 0, "MySQL didn't return a statement id");
        _numColumns = packet.consume!short;
        _numParams  = packet.consume!short;
        packet.popFront(); // Filler
        _numWarnings     = packet.consume!short;
    }

private:
    int   _statementId;
    short _numWarnings;
    short _numParams;
    short _numColumns;
}

/++
Execute a prepared statement

This type act as a builder for the packet. See the method setParam.

See_Also: http://dev.mysql.com/doc/internals/en/com-stmt-execute.html
+/
struct ComStmtExecutePacket
{
public:
    @property
    {
        /// Raw packet
        ubyte[] packet() pure nothrow { return _packet[0.._packetLength]; }

        /// Number of parameters
        ushort numParams() pure const nothrow { return cast(ushort)_params.length; }
    }

    /// Construct
    this(int statementId, ColumnDefinition[] params, CursorType cursor)
    {
        assert(statementId != 0,
                "ComStmtExecutePacket only works on prepared statements");
        enum ubyte newParamsBoundFlag = 1;
        _params = params;
        auto len =
              4 // StatementId
            + 1 // Flags
            + 4 // Iteration count
            ;
        _nullBitmapOffset = len;
        if(_params.length)
        {
            len += calcNullBitmapLength(_params.length);
            len += 1; // newParamsBoundFlag
            if(newParamsBoundFlag)
            {
                _typesOffset = len;

                len += _params.length*2; // type byte + sign byte

                _valuesOffset = len;
                len += _params.length*4; // assume 4 bytes per value. Might need to reallocate
            }
        }
        _packetLength = _valuesOffset ? _valuesOffset : len; // No values yet
        _packet = new ubyte[len];
        _valueBeginOffsets.length = _params.length;
        _valueEndOffsets.length = _params.length;

        foreach(i; 0 .. _params.length)
            setNull(cast(ushort)i);

        auto builder = _packet;
        statementId.encodeIntoAndSkip(builder);
        cursor.encodeIntoAndSkip(builder); // flags
        0.encodeIntoAndSkip(builder); // iteration count
        if(_params.length)
        {
            builder.skip(calcNullBitmapLength(_params.length));
            newParamsBoundFlag.encodeIntoAndSkip(builder);
        }
    }

    /++
    Set a parameter by index.

    This might reallocate the underlying packet to make room for the new type.
    For performance, you should add the parameters in ascending order.

    BUGS:
        Doesn't support Variant
    +/
    void setParam(T)(ushort index, T value) pure
    {
        scope(exit) assertNullOrValue();
        mypenforce(index < _params.length, "Parameter index out of bounds");
//        debug writeln("SetParam ", index, " = ", value);
        assert(index < _params.length);
        const typeOffset  = typeOffset(index);
        const valueBeginOffset = valueBeginOffset(index);
        const valueEndOffset = valueEndOffset(index);

        // TODO: If it's null, we don't need to update the type?

        static if(is(T == typeof(null)))
        {
            _packet[typeOffset]   = _params[index].type;
            _packet[typeOffset+1] = SQLSign.UNSIGNED;
        }
        else
        {
            _packet[typeOffset]   = sqlTypeOf!T;
            _packet[typeOffset+1] = sqlSignOf!T;
        }

        const oldValueSize  = valueSize(index);
        const oldValueEnd   = valueEndOffset;

        static if(is(T == typeof(null)))
            const newValue = cast(ubyte[])null;
        else
            const newValue = toMySQLBinaryValue(value);

        const newValueEnd   = valueBeginOffset + newValue.length;
        const newValueSize  = newValueEnd - valueBeginOffset;

        const sizeDiff      = newValue.length - oldValueSize;

        /+
        debug writefln(
                 " packetLength: %d"
                ~" valueBegin: %d"
                ~" OldValueEnd: %d"
                ~" OldValueSize: %d"
                ~" NewValueSize: %d"
                ~" NewValue: %s"
                ~" NewValue: %s"
                ~" NewValueEnd: %d"
                ~" SizeDiff: %d"
                , _packetLength
                , valueBeginOffset
                , oldValueEnd
                , oldValueSize
                , newValueSize
                , newValue
                , cast(string)newValue
                , newValueEnd
                , sizeDiff
                );
        +/

        if(sizeDiff)
        {
            const newPacketLength = _packetLength + sizeDiff;

            // Possibly extend array
            if(newPacketLength > _packet.length)
                _packet.length += sizeDiff; // TODO: Extended it ever further?
            assert(newPacketLength <= _packet.length);

            // Move all values on the right side
            _packet[oldValueEnd .. _packetLength].encodeInto(
                    _packet[newValueEnd..newPacketLength]);

            // Update positions
            for(size_t i=index+1; i < _params.length; ++i)
            {
                _valueBeginOffsets[i] += sizeDiff;
                _valueEndOffsets[i]   += sizeDiff;
            }

            // Update packet length
            _packetLength = newPacketLength;
            _valueEndOffsets[index] += sizeDiff;
        }

        if(newValue is null)
        {
//            debug writeln("Setting param ", index, " to null");
            setNull(index);
        }
        else
        {
            clearNull(index);
//            debug writeln("Setting param ", index, " to ", newValue);
            newValue.encodeInto(_packet[valueBeginOffset..newValueEnd]);
        }
//        debug writeln("Values: ", _packet[_valuesOffset .. _packetLength]);
//        debug writeln("Nulls : ", _packet[_nullBitmapOffset .. _typesOffset-1]);
    }

private:
    pure const nothrow invariant()
    {
        assert(_packetLength <= _packet.length);
    }

    // Makes sure we either have a null or a value and not both
    void assertNullOrValue() pure const nothrow
    {
        foreach(ushort i; 0 .. cast(ushort)_params.length)
        {
            const psz = valueSize(i);
//            try debug writeln("Param ", i, " is size ", psz, " and has null: ", getNullBit(i));
//            catch(Exception ex) {}
            if(psz > 0)
                assert(!getNullBit(i));
            else
                assert(getNullBit(i));
        }
    }

    /++
    Sets parameter at index to be null

    NOTE: This does not actually clear the value. Use setParam
    +/
    void setNull(ushort index) pure nothrow
    {
        setNullBit(index, true);
        assert(getNullBit(index) == true);
    }

    /// Sets parameter at index to be non-null
    void clearNull(ushort index) pure nothrow
    {
        setNullBit(index, false);
        assert(getNullBit(index) == false);
    }

    /// Offset in _packet where the type information begin
    size_t typeOffset(ushort index) pure const nothrow
    {
        return _typesOffset + (2*index);
    }

    /// Offset in _packet where the value begin
    size_t valueBeginOffset(ushort index) pure const nothrow
    {
        return _valuesOffset + _valueBeginOffsets[index];
    }

    /// Offset in _packet where the value end
    size_t valueEndOffset(ushort index) pure const nothrow
    {
        return _valuesOffset + _valueEndOffsets[index];
    }

    /// Returns the stored length of the value at index
    size_t valueSize(ushort index) pure const nothrow
    {
        return valueEndOffset(index) - valueBeginOffset(index);
    }

    /// Number of bytes in the nullbitmap
    static size_t calcNullBitmapLength(size_t numParams) pure nothrow
    {
        return (numParams+7)/8;
    }

    /// Returns byte position in nullbitmap for this index
    static size_t getNullBytePos(ushort index) pure nothrow
    {
        return index/8;
    }

    /// Returns bit position in this indexs byte. See getNullBytePos
    static ubyte getNullBitPos(ushort index) pure nothrow
    {
        return index%8;
    }

    /// Set a parameters null-flag. Use setParam instead
    void setNullBit(ushort index, bool setNull) pure nothrow
    {
        scope(exit) assert(getNullBit(index) == setNull);
        const bytepos     = getNullBytePos(index);
        const bitpos      = getNullBitPos(index);
        const posInPacket = _nullBitmapOffset + bytepos;
        assert(posInPacket < _typesOffset);
        if(setNull)
            _packet[posInPacket] |= 1 << bitpos;
        else
            _packet[posInPacket] &= ~(1 << bitpos);
    }

    bool getNullBit(short index) const pure nothrow
    {
        const bytepos     = getNullBytePos(index);
        const bitpos      = getNullBitPos(index);
        const posInPacket = _nullBitmapOffset + bytepos;
        return cast(bool)(_packet[posInPacket] >> bitpos & 1);
    }

    ubyte[] _packet;
    size_t _packetLength;
    ColumnDefinition[] _params;

    size_t _nullBitmapOffset;
    size_t _typesOffset; /// Offset in _packet where the types begin
    size_t _valuesOffset; /// Offset in _packet where the values begin
    size_t[] _valueBeginOffsets; /// Offset from valuesOffset where the parameter begin
    size_t[] _valueEndOffsets; /// Offset from valuesOffset where the parameter end
}

/++
A result row from a prepared statement
+/
struct BinaryRow
{
public:
    @property
    {
        /// Number of values
        size_t length() const pure nothrow { return _values.length; }

        /// Values
        Variant[] values() pure nothrow { return _values; }
    }

    /// Return value at index i
    Variant opIndex(size_t i) pure nothrow
    {
        return _values[i];
    }

    /// Construct
    this(ubyte[] packet, in ColumnDefinition[] columns)
    in
    {
        assert(packet);
    }
    out
    {
        assert(!packet.length);
    }
    body
    {
        packet.popFront(); // header. Always 0

        _values = minimallyInitializedArray!(Variant[])(columns.length);

        auto nulls = consumeNullBitmap(packet, cast(uint)(columns.length));
        foreach(i, col; columns)
        {
            if(nulls[i])
            {
                // TODO: Create variant of type col.type?
            }
            else
            {
                auto sqlValue = packet.consumeIfComplete(col.type, true, col.unsigned);
                if(col.type == SQLType.TINY && col.length == 1)
                    _values[i] == cast(bool)sqlValue.value.get!int();
                else
                    _values[i] = sqlValue.value;
            }
        }
    }

private:
    Variant[] _values;

    static bool[] consumeNullBitmap(ref ubyte[] packet, uint numColumns) pure
    {
        const nbmlen = calcBitmapLength(numColumns);
        ubyte[] nbm = packet[0..nbmlen];
        packet.skip(nbmlen);
        return decodeNullBitmap(nbm, numColumns);
    }

    static size_t calcBitmapLength(uint numColumns) pure nothrow
    {
        return (numColumns + 7 + 2) / 8;
    }

    // This is to decode the bitmap in a binary result row. First two bits are skipped
    static bool[] decodeNullBitmap(ubyte[] bitmap, uint numColumns) pure nothrow
    in
    {
        assert(bitmap.length >= calcBitmapLength(numColumns),
                "bitmap not large enough to store all null fields");
    }
    out(result)
    {
        assert(result.length == numColumns);
    }
    body
    {
        bool[] nulls;
        nulls.length = numColumns;

        // the current byte we are processing for nulls
        ubyte bits = bitmap.front();
        // strip away the first two bits as they are reserved
        bits >>= 2;
        // .. and then we only have 6 bits left to process for this byte
        ubyte bitsLeftInByte = 6;
        foreach(ref isNull; nulls)
        {
            assert(bitsLeftInByte <= 8);
            // processed all bits? fetch new byte
            if (bitsLeftInByte == 0)
            {
                assert(bits == 0, "not all bits are processed!");
                assert(!bitmap.empty, "bits array too short for number of columns");
                bitmap.popFront();
                bits = bitmap.front;
                bitsLeftInByte = 8;
            }
            assert(bitsLeftInByte > 0);
            isNull = (bits & 0b0000_0001) != 0;

            // get ready to process next bit
            bits >>= 1;
            --bitsLeftInByte;
        }
        return nulls;
    }
}
