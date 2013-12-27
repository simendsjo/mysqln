/++
This module deals with the interaction with the MySQL server. This includes
sending commands and fetching and parsing results.

Each command has a static or instance method called exec that will perform the
action.

Commands are named like their MySQL equivalent (COM_INIT_DB -> ComInitDB) when
there is an exact match, but there are also a couple of pseudo commands to deal
with more complex packets that requires several roudtrips to the server.

See_Also:
    mysql.protocol.packets
    $(LINK http://dev.mysql.com/doc/internals/en/text-protocol.html, Text protocol)
    $(LINK http://dev.mysql.com/doc/internals/en/prepared-statements.html, Prepared statements)
    $(LINK http://dev.mysql.com/doc/internals/en/connection-phase.html, Connection phase)

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.protocol.commands;

import std.exception;
import std.array;
debug import std.stdio;

import mysql.common;
import mysql.protocol.constants;
import mysql.protocol.extra_types;
import mysql.protocol.packets;
import mysql.connection;

/++
Connects to a server.

This will parse the initial handshake, and send a response.

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/connection-phase.html, Connection phase)
+/
struct Connect
{
public:
    @property
    {
        /// The initial HandshakePacket containing server information
        HandshakePacket greeting() { return _greeting; }
    }

    /// Connect
    OKPacket exec(Connection cn, in string user, in string pwd, in string db,
            in CapabilityFlags clientCapabilities)
    {
        enforceEx!MYX(cn.pktNumber == 0,
                "Cannot run command. Another command already in action.");
        scope(success) cn.resetPacket();
        _greeting = HandshakePacket(cn.getPacket());
        auto res = HandshakeResponsePacket(user, pwd, db,
                clientCapabilities, _greeting.authBuf);

        cn.sendPacket(res.packet);

        auto packet = cn.getPacket();
        packet.enforceOK();
        return OKPacket(packet);
    }

private:
    HandshakePacket _greeting;
}

/++
Ping the server

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-ping.html, COM_PING)
+/
struct ComPing
{
    /// Ping server
    static OKPacket exec(Connection cn)
    {
        scope(success) cn.resetPacket();
        cn.sendCommand(CommandType.PING, []);
        auto packet = cn.getPacket();
        packet.enforceOK();
        return OKPacket(packet);
    }
}

struct ComRefresh
{
    static OKPacket exec(Connection cn, RefreshFlags flags)
    {
        scope(success) cn.resetPacket();
        cn.sendCommand(CommandType.REFRESH, [flags]);
        auto packet = cn.getPacket();
        packet.enforceOK();
        return OKPacket(packet);
    }
}

/++
Quit from the server. This is not intended to be called from other than
Connection

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-quit.html, COM_QUIT)
+/
struct ComQuit
{
    /// Quit
    static void exec(Connection cn)
    {
        scope(success) cn.resetPacket();
        cn.sendCommand(CommandType.QUIT, []);
        // This will either return an OK packet, or close the connection.
        // We don't care either way
    }
}

/++
Human readable short server statistics.

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-statistics.html, COM_STATISTICS)
+/
struct ComStatistics
{
    /// Returns statistics
    static string exec(Connection cn)
    {
        scope(success) cn.resetPacket();
        cn.sendCommand(CommandType.STATISTICS, []);
        return cast(string)cn.getPacket();
    }
}

/++
Change default schema for commands.

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-init-db.html, COM_INIT_DB)
+/
struct ComInitDB
{
   /// Change default schema
    static void exec(Connection cn, in string db)
    {
        scope(exit) cn.resetPacket();
        cn.sendCommand(CommandType.INIT_DB, db);
        auto packet = cn.getPacket();
        packet.enforceOK();
    }
}

/++
Returns column definitions matching a wildcard for a given table.

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-field-list.html, COM_FIELD_LIST)
+/
struct ComFieldList
{
public:
    /// Return column definitions
    static ColumnDefinition[] exec(Connection cn, in string table, in string fieldWildcard)
    {
        scope(exit) cn.resetPacket();

        // Build request
        size_t len = table.length + fieldWildcard.length;
        if(!table.length || table[$-1] != '\0')
            ++len; // table termanated by \0
        auto req = new ubyte[len];
        (cast(ubyte[])table).encodeInto(req);
        (cast(ubyte[])fieldWildcard).encodeInto(req[table.length+1..$]);
        cn.sendCommand(CommandType.FIELD_LIST, req);

        // Handle response
        auto res = cn.getPacket();
        if(res.isErrorPacket)
        {
            throw new MySQLErrorPacketException(ErrorPacket(res),
                    "Unable to get field list for "~table~"."~fieldWildcard);
        }

        ColumnDefinition[] columns;
        while(!res.isEOFPacket())
        {
            columns ~= ColumnDefinition(res);
            res = cn.getPacket();
        }
        return columns;
    }
}

/++
Returns a list of active threads on the server

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-process-info.html, COM_PROCESS_INFO)
+/
struct ComProcessInfo
{
public:
    /// List of active threads
    static TextResultSet exec(Connection cn)
    {
        scope(exit) cn.resetPacket();
        cn.sendCommand(CommandType.PROCESS_INFO, []);
        auto packet = cn.getPacket();
        if(packet.isErrorPacket())
        {
            throw new MySQLErrorPacketException(ErrorPacket(packet),
                    "Unable to get process info.");
        }

        return TextResultSet(cn, packet);
    }
}

/++
Executes an SQL query without parameters.

BUGS:
    All rows are eagerly fetched.

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-query.html, COM_QUERY)
+/
struct ComQuery
{
public:
    @property
    {
        /// Information on a query that doesn't creates a TextResultSet
        OKPacket okPacket() pure nothrow { return _okPacket; }

        /// Result of a query. (e.g. SELECT)
        TextResultSet[] results() pure nothrow { return _results; }
    }

    /// Executes query
    void exec(Connection cn, in string query)
    {
        scope(exit) cn.resetPacket();
        cn.sendCommand(CommandType.QUERY, cast(ubyte[])query);
        auto packet = cn.getPacket();
        if(packet.isErrorPacket)
        {
            throw new MySQLErrorPacketException(ErrorPacket(packet));
        }
        else if(packet.isOKPacket) // Didn't return a result
        {
            _okPacket = OKPacket(packet);
        }
        else
        {
            // TODO: Handle LOCAL_INFILE_Request
            while(true)
            {
                _results ~= TextResultSet(cn, packet);
                packet.enforceEOF();
                auto eof = EOFPacket(packet);
                if((eof.serverStatus & ServerStatus.MORE_RESULTS_EXISTS) == 0)
                    break;
                else
                    packet = cn.getPacket();
            }

//            // The specification says multi resultsets should be terminated by an
//            // empty resultset and an ok packet, but I don't receive any more packets.
//            if(results.length > 1)
//            {
//                packet.enforceOK("Multi result set queries should end with an OK"~
//                        "packet");
//            }
        }
    }

private:
    OKPacket _okPacket;
    TextResultSet[] _results;
}

/++
The result of a query without parameters.

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::Resultset, ProtocolText::ResultSet)
+/
struct TextResultSet
{
public:
    @property
    {
        /// Number of warnings
        short numWarnings() const pure nothrow { return _numWarnings; }

        /// Columns in resultset
        ColumnDefinition[] columns() pure nothrow { return _columns; }

        /// Rows
        TextRow[] rows() pure nothrow { return _rows; }

        /// Number of rows
        size_t length() const pure nothrow { return _rows.length; }
    }

    /// Fetch a row based on index
    TextRow opIndex(size_t i) pure nothrow { return _rows[i]; }

private:
    /++
    Fetches all rows in result

    Params:
        cn     = connection
        packet = The initial packet of the query
    +/
    this(Connection cn, ref ubyte[] packet)
    {
        auto res = ResultSet(packet);
        _columns = readColumnDefinitions(cn, res.columnCount, _numWarnings);

        // TODO: Preinitialize rows? We don't know in advance how many rows
        //       will be returned, so this might cause many reallocations.

        for(packet = cn.getPacket()
            ; !(packet.isEOFPacket || packet.isErrorPacket)
            ; packet = cn.getPacket())
        {
            TextRow row;
            row.exec(cn, packet, _columns);
            _rows ~= row;
            assert(!packet.length);
        }

        if(packet.isErrorPacket)
        {
            throw new MySQLErrorPacketException(ErrorPacket(packet),
                "Unable to get text row.");
        }
    }

    ColumnDefinition[] _columns;
    TextRow[] _rows;
    short _numWarnings;
}

/++
Row values for a query. All values are stored as raw text.

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::ResultsetRow, ProtocolText::ResultsetRow)
+/
struct TextRow
{
public:
    @property
    {
        /// Values
        string[] values() pure nothrow { return _values; }

        /// Number of values
        size_t length() const pure nothrow { return _values.length; }
    }

    /// Get a value based on index
    string opIndex(size_t i) pure nothrow
    {
        return _values[i];
    }

private:
    /++
    Fetches all row values from the server.

    Params:
        cn      = connection
        packet  = Initial row packet
        columns = Columns in the resultset
    +/
    void exec(Connection cn, ref ubyte[] packet, in ColumnDefinition[] columns)
    {
        _values = minimallyInitializedArray!(string[])(columns.length);
        foreach(i; 0 .. _values.length)
        {
            if(packet.empty)
                packet = cn.getPacket();

            if(packet.front == 0xfb) // Null marker for text protocol rows
            {
                packet.popFront();
            }
            else
            {
                auto lci = packet.consumeIfComplete!LCI();
                while(lci.isIncomplete)
                {
                    // FIXME: Avoid these allocations. Will be very slow if
                    //        fetching large data.
                    packet ~= cn.getPacket();
                    lci = packet.consumeIfComplete!LCI();
                }
                assert(!lci.isNull);
                assert(!lci.isIncomplete);
                _values[i] = packet.consume!string(cast(size_t)lci.value);
                if(columns[i].type == SQLType.TINY && columns[i].length == 1)
                    _values[i] = (_values[i] == "1" ? "true" : "false");
            }
        }
        assert(!packet.length);
    }

    string[] _values;
}

/++
Prepare a prepared statement

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-stmt-prepare.html, COM_STMT_PREPARE)
+/
struct ComStmtPrepare
{
public:
    @property
    {
        /// Number of warnings
        short numWarnings() const pure nothrow { return _numWarnings; }

        /// Number of columns in the resultset
        ColumnDefinition[] columns() pure nothrow { return _columns; }

        /// Number of parameters in the query
        ColumnDefinition[] params() pure nothrow { return _params; }

        /// Server response for the command
        StmtPrepareOK prepareResponse() pure nothrow { return _prepareResponse; }
    }

    /// Prepares a query
    void exec(Connection cn, in string query)
    {
        scope(exit) cn.resetPacket();
        cn.sendCommand(CommandType.STMT_PREPARE, cast(ubyte[])query);
        auto packet = cn.getPacket();
        if(packet.isErrorPacket)
            throw new MySQLErrorPacketException(ErrorPacket(packet));
        _prepareResponse = StmtPrepareOK(packet);
        _numWarnings = _prepareResponse.numWarnings;
        if(_prepareResponse.numParams)
            _params = readColumnDefinitions(cn, _prepareResponse.numParams, _numWarnings);
        if(_prepareResponse.numColumns)
            _columns = readColumnDefinitions(cn, _prepareResponse.numColumns, _numWarnings);
    }
    alias prepareResponse this;

private:
    short _numWarnings;
    StmtPrepareOK _prepareResponse;
    ColumnDefinition[] _params;
    ColumnDefinition[] _columns;
}

/++
Executes a prepared statement

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/com-stmt-execute.html, COM_STMT_EXECUTE)
+/
struct ComStmtExecute
{
public:
    @property
    {
        /// Information about queries that doesn't return a result set
        OKPacket okPacket() pure nothrow { return _okPacket; }

        /// Results from the query
        BinaryResultSet[] results() pure nothrow { return _results; }
    }

    /// Execute a prepared statement
    void exec(Connection cn, ref ComStmtExecutePacket exePacket)
    {
        scope(exit) cn.resetPacket();
        cn.sendCommand(CommandType.STMT_EXECUTE, exePacket.packet);
        auto packet = cn.getPacket();
        if(packet.isErrorPacket)
            throw new MySQLErrorPacketException(ErrorPacket(packet));
        if(packet.isOKPacket())
            _okPacket = OKPacket(packet);
        else
            _results ~= BinaryResultSet(cn, packet);
    }

private:
    OKPacket _okPacket;
    BinaryResultSet[] _results;
}

/++
Result set from a prepared statement

See_Also: $(LINK http://dev.mysql.com/doc/internals/en/binary-protocol-resultset.html, Binary Protocol Resultset)
+/
struct BinaryResultSet
{
public:
    @property
    {
        /// Number of rows
        size_t length() const pure nothrow { return _rows.length; }

        /// Columns
        ColumnDefinition[] columns() pure nothrow { return _columns; }
    }

    /// Returns a row based on index
    BinaryRow opIndex(size_t i) { return _rows[i]; }

    /// Construct
    this(Connection cn, ubyte[] packet)
    {
        auto lci = packet.consumeIfComplete!LCI();
        assert(!lci.isNull);
        assert(!lci.isIncomplete);
        long columnCount = lci.value;
        short numWarnings;
        _columns = readColumnDefinitions(cn, columnCount, numWarnings);
        for(packet = cn.getPacket(); !packet.isEOFPacket; packet = cn.getPacket())
            _rows ~= BinaryRow(packet, _columns);
        assert(packet.isEOFPacket());
    }

private:
    ColumnDefinition[] _columns;
    BinaryRow[] _rows;
}

/++
Send an initial command to the server.

This will set the required packet header and make sure we doesn't execute
commands out of order.
+/
private void sendCommand(T)(Connection cn, in CommandType cmd, in T[] data = [])
in
{
    import std.conv;
    assert(cn.pktNumber == 0, "Another command in action with id " ~ cn.pktNumber.to!string);

    // Internal thread states. Clients shouldn't use this
    assert(cmd != CommandType.SLEEP);
    assert(cmd != CommandType.CONNECT);
    assert(cmd != CommandType.TIME);
    assert(cmd != CommandType.DELAYED_INSERT);
    assert(cmd != CommandType.CONNECT_OUT);

    // Deprecated
    assert(cmd != CommandType.CREATE_DB);
    assert(cmd != CommandType.DROP_DB);
    assert(cmd != CommandType.TABLE_DUMP);

    // cannot send more than uint.max bytes. TODO: better error message if we try?
    assert(data.length <= uint.max);
}
out
{
    // at this point we should have sent a command
    assert(cn.pktNumber == 1, "Another command has executed while sending command");
}
body
{
    ubyte[] header;
    header.length = 4 /*header*/ + 1 /*cmd*/;
    header.setPacketHeader(cn.pktNumber, cast(uint)data.length +1/*cmd byte*/);
    header[4] = cmd;
    cn.write(header, cast(ubyte[])data);
    cn.bumpPacket();
}


/++
Reads column definition from a connection

Params:
    cn          = connection
    num         = number of columns
    numWarnings = an aggregate of all warnings in the columns
+/
ColumnDefinition[] readColumnDefinitions(Connection cn, long num,
        ref short numWarnings)
{
    assert(num <= size_t.max);
    assert(num >= size_t.min);
    auto columns = minimallyInitializedArray!(ColumnDefinition[])(cast(size_t)num);
    if(columns.length)
    {
        foreach (size_t i; 0..columns.length)
            columns[i] = ColumnDefinition(cn.getPacket());
        auto packet = cn.getPacket();
        packet.enforceEOF();
        auto eof = EOFPacket(packet);
        numWarnings += eof.warnings;
    }
    return columns;
}

