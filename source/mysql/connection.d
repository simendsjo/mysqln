/++
A connection to MySQL

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.connection;

import mysql.protocol.protocol;
import mysql.protocol.commands;
import mysql.protocol.packet_helpers;
import mysql.common;

version(Have_vibe_d)
{
    static if(__traits(compiles, (){ import vibe.core.net; } ))
        import vibe.core.net;
    else
        static assert(false, "mysql-native can't find Vibe.d's 'vibe.core.net'.");
}

import std.algorithm;
import std.conv;
import std.datetime;
import std.exception;
import std.range;
import std.socket;
import std.stdio;
import std.string;
import std.traits;
import std.variant;

/// Default flags used if no capabilities is sent when connecting to the server
immutable CapabilityFlags defaultClientFlags =
        CapabilityFlags.LONG_PASSWORD
        | CapabilityFlags.LONG_FLAG
        | CapabilityFlags.CONNECT_WITH_DB
        | CapabilityFlags.PROTOCOL_41
        | CapabilityFlags.SECURE_CONNECTION
        | CapabilityFlags.MULTI_RESULTS
        | CapabilityFlags.MULTI_STATEMENTS
        | CapabilityFlags.PS_MULTI_RESULTS // FIXME: PS_MULTI_RESULTS Doesn't work
        ;

/++
A database connection.

Implementation_notes:
    The Connection is responsible for handshaking with the server to establish
    authentication.  It then passes client preferences to the server, and
    subsequently is the channel for all command packets that are sent, and all
    response packets received.

    Uncompressed packets consist of a 4 byte header - 3 bytes of length, and
    one byte as a packet number. Connection deals with the headers and ensures
    that packet numbers are sequential.

    The initial packet is sent by the server - esentially a 'hello' packet
    inviting login. That packet has a sequence number of zero. That sequence
    number is the incremented by client and server packets through the
    handshake sequence.

    After login all further sequences are initialized by the client sending
    a command packet with a zero sequence number, to which the server replies
    with zero or more packets with sequential sequence numbers.
+/
class Connection : MySQLEventedObject
{
public:

    /// Returns info sent by the server when connecting
    @property HandshakePacket serverInfo() pure nothrow { return _greeting; }

    /// Server capability flags
    @property CapabilityFlags serverCapabilities() pure const nothrow
    {
        return _greeting.serverCapabilities;
    }

    /// Database supplied when connecting
    @property string initialDB() pure const nothrow { return _db; }

    /// Socket type being used
    @property MySQLSocketType socketType() pure const nothrow { return _socketType; }

    /// INTERNAL: Sends a packet
    void sendPacket(ubyte[] packet)
    {
        packet.setPacketHeader(pktNumber);
        write(packet);
        bumpPacket();
    }

    /// INTERNAL: Write to the underlying socket
    void write(in ubyte[] packet)
    in
    {
        assert(packet.length > 4); // at least 1 byte more than header
    }
    body
    {
        _socket.write(packet);
    }

    /// INTERNAL: Write to the underlying socket
    void write(in ubyte[] header, in ubyte[] data)
    in
    {
        assert(header.length == 4 || header.length == 5/*command type included*/);
    }
    body
    {
        _socket.write(header);
        if(data.length)
            _socket.write(data);
    }

    /// INTERNAL: Current packetnumber
    @property ubyte pktNumber() const pure nothrow { return _sequenceId.id; }

    /// INTERNAL: Increments packet number
    void bumpPacket() pure nothrow { _sequenceId.bump(); }

    /// INTERNAL: Sets the packet number to zero
    void resetPacket() pure nothrow { _sequenceId = SequenceId.init; }

    /// INTERNAL: Reads next packet from server
    ubyte[] getPacket()
    {
        ubyte[4] header;
        _socket.read(header);
        // number of bytes always set as 24-bit
        uint numDataBytes = (header[2] << 16) + (header[1] << 8) + header[0];
        mypenforce(header[3] == pktNumber, "Server packet out of order");
        bumpPacket();

        ubyte[] packet = new ubyte[numDataBytes];
        _socket.read(packet);
        assert(packet.length == numDataBytes, "Wrong number of bytes read");
        return packet;
    }

    /++
    Construct opened connection.

    After the connection is created, and the initial invitation is received
    from the server client preferences can be set, and authentication can then
    be attempted.

    Params:
       host       = An IP address in numeric dotted form, or as a host  name.
       user       = The user name to authenticate.
       pwd        = Users password.
       db         = Desired initial database.
       port       = Port
       capFlags   = The set of flag bits from the server's capabilities that
                    the client requires
    +/
    this(string host, string user, string pwd, string db, ushort port = 3306, CapabilityFlags capFlags = defaultClientFlags)
    {
        version(Have_vibe_d)
            enum defaultSocketType = MySQLSocketType.vibed;
        else
            enum defaultSocketType = MySQLSocketType.phobos;

        this(defaultSocketType, host, user, pwd, db, port, capFlags);
    }

    /// ditto
    this(MySQLSocketType socketType, string host, string user, string pwd, string db, ushort port = 3306, CapabilityFlags capFlags = defaultClientFlags)
    {
        version(Have_vibe_d) {} else
            enforceEx!MYX(socketType != MySQLSocketType.vibed, "Cannot use Vibe.d sockets without -version=Have_vibe_d");

        this(socketType, &defaultOpenSocketPhobos, &defaultOpenSocketVibeD,
            host, user, pwd, db, port, capFlags);
    }

    /// ditto
    this(OpenSocketCallbackPhobos openSocket,
        string host, string user, string pwd, string db, ushort port = 3306, CapabilityFlags capFlags = defaultClientFlags)
    {
        this(MySQLSocketType.phobos, openSocket, null, host, user, pwd, db, port, capFlags);
    }

    version(Have_vibe_d)
    /// ditto
    this(OpenSocketCallbackVibeD openSocket,
        string host, string user, string pwd, string db, ushort port = 3306, CapabilityFlags capFlags = defaultClientFlags)
    {
        this(MySQLSocketType.vibed, null, openSocket, host, user, pwd, db, port, capFlags);
    }

    private this(MySQLSocketType socketType,
        OpenSocketCallbackPhobos openSocketPhobos, OpenSocketCallbackVibeD openSocketVibeD,
        string host, string user, string pwd, string db, ushort port = 3306, CapabilityFlags capFlags = defaultClientFlags)
    in
    {
        final switch(socketType)
        {
            case MySQLSocketType.phobos: assert(openSocketPhobos !is null); break;
            case MySQLSocketType.vibed:  assert(openSocketVibeD  !is null); break;
        }
    }
    body
    {
        enforceEx!MYX(capFlags & CapabilityFlags.PROTOCOL_41, "This client only supports protocol v4.1");
        enforceEx!MYX(capFlags & CapabilityFlags.SECURE_CONNECTION, "This client only supports protocol v4.1 connection");
        version(Have_vibe_d) {} else
            enforceEx!MYX(socketType != MySQLSocketType.vibed, "Cannot use Vibe.d sockets without -version=Have_vibe_d");

        _socketType = socketType;
        _host = host;
        _user = user;
        _pwd = pwd;
        _db = db;
        _port = port;

        _openSocketPhobos = openSocketPhobos;
        _openSocketVibeD  = openSocketVibeD;

        connect(capFlags);
    }

    /++
    Construct opened connection.

    After the connection is created, and the initial invitation is received
    from the server client preferences are set, and authentication can then be
    attempted.

    Bugs:
        The connection string needs work to allow for semicolons in its parts!

    Params:
        cs         = A connection string of the form
                     "host=localhost;user=user;pwd=password;db=mysqld"
        capFlags   = The set of flag bits from the server's capabilities that
                     the client requires
    +/
    this(string cs, CapabilityFlags capFlags = defaultClientFlags)
    {
        string[] a = parseConnectionString(cs);
        this(a[0], a[1], a[2], a[3], to!ushort(a[4]), capFlags);
    }

    ///ditto
    this(MySQLSocketType socketType, string cs, CapabilityFlags capFlags = defaultClientFlags)
    {
        string[] a = parseConnectionString(cs);
        this(socketType, a[0], a[1], a[2], a[3], to!ushort(a[4]), capFlags);
    }

    ///ditto
    this(OpenSocketCallbackPhobos openSocket, string cs, CapabilityFlags capFlags = defaultClientFlags)
    {
        string[] a = parseConnectionString(cs);
        this(openSocket, a[0], a[1], a[2], a[3], to!ushort(a[4]), capFlags);
    }

    version(Have_vibe_d)
    {
        ///ditto
        this(OpenSocketCallbackVibeD openSocket, string cs, CapabilityFlags capFlags = defaultClientFlags)
        {
            string[] a = parseConnectionString(cs);
            this(openSocket, a[0], a[1], a[2], a[3], to!ushort(a[4]), capFlags);
        }
    }

    /// Returns true if the connection is closed
    @property bool closed()
    {
        return _open == OpenState.notConnected || !_socket.connected;
    }

    version(Have_vibe_d)
    {
        void acquire() { if( _socket ) _socket.acquire(); }
        void release() { if( _socket ) _socket.release(); }
        bool isOwner() { return _socket ? _socket.isOwner() : false; }
        bool amOwner() { return _socket ? _socket.isOwner() : false; }
    }
    else
    {
        void acquire() { /+ Do nothing +/ }
        void release() { /+ Do nothing +/ }
        bool isOwner() { return !!_socket; }
        bool amOwner() { return !!_socket; }
    }

    /++
    Explicitly close the connection.

    This is a two-stage process. First tell the server we are quitting this
    connection, and then close the socket.

    Idiomatic use as follows is suggested:
    ------------------
    {
        auto con = Connection("localhost:user:password:mysqld");
        scope(exit) con.close();
        // Use the connection
        ...
    }
    ------------------
    +/
    void close()
    {
        if (_open == OpenState.authenticated && _socket.connected)
            quit();

        if (_open == OpenState.connected)
        {
            if(_socket.connected)
                _socket.close();
            _open = OpenState.notConnected;
        }
        resetPacket();
    }

    /++
    Reconnects to the database.

    If the connection is already open and no
    changes is made to the client capability flags has been made, it just
    returns.
    +/
    void reconnect()
    {
        reconnect(_clientCapabilities);
    }

    /// ditto
    void reconnect(CapabilityFlags clientCapabilities)
    {
        bool sameCaps = clientCapabilities == _clientCapabilities;
        if(!closed)
        {
            // Same caps as before?
            if(clientCapabilities == _clientCapabilities)
                return; // Nothing to do, just keep current connection

            close();
        }

        connect(clientCapabilities);
    }

    /// Send quit to the server
    private void quit()
    in
    {
        assert(_open == OpenState.authenticated);
    }
    out
    {
        assert(_open == OpenState.notConnected);
    }
    body
    {
        ComQuit.exec(this);
        _open = OpenState.notConnected;
    }

    static string[] parseConnectionString(string cs)
    {
        string[] rv;
        rv.length = 5;
        rv[4] = "3306"; // Default port
        string[] a = split(cs, ";");
        foreach (s; a)
        {
            string[] a2 = split(s, "=");
            enforceEx!MYX(a2.length == 2, "Bad connection string: " ~ cs);
            string name = strip(a2[0]);
            string val = strip(a2[1]);
            switch (name)
            {
                case "host":
                    rv[0] = val;
                    break;
                case "user":
                    rv[1] = val;
                    break;
                case "pwd":
                    rv[2] = val;
                    break;
                case "db":
                    rv[3] = val;
                    break;
                case "port":
                    rv[4] = val;
                    break;
                default:
                    throw new MYX("Bad connection string: " ~ cs, __FILE__, __LINE__);
            }
        }
        return rv;
    }

protected:
    SequenceId _sequenceId;

    enum OpenState
    {
        /++
        We have not yet connected to the server, or have sent QUIT to the
        server and closed the connection
        +/
        notConnected,

        /++
        We have connected to the server and parsed the greeting, but not yet
        authenticated
        +/
        connected,

        /++
        We have successfully authenticated against the server, and need to send
        QUIT to the server when closing the connection
        +/
        authenticated

    }
    OpenState   _open;
    MySQLSocket _socket;

    CapabilityFlags _clientCapabilities;
    uint    _connectionId;

    string _host, _user, _pwd, _db;
    ushort _port;

    MySQLSocketType _socketType;

    OpenSocketCallbackPhobos _openSocketPhobos;
    OpenSocketCallbackVibeD  _openSocketVibeD;

    version(Have_vibe_d) {} else
    pure const nothrow invariant()
    {
        assert(_socketType != MySQLSocketType.vibed);
    }

    static PlainPhobosSocket defaultOpenSocketPhobos(string host, ushort port)
    {
        auto s = new PlainPhobosSocket();
        s.connect(new InternetAddress(host, port));
        return s;
    }

    static PlainVibeDSocket defaultOpenSocketVibeD(string host, ushort port)
    {
        version(Have_vibe_d)
            return vibe.core.net.connectTcp(host, port);
        else
            assert(0);
    }

    void initConnection()
    {
        resetPacket();
        final switch(_socketType)
        {
            case MySQLSocketType.phobos:
                _socket = new MySQLSocketPhobos(_openSocketPhobos(_host, _port));
                break;

            case MySQLSocketType.vibed:
                version(Have_vibe_d) {
                    _socket = new MySQLSocketVibeD(_openSocketVibeD(_host, _port));
                    break;
                } else assert(0, "Unsupported socket type. Need version Have_vibe_d.");
        }
    }

    CapabilityFlags getCommonCapabilities(CapabilityFlags server, CapabilityFlags client) pure
    {
        CapabilityFlags common;
        uint filter = CapabilityFlags.min;
        while(true)
        {
            bool serverSupport = (server & filter) != 0; // can the server do this capability?
            bool clientSupport = (client & filter) != 0; // can we support it?
            if(serverSupport && clientSupport)
                common |= filter;
            if(filter == CapabilityFlags.max)
                break;
            filter <<= 1; // check next flag
        }
        return common;
    }

    void connect(CapabilityFlags clientCapabilities)
    in
    {
        assert(closed);
    }
    out
    {
        assert(_open == OpenState.authenticated);
    }
    body
    {
        initConnection();
        _clientCapabilities = clientCapabilities;

        // We cannot operate in <4.1 protocol, so we'll force it even if the user
        // didn't supply it
        _clientCapabilities |= CapabilityFlags.PROTOCOL_41;
        _clientCapabilities |= CapabilityFlags.SECURE_CONNECTION;

        Connect cmd;
        cmd.exec(this, _user, _pwd, _db, _clientCapabilities);
        _greeting = cmd.greeting;
        _clientCapabilities = getCommonCapabilities(serverCapabilities, _clientCapabilities);

        // TODO: Make sure we succeeded before setting this
        _open = OpenState.authenticated;
    }

    HandshakePacket _greeting;

}
