/++
Constants related to the MySQL protocol

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.protocol.constants;

/++
Server and client capability flags.

Used to communicate what features are supported, and what you want to use.

Server: How the server interprets the values
Client: How the client is supposed to interpret the values

See_Also: http://dev.mysql.com/doc/internals/en/connection-phase.html#capability-flags
+/
enum CapabilityFlags: uint
{
    /++
    Use improved "Old Password Authentication". Deprecated in 4.1.1
    +/
    LONG_PASSWORD       = 0x0000_0001,

    /++
    Send found rows instead of affected rows in EOF packets
    +/
    FOUND_ROWS          = 0x0000_0002,

    /++
    Longer flags in ColumnDefinition / ColumnDescription

    Server: Supports longer flags
    Client: Expects longer flags
    +/
    LONG_FLAG           = 0x0000_0004,

    /++
    Can specify database on connect in HandshakeResponsePacket

    Server: Supports schema-name in HandshakeResponsePacket
    Client: HandshakeResponsePacket contains database
    +/
    CONNECT_WITH_DB     = 0x0000_0008,

    /++
    Server: Don't allow database.table.column
    +/
    NO_SCHEMA           = 0x0000_0010,

    /++
    Compression protocol supported.

    Server: Supports compression
    Client: Switches to compressed protocol after successful auth
    +/
    COMPRESS            = 0x0000_0020,

    /++
    Special handling of ODBC behaviour
    +/
    ODBC                = 0x0000_0040,

    /++
    Can use LOAD DATA LOCAL
    +/
    LOCAL_FILES         = 0x0000_0080,

    /++
    Server: Parser can ignore spaces before '$(LPAREN)'
    Client: Let the parser ignore spaces before '$(LPAREN)'
    +/
    IGNORE_SPACE        = 0x0000_0100,

    /++
    Server: Supports the 4.1 protocol
    Client: USes the 4.1 protocol
    +/
    PROTOCOL_41         = 0x0000_0200,

    /++
    wait_timeout vs. wait_interactive_timeout

    Server: Supports interactive and non-interactive clients
    Client: Client is interactive
    +/
    INTERACTIVE         = 0x0000_0400,

    /++
    Server: Supports SSL
    Client: Switch to SSL after sending the capability-flags
    +/
    SSL                 = 0x0000_0800,

    /++
    Client: Don't issue SIGPIPE if network failures (libmysqlclient only)
    See_Also: http://dev.mysql.com/doc/refman/5.0/en/mysql-real-connect.html
    +/
    IGNORE_SIGPIPE      = 0x0000_1000,

    /++
    Always enabled in the server

    Server: Can send status flags in EOFPacket
    Client: Expects status flags in EOFPacket
    +/
    TRANSACTIONS        = 0x0000_2000,

    /++
    Unused. Was PROTOCOL_41 in version 4.1.0
    See PROTOCOL_41
    +/
    RESERVED            = 0x0000_4000,

    /++
    See_Also: http://dev.mysql.com/doc/internals/en/secure-password-authentication.html#packet-Authentication::Native41

    Server: Supports secure authentication
    Client: Supports secure authentication
    +/
    SECURE_CONNECTION   = 0x0000_8000,

    /++
    Server: Can handle multiple statements per ComQuery and ComStmtPrepare
    Client: May send multiple statements per ComQuery and ComStmtPrepare
    +/
    MULTI_STATEMENTS    = 0x0001_0000,

    /++
    Server: Can send multiple resultsets for ComQuery
    Client: Can handle multiple resultsets for ComQuery
    +/
    MULTI_RESULTS       = 0x0002_0000,

    /++
    Server: Can send multiple resultsets for ComStmtExecute
    Client: Can handle multiple resultsets for ComStmtExecute
    +/
    PS_MULTI_RESULTS    = 0x0004_0000,

    /++
    Server: "Supports more fields in" (.. yes, thats what the documentation says..)
    Client: Supports auth plugins
    +/
    PLUGIN_AUTH         = 0x0008_0000,

    /++
    Server: Allows connection attributes in HandshakeResponse
    Client: Sends connection attributes in HandshakeResponse
    +/
    CONNECT_ATTRS       = 0x0010_0000,

    /++
    Server: Understands length encoded integer (LCB) for auth response data in
            HandshakeResponse.
    Client: Length of auth response data in HandshakeResponse is a length
            encoded integer (LCB)
    +/
    PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x0010_0000,
}


/++
Type of Command Packet (COM_XXX)

See_Also: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Command_Packet_.28Overview.29
+/
enum CommandType : ubyte
{
    SLEEP               = 0x00,

    /// Tell server to close our connection
    QUIT                = 0x01,

    /// Change default schema for connection
    INIT_DB             = 0x02,

    /// Send a text based query that is executed immediately
    QUERY               = 0x03,

    /// Get column definition for a table
    FIELD_LIST          = 0x04,

    /// DEPRECATED. Creates a schema
    CREATE_DB           = 0x05,

    /// DEPRECATED. Drop a schema
    DROP_DB             = 0x06,

    /// Call REFRESH or FLUSH statements
    REFRESH             = 0x07,

    /// Shutdown server
    SHUTDOWN            = 0x08,

    /// Get a list of active threads
    STATISTICS          = 0x09,

    /// Get a list of active threads
    PROCESS_INFO        = 0x0a,

    /// Internal server command
    CONNECT             = 0x0b,

    /// Ask the server to terminate a connection
    PROCESS_KILL        = 0x0c,

    /++
    Triggers a dump on internal debug info to stdout on the server.
    Requires SUPER privilege.
    +/
    DEBUG               = 0x0d,

    /// Check if server is alive
    PING                = 0x0e,

    /// Internal server command
    TIME                = 0x0f,

    /// Internal server command
    DELAYED_INSERT      = 0x10,

    /// Change user for current connection
    CHANGE_USER         = 0x11,

    /// Request binlog-stream from server
    BINLOG_DUBP         = 0x12,

    /// Dump a table
    TABLE_DUMP          = 0x13,

    /// Internal server command
    CONNECT_OUT         = 0x14,

    /// Register a slave at the master
    REGISTER_SLAVE      = 0x15,

    /// Create a prepared statement
    STMT_PREPARE        = 0x16,

    /// Execute a prepared statement
    STMT_EXECUTE        = 0x17,

    /// Sends data for a column. Has to be sent before STMT_EXECUTE.
    STMT_SEND_LONG_DATA = 0x18,

    /// Deallocates a prepared statement
    STMT_CLOSE          = 0x19,

    /// Reset prepared statement data accumulated with STMT_SEND_LONG_DATA.
    STMT_RESET          = 0x1a,

    /// Enable/disable MultiStatement
    SET_OPTION         = 0x1b,

    /// Fetch a row from a existing resultset after a STMT_EXECUTE
    STMT_FETCH         = 0x1c,

    /// Internal server command
    DAEMON             = 0x1d,

    /// Request the Binlog Network Stream based on a GTID
    BINLOG_DUMP_GTID   = 0x1e,
}

/++
Binlog flags

See_Also: http://dev.mysql.com/doc/internals/en/com-binlog-dump-gtid.html#packet-COM_BINLOG_DUMP_GTID
+/
enum BinlogFlags
{
    /// DUMP_NON_BLOCK
    DUMP_NON_BLOCK      = 0x01,

    /// THROUGH_POSITION
    THROUGH_POSITION    = 0x02,

    /// THROUGH_GTID
    THROUGH_GTID        = 0x04,
}

/++
Server status

See_Also: http://dev.mysql.com/doc/internals/en/status-flags.html
+/
enum ServerStatus : ushort
{
    IN_TRANS                = 0x0001, /// A transaction is active
    AUTOCOMMIT              = 0x0002, /// Autocommit is enabled
    MORE_RESULTS_EXISTS     = 0x0008, /// MORE_RESULTS_EXISTS
    NO_GOOD_INDEX_USED      = 0x0010, /// NO_GOOD_INDEX_USED
    NO_INDEX_USED           = 0x0020, /// NO_INDEX_USED
    CURSOR_EXISTS           = 0x0040, /// CURSOR_EXISTS
    LAST_ROW_SENT           = 0x0080, /// LAST_ROW_SENT
    DB_DROPPED              = 0x0100, /// DB_DROPPED
    NO_BACKSLASH_ESCAPES    = 0x0200, /// NO_BACKSLASH_ESCAPES
    METADATA_CHANGED        = 0x0400, /// METADATA_CHANGED
    QUERY_WAS_SLOW          = 0x0800, /// QUERY_WAS_SLOW
    PS_OUT_PARAMS           = 0x1000, /// PS_OUT_PARAMS
}

/++
Cursor type

See_Also: http://dev.mysql.com/doc/internals/en/com-stmt-execute.html
+/
enum CursorType : ubyte
{
    NO_CURSOR  = 0x00,
    READ_ONLY  = 0x01,
    FOR_UPDATE = 0x02,
    SCROLLABLE = 0x04
}

/++
Column type codes
See_Also: http://dev.mysql.com/doc/internals/en/com-query-response.html#column-type
+/
enum SQLType : ubyte
{
    DECIMAL      = 0x00,
    TINY         = 0x01,
    SHORT        = 0x02,
    INT          = 0x03,
    FLOAT        = 0x04,
    DOUBLE       = 0x05,
    NULL         = 0x06,
    TIMESTAMP    = 0x07,
    LONGLONG     = 0x08,
    INT24        = 0x09,
    DATE         = 0x0a,
    TIME         = 0x0b,
    DATETIME     = 0x0c,
    YEAR         = 0x0d,
    NEWDATE      = 0x0e,
    VARCHAR      = 0x0f, // new in MySQL 5.0
    BIT          = 0x10, // new in MySQL 5.0
    INFER_FROM_D_TYPE = 0x11, // HACK: This value might be used in a future version of MySQL
    NEWDECIMAL   = 0xf6, // new in MYSQL 5.0
    ENUM         = 0xf7,
    SET          = 0xf8,
    TINYBLOB     = 0xf9,
    MEDIUMBLOB   = 0xfa,
    LONGBLOB     = 0xfb,
    BLOB         = 0xfc,
    VARSTRING    = 0xfd,
    STRING       = 0xfe,
    GEOMETRY     = 0xff
}

/// Special marker for sign/unsign of prepared parameters
enum SQLSign : ubyte
{
    UNSIGNED = 0x80,
    SIGNED   = 0x00
}

/// Server refresh flags
enum RefreshFlags : ubyte
{
    /// Refresh grant tables - FLUSH PRIVILEGES
    GRANT   = 0x01,

    /// Start on new log file - FLUSH LOGS
    LOG     = 0x02,

    /// Close all tables - FLUSH TABLES
    TABLES  = 0x04,

    /// Flush host cache - FLUSH HOSTS
    HOSTS   = 0x08,

    /// Flush status variables - FLUSH STATUS
    STATUS  = 0x10,

    /// Flush thread cache
    THREADS = 0x20,

    /// Reset master info and restart slave thread - RESET THREAD
    SLAVE   = 0x40,

    /// Remove all bin logs in the index and truncate the index - RESET MASTER
    MASTER  = 0x80
}

enum ShutdownFlags : ubyte
{
    /// Defaults to SHUTDOWN_WAIT_ALL_BUFFERS
    DEFAULT                 = 0x00,

    /// Wait for existing connections to finish
    WAIT_CONNECTIONS        = 0x01,

    /// Wait for existing transactions to finish
    WAIT_TRANSACTIONS       = 0x02,

    /// Wait for existing updates to finish (No partial MyISAM updates)
    WAIT_UPDATES            = 0x08,

    /// Flush InnoDB buffers and other storage engines' buffers
    WAIL_ALL_BUFFERS        = 0x10,

    /// Dont't flush InnoDB buffers, flush other storage engines' buffers
    WAIT_CRITICAL_BUFFERS   = 0x11,

    /// KILL_QUERY
    KILL_QUERY              = 0xfe,

    /// KILL_CONNECTION
    KILL_CONNECTION         = 0xff,
}

/++
Field Flags
See_Also: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Field_Packet
+/
enum FieldFlags : ushort
{
    NOT_NULL        = 0x0001,
    PRI_KEY         = 0x0002,
    UNIQUE_KEY      = 0x0004,
    MULTIPLE_KEY    = 0x0008,
    BLOB            = 0x0010,
    UNSIGNED        = 0x0020,
    ZEROFILL        = 0x0040,
    BINARY          = 0x0080,
    ENUM            = 0x0100,
    AUTO_INCREMENT  = 0x0200,
    TIMESTAMP       = 0x0400,
    SET             = 0x0800
}
