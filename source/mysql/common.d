/++
A native D driver for the MySQL and MariaDB database systems.

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.common;

import std.exception;
import std.socket;

/++
An exception type to distinguish exceptions thrown by this module.
+/
class MySQLException: Exception
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) pure
    {
        super(msg, file, line);
    }
}
alias MySQLException MYX;

/++
Received invalid data from the server which violates the MySQL network protocol.
+/
class MySQLProtocolException: MySQLException
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) pure
    {
        super(msg, file, line);
    }
}
alias MySQLProtocolException MYXProtocol;

alias mypenforce = enforceEx!MYXProtocol;

// Phobos/Vibe.d type aliases
package alias std.socket.TcpSocket PlainPhobosSocket;
version(Have_vibe_d)
{
    package alias EventedObject MySQLEventedObject;
    package alias vibe.core.net.TcpConnection PlainVibeDSocket;
}
else
{
    // Dummy types
    package alias Object MySQLEventedObject;
    package alias Object PlainVibeDSocket;
}

alias PlainPhobosSocket function(string,ushort) OpenSocketCallbackPhobos;
alias PlainVibeDSocket  function(string,ushort) OpenSocketCallbackVibeD;

/// Type of socket
enum MySQLSocketType { phobos, vibed }

// A minimal socket interface similar to Vibe.d's TcpConnection.
// Used to wrap both Phobos and Vibe.d sockets with a common interface.
package interface MySQLSocket
{
    void close();
    @property bool connected() const;
    void read(ubyte[] dst);
    void write(in ubyte[] bytes);

    void acquire();
    void release();
    bool isOwner();
    bool amOwner();
}

// Wraps a Phobos socket with the common interface
package class MySQLSocketPhobos : MySQLSocket
{
    private PlainPhobosSocket socket;

    // The socket should already be open
    this(PlainPhobosSocket socket)
    {
        enforceEx!MYX(socket, "Tried to use a null Phobos socket - Maybe the 'openSocket' callback returned null?");
        enforceEx!MYX(socket.isAlive, "Tried to use a closed Phobos socket - Maybe the 'openSocket' callback created a socket but forgot to open it?");
        this.socket = socket;
    }

    invariant()
    {
        assert(!!socket);
    }

    void close()
    {
        socket.shutdown(SocketShutdown.BOTH);
        socket.close();
    }

    @property bool connected() const
    {
        return socket.isAlive;
    }

    void read(ubyte[] dst)
    {
        auto bytesRead = socket.receive(dst);
        enforceEx!MYX(bytesRead == dst.length, "Wrong number of bytes read");
        enforceEx!MYX(bytesRead != socket.ERROR, "Received std.socket.Socket.ERROR");
    }

    void write(in ubyte[] bytes)
    {
        socket.send(bytes);
    }

    void acquire() { /+ Do nothing +/ }
    void release() { /+ Do nothing +/ }
    bool isOwner() { return true; }
    bool amOwner() { return true; }
}

// Wraps a Vibe.d socket with the common interface
version(Have_vibe_d) {
    package class MySQLSocketVibeD : MySQLSocket
    {
        private PlainVibeDSocket socket;

        // The socket should already be open
        this(PlainVibeDSocket socket)
        {
            enforceEx!MYX(socket, "Tried to use a null Vibe.d socket - Maybe the 'openSocket' callback returned null?");
            enforceEx!MYX(socket.connected, "Tried to use a closed Vibe.d socket - Maybe the 'openSocket' callback created a socket but forgot to open it?");
        this.socket = socket;
        }

        invariant()
        {
            assert(!!socket);
        }

        void close()
        {
            socket.close();
        }

        @property bool connected() const
        {
            return socket.connected;
        }

        void read(ubyte[] dst)
        {
            socket.read(dst);
        }

        void write(in ubyte[] bytes)
        {
            socket.write(bytes);
        }

        static if (is(typeof(&TCPConnection.isOwner))) {
            void acquire() { socket.acquire(); }
            void release() { socket.release(); }
            bool isOwner() { return socket.isOwner(); }
            bool amOwner() { return socket.isOwner(); }
        } else {
            void acquire() { /+ Do nothing +/ }
            void release() { /+ Do nothing +/ }
            bool isOwner() { return true; }
            bool amOwner() { return true; }
        }
    }
}

