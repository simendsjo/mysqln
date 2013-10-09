/++
A vibe.d based connection pool.

This module requires vibe.d.

See_Also: $(LINK http://vibed.org)

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.db;

public import mysql.connection;
import std.conv;

version(Have_vibe_d)
{
    import vibe.core.connectionpool;

    /++
    A vibe.d based connection pool
    +/
    class MysqlDB {
       private {
          string m_host;
          string m_user;
          string m_password;
          string m_database;
          ushort m_port;
          SvrCapFlags m_capFlags;
          ConnectionPool!Connection m_pool;
       }

       this(string host, string user, string password, string database, ushort port = 3306, SvrCapFlags capFlags = defaultClientFlags)
       {
          m_host = host;
          m_user = user;
          m_password = password;
          m_database = database;
          m_port = port;
          m_capFlags = capFlags;
          m_pool = new ConnectionPool!Connection(&createConnection);
       }

       this(string connStr, SvrCapFlags capFlags = defaultClientFlags)
       {
          auto parts = Connection.parseConnectionString(connStr);
          this(parts[0], parts[1], parts[2], parts[3], to!ushort(parts[4]), capFlags);
       }

       auto lockConnection() { return m_pool.lockConnection(); }

       private Connection createConnection()
       {
          return new Connection(m_host, m_user, m_password, m_database, m_port, m_capFlags);
       }
    }
}
else
{
    /// ditto
    class MysqlDB() {
        static assert(false,
            "The 'mysql.db.MysqlDB' connection pool requires Vibe.d and therefore "~
            "must be used with -version=Have_vibe_d"
        );
    }
}
