/++
Convenience functions for database queries.

If parameters is sent in the functions, a prepared statement is used. In that
case, every parameter the query has needs to be bound.

Note that you have to use the NULL-safe equal if you wish to use NULL in WHERE
clauses for prepared statements.
See $(LINK, http://dev.mysql.com/doc/refman/5.5/en/comparison-operators.html#operator_equal-to, NULL-safe equal)

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.adhoc;

public import std.variant;
import std.exception;
import std.string;

public import mysql.connection;
public import mysql.protocol.packets;
public import mysql.common;
public import mysql.result;
import mysql.protocol.constants;
import mysql.protocol.commands;

/// Ping database
void ping(Connection cn)
{
    ComPing.exec(cn);
}

/// Change database schema
void initDB(Connection cn, string db)
{
    ComInitDB.exec(cn, db);
}

/// Server statistics
string statistics(Connection cn)
{
    return ComStatistics.exec(cn);
}

/// Columns in table matching wildcard
ColumnDefinition[] fieldList(Connection cn, string table, string wildcard)
{
    return ComFieldList.exec(cn, table, wildcard);
}

/// Active server threads
Table processInfo(Connection cn)
{
    ComProcessInfo cmd;
    auto trs = cmd.exec(cn);
    return new Table(trs);
}

private PreparedStatement prepareAndBind(Params...)(Connection cn, string query, Params params)
{
    auto cmd = cn.prepare(query);
    cmd.bindAll(params);
    return cmd;
}

/// Execute a query that doesn't include a resultset
OKPacket exec(Params...)(Connection cn, string query, Params params)
{
    static if(Params.length)
    {
        return cn.prepareAndBind(query, params).exec();
    }
    else
    {
        ComQuery cmd;
        cmd.exec(cn, query);
        enforceEx!MYX(cmd.results.length == 0, "Didn't expect a result");
        return cmd.okPacket;
    }
}

/// Execute a query that returns one or more resultsets
DataSet query(Params...)(Connection cn, string query, Params params)
{
    static if(Params.length)
    {
        return cn.prepareAndBind(query, params).query();
    }
    else
    {
        ComQuery cmd;
        cmd.exec(cn, query);
        auto tds = cmd.results;
        return new DataSet(tds);
    }
}

/// Execute a query that returns a single row
Row querySingle(Params...)(Connection cn, string query, Params params)
{
    static if(Params.length)
    {
        return cn.prepareAndBind(query, params).querySingle();
    }
    else
    {
        auto ds = cn.query(query);
        enforceEx!MYX(ds.length == 1, "Expected a single resultset");
        auto tbl = ds[0];
        enforceEx!MYX(tbl.length == 1, "Expected a single row");
        return tbl[0];
    }
}

/// Execute a query that returns a single value
Variant queryScalar(Params...)(Connection cn, string query, Params params)
{
    static if(Params.length)
    {
        return cn.prepareAndBind(query, params).queryScalar();
    }
    else
    {
        auto row = cn.querySingle(query);
        enforceEx!MYX(row.length == 1, "Expected a single value");
        return row[0];
    }
}

/// Prepare a query
PreparedStatement prepare(Connection cn, string query)
{
    return PreparedStatement(cn, query);
}

/++
A prepared statement.

BUGS:
    Missing purge and release
+/
struct PreparedStatement
{
public:
    /// Construct and prepare query
    this(Connection cn, string query)
    {
        _cn = cn;
        _prepare.exec(cn, query);
        _exePacket = ComStmtExecutePacket(_prepare.statementId,
                _prepare.params, CursorType.NO_CURSOR);
    }

    /// Execute a query that doesn't return a resultset
    OKPacket exec()
    {
        ComStmtExecute cmd;
        cmd.exec(_cn, _exePacket);
        enforceEx!MYX(cmd.results.length == 0, "Didn't expect a result");
        return cmd.okPacket;
    }

    /// Execute a query that returns one or more resultsets
    DataSet query()
    {
        ComStmtExecute cmd;
        cmd.exec(_cn, _exePacket);
        return new DataSet(cmd.results);
    }

    /// Execute a query that returns a single Row
    Row querySingle()
    {
        auto ds = query();
        enforceEx!MYX(ds.length == 1, "Expected a single resultset");
        auto rs = ds[0];
        enforceEx!MYX(rs.length == 1, format("Expected a single row, but got %d", rs.length));
        return rs[0];
    }

    /// Execute a query that returns a single value
    Variant queryScalar()
    {
        auto row = querySingle();
        enforceEx!MYX(row.length == 1, "Expected a single value");
        return row[0];
    }

    /// Bind a parameter to a value
    void bind(T)(ushort index, T value)
    {
        _exePacket.setParam(index, value);
    }

    /// Binds all params in one go
    void bindAll(Params...)(Params params)
    {
        foreach(i, param; params)
            _exePacket.setParam(i, param);
    }

private:
    Connection _cn;
    ComStmtPrepare _prepare;
    ComStmtExecutePacket _exePacket;
}
