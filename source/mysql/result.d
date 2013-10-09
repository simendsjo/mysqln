/++
Resultset from database.

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.result;

import std.variant;
import std.array;

import mysql.protocol.commands;
import mysql.protocol.packets;

/// Container for resultsets/Tables
class DataSet
{
public:
    @property
    {
        /// Number of tables
        size_t length() { return _tables.length; }

        Table[] tables() { return _tables; }
    }

    /// Get table by index
    Table opIndex(size_t i) { return _tables[i]; }

    this(T)(T[] ds) if(is(T == TextResultSet) || is(T == BinaryResultSet))
    {
        _tables = minimallyInitializedArray!(Table[])(ds.length);
        foreach(i; 0 .. ds.length)
            _tables[i] = new Table(ds[i]);
    }

private:
    Table[] _tables;
}


/// Single resultset/Table
class Table
{
public:
    @property
    {
        /// Columns
        ColumnDefinition[] columns() { return _columns; }

        /// Rows
        Row[] rows() { return _rows; }

        /// Number of rows
        size_t length() { return _rows.length; }
    }

    /// Get row by index
    Row opIndex(size_t i) { return _rows[i]; }

    this(T)(T rs) if(is(T == TextResultSet) || is(T == BinaryResultSet))
    {
        _columns = rs.columns;
        _rows = minimallyInitializedArray!(Row[])(rs.length);
        foreach(i; 0 .. rs.length)
            _rows[i] = new Row(rs[i], rs.columns);
    }

private:
    Row[] _rows;
    ColumnDefinition[] _columns;
}

/// Single row
class Row
{
public:
    @property
    {
        /// Number of values
        size_t length() { return _values.length; }

        /// Values
        Variant[] values() { return _values; }
    }

    /// Get value by index
    Variant opIndex(size_t i) { return _values[i]; }


    this(TextRow row, ColumnDefinition[] columns)
    {
        _values = minimallyInitializedArray!(Variant[])(columns.length);
        foreach(i, col; columns)
            _values[i] = row[i].fromSQLTextValue(col.type, col.length, col.unsigned);
    }

    this(BinaryRow row, ColumnDefinition[] columns)
    {
        _values = row.values;
    }

private:
    Variant[] _values;
}
