/++
Integration tests against a live database.

See defaultCnStr at the top of the module.

To enable these tests, you have to add the MYSQL_INTEGRATION_TESTS
debug specifier. The reason it uses debug and not version is because dub
doesn't allow adding version specifiers on the command-line.

Copyright: Copyright 2011-2013
License:   $(LINK www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors:   Steve Teale, James W. Oliphant, simendsjo, Sönke Ludwig, sshamov,
           Nick Sabalausky
+/
module mysql.test;

debug(MYSQL_INTEGRATION_TESTS)
{
    version(unittest)
    {
        string defaultCnStr = "host=localhost;port=3306;user=mysql-native"~
            ";pwd=mysql-native;db=mysql_native_tests";
    }

    version(unittest)
    {
        import std.stdio;
        import std.conv;
        import std.datetime;

        import mysql.adhoc;
        import mysql.protocol.constants;
        import mysql.protocol.extra_types;

        Connection createCn(string cnStr = defaultCnStr)
        {
            return new Connection(cnStr);
        }

        enum scopedCn = "auto cn = createCn(); scope(exit) cn.close();";

        void assertScalar(T, U)(Connection cn, string query, U expected)
        {
            // Timestamp is a bit special as it's converted to a DateTime when
            // returning from MySql to avoid having to use a mysql specific type.
            static if(is(T == DateTime) && is(U == Timestamp))
                assert(cn.queryScalar(query).get!DateTime == expected.toDateTime());
            else
                assert(cn.queryScalar(query).get!T == expected);
        }

        void truncate(Connection cn, string table)
        {
            cn.exec("TRUNCATE `"~table~"`;");
        }
    }

    // Bind values in prepared statements
    unittest
    {
        mixin(scopedCn);
        cn.exec("DROP TABLE IF EXISTS manytypes");
        cn.exec( "CREATE TABLE manytypes ("
                ~"  i    INT"
                ~", f    FLOAT"
                ~", dttm DATETIME"
                ~", dt   DATE"
                ~")");

        DataSet ds;
        Table tbl;
        Row row;
        PreparedStatement cmd;
        Variant value;

        // Index out of bounds throws
        try
        {
            cn.query("SELECT TRUE", 1);
            assert(0);
        }
        catch(Exception ex) {}

        // Select without result
        cn.truncate("manytypes");
        cn.exec("INSERT INTO manytypes (i, f) VALUES (1, NULL)");
        cmd = cn.prepare("SELECT * FROM manytypes WHERE i = ?");
        cmd.bind(0, 2);
        ds = cmd.query();
        assert(ds.length == 1);
        assert(ds[0].length == 0);

        // Bind single primitive value
        cn.truncate("manytypes");
        cn.exec("INSERT INTO manytypes (i, f) VALUES (1, NULL)");
        cmd = cn.prepare("SELECT * FROM manytypes WHERE i = ?");
        cmd.bind(0, 1);
        cmd.querySingle();

        // Bind multiple primitive values
        cn.truncate("manytypes");
        cn.exec("INSERT INTO manytypes (i, f) VALUES (1, 2)");
        row = cn.querySingle("SELECT * FROM manytypes WHERE i = ? AND f = ?", 1, 2);
        assert(row[0] == 1);
        assert(row[1] == 2);

        // Insert null - params defaults to null
        cn.truncate("manytypes");
        cn.prepare("INSERT INTO manytypes (i, f) VALUES (1, ?)" ).exec();
        cn.assertScalar!int("SELECT i FROM manytypes WHERE f IS NULL", 1);

        // Insert null
        cn.truncate("manytypes");
        cn.exec("INSERT INTO manytypes (i, f) VALUES (1, ?)", null);
        cn.assertScalar!int("SELECT i FROM manytypes WHERE f IS NULL", 1);

        // select where null
        cn.truncate("manytypes");
        cn.exec("INSERT INTO manytypes (i, f) VALUES (1, NULL)");
        value = cn.queryScalar("SELECT i FROM manytypes WHERE f <=> ?", null);
        assert(value.get!int == 1);

        // rebind parameter
        cn.truncate("manytypes");
        cn.exec("INSERT INTO manytypes (i, f) VALUES (1, NULL)");
        cmd = cn.prepare("SELECT i FROM manytypes WHERE f <=> ?");
        cmd.bind(0, 1);
        tbl = cmd.query()[0];
        assert(tbl.length == 0);
        cmd.bind(0, null);
        assert(cmd.queryScalar().get!int == 1);
    }


    // Simple commands
    unittest
    {
        mixin(scopedCn);

        cn.ping();
        assert(cn.statistics(), "COM_STATISTICS didn't return a result");

        cn.initDB("test");
        try
        {
            cn.initDB("this cannot exist");
            assert(false);
        } catch(MySQLErrorPacketException ex) {
            assert(ex.errorPacket.errorCode == 1044, // Access denied
                    "Unexpected error code when connecting to non-existing schema");
        }

    }

    // COM_FIELD_LIST and some ColumnDescription
    unittest
    {
        mixin(scopedCn);

        cn.initDB("information_schema");
        try
        {
            cn.fieldList("this one doesn't exist", "%");
            assert(false);
        }
        catch(MySQLErrorPacketException ex)
        {
            assert(ex.errorPacket.errorCode == 1146, // Table doesn't exist
                    "Unexpected error code when table doesn't exist");
        }

        // We don't expect this table to change much, so we,ll test this
        auto fields = cn.fieldList("character_sets", "%");
        assert(fields.length == 4);

        auto field = fields[0];
        assert(field.schema == "information_schema");
        assert(field.table == "character_sets");
        // Skip originalTable. Seems like it changes between runs as it references
        // a temporary file
        assert(field.name == "CHARACTER_SET_NAME");
        assert(field.originalName == field.name);
        // Skip charset. Think it might be defined by the default character set for
        // the database.
        assert(field.length == 96);
        assert(field.type == SQLType.VARSTRING);
        assert(field.flags == FieldFlags.NOT_NULL);
        assert(field.scale == 0);
        assert(field.defaultValues == "");

        field = fields[1];
        assert(field.schema == "information_schema");
        assert(field.table == "character_sets");
        // Skip originalTable. Seems like it changes between runs as it references
        // a temporary file
        assert(field.name == "DEFAULT_COLLATE_NAME");
        assert(field.originalName == field.name);
        // Skip charset. Think it might be defined by the default character set for
        // the database.
        assert(field.length == 96);
        assert(field.type == SQLType.VARSTRING);
        assert(field.flags == FieldFlags.NOT_NULL);
        assert(field.scale == 0);
        assert(field.defaultValues == "");

        field = fields[2];
        assert(field.schema == "information_schema");
        assert(field.table == "character_sets");
        // Skip originalTable. Seems like it changes between runs as it references
        // a temporary file
        assert(field.name == "DESCRIPTION");
        assert(field.originalName == field.name);
        // Skip charset. Think it might be defined by the default character set for
        // the database.
        assert(field.length == 180);
        assert(field.type == SQLType.VARSTRING);
        assert(field.flags == FieldFlags.NOT_NULL);
        assert(field.scale == 0);
        assert(field.defaultValues == "");

        field = fields[3];
        assert(field.schema == "information_schema");
        assert(field.table == "character_sets");
        // Skip originalTable. Seems like it changes between runs as it references
        // a temporary file
        assert(field.name == "MAXLEN");
        assert(field.originalName == field.name);
        // Skip charset. Think it might be defined by the default character set for
        // the database.
        assert(field.length == 3);
        assert(field.type == SQLType.LONGLONG);
        assert(field.flags == FieldFlags.NOT_NULL);
        assert(field.scale == 0);
        assert(field.defaultValues == "0");
    }

    unittest
    {
        mixin(scopedCn);
        auto pi = cn.processInfo();
        // TODO: Test result
    }

    // Simple text queries
    unittest
    {
        mixin(scopedCn);
        auto ds = cn.query("SELECT 1");
        assert(ds.length == 1);
        auto rs = ds[0];
        assert(rs.rows.length == 1);
        auto row = rs.rows[0];
        assert(row.length == 1);
        assert(row[0].get!long == 1);
    }

    // Multi results
    unittest
    {
        mixin(scopedCn);
        auto ds = cn.query("SELECT 1; SELECT 2;");
        assert(ds.length == 2);
        auto rs = ds[0];
        assert(rs.rows.length == 1);
        auto row = rs.rows[0];
        assert(row.length == 1);
        assert(row[0].get!long == 1);
        rs = ds[1];
        assert(rs.rows.length == 1);
        row = rs.rows[0];
        assert(row.length == 1);
        assert(row[0].get!long == 2);
    }

    // Create and query table
    unittest
    {
        mixin(scopedCn);

        void assertBasicTests(T, U)(string sqlType, U[] values ...)
        {
            import std.array;
            immutable tablename = "`basic_"~sqlType.replace(" ", "")~"`";
            cn.exec("CREATE TABLE IF NOT EXISTS "~tablename~" (value "~sqlType~ ")");

            // Missing and NULL
            cn.exec("TRUNCATE "~tablename);
            immutable selectOneSql = "SELECT value FROM "~tablename~" LIMIT 1";
            assert(cn.query(selectOneSql)[0].length == 0);

            immutable insertNullSql = "INSERT INTO "~tablename~" VALUES (NULL)";
            auto okp = cn.exec(insertNullSql);
            assert(okp.affectedRows == 1);
            okp = cn.prepare(insertNullSql).exec();
            assert(okp.affectedRows == 1);

            assert(!cn.queryScalar(selectOneSql).hasValue);

            auto inscmd = cn.prepare("INSERT INTO "~tablename~" VALUES (?)");
            foreach(value; values)
            {
                cn.exec("TRUNCATE "~tablename);

                inscmd.bind(0, value);
                okp = inscmd.exec();
                assert(okp.affectedRows == 1, "value not inserted");

                cn.assertScalar!T(selectOneSql, value);
            }
        }

        // TODO: Add tests for epsilon
        assertBasicTests!float("FLOAT", 0.0f, 0.1f, -0.1f, 1.0f, -1.0f);
        assertBasicTests!double("DOUBLE", 0.0, 0.1, -0.1, 1.0, -1.0);

        assertBasicTests!bool("BOOL", true, false);
        assertBasicTests!bool("TINYINT(1)", true, false);

        assertBasicTests!byte("TINYINT",
                cast(byte)0, cast(byte)1, cast(byte)-1, byte.min, byte.max);
        assertBasicTests!ubyte("TINYINT UNSIGNED",
                cast(ubyte)0, cast(ubyte)1, ubyte.max);
        assertBasicTests!short("SMALLINT",
                cast(short)0, cast(short)1, cast(short)-1, short.min, short.max);
        assertBasicTests!ushort("SMALLINT UNSIGNED",
                cast(ushort)0, cast(ushort)1, ushort.max);
        assertBasicTests!int("INT", 0, 1, -1, int.min, int.max);
        assertBasicTests!uint("INT UNSIGNED", 0U, 1U, uint.max);
        assertBasicTests!long("BIGINT", 0L, 1L, -1L, long.min, long.max);
        assertBasicTests!ulong("BIGINT UNSIGNED", 0LU, 1LU, ulong.max);

        assertBasicTests!string("VARCHAR(10)", "", "aoeu");
        assertBasicTests!string("CHAR(10)", "", "aoeu");

        assertBasicTests!(ubyte[])("TINYTEXT", "", "aoeu");
        assertBasicTests!(ubyte[])("MEDIUMTEXT", "", "aoeu");
        assertBasicTests!(ubyte[])("TEXT", "", "aoeu");
        assertBasicTests!(ubyte[])("LONGTEXT", "", "aoeu");

        assertBasicTests!(ubyte[])("TINYBLOB", "", "aoeu");
        assertBasicTests!(ubyte[])("MEDIUMBLOB", "", "aoeu");
        assertBasicTests!(ubyte[])("BLOB", "", "aoeu");
        assertBasicTests!(ubyte[])("LONGBLOB", "", "aoeu");

        assertBasicTests!Date("DATE", Date(2013, 10, 03));
        assertBasicTests!DateTime("DATETIME", DateTime(2013, 10, 03, 12, 55, 35));
        assertBasicTests!TimeOfDay("TIME", TimeOfDay(12, 55, 35));
        assertBasicTests!DateTime("TIMESTAMP NULL", Timestamp(2013_10_03_12_55_35));
    }

    unittest
    {
        mixin(scopedCn);
        auto cmd = cn.prepare(
                "SELECT * FROM information_schema.character_sets"~
                " WHERE CHARACTER_SET_NAME=?");
        cmd.bind(0, "utf8");
        auto row = cmd.querySingle();
        assert(row.length == 4);
        assert(row[0] == "utf8");
        assert(row[1] == "utf8_general_ci");
        assert(row[2] == "UTF-8 Unicode");
        assert(row[3] == 3);
    }
}
