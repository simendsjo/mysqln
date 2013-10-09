module mysql.protocol.protocol;

import std.exception;
import std.array;
import std.datetime;
import std.variant;
import std.traits;
import std.string;
import std.algorithm;
import std.conv;

import mysql.common;
public import mysql.protocol.constants;
public import mysql.protocol.extra_types;
public import mysql.protocol.packets;
public import mysql.protocol.packet_helpers;

/++
Each command inserts an id in the packet to ensure packets are received in
order. Each command starts at 0, and each packet sent should increment this
number.

See_Also: http://dev.mysql.com/doc/internals/en/sequence-id.html
+/
struct SequenceId
{
public:
    @property ubyte id() const pure nothrow { return _sequenceId; }

    void bump() pure nothrow { ++_sequenceId; }

private:
    ubyte _sequenceId;
}

