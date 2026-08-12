//! Secure Sockets - TLS functionality for Tardy Sockets
pub const Secsock = @This();

impl: *anyopaque,
vtable: *const VTable,

pub fn info(tls: *const Secsock) Info {
    return tls.vtable.info(tls.impl);
}

pub fn deinit(tls: *const Secsock, gpa: mem.Allocator) void {
    tls.vtable.deinit(tls.impl, gpa);
}

pub fn accept(tls: *const Secsock, rt: *Runtime) !Secsock {
    return try tls.vtable.accept(tls.impl, rt);
}

pub fn connect(tls: *const Secsock, rt: *Runtime) !void {
    try tls.vtable.connect(tls.impl, rt);
}

pub fn recv(tls: *Secsock, rt: *Runtime, buffer: []u8) !usize {
    return try tls.vtable.recv(tls.impl, rt, buffer);
}

pub fn send(tls: *Secsock, rt: *Runtime, buffer: []const u8) !usize {
    return try tls.vtable.send(tls.impl, rt, buffer);
}

pub fn send_all(tls: *Secsock, rt: *Runtime, buffer: []const u8) !usize {
    var count: usize = 0;
    while (count != buffer.len) {
        count += tls.send(rt, buffer[count..]) catch |e|
            switch (e) {
                error.Closed => return count,
                else => return e,
            };
    }

    return count;
}

pub const Info = struct {
    name: Implementation,
    address: [21:0]u8,
};
const Implementation = enum(u8) {
    bearssl,
    @"s2n-tls",
    unsecured,
    unix,
};

pub const VTable = struct {
    info: *const fn (impl: *const anyopaque) Info,
    deinit: *const fn (impl: *const anyopaque, mem.Allocator) void,
    accept: *const fn (impl: *const anyopaque, *Runtime) anyerror!Secsock,
    connect: *const fn (impl: *const anyopaque, *Runtime) anyerror!void,
    recv: *const fn (impl: *anyopaque, *Runtime, []u8) anyerror!usize,
    send: *const fn (impl: *anyopaque, *Runtime, []const u8) anyerror!usize,
};

pub const BearSSL = if (options.tls == .bearssl) @import("BearSSL.zig");
pub const S2N = if (options.tls == .s2n_tls) @import("S2N.zig");
pub const Unix = if (builtin.os.tag != .windows) @import("Unix.zig");

const std = @import("std");
const mem = std.mem;
const builtin = @import("builtin");

const options = @import("options");
const tardy = @import("tardy");
const Runtime = tardy.Runtime;
const Socket = tardy.net.Socket;

pub const Unsecured = @import("Unsecured.zig");
