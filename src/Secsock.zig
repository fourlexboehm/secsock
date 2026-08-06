//! Secure Sockets - TLS functionality for Tardy Sockets
pub const Secsock = @This();

ctx: *anyopaque,
vtable: *const VTable,

pub fn info(tls: *const Secsock) Info {
    return tls.vtable.info(tls.ctx);
}

pub fn deinit(tls: *const Secsock, allocator: mem.Allocator) void {
    tls.vtable.deinit(tls.ctx, allocator);
}

pub fn accept(tls: *const Secsock, rt: *Runtime) !Secsock {
    return try tls.vtable.accept(tls.ctx, rt);
}

pub fn connect(tls: *const Secsock, rt: *Runtime) !void {
    try tls.vtable.connect(tls.ctx, rt);
}

pub fn recv(tls: *Secsock, rt: *Runtime, buffer: []u8) !usize {
    return try tls.vtable.recv(tls.ctx, rt, buffer);
}

pub fn send(tls: *Secsock, rt: *Runtime, buffer: []const u8) !usize {
    return try tls.vtable.send(tls.ctx, rt, buffer);
}

pub fn send_all(tls: *const Secsock, rt: *Runtime, buffer: []const u8) !usize {
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
    name: [:0]const u8,
    address_fmt: [20:0]u8,
};

pub const VTable = struct {
    info: *const fn (ctx: *const anyopaque) Info,
    deinit: *const fn (ctx: *const anyopaque, mem.Allocator) void,
    accept: *const fn (ctx: *const anyopaque, *Runtime) anyerror!Secsock,
    connect: *const fn (ctx: *const anyopaque, *Runtime) anyerror!void,
    recv: *const fn (ctx: *anyopaque, *Runtime, []u8) anyerror!usize,
    send: *const fn (ctx: *anyopaque, *Runtime, []const u8) anyerror!usize,
};

pub const BearSSL = if (options.tls == .bearssl) @import("BearSSL.zig");

pub const S2N = if (options.tls == .s2n_tls) @import("S2N.zig");

const std = @import("std");
const mem = std.mem;

const options = @import("options");
const tardy = @import("tardy");
const Runtime = tardy.Runtime;
const Socket = tardy.net.Socket;

pub const Unsecured = @import("Unsecured.zig");
