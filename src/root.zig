//! Secure Sockets - TLS functionality for Tardy Sockets
pub const Tls = @This();

socket: Socket,
vtable: VTable,

pub fn unsecured(socket: Socket) Tls {
    return .{
        .socket = socket,
        .vtable = .{
            .ctx = undefined,
            .deinit = struct {
                fn deinit(_: *anyopaque) void {}
            }.deinit,
            .accept = struct {
                fn accept(s: Socket, r: *Runtime, _: *anyopaque) !Tls {
                    const child = try s.accept(r);
                    return .unsecured(child);
                }
            }.accept,
            .connect = struct {
                fn connect(s: Socket, r: *Runtime, _: *anyopaque) !void {
                    try s.connect(r);
                }
            }.connect,
            .recv = struct {
                fn recv(s: Socket, r: *Runtime, _: *anyopaque, buf: []u8) !usize {
                    return try s.recv(r, buf);
                }
            }.recv,
            .send = struct {
                fn send(s: Socket, r: *Runtime, _: *anyopaque, buf: []const u8) !usize {
                    return try s.send(r, buf);
                }
            }.send,
        },
    };
}

pub fn deinit(tls: *const Tls) void {
    return tls.vtable.deinit(tls.vtable.ctx);
}

pub fn accept(tls: *const Tls, rt: *Runtime) !*Tls {
    return try tls.vtable.accept(tls.socket, rt, tls.vtable.ctx);
}

pub fn connect(tls: *const Tls, rt: *Runtime) !void {
    return try tls.vtable.connect(tls.socket, rt, tls.vtable.ctx);
}

pub fn recv(tls: *const Tls, rt: *Runtime, buffer: []u8) !usize {
    return try tls.vtable.recv(tls.socket, rt, tls.vtable.ctx, buffer);
}

pub fn send(tls: *const Tls, rt: *Runtime, buffer: []const u8) !usize {
    return try tls.vtable.send(tls.socket, rt, tls.vtable.ctx, buffer);
}

pub fn send_all(tls: *const Tls, rt: *Runtime, buffer: []const u8) !usize {
    var count: usize = 0;
    while (count != buffer.len) {
        count += tls.send(rt, buffer[count..]) catch |e| switch (e) {
            error.Closed => return count,
            else => return e,
        };
    }

    return count;
}

const VTable = struct {
    ctx: *anyopaque,
    deinit: *const fn (tls: *anyopaque) void,
    accept: *const fn (Socket, *Runtime, ctx: *anyopaque) anyerror!*Tls,
    connect: *const fn (Socket, *Runtime, ctx: *anyopaque) anyerror!void,
    recv: *const fn (Socket, *Runtime, ctx: *anyopaque, []u8) anyerror!usize,
    send: *const fn (Socket, *Runtime, ctx: *anyopaque, []const u8) anyerror!usize,
};

pub const Mode = enum { client, server };

pub const BearSSL = if (options.tls == .bearssl) @import("BearSSL.zig");

pub const S2N = if (options.tls == .s2n_tls) @import("S2N.zig");

const std = @import("std");

const options = @import("options");
const tardy = @import("tardy");
const Runtime = tardy.Runtime;
const Socket = tardy.net.Socket;
