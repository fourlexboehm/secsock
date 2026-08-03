//! Secure Sockets - TLS functionality for Tardy Sockets
pub const Tls = @This();

socket: Socket,
tls: VTable,

pub fn unsecured(socket: Socket) Tls {
    return .{
        .socket = socket,
        .tls = .{
            .tls_impl = undefined,
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

pub fn deinit(self: *const Tls) void {
    return self.tls.deinit(self.tls.tls_impl);
}

pub fn accept(self: *const Tls, rt: *Runtime) !*Tls {
    return try self.tls.accept(self.socket, rt, self.tls.tls_impl);
}

pub fn connect(self: *const Tls, rt: *Runtime) !void {
    return try self.tls.connect(self.socket, rt, self.tls.tls_impl);
}

pub fn recv(self: *const Tls, rt: *Runtime, buffer: []u8) !usize {
    return try self.tls.recv(self.socket, rt, self.tls.tls_impl, buffer);
}

pub fn send(self: *const Tls, rt: *Runtime, buffer: []const u8) !usize {
    return try self.tls.send(self.socket, rt, self.tls.tls_impl, buffer);
}

pub fn send_all(self: *const Tls, rt: *Runtime, buffer: []const u8) !usize {
    var count: usize = 0;
    while (count != buffer.len) {
        count += self.send(rt, buffer[count..]) catch |e| switch (e) {
            error.Closed => return count,
            else => return e,
        };
    }

    return count;
}

const VTable = struct {
    tls_impl: *anyopaque,
    deinit: *const fn (tls: *anyopaque) void,
    accept: *const fn (Socket, *Runtime, *anyopaque) anyerror!*Tls,
    connect: *const fn (Socket, *Runtime, *anyopaque) anyerror!void,
    recv: *const fn (Socket, *Runtime, *anyopaque, []u8) anyerror!usize,
    send: *const fn (Socket, *Runtime, *anyopaque, []const u8) anyerror!usize,
};

pub const Mode = enum { client, server };

pub const BearSSL = if (options.tls == .bearssl) @import("BearSSL.zig");

pub const S2N = if (options.tls == .s2n_tls) @import("S2N.zig");

const std = @import("std");

const options = @import("options");
const tardy = @import("tardy");
const Runtime = tardy.Runtime;
const Socket = tardy.net.Socket;
