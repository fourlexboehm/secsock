const Unsecured = @This();
socket: *const Socket,

// TODO: this should create a socket
pub fn init(socket: *const Socket) Unsecured {
    return .{
        .socket = socket,
    };
}

pub fn initWithSock(socket: *const Socket) Unsecured {
    return .{
        .socket = socket,
    };
}

// TODO: full impl
pub fn deinit(unsecured: Unsecured) void {
    unsecured.socket.close_blocking();
}

pub fn raw(socket: *const Socket) Secsock {
    return .{
        .ctx = socket,
        .vtable = &vtable,
    };
}

const Impl = struct {
    unsecured: Unsecured,

    fn deinit(ct: *const anyopaque, _: mem.Allocator) void {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));
        _ = ctx; // autofix
    }

    fn accept(ct: *const anyopaque, r: *Runtime) !Secsock {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));
        const new_socket = try ctx.unsecured.socket.accept(r);
        return raw(new_socket);
    }

    fn connect(ct: *const anyopaque, r: *Runtime) !void {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));
        try ctx.unsecured.socket.connect(r);
    }

    fn recv(ct: *anyopaque, r: *Runtime, buf: []u8) !usize {
        const ctx: *Impl = @ptrCast(@alignCast(ct));
        return try ctx.unsecured.socket.recv(r, buf);
    }

    fn send(ct: *anyopaque, r: *Runtime, buf: []const u8) !usize {
        const ctx: *Impl = @ptrCast(@alignCast(ct));
        return try ctx.unsecured.socket.send(r, buf);
    }
};

const vtable: Secsock.VTable = .{
    .deinit = Impl.deinit,
    .accept = Impl.accept,
    .connect = Impl.connect,
    .recv = Impl.recv,
    .send = Impl.send,
};

const std = @import("std");
const mem = std.mem;

const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Secsock = @import("Secsock.zig");
