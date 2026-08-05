const Unsecured = @This();

socket: *const Socket,
init_by: enum(u8) { init, init_with_sock, impl },

pub fn init(config: Socket.Config, allocator: mem.Allocator) Unsecured {
    const socket = allocator.create(Socket) catch @panic("OOM");
    socket.* = .init(config) catch unreachable;

    socket.bind() catch unreachable;
    socket.listen(config.backlog) catch unreachable;

    return .{
        .socket = socket,
        .init_by = .init,
    };
}

/// if `initWithSock` is used to initialize `Unsecured`
/// then you are responsible for closing and free the socket
/// if applicable
pub fn initWithSock(socket: *const Socket) Unsecured {
    return .{
        .socket = socket,
        .init_by = .init_with_sock,
    };
}

pub fn deinit(unsecured: Unsecured, allocator: mem.Allocator) void {
    switch (unsecured.init_by) {
        .init => {
            unsecured.socket.close_blocking();
            allocator.destroy(unsecured.socket);
        },
        else => {},
    }
}

pub fn raw(unsecured: *const Unsecured) Secsock {
    return .{
        .ctx = unsecured,
        .vtable = &vtable,
    };
}

const Impl = struct {
    raw: Unsecured,

    fn deinit(ct: *const anyopaque, allocator: mem.Allocator) void {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));
        switch (ctx.raw.init_by) {
            .impl => {
                ctx.raw.socket.close_blocking();
                allocator.destroy(ctx.raw.socket);
            },
            else => {},
        }
    }

    fn accept(ct: *const anyopaque, r: *Runtime) !Secsock {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));

        const new_socket = try r.allocator.create(Socket);
        new_socket.* = try ctx.raw.socket.accept(r);
        errdefer r.allocator.destroy(new_socket);
        errdefer new_socket.close_blocking();

        var unsecured = initWithSock(new_socket);
        unsecured.init_by = .impl;

        return unsecured.raw();
    }

    fn connect(ct: *const anyopaque, r: *Runtime) !void {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));
        try ctx.raw.socket.connect(r);
    }

    fn recv(ct: *anyopaque, r: *Runtime, buf: []u8) !usize {
        const ctx: *Impl = @ptrCast(@alignCast(ct));
        return try ctx.raw.socket.recv(r, buf);
    }

    fn send(ct: *anyopaque, r: *Runtime, buf: []const u8) !usize {
        const ctx: *Impl = @ptrCast(@alignCast(ct));
        return try ctx.raw.socket.send(r, buf);
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
