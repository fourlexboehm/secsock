const Unsecured = @This();

pub const empty: Unsecured = .{};

pub fn tcp(
    _: *Unsecured,
    allocator: mem.Allocator,
    config: Socket.Config,
) !Secsock {
    const socket = try allocator.create(Socket);
    socket.* = try .init(.{ .tcp = config });
    errdefer allocator.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(config.backlog);

    return try tcpWithSock(allocator, socket);
}

fn tcpWithSock(
    allocator: mem.Allocator,
    socket: *const Socket,
) !Secsock {
    const context = try allocator.create(Impl);
    errdefer allocator.destroy(context);

    context.* = .{ .socket = socket };

    return .{
        .ctx = context,
        .vtable = &vtable,
    };
}

const Impl = struct {
    socket: *const Socket,

    fn deinit(ct: *const anyopaque, allocator: mem.Allocator) void {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));

        ctx.socket.close_blocking();
        allocator.destroy(ctx.socket);
        allocator.destroy(ctx);
    }

    fn accept(ct: *const anyopaque, r: *Runtime) !Secsock {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));

        const new_socket = try r.allocator.create(Socket);
        new_socket.* = try ctx.socket.accept(r);
        errdefer r.allocator.destroy(new_socket);
        errdefer new_socket.close_blocking();

        const new_raw_tcp = try tcpWithSock(
            r.allocator,
            new_socket,
        );
        errdefer new_raw_tcp.deinit(r.allocator);

        return new_raw_tcp;
    }

    fn connect(ct: *const anyopaque, r: *Runtime) !void {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));
        try ctx.socket.connect(r);
    }

    fn recv(ct: *anyopaque, r: *Runtime, buf: []u8) !usize {
        const ctx: *Impl = @ptrCast(@alignCast(ct));
        return try ctx.socket.recv(r, buf);
    }

    fn send(ct: *anyopaque, r: *Runtime, buf: []const u8) !usize {
        const ctx: *Impl = @ptrCast(@alignCast(ct));
        return try ctx.socket.send(r, buf);
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
