const Unsecured = @This();

pub const empty: Unsecured = .{};

pub fn tcp(
    _: *const Unsecured,
    gpa: mem.Allocator,
    config: Socket.Config,
) !Secsock {
    const socket = try gpa.create(Socket);
    socket.* = try .init(.{ .tcp = config });
    errdefer gpa.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(config.backlog);

    return try tcpWithSock(gpa, socket);
}

fn tcpWithSock(
    gpa: mem.Allocator,
    socket: *const Socket,
) !Secsock {
    const impl = try gpa.create(Impl);
    errdefer gpa.destroy(impl);

    impl.* = .{ .socket = .init(socket) };

    return .{
        .impl = impl,
        .vtable = &vtable,
    };
}

const Impl = struct {
    socket: Secsock.ManagedSocket,

    fn info(ct: *const anyopaque) Secsock.Info {
        const impl: *const Impl = @ptrCast(@alignCast(ct));

        var buf: [21:0]u8 = @splat(0x0);
        _ = mem.print(&buf, "{f}", .{
            impl.socket.socket.addr,
        }) catch unreachable;

        return .{
            .name = .unsecured,
            .address = buf,
        };
    }

    fn deinit(ct: *anyopaque, gpa: mem.Allocator) void {
        const impl: *Impl = @ptrCast(@alignCast(ct));

        impl.socket.deinit(gpa);
        gpa.destroy(impl);
    }

    fn accept(ct: *const anyopaque, r: *Runtime) !Secsock {
        const impl: *const Impl = @ptrCast(@alignCast(ct));

        const client = try r.gpa.create(Socket);
        errdefer r.gpa.destroy(client);
        client.* = try impl.socket.socket.accept(r);
        errdefer client.close_blocking();

        const new_tcp = try tcpWithSock(r.gpa, client);
        errdefer new_tcp.deinit(r.gpa);

        return new_tcp;
    }

    fn cancelAccepts(ct: *const anyopaque, r: *Runtime) !usize {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        return try impl.socket.cancelAccepts(r);
    }

    fn stopAccepting(ct: *anyopaque) void {
        const impl: *Impl = @ptrCast(@alignCast(ct));
        impl.socket.stopAccepting();
    }

    fn shutdown(ct: *const anyopaque, r: *Runtime) !void {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        try impl.socket.shutdown(r);
    }

    fn connect(ct: *const anyopaque, r: *Runtime) !void {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        try impl.socket.socket.connect(r);
    }

    fn recv(ct: *const anyopaque, r: *Runtime, buf: []u8) !usize {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        return try impl.socket.socket.recv(r, buf);
    }

    fn send(ct: *const anyopaque, r: *Runtime, buf: []const u8) !usize {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        return try impl.socket.socket.send(r, buf);
    }
};

const vtable: Secsock.VTable = .{
    .info = Impl.info,
    .deinit = Impl.deinit,
    .accept = Impl.accept,
    .cancel_accepts = Impl.cancelAccepts,
    .stop_accepting = Impl.stopAccepting,
    .shutdown = Impl.shutdown,
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
