const Unsecured = @This();

socket: *const Socket,

pub fn init(
    gpa: mem.Allocator,
    config: Socket.Config,
) !secsock.Secsock {
    const socket = try gpa.create(Socket);
    socket.* = try .init(.{ .tcp = config });
    errdefer gpa.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(config.backlog);

    return try tcpWithSock(gpa, socket);
}

pub fn deinit(unsecured: *const Unsecured, gpa: mem.Allocator) void {
    unsecured.socket.close_blocking();
    gpa.destroy(unsecured.socket);
    gpa.destroy(unsecured);
}

fn tcpWithSock(
    gpa: mem.Allocator,
    socket: *const Socket,
) !secsock.Secsock {
    const unsecured = try gpa.create(Unsecured);
    errdefer gpa.destroy(unsecured);

    unsecured.* = .{ .socket = socket };

    return .{
        .tcp = .{ .raw = unsecured },
    };
}

pub fn info(unsecured: *const Unsecured) secsock.Info {
    var buf: [21:0]u8 = @splat(0x0);
    _ = mem.print(&buf, "{f}", .{
        unsecured.socket.addr,
    }) catch unreachable;

    return .{
        .name = .unsecured,
        .address = buf,
    };
}

pub fn accept(unsecured: *const Unsecured, r: *Runtime) !secsock.Secsock {
    const client = try r.gpa.create(Socket);
    client.* = try unsecured.socket.accept(r);
    errdefer r.gpa.destroy(client);
    errdefer client.close_blocking();

    const new_tcp = try tcpWithSock(r.gpa, client);
    errdefer new_tcp.deinit(r.gpa);

    return new_tcp;
}

pub fn connect(unsecured: *const Unsecured, r: *Runtime) !void {
    try unsecured.socket.connect(r);
}

pub fn recv(unsecured: *const Unsecured, r: *Runtime, buf: []u8) !usize {
    return try unsecured.socket.recv(r, buf);
}

pub fn send(unsecured: *const Unsecured, r: *Runtime, buf: []const u8) !usize {
    return try unsecured.socket.send(r, buf);
}

const std = @import("std");
const mem = std.mem;

const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const secsock = @import("secsock.zig");
