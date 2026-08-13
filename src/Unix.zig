const Unix = @This();

socket: *const Socket,

pub fn init(
    gpa: mem.Allocator,
    path: []const u8,
) !secsock.Secsock {
    debug.assert(mem.endsWith(u8, path, ".sock"));

    const socket = try gpa.create(Socket);
    socket.* = try .init(.{ .unix = path });
    errdefer gpa.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(4096);

    const unix = try gpa.create(Unix);
    unix.* = .{ .socket = socket };

    return .{
        .tcp = .{ .unix = unix },
    };
}

pub fn free(unix: *const Unix, io: Io) void {
    Io.Dir.deleteFileAbsolute(io, unix.path) catch unreachable;
}

pub fn deinit(unix: *const Unix, gpa: mem.Allocator) void {
    debug.assert(unix.socket.addr.family() == .unix);

    unix.socket.close_blocking();

    gpa.destroy(unix.socket);
    gpa.destroy(unix);
}

pub fn info(unix: *const Unix) secsock.Info {
    var buf: [21:0]u8 = @splat(0x0);
    _ = mem.print(&buf, "{f}", .{
        unix.socket.addr,
    }) catch unreachable;

    return .{
        .name = .unix,
        .address = buf,
    };
}

pub fn accept(unix: *const Unix, r: *Runtime) !secsock.Secsock {
    const client = try r.gpa.create(Socket);
    client.* = try unix.socket.accept(r);
    errdefer r.gpa.destroy(client);
    errdefer client.close_blocking();

    const new = try r.gpa.create(Unix);
    errdefer r.gpa.destroy(new);
    new.* = .{ .socket = client };

    return .{ .tcp = .{ .unix = new } };
}

pub fn connect(unix: *const Unix, r: *Runtime) !void {
    try unix.socket.connect(r);
}

pub fn recv(unix: *const Unix, r: *Runtime, buf: []u8) !usize {
    return try unix.socket.recv(r, buf);
}

pub fn send(unix: *const Unix, r: *Runtime, buf: []const u8) !usize {
    return try unix.socket.send(r, buf);
}

const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const mem = std.mem;
const debug = std.debug;

const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const secsock = @import("secsock.zig");
