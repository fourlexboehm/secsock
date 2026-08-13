//! Secure Sockets - TLS functionality for Tardy Sockets
pub const Secsock = union(enum) {
    tls: union(enum) {
        bearssl: *BearSSL,
        s2n: *S2N,
    },
    tcp: union(enum) {
        raw: *Unsecured,
        unix: *Unix,
    },

    pub fn init(gpa: mem.Allocator, config: Config) !Secsock {
        return try switch (config) {
            .tls => |tls| switch (tls) {
                .bearssl => |bearssl| BearSSL.init(gpa, bearssl),
                .s2n => |s2n| S2N.init(s2n),
            },
            .tcp => |tcp| switch (tcp) {
                .raw => |raw| Unsecured.init(gpa, raw),
                .unix => |unix| Unix.init(gpa, unix),
            },
        };
    }

    pub fn info(tls: *const Secsock) Info {
        switch (tls.*) {
            inline else => |spec| switch (spec) {
                inline else => |impl| return impl.info(),
            },
        }
    }

    pub fn deinit(tls: *const Secsock, gpa: mem.Allocator) void {
        switch (tls.*) {
            inline else => |spec| switch (spec) {
                inline else => |impl| return impl.deinit(gpa),
            },
        }
    }

    pub fn accept(tls: *const Secsock, rt: *Runtime) !Secsock {
        switch (tls.*) {
            inline else => |spec| switch (spec) {
                inline else => |impl| return impl.accept(rt),
            },
        }
    }

    pub fn connect(tls: *const Secsock, rt: *Runtime) !void {
        switch (tls.*) {
            inline else => |spec| switch (spec) {
                inline else => |impl| try impl.connect(rt),
            },
        }
    }

    pub fn recv(tls: *Secsock, rt: *Runtime, buffer: []u8) !usize {
        switch (tls.*) {
            inline else => |spec| switch (spec) {
                inline else => |impl| return try impl.recv(rt, buffer),
            },
        }
    }

    pub fn send(tls: *Secsock, rt: *Runtime, buffer: []const u8) !usize {
        switch (tls.*) {
            inline else => |spec| switch (spec) {
                inline else => |impl| return try impl.send(rt, buffer),
            },
        }
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
};

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

pub const BearSSL = if (options.tls == .bearssl) @import("BearSSL.zig") else void;
pub const S2N = if (options.tls == .s2n_tls) @import("S2N.zig") else struct {
    pub const Init = struct {};
    pub fn init(_: S2N.Init) !Secsock {
        unreachable;
    }
    pub fn info(_: *const S2N) Info {
        unreachable;
    }
    pub fn deinit(_: *const S2N, _: mem.Allocator) void {
        unreachable;
    }
    pub fn accept(_: *const S2N, _: *Runtime) anyerror!Secsock {
        unreachable;
    }
    pub fn connect(_: *const S2N, _: *Runtime) anyerror!void {
        unreachable;
    }
    pub fn recv(_: *S2N, _: *Runtime, _: []u8) anyerror!usize {
        unreachable;
    }
    pub fn send(_: *S2N, _: *Runtime, _: []const u8) anyerror!usize {
        unreachable;
    }
};
pub const VTable = struct {};
pub const Unix = if (is_unix) @import("Unix.zig") else void;
const is_unix = builtin.target.os.tag != .windows;

const Config = union(enum) {
    tls: union(enum) {
        bearssl: BearSSL.Init,
        s2n: S2N.Init,
    },
    tcp: union(enum) {
        raw: Socket.Config,
        unix: []const u8,
    },
};
const std = @import("std");
const mem = std.mem;
const builtin = @import("builtin");

const options = @import("options");
const tardy = @import("tardy");
const Runtime = tardy.Runtime;
const Socket = tardy.net.Socket;

pub const Unsecured = @import("Unsecured.zig");
