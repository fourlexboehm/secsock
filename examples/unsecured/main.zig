const Tardy = tardy.Tardy(.auto);

/// curl -vk https://127.0.0.1:9862
pub fn main(init: std.process.Init) !void {
    const unsecured: Secsock.Unsecured = .empty;

    const tcp: Secsock = try unsecured.tcp(
        init.gpa,
        .{
            .host = "127.0.0.1",
            .port = 9862,
        },
    );
    defer tcp.deinit(init.gpa);

    const info = tcp.info();
    log.info("tls: '{t}', address: ({s})", .{
        info.name,
        info.address,
    });

    var td: Tardy = try .init(init.gpa, init.io, .{
        .threading = .single,
    });
    defer td.deinit();

    try td.entry(&tcp, struct {
        fn entry(rt: *tardy.Runtime, raw_tcp: *const Secsock) !void {
            try rt.spawn(
                echo_frame,
                .{ rt, raw_tcp },
                .KiB(48),
            );
        }
    }.entry);
}

fn echo_frame(rt: *tardy.Runtime, tcp: *const Secsock) !void {
    var connected = try tcp.accept(rt);
    defer connected.deinit(rt.allocator);

    while (true) {
        var buf: [1024]u8 = undefined;
        const count = connected.recv(rt, &buf) catch |e|
            if (e == error.Closed) break else return e;

        log.info("recv count: {d}", .{count});

        _ = connected.send(rt, buf[0..count]) catch |e|
            if (e == error.Closed) break else return e;
    }
}

const log = std.log.scoped(.@"examples/unsecured");

const std = @import("std");

const Secsock = @import("secsock");
const tardy = @import("tardy");
