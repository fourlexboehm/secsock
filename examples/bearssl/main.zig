const Tardy = tardy.Tardy(.auto);

/// curl -vk https://127.0.0.1:9862
pub fn main(init: std.process.Init) !void {
    var bearssl: Secsock.BearSSL = try .init(
        init.gpa,
        "CERTIFICATE",
        @embedFile("certs/rsa_cert.pem"),
        "PRIVATE KEY",
        @embedFile("certs/rsa_key.pem"),
    );
    defer bearssl.deinit(init.gpa);

    // var bearssl: Secsock.BearSSL = try .init(
    //     init.gpa,
    //     "CERTIFICATE",
    //     @embedFile("certs/cert.pem"),
    //     "EC PRIVATE KEY",
    //     @embedFile("certs/key.pem"),
    // );

    const tls: Secsock = try bearssl.tls(init.gpa, .{
        .host = "127.0.0.1",
        .port = 9862,
    });
    defer tls.deinit(init.gpa);

    var td: Tardy = try .init(init.gpa, init.io, .{
        .threading = .single,
    });
    defer td.deinit();

    try td.entry(&tls, struct {
        fn entry(rt: *tardy.Runtime, s: *const Secsock) !void {
            try rt.spawn(
                echo_frame,
                .{ rt, s },
                .KiB(48),
            );
        }
    }.entry);
}

fn echo_frame(rt: *tardy.Runtime, tls: *const Secsock) !void {
    var connected = try tls.accept(rt);
    defer connected.deinit(rt.gpa);

    while (true) {
        var buf: [1024]u8 = undefined;
        const count = connected.recv(rt, &buf) catch |e|
            if (e == error.Closed) break else return e;

        log.info("recv count: {d}", .{count});

        _ = connected.send(rt, buf[0..count]) catch |e|
            if (e == error.Closed) break else return e;
    }
}

const log = std.log.scoped(.@"examples/bearssl");

const std = @import("std");

const Secsock = @import("secsock");
const tardy = @import("tardy");
