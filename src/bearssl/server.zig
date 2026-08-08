pub fn to_secure_socket_server(
    bearssl: *BearSSL,
    allocator: mem.Allocator,
    socket: *const Socket,
) !Secsock {
    const io_buf = try allocator.alloc(u8, h.BR_SSL_BUFSIZE_BIDI);
    errdefer allocator.free(io_buf);

    const cb_ctx = try allocator.create(Callback);
    errdefer allocator.destroy(cb_ctx);

    cb_ctx.* = .{ .runtime = null, .socket = socket };

    const context = try allocator.create(Impl);
    errdefer allocator.destroy(context);

    context.* = .{
        .bearssl = bearssl,
        .server = undefined,
        .io_buf = io_buf,
        .cb = cb_ctx,
        .sslio = undefined,
    };

    switch (bearssl.pkey) {
        .rsa => |*rsa| h.br_ssl_server_init_full_rsa(
            &context.server,
            @ptrCast(&bearssl.x509),
            1,
            @ptrCast(rsa),
        ),
        .ec => |*ec| h.br_ssl_server_init_full_ec(
            &context.server,
            @ptrCast(&bearssl.x509),
            1,
            @intCast(bearssl.cert_signer_algo),
            @ptrCast(ec),
        ),
    }

    h.br_ssl_engine_set_buffer(
        &context.server.eng,
        io_buf.ptr,
        io_buf.len,
        1,
    );
    const reset_status = h.br_ssl_server_reset(&context.server);
    if (reset_status <= 0) return error.ServerResetFailed;

    h.br_sslio_init(
        &context.sslio,
        &context.server.eng,
        Callback.recv,
        cb_ctx,
        Callback.send,
        cb_ctx,
    );

    return .{
        .ctx = context,
        .vtable = &vtable,
    };
}

const Impl = struct {
    bearssl: *BearSSL,
    io_buf: []const u8,
    sslio: h.br_sslio_context,
    cb: *Callback,
    server: h.br_ssl_server_context,

    fn info(ct: *const anyopaque) Secsock.Info {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));

        var buf: [21:0]u8 = @splat(0x0);
        _ = mem.print(&buf, "{f}", .{
            ctx.cb.socket.addr,
        }) catch unreachable;

        return .{
            .name = .bearssl,
            .address = buf,
        };
    }

    fn deinit(ct: *const anyopaque, alloc: mem.Allocator) void {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));

        ctx.cb.socket.close_blocking();
        alloc.destroy(ctx.cb.socket);

        alloc.destroy(ctx.cb);
        alloc.free(ctx.io_buf);
        alloc.destroy(ctx);
    }

    fn accept(ct: *const anyopaque, r: *Runtime) !Secsock {
        const ctx: *const Impl = @ptrCast(@alignCast(ct));
        const cb = ctx.cb;

        const sock = r.allocator.create(Socket) catch @panic("OOM");
        sock.* = try cb.socket.accept(r);
        errdefer r.allocator.destroy(sock);
        errdefer sock.close_blocking();

        const new_tls = try ctx.bearssl.tlsWithSock(
            r.allocator,
            sock,
            .server,
        );
        // if we fail, we want to clean this connection up.
        errdefer new_tls.deinit(r.allocator);

        const new_ctx: *const Impl = @ptrCast(@alignCast(new_tls.ctx));
        new_ctx.cb.runtime = r;

        return new_tls;
    }

    fn connect(_: *const anyopaque, _: *Runtime) !void {
        return error.TLSServerCantConnect;
    }

    fn recv(ct: *anyopaque, r: *Runtime, b: []u8) !usize {
        const ctx: *Impl = @ptrCast(@alignCast(ct));
        ctx.cb.runtime = r;

        const result = h.br_sslio_read(
            &ctx.sslio,
            b.ptr,
            b.len,
        );

        if (result < 0) {
            const last_error: EngineStatus = .convert(
                h.br_ssl_engine_last_error(&ctx.server.eng),
            );
            switch (last_error) {
                .InputOutput => return error.Closed,
                else => {
                    log.err("sslio recv failed: {t}", .{
                        last_error,
                    });
                    return error.TlsRecvFailed;
                },
            }
        }

        return @intCast(result);
    }

    fn send(ct: *anyopaque, r: *Runtime, b: []const u8) !usize {
        const ctx: *Impl = @ptrCast(@alignCast(ct));
        ctx.cb.runtime = r;

        const write_result = h.br_sslio_write(
            &ctx.sslio,
            b.ptr,
            b.len,
        );
        if (write_result < 0) {
            const last_error: EngineStatus = .convert(
                h.br_ssl_engine_last_error(&ctx.server.eng),
            );
            switch (last_error) {
                .InputOutput => return error.Closed,
                else => {
                    log.err("sslio send failed: {t}", .{last_error});
                    return error.TlsSendFailed;
                },
            }
        }

        // Force flush. We should be buffering a layer above this.
        const flush_result = h.br_sslio_flush(&ctx.sslio);
        if (flush_result < 0) {
            const last_error: EngineStatus = .convert(
                h.br_ssl_engine_last_error(&ctx.server.eng),
            );
            switch (last_error) {
                .InputOutput => return error.Closed,
                else => {
                    log.err("sslio flush failed: {t}", .{
                        last_error,
                    });
                    return error.TlsSendFailed;
                },
            }
        }

        return @intCast(write_result);
    }
};

const Callback = struct {
    socket: *const Socket,
    runtime: ?*Runtime,

    fn recv(cb: ?*anyopaque, buf: [*c]u8, len: usize) callconv(.c) c_int {
        const ctx: *Callback = @ptrCast(@alignCast(cb.?));
        const count = ctx.socket.recv(
            ctx.runtime.?,
            buf[0..len],
        ) catch |e| {
            log.err("sslio recv cb failed: {t}", .{e});
            return -1;
        };
        return @intCast(count);
    }

    fn send(cb: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.c) c_int {
        const ctx: *Callback = @ptrCast(@alignCast(cb.?));
        const count = ctx.socket.send(
            ctx.runtime.?,
            buf[0..len],
        ) catch |e| {
            log.err("sslio send cb failed: {t}", .{e});
            return -1;
        };
        return @intCast(count);
    }
};

const vtable: Secsock.VTable = .{
    .info = Impl.info,
    .deinit = Impl.deinit,
    .accept = Impl.accept,
    .connect = Impl.connect,
    .recv = Impl.recv,
    .send = Impl.send,
};

const log = std.log.scoped(.@"bearssl/server");

const std = @import("std");
const mem = std.mem;

const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Secsock = @import("../Secsock.zig");
const BearSSL = Secsock.BearSSL;
const h = BearSSL.h;
const PrivateKey = BearSSL.PrivateKey;
const EngineStatus = BearSSL.EngineStatus;
