pub fn to_secure_socket_server(
    tls: *BearSSL,
    allocator: mem.Allocator,
    socket: Socket,
) !*Tls {
    const io_buf = try allocator.alloc(u8, bearssl.BR_SSL_BUFSIZE_BIDI);
    errdefer allocator.free(io_buf);

    const cb_ctx = try allocator.create(Callback);
    errdefer allocator.destroy(cb_ctx);

    cb_ctx.* = .{ .runtime = null, .socket = socket };

    const context = try allocator.create(Vtable);
    errdefer allocator.destroy(context);

    context.* = .{
        .bearssl = tls,
        .context = undefined,
        .io_buf = io_buf,
        .cb_ctx = cb_ctx,
        .sslio_ctx = undefined,
    };

    switch (tls.pkey.?) {
        .rsa => |*rsa| bearssl.br_ssl_server_init_full_rsa(
            &context.context,
            @ptrCast(&tls.x509.?),
            1,
            @ptrCast(rsa),
        ),
        .ec => |*ec| bearssl.br_ssl_server_init_full_ec(
            &context.context,
            @ptrCast(&tls.x509.?),
            1,
            @intCast(tls.cert_signer_algo.?),
            @ptrCast(ec),
        ),
    }

    bearssl.br_ssl_engine_set_buffer(
        &context.context.eng,
        io_buf.ptr,
        io_buf.len,
        1,
    );
    const reset_status = bearssl.br_ssl_server_reset(&context.context);
    if (reset_status <= 0) return error.ServerResetFailed;

    bearssl.br_sslio_init(
        &context.sslio_ctx,
        &context.context.eng,
        struct {
            fn recv_cb(i: ?*anyopaque, b: [*c]u8, l: usize) callconv(.c) c_int {
                const ctx: *Callback = @ptrCast(@alignCast(i.?));
                const len = ctx.socket.recv(
                    ctx.runtime.?,
                    b[0..l],
                ) catch |e| {
                    log.err("sslio recv cb failed: {t}", .{e});
                    return -1;
                };
                return @intCast(len);
            }
        }.recv_cb,
        cb_ctx,
        struct {
            fn send_cb(i: ?*anyopaque, b: [*c]const u8, l: usize) callconv(.c) c_int {
                const ctx: *Callback = @ptrCast(@alignCast(i.?));
                const len = ctx.socket.send(
                    ctx.runtime.?,
                    b[0..l],
                ) catch |e| {
                    log.err("sslio send cb failed: {t}", .{e});
                    return -1;
                };
                return @intCast(len);
            }
        }.send_cb,
        cb_ctx,
    );

    return .{
        .socket = socket,
        .vtable = .{
            .tls_impl = context,
            .deinit = struct {
                fn deinit(vt: *anyopaque, alloc: mem.Allocator) void {
                    const ctx: *Vtable = @ptrCast(@alignCast(vt));

                    alloc.destroy(ctx.cb_ctx);
                    alloc.free(ctx.io_buf);
                    alloc.destroy(ctx);
                }
            }.deinit,
            .accept = struct {
                fn accept(s: Socket, r: *Runtime, vt: *anyopaque) !Tls {
                    const ctx: *Vtable = @ptrCast(@alignCast(vt));
                    const sock = try s.accept(r);
                    errdefer sock.close_blocking();

                    const child = try ctx.bearssl.to_secure_socket(
                        sock,
                        .server,
                    );
                    // if we fail, we want to clean this connection up.
                    errdefer child.deinit();

                    const new_ctx: *Vtable = @ptrCast(@alignCast(
                        child.vtable.tls_impl,
                    ));
                    new_ctx.cb_ctx.runtime = r;

                    return child;
                }
            }.accept,
            .connect = struct {
                fn connect(_: Socket, _: *Runtime, _: *anyopaque) !void {
                    return error.TLSServerCantConnect;
                }
            }.connect,
            .recv = struct {
                fn recv(_: Socket, r: *Runtime, vt: *anyopaque, b: []u8) !usize {
                    const ctx: *Vtable = @ptrCast(@alignCast(vt));
                    ctx.cb_ctx.runtime = r;

                    const result = bearssl.br_sslio_read(
                        &ctx.sslio_ctx,
                        b.ptr,
                        b.len,
                    );

                    if (result < 0) {
                        const last_error: EngineStatus = .convert(
                            bearssl.br_ssl_engine_last_error(&ctx.context.eng),
                        );
                        switch (last_error) {
                            .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio recv failed: {t}", .{last_error});
                                return error.TlsRecvFailed;
                            },
                        }
                    }

                    return @intCast(result);
                }
            }.recv,
            .send = struct {
                fn send(_: Socket, r: *Runtime, i: *anyopaque, b: []const u8) !usize {
                    const ctx: *Vtable = @ptrCast(@alignCast(i));
                    ctx.cb_ctx.runtime = r;

                    const write_result = bearssl.br_sslio_write(&ctx.sslio_ctx, b.ptr, b.len);
                    if (write_result < 0) {
                        const last_error: EngineStatus = .convert(bearssl.br_ssl_engine_last_error(&ctx.context.eng));
                        switch (last_error) {
                            .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio send failed: {t}", .{last_error});
                                return error.TlsSendFailed;
                            },
                        }
                    }

                    // Force flush. We should be buffering a layer above this.
                    const flush_result = bearssl.br_sslio_flush(&ctx.sslio_ctx);
                    if (flush_result < 0) {
                        const last_error: EngineStatus = .convert(
                            bearssl.br_ssl_engine_last_error(&ctx.context.eng),
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
            }.send,
        },
    };
}

const Callback = struct { socket: Socket, runtime: ?*Runtime };

const Vtable = struct {
    bearssl: *BearSSL,
    io_buf: []const u8,
    sslio_ctx: bearssl.br_sslio_context,
    cb_ctx: *Callback,
    context: bearssl.br_ssl_server_context,
};

const log = std.log.scoped(.@"bearssl/server");

const std = @import("std");
const mem = std.mem;

const bearssl = @import("bearssl_h");
const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Tls = @import("../root.zig");
const BearSSL = Tls.BearSSL;
const PrivateKey = BearSSL.PrivateKey;
const EngineStatus = BearSSL.EngineStatus;
