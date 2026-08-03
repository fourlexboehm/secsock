/// s2n-tls is an implementation of the TLS/SSL protocols by Amazon (AWS).
/// https://github.com/aws/s2n-tls
pub const S2N = @This();

var initalized: bool = false;
var deinitalized: bool = false;

config: *h.s2n_config,
cert: ?*h.s2n_cert_chain_and_key,
// TODO: This needs to go.
lock: std.Io.Mutex = .init,

pub fn init() !S2N {
    if (initalized) @panic("Can only initalize s2n once!");
    initalized = true;

    const init_rc = h.s2n_init();
    try handle_error("s2n_init", init_rc);

    const config = h.s2n_config_new();

    return .{ .config = config.?, .cert = null };
}

pub fn deinit(s2n: S2N) void {
    if (deinitalized) @panic("Can only deinitalize s2n once!");
    _ = h.s2n_config_free(s2n.config);
    if (s2n.cert) |cert| _ = h.s2n_cert_chain_and_key_free(cert);
    _ = h.s2n_cleanup();
}

pub fn add_cert_chain(s2n: *S2N, cert: []const u8, key: []const u8) !void {
    const chain = h.s2n_cert_chain_and_key_new();
    s2n.cert = chain.?;
    const load_pem_bytes_rc = h.s2n_cert_chain_and_key_load_pem_bytes(
        chain,
        @constCast(cert.ptr),
        @intCast(cert.len),
        @constCast(key.ptr),
        @intCast(key.len),
    );
    try handle_error("adding pem bytes to cert chain", load_pem_bytes_rc);
    const add_cert_chain_rc = h.s2n_config_add_cert_chain_and_key_to_store(
        s2n.config,
        chain,
    );
    try handle_error("adding cert chain to config", add_cert_chain_rc);
}

pub fn to_secure_socket(
    s2n: *S2N,
    allocator: mem.Allocator,
    io: std.Io,
    socket: Socket,
    mode: Tls.Mode,
) !Tls {
    s2n.lock.lockUncancelable(io);
    defer s2n.lock.unlock(io);

    const conn = h.s2n_connection_new(switch (mode) {
        .client => h.S2N_CLIENT,
        .server => h.S2N_SERVER,
    });
    if (conn == null) return error.NewConnectionFailed;
    errdefer _ = h.s2n_connection_free(conn);

    const set_blind_rc = h.s2n_connection_set_blinding(
        conn,
        h.S2N_SELF_SERVICE_BLINDING,
    );
    try handle_error("setting blinding", set_blind_rc);

    const set_config_rc = h.s2n_connection_set_config(conn, s2n.config);
    try handle_error("setting config", set_config_rc);

    const cb_ctx = try allocator.create(Callback);
    errdefer allocator.destroy(cb_ctx);
    cb_ctx.* = .{ .socket = socket, .runtime = null };

    const set_recv_ctx_rc = h.s2n_connection_set_recv_ctx(conn, @ptrCast(cb_ctx));
    try handle_error("setting recv cb ctx", set_recv_ctx_rc);

    const set_send_ctx_rc = h.s2n_connection_set_send_ctx(conn, @ptrCast(cb_ctx));
    try handle_error("setting send cb ctx", set_send_ctx_rc);

    const set_recv_cb_rc = h.s2n_connection_set_recv_cb(conn, struct {
        fn recv_cb(cb: ?*anyopaque, buf: [*c]u8, len: u32) callconv(.c) c_int {
            const ctx: *Callback = @ptrCast(@alignCast(cb.?));
            const sock = ctx.socket;
            const runtime = ctx.runtime;

            const result = sock.recv(runtime.?, buf[0..len]) catch |e|
                switch (e) {
                    error.Closed => return 0,
                    // TODO: Properly handle errors.
                    else => {
                        log.err("error on recv: {t}", .{e});
                        return h.S2N_FAILURE;
                    },
                };

            return @intCast(result);
        }
    }.recv_cb);
    try handle_error("setting recv cb", set_recv_cb_rc);

    const set_send_cb_rc = h.s2n_connection_set_send_cb(conn, struct {
        fn send_cb(cb: ?*anyopaque, buf: [*c]const u8, len: u32) callconv(.c) c_int {
            const ctx: *Callback = @ptrCast(@alignCast(cb.?));
            const sock = ctx.socket;
            const runtime = ctx.runtime;

            const result = sock.send(runtime.?, buf[0..len]) catch |e|
                switch (e) {
                    error.Closed => {
                        h.s2n_errno_location().* = h.S2N_ERR_T_CLOSED;
                        return h.S2N_FAILURE;
                    },
                    // TODO: Properly handle errors.
                    else => {
                        log.err("error on send: {t}", .{e});
                        return h.S2N_FAILURE;
                    },
                };

            return @intCast(result);
        }
    }.send_cb);
    try handle_error("setting send cb", set_send_cb_rc);

    const context = try allocator.create(Context);
    context.* = .{
        .s2n = s2n,
        .conn = conn.?,
        .cb = cb_ctx,
    };

    return .{
        .socket = socket,
        .vtable = .{
            .ctx = context,
            .deinit = struct {
                fn deinit(ct: *anyopaque, alloc: mem.Allocator) void {
                    const ctx: *Context = @ptrCast(@alignCast(ct));

                    var blocked_status: h.s2n_blocked_status = undefined;
                    _ = h.s2n_shutdown(ctx.conn, &blocked_status);
                    _ = h.s2n_connection_free(ctx.conn);
                    alloc.destroy(ctx.cb);
                    alloc.destroy(ctx);
                }
            }.deinit,
            .accept = struct {
                fn accept(s: Socket, r: *Runtime, ct: *anyopaque) !Tls {
                    const ctx: *Context = @ptrCast(@alignCast(ct));
                    ctx.cb.runtime = r;
                    const sock = try s.accept(r);
                    errdefer sock.close_blocking();

                    const child = try ctx.s2n.to_secure_socket(
                        r.io,
                        sock,
                        .server,
                    );
                    // if we fail, we want to clean this connection up.
                    errdefer child.deinit();

                    const new_ctx: *Context = @ptrCast(@alignCast(child.vtable.ctx));
                    new_ctx.cb.runtime = r;

                    var blocked_status: h.s2n_blocked_status = h.S2N_NOT_BLOCKED;
                    while (h.s2n_negotiate(new_ctx.conn, &blocked_status) !=
                        h.S2N_SUCCESS)
                    {
                        switch (h.s2n_error_get_type(h.s2n_errno)) {
                            h.S2N_ERR_T_BLOCKED => continue,
                            h.S2N_ERR_T_CLOSED => return error.Closed,
                            else => try handle_error(
                                "accept negotiating connection",
                                -1,
                            ),
                        }
                    }

                    return child;
                }
            }.accept,
            .connect = struct {
                fn connect(s: Socket, r: *Runtime, ct: *anyopaque) !void {
                    const ctx: *Context = @ptrCast(@alignCast(ct));
                    ctx.cb.runtime = r;
                    try s.connect(r);

                    var blocked_status: h.s2n_blocked_status = h.S2N_NOT_BLOCKED;
                    while (h.s2n_negotiate(ctx.conn, &blocked_status) !=
                        h.S2N_SUCCESS)
                    {
                        switch (h.s2n_error_get_type(h.s2n_errno)) {
                            h.S2N_ERR_T_BLOCKED => continue,
                            h.S2N_ERR_T_CLOSED => return error.Closed,
                            else => try handle_error(
                                "connect negotiating connection",
                                -1,
                            ),
                        }
                    }
                }
            }.connect,
            .recv = struct {
                fn recv(_: Socket, r: *Runtime, ct: *anyopaque, buf: []u8) !usize {
                    const ctx: *Context = @ptrCast(@alignCast(ct));
                    ctx.cb.runtime = r;
                    var blocked_status: h.s2n_blocked_status = undefined;

                    const res = h.s2n_recv(
                        ctx.conn,
                        buf.ptr,
                        @intCast(buf.len),
                        &blocked_status,
                    );
                    if (res < 0) {
                        switch (h.s2n_error_get_type(h.s2n_errno)) {
                            h.S2N_ERR_T_CLOSED => return error.Closed,
                            else => return error.FailedRecv,
                        }
                    }

                    return @intCast(res);
                }
            }.recv,
            .send = struct {
                fn send(_: Socket, r: *Runtime, ct: *anyopaque, buf: []const u8) !usize {
                    const ctx: *Context = @ptrCast(@alignCast(ct));
                    ctx.cb.runtime = r;
                    var blocked_status: h.s2n_blocked_status = undefined;

                    const res = h.s2n_send(
                        ctx.conn,
                        buf.ptr,
                        @intCast(buf.len),
                        &blocked_status,
                    );
                    if (res < 0) {
                        switch (h.s2n_error_get_type(h.s2n_errno)) {
                            h.S2N_ERR_T_CLOSED => return error.Closed,
                            else => return error.FailedSend,
                        }
                    }
                    return @intCast(res);
                }
            }.send,
        },
    };
}

fn handle_error(state: []const u8, rc: c_int) !void {
    if (rc < 0) {
        log.err(
            "{s} failed: {s} | {s}",
            .{
                state,
                h.s2n_strerror(h.s2n_errno, "EN"),
                h.s2n_strerror_debug(h.s2n_errno, "EN"),
            },
        );
        h.s2n_errno_location().* = h.S2N_ERR_T_OK;

        return error.InternalError;
    }
}

const Context = struct {
    s2n: *S2N,
    conn: *h.s2n_connection,
    cb: *Callback,
};
const Callback = struct { socket: Socket, runtime: ?*Runtime };

const log = std.log.scoped(.s2n);

const std = @import("std");
const mem = std.mem;

const h = @import("s2n.h");
const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Tls = @import("root.zig");
