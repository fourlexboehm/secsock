/// s2n-tls is an implementation of the TLS/SSL protocols by Amazon (AWS).
/// https://github.com/aws/s2n-tls
pub const S2N = @This();

var initalized: bool = false;
var deinitalized: bool = false;

config: *s2n.s2n_config,
cert: ?*s2n.s2n_cert_chain_and_key,
// TODO: This needs to go.
lock: std.Io.Mutex = .init,

pub fn init() !S2N {
    if (initalized) @panic("Can only initalize s2n once!");
    initalized = true;

    const init_rc = s2n.s2n_init();
    try handle_error("s2n_init", init_rc);

    const config = s2n.s2n_config_new();

    return .{ .config = config.?, .cert = null };
}

pub fn add_cert_chain(self: *S2N, cert: []const u8, key: []const u8) !void {
    const chain = s2n.s2n_cert_chain_and_key_new();
    self.cert = chain.?;
    const load_pem_bytes_rc = s2n.s2n_cert_chain_and_key_load_pem_bytes(
        chain,
        @constCast(cert.ptr),
        @intCast(cert.len),
        @constCast(key.ptr),
        @intCast(key.len),
    );
    try handle_error("adding pem bytes to cert chain", load_pem_bytes_rc);
    const add_cert_chain_rc = s2n.s2n_config_add_cert_chain_and_key_to_store(
        self.config,
        chain,
    );
    try handle_error("adding cert chain to config", add_cert_chain_rc);
}

pub fn deinit(self: S2N) void {
    if (deinitalized) @panic("Can only deinitalize s2n once!");
    _ = s2n.s2n_config_free(self.config);
    if (self.cert) |cert| _ = s2n.s2n_cert_chain_and_key_free(cert);
    _ = s2n.s2n_cleanup();
}

pub fn to_secure_socket(
    self: *S2N,
    allocator: mem.Allocator,
    io: std.Io,
    socket: Socket,
    mode: Tls.Mode,
) !Tls {
    self.lock.lockUncancelable(io);
    defer self.lock.unlock(io);

    const conn = s2n.s2n_connection_new(switch (mode) {
        .client => s2n.S2N_CLIENT,
        .server => s2n.S2N_SERVER,
    });
    if (conn == null) return error.NewConnectionFailed;
    errdefer _ = s2n.s2n_connection_free(conn);

    const set_blind_rc = s2n.s2n_connection_set_blinding(
        conn,
        s2n.S2N_SELF_SERVICE_BLINDING,
    );
    try handle_error("setting blinding", set_blind_rc);

    const set_config_rc = s2n.s2n_connection_set_config(conn, self.config);
    try handle_error("setting config", set_config_rc);

    const cb_ctx = try allocator.create(Callback);
    errdefer allocator.destroy(cb_ctx);
    cb_ctx.* = .{ .socket = socket, .runtime = null };

    const set_recv_ctx_rc = s2n.s2n_connection_set_recv_ctx(conn, @ptrCast(cb_ctx));
    try handle_error("setting recv cb ctx", set_recv_ctx_rc);

    const set_send_ctx_rc = s2n.s2n_connection_set_send_ctx(conn, @ptrCast(cb_ctx));
    try handle_error("setting send cb ctx", set_send_ctx_rc);

    const set_recv_cb_rc = s2n.s2n_connection_set_recv_cb(conn, struct {
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
                        return s2n.S2N_FAILURE;
                    },
                };

            return @intCast(result);
        }
    }.recv_cb);
    try handle_error("setting recv cb", set_recv_cb_rc);

    const set_send_cb_rc = s2n.s2n_connection_set_send_cb(conn, struct {
        fn send_cb(cb: ?*anyopaque, buf: [*c]const u8, len: u32) callconv(.c) c_int {
            const ctx: *Callback = @ptrCast(@alignCast(cb.?));
            const sock = ctx.socket;
            const runtime = ctx.runtime;

            const result = sock.send(runtime.?, buf[0..len]) catch |e|
                switch (e) {
                    error.Closed => {
                        s2n.s2n_errno_location().* = s2n.S2N_ERR_T_CLOSED;
                        return s2n.S2N_FAILURE;
                    },
                    // TODO: Properly handle errors.
                    else => {
                        log.err("error on send: {t}", .{e});
                        return s2n.S2N_FAILURE;
                    },
                };

            return @intCast(result);
        }
    }.send_cb);
    try handle_error("setting send cb", set_send_cb_rc);

    const vtable = try allocator.create(Vtable);
    vtable.* = .{
        .s2n = self,
        .conn = conn.?,
        .cb_ctx = cb_ctx,
    };

    return .{
        .socket = socket,
        .tls = .{
            .tls_impl = vtable,
            .deinit = struct {
                fn deinit(vt: *anyopaque, alloc: mem.Allocator) void {
                    const ctx: *Vtable = @ptrCast(@alignCast(vt));

                    var blocked_status: s2n.s2n_blocked_status = undefined;
                    _ = s2n.s2n_shutdown(ctx.conn, &blocked_status);
                    _ = s2n.s2n_connection_free(ctx.conn);
                    alloc.destroy(ctx.cb_ctx);
                    alloc.destroy(ctx);
                }
            }.deinit,
            .accept = struct {
                fn accept(s: Socket, r: *Runtime, vt: *anyopaque) !Tls {
                    const ctx: *Vtable = @ptrCast(@alignCast(vt));
                    ctx.cb_ctx.runtime = r;
                    const sock = try s.accept(r);
                    errdefer sock.close_blocking();

                    const child = try ctx.s2n.to_secure_socket(
                        r.io,
                        sock,
                        .server,
                    );
                    // if we fail, we want to clean this connection up.
                    errdefer child.deinit();

                    const new_ctx: *Vtable = @ptrCast(@alignCast(child.tls.tls_impl));
                    new_ctx.cb_ctx.runtime = r;

                    var blocked_status: s2n.s2n_blocked_status = s2n.S2N_NOT_BLOCKED;
                    while (s2n.s2n_negotiate(new_ctx.conn, &blocked_status) !=
                        s2n.S2N_SUCCESS)
                    {
                        switch (s2n.s2n_error_get_type(s2n.s2n_errno)) {
                            s2n.S2N_ERR_T_BLOCKED => continue,
                            s2n.S2N_ERR_T_CLOSED => return error.Closed,
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
                fn connect(s: Socket, r: *Runtime, vt: *anyopaque) !void {
                    const ctx: *Vtable = @ptrCast(@alignCast(vt));
                    ctx.cb_ctx.runtime = r;
                    try s.connect(r);

                    var blocked_status: s2n.s2n_blocked_status = s2n.S2N_NOT_BLOCKED;
                    while (s2n.s2n_negotiate(ctx.conn, &blocked_status) !=
                        s2n.S2N_SUCCESS)
                    {
                        switch (s2n.s2n_error_get_type(s2n.s2n_errno)) {
                            s2n.S2N_ERR_T_BLOCKED => continue,
                            s2n.S2N_ERR_T_CLOSED => return error.Closed,
                            else => try handle_error(
                                "connect negotiating connection",
                                -1,
                            ),
                        }
                    }
                }
            }.connect,
            .recv = struct {
                fn recv(_: Socket, r: *Runtime, vt: *anyopaque, buf: []u8) !usize {
                    const ctx: *Vtable = @ptrCast(@alignCast(vt));
                    ctx.cb_ctx.runtime = r;
                    var blocked_status: s2n.s2n_blocked_status = undefined;

                    const res = s2n.s2n_recv(
                        ctx.conn,
                        buf.ptr,
                        @intCast(buf.len),
                        &blocked_status,
                    );
                    if (res < 0) {
                        switch (s2n.s2n_error_get_type(s2n.s2n_errno)) {
                            s2n.S2N_ERR_T_CLOSED => return error.Closed,
                            else => return error.FailedRecv,
                        }
                    }

                    return @intCast(res);
                }
            }.recv,
            .send = struct {
                fn send(_: Socket, r: *Runtime, vt: *anyopaque, buf: []const u8) !usize {
                    const ctx: *Vtable = @ptrCast(@alignCast(vt));
                    ctx.cb_ctx.runtime = r;
                    var blocked_status: s2n.s2n_blocked_status = undefined;

                    const res = s2n.s2n_send(
                        ctx.conn,
                        buf.ptr,
                        @intCast(buf.len),
                        &blocked_status,
                    );
                    if (res < 0) {
                        switch (s2n.s2n_error_get_type(s2n.s2n_errno)) {
                            s2n.S2N_ERR_T_CLOSED => return error.Closed,
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
                s2n.s2n_strerror(s2n.s2n_errno, "EN"),
                s2n.s2n_strerror_debug(s2n.s2n_errno, "EN"),
            },
        );
        s2n.s2n_errno_location().* = s2n.S2N_ERR_T_OK;

        return error.InternalError;
    }
}

const Vtable = struct {
    s2n: *S2N,
    conn: *s2n.s2n_connection,
    cb_ctx: *Callback,
};
const Callback = struct { socket: Socket, runtime: ?*Runtime };

const log = std.log.scoped(.s2n);

const std = @import("std");
const mem = std.mem;

const s2n = @import("s2n_h");
const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Tls = @import("root.zig");
