pub const BearSSL = @This();

x509: h.br_x509_certificate,
pkey: PrivateKey,
cert_signer_algo: c_int,

io_buf: []const u8 = undefined,
sslio: h.br_sslio_context = undefined,
cb: *Callback = undefined,
server: h.br_ssl_server_context = undefined,

pub fn init(gpa: mem.Allocator, config: Init) !Secsock {
    const socket = gpa.create(Socket) catch @panic("OOM");
    socket.* = try .init(.{ .tcp = config.socket });
    errdefer gpa.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(config.socket.backlog);

    var bearssl = try tlsInit(gpa, config);
    errdefer bearssl.deinit(gpa);

    const new = try bearssl.tlsWithSock(
        gpa,
        socket,
        config.socket.mode,
    );
    errdefer new.deinit(gpa);

    return new;
}

pub fn deinit(bearssl: *const BearSSL, gpa: mem.Allocator) void {
    bearssl.cb.socket.close_blocking();
    gpa.destroy(bearssl.cb.socket);

    gpa.destroy(bearssl.cb);
    gpa.free(bearssl.io_buf);
    gpa.destroy(bearssl);
}

pub fn free(bearssl: BearSSL, gpa: mem.Allocator) void {
    gpa.free(bearssl.x509.data[0..bearssl.x509.data_len]);

    switch (bearssl.pkey) {
        .rsa => |rsa| {
            gpa.free(rsa.p[0..rsa.plen]);
            gpa.free(rsa.q[0..rsa.qlen]);
            gpa.free(rsa.dp[0..rsa.dplen]);
            gpa.free(rsa.dq[0..rsa.dqlen]);
            gpa.free(rsa.iq[0..rsa.iqlen]);
        },
        .ec => |ec| {
            gpa.free(ec.x[0..ec.xlen]);
        },
    }
}

pub fn info(bearssl: *const BearSSL) secsock.Info {
    var buf: [21:0]u8 = @splat(0x0);
    _ = mem.print(&buf, "{f}", .{
        bearssl.cb.socket.addr,
    }) catch unreachable;

    return .{
        .name = .bearssl,
        .address = buf,
    };
}

pub fn accept(bearssl: *const BearSSL, r: *Runtime) !secsock.Secsock {
    const cb = bearssl.cb;

    const client = try r.gpa.create(Socket);
    errdefer r.gpa.destroy(client);

    client.* = try cb.socket.accept(r);
    errdefer client.close_blocking();

    const new: *BearSSL = @ptrCast(try r.gpa.dupe(BearSSL, &.{bearssl.*}));
    errdefer r.gpa.destroy(new);

    // TODO: is it valid to use previous or reset (REMOVE BEFORE COMMIT)
    new.cb.runtime = r;

    const new_bearssl = try new.tlsWithSock(
        r.gpa,
        client,
        .server,
    );
    // if we fail, we want to clean this connection up.
    errdefer new_bearssl.deinit(r.gpa);

    return new_bearssl;
}

pub fn connect(_: *const BearSSL, _: *Runtime) !void {
    return error.TLSServerCantConnect;
}

pub fn recv(bearssl: *BearSSL, r: *Runtime, b: []u8) !usize {
    bearssl.cb.runtime = r;

    const result = h.br_sslio_read(&bearssl.sslio, b.ptr, b.len);

    if (result < 0) {
        const last_error: EngineStatus = .convert(
            h.br_ssl_engine_last_error(&bearssl.server.eng),
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

pub fn send(bearssl: *BearSSL, r: *Runtime, b: []const u8) !usize {
    bearssl.cb.runtime = r;

    const write_result = h.br_sslio_write(
        &bearssl.sslio,
        b.ptr,
        b.len,
    );
    if (write_result < 0) {
        const last_error: EngineStatus = .convert(
            h.br_ssl_engine_last_error(&bearssl.server.eng),
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
    const flush_result = h.br_sslio_flush(&bearssl.sslio);
    if (flush_result < 0) {
        const last_error: EngineStatus = .convert(
            h.br_ssl_engine_last_error(&bearssl.server.eng),
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

fn tlsInit(gpa: mem.Allocator, config: Init) !*BearSSL {
    var bearssl = try gpa.create(BearSSL);

    try bearssl.add_cert_chain(
        gpa,
        config.cert_section_title,
        config.cert,
        config.key_section_title,
        config.key,
    );

    return bearssl;
}

fn add_cert_chain(
    bearssl: *BearSSL,
    gpa: mem.Allocator,
    cert_section_title: ?[]const u8,
    cert: []const u8,
    key_section_title: ?[]const u8,
    key: []const u8,
) !void {
    const decoded_cert = try decode_pem(
        gpa,
        cert_section_title,
        cert,
    );
    errdefer gpa.free(decoded_cert);

    bearssl.x509 = .{
        .data = @constCast(decoded_cert.ptr),
        .data_len = decoded_cert.len,
    };

    const decoded_key = try decode_pem(
        gpa,
        key_section_title,
        key,
    );
    defer gpa.free(decoded_key);

    bearssl.pkey = try decode_private_key(
        gpa,
        decoded_key,
    );

    bearssl.cert_signer_algo = get_cert_signer_algo(&bearssl.x509);
}

/// This takes in the PEM section and the given bytes and decodes it into a byte format
/// that can be ingested later by the BearSSL x509 certificate.
fn decode_pem(
    gpa: mem.Allocator,
    section_title: ?[]const u8,
    bytes: []const u8,
) ![]const u8 {
    var p_ctx: h.br_pem_decoder_context = undefined;
    h.br_pem_decoder_init(&p_ctx);

    var decoded: std.ArrayList(u8) = try .initCapacity(
        gpa,
        bytes.len,
    );
    defer decoded.deinit(gpa);

    h.br_pem_decoder_setdest(&p_ctx, struct {
        fn decoder(
            ctx: ?*anyopaque,
            src: ?*const anyopaque,
            size: usize,
        ) callconv(.c) void {
            var list: *std.ArrayList(u8) = @ptrCast(@alignCast(ctx.?));
            const data = @as([*]const u8, @ptrCast(src.?))[0..size];
            list.appendSliceAssumeCapacity(data);
        }
    }.decoder, &decoded);

    var found = false;
    var written: usize = 0;

    while (written < bytes.len) {
        written += h.br_pem_decoder_push(
            &p_ctx,
            bytes[written..].ptr,
            bytes.len - written,
        );
        const event = h.br_pem_decoder_event(&p_ctx);
        switch (event) {
            0 => continue,
            h.BR_PEM_BEGIN_OBJ => {
                const name = h.br_pem_decoder_name(&p_ctx);
                if (section_title) |title| {
                    if (mem.eql(u8, mem.span(name), title)) {
                        found = true;
                        decoded.clearRetainingCapacity();
                    }
                } else found = true;
            },
            h.BR_PEM_END_OBJ => if (found)
                return decoded.toOwnedSlice(gpa),
            h.BR_PEM_ERROR => return error.PemDecodeFailed,
            else => return error.PemDecodeUnknownEvent,
        }
    }

    return error.PemDecodeNotFinished;
}

fn decode_private_key(gpa: mem.Allocator, decoded_key: []const u8) !PrivateKey {
    var sk_ctx: h.br_skey_decoder_context = undefined;
    h.br_skey_decoder_init(&sk_ctx);
    h.br_skey_decoder_push(
        &sk_ctx,
        decoded_key.ptr,
        decoded_key.len,
    );

    if (h.br_skey_decoder_last_error(&sk_ctx) != 0)
        return error.PrivateKeyDecodeFailed;

    const key_type = h.br_skey_decoder_key_type(&sk_ctx);

    return switch (key_type) {
        h.BR_KEYTYPE_RSA => key: {
            const key = h.br_skey_decoder_get_rsa(&sk_ctx)[0];

            const p = try gpa.dupe(u8, key.p[0..key.plen]);
            errdefer gpa.free(p);

            const q = try gpa.dupe(u8, key.q[0..key.qlen]);
            errdefer gpa.free(q);

            const dp = try gpa.dupe(u8, key.dp[0..key.dplen]);
            errdefer gpa.free(dp);

            const dq = try gpa.dupe(u8, key.dq[0..key.dqlen]);
            errdefer gpa.free(dq);

            const iq = try gpa.dupe(u8, key.iq[0..key.iqlen]);
            errdefer gpa.free(iq);

            break :key .{
                .rsa = .{
                    .p = p.ptr,
                    .plen = key.plen,
                    .q = q.ptr,
                    .qlen = key.qlen,
                    .dp = dp.ptr,
                    .dplen = key.dplen,
                    .dq = dq.ptr,
                    .dqlen = key.dqlen,
                    .iq = iq.ptr,
                    .iqlen = key.iqlen,
                    .n_bitlen = key.n_bitlen,
                },
            };
        },
        h.BR_KEYTYPE_EC => key: {
            const key = h.br_skey_decoder_get_ec(&sk_ctx)[0];
            const x = try gpa.dupe(u8, key.x[0..key.xlen]);
            errdefer gpa.free(x);

            break :key .{
                .ec = .{
                    .x = x.ptr,
                    .xlen = key.xlen,
                    .curve = key.curve,
                },
            };
        },
        else => return error.InvalidKeyType,
    };
}

fn get_cert_signer_algo(x509: *const h.br_x509_certificate) c_int {
    var x509_ctx: h.br_x509_decoder_context = undefined;

    h.br_x509_decoder_init(
        &x509_ctx,
        null,
        null,
    );
    h.br_x509_decoder_push(
        &x509_ctx,
        x509.data.?,
        x509.data_len,
    );

    if (h.br_x509_decoder_last_error(&x509_ctx) != 0) return 0;

    return h.br_x509_decoder_get_signer_key_type(&x509_ctx);
}

/// internal API
pub fn tlsWithSock(
    bearssl: *BearSSL,
    gpa: mem.Allocator,
    socket: *const Socket,
    mode: Socket.Mode,
) !Secsock {
    switch (mode) {
        .client => @panic("Client bearssl not supported yet!"),
        .server => {
            return server_tls(
                bearssl,
                gpa,
                socket,
            );
        },
    }
}

fn server_tls(
    bearssl: *BearSSL,
    gpa: mem.Allocator,
    socket: *const Socket,
) !secsock.Secsock {
    const io_buf = try gpa.alloc(u8, h.BR_SSL_BUFSIZE_BIDI);
    errdefer gpa.free(io_buf);

    const cb_ctx = try gpa.create(Callback);
    errdefer gpa.destroy(cb_ctx);

    cb_ctx.* = .{ .runtime = null, .socket = socket };

    bearssl.cb = cb_ctx;
    bearssl.io_buf = io_buf;

    switch (bearssl.pkey) {
        .rsa => |*rsa| h.br_ssl_server_init_full_rsa(
            &bearssl.server,
            @ptrCast(&bearssl.x509),
            1,
            @ptrCast(rsa),
        ),
        .ec => |*ec| h.br_ssl_server_init_full_ec(
            &bearssl.server,
            @ptrCast(&bearssl.x509),
            1,
            @intCast(bearssl.cert_signer_algo),
            @ptrCast(ec),
        ),
    }

    h.br_ssl_engine_set_buffer(
        &bearssl.server.eng,
        io_buf.ptr,
        io_buf.len,
        1,
    );
    const reset_status = h.br_ssl_server_reset(&bearssl.server);
    if (reset_status <= 0) return error.ServerResetFailed;

    h.br_sslio_init(
        &bearssl.sslio,
        &bearssl.server.eng,
        Callback.recv,
        cb_ctx,
        Callback.send,
        cb_ctx,
    );

    return .{
        .tls = .{ .bearssl = bearssl },
    };
}

const Callback = struct {
    socket: *const Socket,
    runtime: ?*Runtime,

    fn recv(c: ?*anyopaque, buf: [*c]u8, len: usize) callconv(.c) c_int {
        const cb: *Callback = @ptrCast(@alignCast(c.?));
        const count = cb.socket.recv(
            cb.runtime.?,
            buf[0..len],
        ) catch |e| {
            log.err("sslio recv cb failed: {t}", .{e});
            return -1;
        };
        return @intCast(count);
    }

    fn send(c: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.c) c_int {
        const cb: *Callback = @ptrCast(@alignCast(c.?));
        const count = cb.socket.send(
            cb.runtime.?,
            buf[0..len],
        ) catch |e| {
            log.err("sslio send cb failed: {t}", .{e});
            return -1;
        };
        return @intCast(count);
    }
};

pub const EngineStatus = enum {
    Ok,
    BadParam,
    BadState,
    UnsupportedVersion,
    BadVersion,
    TooLarge,
    BadMac,
    NoRandom,
    UnknownType,
    Unexpected,
    BadCcs,
    BadAlert,
    BadHandshake,
    OversizedId,
    BadCipherSuite,
    BadCompression,
    BadFragLen,
    BadSecretReneg,
    ExtraExtension,
    BadSNI,
    BadHelloDone,
    LimitExceeded,
    BadFinished,
    ResumeMismatch,
    InvalidAlgorithm,
    BadSignature,
    WrongKeyUsage,
    NoClientAuth,
    InputOutput,
    RecvFatal,
    SendFatal,
    Unknown,

    pub fn convert(status_code: c_int) EngineStatus {
        return switch (status_code) {
            h.BR_ERR_OK => .Ok,
            h.BR_ERR_BAD_PARAM => .BadParam,
            h.BR_ERR_BAD_STATE => .BadState,
            h.BR_ERR_UNSUPPORTED_VERSION => .UnsupportedVersion,
            h.BR_ERR_BAD_VERSION => .BadVersion,
            h.BR_ERR_TOO_LARGE => .TooLarge,
            h.BR_ERR_BAD_MAC => .BadMac,
            h.BR_ERR_NO_RANDOM => .NoRandom,
            h.BR_ERR_UNKNOWN_TYPE => .UnknownType,
            h.BR_ERR_UNEXPECTED => .Unexpected,
            h.BR_ERR_BAD_CCS => .BadCcs,
            h.BR_ERR_BAD_ALERT => .BadAlert,
            h.BR_ERR_BAD_HANDSHAKE => .BadHandshake,
            h.BR_ERR_OVERSIZED_ID => .OversizedId,
            h.BR_ERR_BAD_CIPHER_SUITE => .BadCipherSuite,
            h.BR_ERR_BAD_COMPRESSION => .BadCompression,
            h.BR_ERR_BAD_FRAGLEN => .BadFragLen,
            h.BR_ERR_BAD_SECRENEG => .BadSecretReneg,
            h.BR_ERR_EXTRA_EXTENSION => .ExtraExtension,
            h.BR_ERR_BAD_SNI => .BadSNI,
            h.BR_ERR_BAD_HELLO_DONE => .BadHelloDone,
            h.BR_ERR_LIMIT_EXCEEDED => .LimitExceeded,
            h.BR_ERR_BAD_FINISHED => .BadFinished,
            h.BR_ERR_RESUME_MISMATCH => .ResumeMismatch,
            h.BR_ERR_INVALID_ALGORITHM => .InvalidAlgorithm,
            h.BR_ERR_BAD_SIGNATURE => .BadSignature,
            h.BR_ERR_WRONG_KEY_USAGE => .WrongKeyUsage,
            h.BR_ERR_NO_CLIENT_AUTH => .NoClientAuth,
            h.BR_ERR_IO => .InputOutput,
            h.BR_ERR_RECV_FATAL_ALERT => .RecvFatal,
            h.BR_ERR_SEND_FATAL_ALERT => .SendFatal,
            else => .Unknown,
        };
    }
};

pub const PrivateKey = union(enum) {
    rsa: h.br_rsa_private_key,
    ec: h.br_ec_private_key,
};

pub const Init = struct {
    cert_section_title: ?[]const u8,
    cert: []const u8,
    key_section_title: ?[]const u8,
    key: []const u8,
    socket: Socket.Config,
};

const log = std.log.scoped(.@"secsock/BearSSL");

const std = @import("std");
const mem = std.mem;

pub const h = @import("bearssl.h");
const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const secsock = @import("secsock.zig");
const Secsock = secsock.Secsock;
