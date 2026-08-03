pub const BearSSL = @This();

pub const PrivateKey = union(enum) {
    rsa: bearssl.br_rsa_private_key,
    ec: bearssl.br_ec_private_key,
};

x509: ?bearssl.br_x509_certificate,
pkey: ?PrivateKey,
cert_signer_algo: ?c_int,

pub fn init() BearSSL {
    return .{
        .x509 = null,
        .pkey = null,
        .cert_signer_algo = null,
    };
}

pub fn deinit(self: BearSSL, allocator: mem.Allocator) void {
    if (self.x509) |x509|
        allocator.free(x509.data[0..x509.data_len]);

    if (self.pkey) |pkey| switch (pkey) {
        .rsa => |inner| {
            allocator.free(inner.p[0..inner.plen]);
            allocator.free(inner.q[0..inner.qlen]);
            allocator.free(inner.dp[0..inner.dplen]);
            allocator.free(inner.dq[0..inner.dqlen]);
            allocator.free(inner.iq[0..inner.iqlen]);
        },
        .ec => |inner| {
            allocator.free(inner.x[0..inner.xlen]);
        },
    };
}

/// This takes in the PEM section and the given bytes and decodes it into a byte format
/// that can be ingested later by the BearSSL x509 certificate.
fn decode_pem(
    allocator: mem.Allocator,
    section_title: ?[]const u8,
    bytes: []const u8,
) ![]const u8 {
    var p_ctx: bearssl.br_pem_decoder_context = undefined;
    bearssl.br_pem_decoder_init(&p_ctx);

    var decoded: std.ArrayList(u8) = try .initCapacity(
        allocator,
        bytes.len,
    );
    defer decoded.deinit(allocator);

    bearssl.br_pem_decoder_setdest(&p_ctx, struct {
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
        written += bearssl.br_pem_decoder_push(
            &p_ctx,
            bytes[written..].ptr,
            bytes.len - written,
        );
        const event = bearssl.br_pem_decoder_event(&p_ctx);
        switch (event) {
            0 => continue,
            bearssl.BR_PEM_BEGIN_OBJ => {
                const name = bearssl.br_pem_decoder_name(&p_ctx);
                if (section_title) |title| {
                    if (mem.eql(u8, mem.span(name), title)) {
                        found = true;
                        decoded.clearRetainingCapacity();
                    }
                } else found = true;
            },
            bearssl.BR_PEM_END_OBJ => if (found)
                return decoded.toOwnedSlice(allocator),
            bearssl.BR_PEM_ERROR => return error.PemDecodeFailed,
            else => return error.PemDecodeUnknownEvent,
        }
    }

    return error.PemDecodeNotFinished;
}

fn decode_private_key(allocator: mem.Allocator, decoded_key: []const u8) !PrivateKey {
    var sk_ctx: bearssl.br_skey_decoder_context = undefined;
    bearssl.br_skey_decoder_init(&sk_ctx);
    bearssl.br_skey_decoder_push(
        &sk_ctx,
        decoded_key.ptr,
        decoded_key.len,
    );

    if (bearssl.br_skey_decoder_last_error(&sk_ctx) != 0)
        return error.PrivateKeyDecodeFailed;

    const key_type = bearssl.br_skey_decoder_key_type(&sk_ctx);

    return switch (key_type) {
        bearssl.BR_KEYTYPE_RSA => key: {
            const key = bearssl.br_skey_decoder_get_rsa(&sk_ctx)[0];

            const p = try allocator.dupe(u8, key.p[0..key.plen]);
            errdefer allocator.free(p);

            const q = try allocator.dupe(u8, key.q[0..key.qlen]);
            errdefer allocator.free(q);

            const dp = try allocator.dupe(u8, key.dp[0..key.dplen]);
            errdefer allocator.free(dp);

            const dq = try allocator.dupe(u8, key.dq[0..key.dqlen]);
            errdefer allocator.free(dq);

            const iq = try allocator.dupe(u8, key.iq[0..key.iqlen]);
            errdefer allocator.free(iq);

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
        bearssl.BR_KEYTYPE_EC => key: {
            const key = bearssl.br_skey_decoder_get_ec(&sk_ctx)[0];
            const x = try allocator.dupe(u8, key.x[0..key.xlen]);
            errdefer allocator.free(x);

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

fn get_cert_signer_algo(x509: *const bearssl.br_x509_certificate) c_int {
    var x509_ctx: bearssl.br_x509_decoder_context = undefined;

    bearssl.br_x509_decoder_init(
        &x509_ctx,
        null,
        null,
    );
    bearssl.br_x509_decoder_push(
        &x509_ctx,
        x509.data.?,
        x509.data_len,
    );

    if (bearssl.br_x509_decoder_last_error(&x509_ctx) != 0) return 0;

    return bearssl.br_x509_decoder_get_signer_key_type(&x509_ctx);
}

pub fn add_cert_chain(
    self: *BearSSL,
    cert_section_title: ?[]const u8,
    cert: []const u8,
    key_section_title: ?[]const u8,
    key: []const u8,
) !void {
    const decoded_cert = try decode_pem(
        self.allocator,
        cert_section_title,
        cert,
    );
    errdefer self.allocator.free(decoded_cert);

    self.x509 = .{
        .data = @constCast(decoded_cert.ptr),
        .data_len = decoded_cert.len,
    };

    const decoded_key = try decode_pem(
        self.allocator,
        key_section_title,
        key,
    );
    defer self.allocator.free(decoded_key);

    self.pkey = try decode_private_key(
        self.allocator,
        decoded_key,
    );

    self.cert_signer_algo = get_cert_signer_algo(&self.x509.?);
}

pub fn to_secure_socket(
    self: *BearSSL,
    socket: Socket,
    mode: Tls.Mode,
) !*Tls {
    switch (mode) {
        .client => @panic("Client TLS not supported yet!"),
        .server => {
            const server = @import("server.zig");
            return server.to_secure_socket_server(self, socket);
        },
    }
}

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
            bearssl.BR_ERR_OK => .Ok,
            bearssl.BR_ERR_BAD_PARAM => .BadParam,
            bearssl.BR_ERR_BAD_STATE => .BadState,
            bearssl.BR_ERR_UNSUPPORTED_VERSION => .UnsupportedVersion,
            bearssl.BR_ERR_BAD_VERSION => .BadVersion,
            bearssl.BR_ERR_TOO_LARGE => .TooLarge,
            bearssl.BR_ERR_BAD_MAC => .BadMac,
            bearssl.BR_ERR_NO_RANDOM => .NoRandom,
            bearssl.BR_ERR_UNKNOWN_TYPE => .UnknownType,
            bearssl.BR_ERR_UNEXPECTED => .Unexpected,
            bearssl.BR_ERR_BAD_CCS => .BadCcs,
            bearssl.BR_ERR_BAD_ALERT => .BadAlert,
            bearssl.BR_ERR_BAD_HANDSHAKE => .BadHandshake,
            bearssl.BR_ERR_OVERSIZED_ID => .OversizedId,
            bearssl.BR_ERR_BAD_CIPHER_SUITE => .BadCipherSuite,
            bearssl.BR_ERR_BAD_COMPRESSION => .BadCompression,
            bearssl.BR_ERR_BAD_FRAGLEN => .BadFragLen,
            bearssl.BR_ERR_BAD_SECRENEG => .BadSecretReneg,
            bearssl.BR_ERR_EXTRA_EXTENSION => .ExtraExtension,
            bearssl.BR_ERR_BAD_SNI => .BadSNI,
            bearssl.BR_ERR_BAD_HELLO_DONE => .BadHelloDone,
            bearssl.BR_ERR_LIMIT_EXCEEDED => .LimitExceeded,
            bearssl.BR_ERR_BAD_FINISHED => .BadFinished,
            bearssl.BR_ERR_RESUME_MISMATCH => .ResumeMismatch,
            bearssl.BR_ERR_INVALID_ALGORITHM => .InvalidAlgorithm,
            bearssl.BR_ERR_BAD_SIGNATURE => .BadSignature,
            bearssl.BR_ERR_WRONG_KEY_USAGE => .WrongKeyUsage,
            bearssl.BR_ERR_NO_CLIENT_AUTH => .NoClientAuth,
            bearssl.BR_ERR_IO => .InputOutput,
            bearssl.BR_ERR_RECV_FATAL_ALERT => .RecvFatal,
            bearssl.BR_ERR_SEND_FATAL_ALERT => .SendFatal,
            else => .Unknown,
        };
    }
};

const std = @import("std");
const mem = std.mem;

const bearssl = @import("bearssl_h");
const tardy = @import("tardy");
const Socket = tardy.net.Socket;

const Tls = @import("root.zig");
