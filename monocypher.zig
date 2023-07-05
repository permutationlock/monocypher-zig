// Copyright (c) 2023 Daniel Aven Bross
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const std = @import("std");

const testing = std.testing;
const expect = std.testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;
const expectEqualStrings = testing.expectEqualStrings;

const assert = std.debug.assert;

const raw = @import("monocypher_raw.zig");

pub const DecryptError = error{MessageCorrupted};

pub fn verify16(a: *const [16]u8, b: *const [16]u8) bool {
    return 0 == raw.crypto_verify16(
        @ptrCast([*c]const u8, a),
        @ptrCast([*c]const u8, b)
    );
}

pub fn verify32(a: *const [32]u8, b: *const [32]u8) bool {
    return 0 == raw.crypto_verify32(
        @ptrCast([*c]const u8, a),
        @ptrCast([*c]const u8, b)
    );
}

pub fn verify64(a: *const [64]u8, b: *const [64]u8) bool {
    return 0 == raw.crypto_verify64(
        @ptrCast([*c]const u8, a),
        @ptrCast([*c]const u8, b)
    );
}

test "constant time comparison" {
    const a16 = [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const b16 = [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const c16 = [16]u8{ 1, 72, 3, 41, 15, 23, 7, 3, 9, 0, 1, 1, 3, 1, 5, 1 };

    try expectEqual(verify16(&a16, &b16), true);
    try expectEqual(verify16(&a16, &c16), false);

    var a32: [32]u8 = undefined;
    var b32: [32]u8 = undefined;
    var c32: [32]u8 = undefined;

    for (a32[0..]) |_, i| {
        a32[i] = @truncate(u8, i);
        b32[i] = @truncate(u8, i);
        c32[i] = 5;
    }

    try expectEqual(verify32(&a32, &b32), true);
    try expectEqual(verify32(&a32, &c32), false);

    var a64: [64]u8 = undefined;
    var b64: [64]u8 = undefined;
    var c64: [64]u8 = undefined;

    for (a64[0..]) |_, i| {
        a64[i] = @truncate(u8, i);
        b64[i] = @truncate(u8, i);
        c64[i] = 5;
    }

    try expectEqual(verify64(&a64, &b64), true);
    try expectEqual(verify64(&a64, &c64), false);
}

pub const wipe = raw.crypto_wipe;

test "memory wipe" {
    const MyData = struct {
        id: u64,
        blocks: [4]u16,
    };
    var data = MyData{
        .id = 72,
        .blocks = [4]u16{ 7, 2, 3, 1 },
    };
    wipe(&data, @sizeOf(MyData));
    try expectEqual(data.id, 0);
    const zeros = [4]u16{ 0, 0, 0, 0 };
    try expectEqualSlices(u16, &data.blocks, &zeros);
}

pub fn ae_lock(
    cipher_text: []u8,
    mac: *[16]u8,
    key: *const [32]u8,
    nonce: *const [24]u8,
    plain_text: []const u8
) void {
    assert(cipher_text.len >= plain_text.len);
    raw.crypto_aead_lock(
        @ptrCast([*c]u8, cipher_text), 
        @ptrCast([*c]u8, mac),
        @ptrCast([*c]const u8, key),
        @ptrCast([*c]const u8, nonce),
        @intToPtr([*c]const u8, 0),
        0,
        @ptrCast([*c]const u8, plain_text),
        plain_text.len
    );
}

pub fn ae_unlock(
    plain_text: []u8,
    mac: *const [16]u8,
    key: *const [32]u8,
    nonce: *const [24]u8,
    cipher_text: []const u8
) DecryptError!void {
    assert(cipher_text.len <= plain_text.len);
    if (0 != raw.crypto_aead_unlock(
            @ptrCast([*c]u8, plain_text),
            @ptrCast([*c]const u8, mac),
            @ptrCast([*c]const u8, key),
            @ptrCast([*c]const u8, nonce),
            @intToPtr([*c]const u8, 0), 0,
            @ptrCast([*c]const u8, cipher_text),
            cipher_text.len
        )
    ) {
        return DecryptError.MessageCorrupted;
    }
}

test "authenticated encryption" {
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    const original_string = "Shh, this is a secret.";
    const original_text = @as(*const [original_string.len]u8, original_string);
    var mac: [16]u8 = undefined;
    var cipher_text: [original_text.len]u8 = undefined;
    var plain_text: [original_text.len]u8 = undefined;

    try std.os.getrandom(&key);
    try std.os.getrandom(&nonce);
    ae_lock(&cipher_text, &mac, &key, &nonce, original_text);

    try ae_unlock(&plain_text, &mac, &key, &nonce, &cipher_text);

    try expectEqualStrings(original_text, &plain_text);
}

pub fn aead_lock(
    cipher_text: []u8,
    mac: *[16]u8,
    key: *const [32]u8,
    nonce: *const [24]u8,
    ad: []const u8,
    plain_text: []const u8
) void {
    assert(cipher_text.len >= plain_text.len);
    raw.crypto_aead_lock(
        @ptrCast([*c]u8, cipher_text),
        @ptrCast([*c]u8, mac),
        @ptrCast([*c]const u8, key),
        @ptrCast([*c]const u8, nonce),
        @ptrCast([*c]const u8, ad),
        ad.len, @ptrCast([*c]const u8, plain_text),
        plain_text.len
    );
}

pub fn aead_unlock(
    plain_text: []u8,
    mac: *const [16]u8,
    key: *const [32]u8,
    nonce: *const [24]u8,
    ad: []const u8,
    cipher_text: []const u8
) DecryptError!void {
    assert(cipher_text.len <= plain_text.len);
    if (0 != raw.crypto_aead_unlock(
            @ptrCast([*c]u8, plain_text),
            @ptrCast([*c]const u8, mac),
            @ptrCast([*c]const u8, key),
            @ptrCast([*c]const u8, nonce),
            @ptrCast([*c]const u8, ad),
            ad.len,
            @ptrCast([*c]const u8, cipher_text),
            cipher_text.len
        )
    ) {
        return DecryptError.MessageCorrupted;
    }
}

test "authenticated encryption with additional data" {
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    const original_string = "Shh, this is a secret.";
    const original_text = @as(*const [original_string.len]u8, original_string);
    const ad = [_]u8{ 8, 3, 1, 2, 43, 2, 23, 2 };
    var mac: [16]u8 = undefined;
    var cipher_text: [original_text.len]u8 = undefined;
    var plain_text: [original_text.len]u8 = undefined;

    try std.os.getrandom(&key);
    try std.os.getrandom(&nonce);
    aead_lock(&cipher_text, &mac, &key, &nonce, &ad, original_text);

    try aead_unlock(&plain_text, &mac, &key, &nonce, &ad, &cipher_text);

    try expectEqualStrings(original_text, &plain_text);
}

pub fn AuthenticatedReader(
    comptime ReaderType: type,
    comptime chunk_size: comptime_int
) type {
    return struct {
        const Self = @This();

        pub const block_size = chunk_size + @sizeOf(usize);
        pub const len_index = chunk_size;
        context: raw.crypto_aead_ctx,
        block_index: usize,
        block_len: usize,
        block: [block_size]u8,
        child_stream: ReaderType,

        pub const Error = ReaderType.Error || DecryptError;
        pub const Reader = std.io.Reader(*Self, Error, read);

        pub fn read(self: *Self, bytes: []u8) Error!usize {
            var index: usize = 0;

            // read any remaining data from last decrypted block
            if (self.block_index < self.block_len) {
                index = std.math.min(
                    bytes.len,
                    self.block_len - self.block_index
                );
                std.mem.copy(
                    u8,
                    bytes[0..index],
                    self.block[self.block_index..self.block_len]
                );
                self.block_index += index;
            }
            if (index == bytes.len) {
                return index;
            }

            // read next mac
            var mac: [16]u8 = undefined;
            const mac_bytes = try self.child_stream.readAll(&mac);
            if (mac_bytes == 0) {
                return index;
            } else if (mac_bytes < 16) {
                return Error.MessageCorrupted;
            }

            // read next block
            self.block_index = 0;
            const amt = try self.child_stream.readAll(self.block[0..]);
            if (amt != block_size) {
                return Error.MessageCorrupted;
            }

            // decrypt block
            var bptr = @ptrCast([*c]u8, self.block[0..]);
            if (0 != raw.crypto_aead_read(
                    &self.context,
                    bptr,
                    &mac,
                    @intToPtr([*c]const u8, 0),
                    0,
                    bptr,
                    block_size
                )
            ) {
                return Error.MessageCorrupted;
            }
            self.block_len = std.mem.readIntLittle(
                usize,
                self.block[len_index..]
            );

            const next_index = std.math.min(index + self.block_len, bytes.len);
            self.block_index = next_index - index;
            std.mem.copy(
                u8, 
                bytes[index..next_index],
                self.block[0..self.block_index]
            );

            return next_index;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

pub fn authenticatedReader(
    child_stream: anytype,
    comptime block_size: comptime_int,
    key: *const [32]u8,
    nonce: *const [24]u8
) AuthenticatedReader(@TypeOf(child_stream), block_size) {
    var areader = AuthenticatedReader(@TypeOf(child_stream), block_size){
        .block = undefined,
        .context = undefined,
        .child_stream = child_stream,
        .block_index = 0,
        .block_len = 0,
    };
    raw.crypto_aead_init_x(
        &areader.context,
        @ptrCast([*c]const u8, key),
        @ptrCast([*c]const u8, nonce)
    );
    return areader;
}

pub fn AuthenticatedWriter(
    comptime WriterType: type,
    comptime chunk_size: comptime_int
) type {
    return struct {
        const Self = @This();

        pub const block_size = chunk_size + @sizeOf(usize);
        pub const len_index = chunk_size;
        context: raw.crypto_aead_ctx,
        child_stream: WriterType,

        pub const Error = WriterType.Error;
        pub const Writer = std.io.Writer(*Self, Error, write);

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            var mac: [16]u8 = undefined;
            var block: [block_size]u8 = undefined;

            // copy chunk bytes and length for encryption
            const index: usize = std.math.min(chunk_size, bytes.len);
            std.mem.copy(u8, block[0..index], bytes[0..index]);
            std.mem.writeIntLittle(usize, block[len_index..], index);

            // encrypt block
            var bptr = @ptrCast([*c]u8, &block);
            raw.crypto_aead_write(
                &self.context,
                bptr, 
                &mac,
                @intToPtr([*c]const u8, 0),
                0,
                bptr,
                block_size
            );

            // write the mac and encrypted block
            try self.child_stream.writeAll(&mac);
            try self.child_stream.writeAll(block[0..block_size]);

            return index;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

pub fn authenticatedWriter(
    child_stream: anytype,
    comptime block_size: comptime_int,
    key: *const [32]u8,
    nonce: *const [24]u8
) AuthenticatedWriter(@TypeOf(child_stream), block_size) {
    var awriter = AuthenticatedWriter(@TypeOf(child_stream), block_size){
        .context = undefined,
        .child_stream = child_stream,
    };
    raw.crypto_aead_init_x(
        &awriter.context,
        @ptrCast([*c]const u8, key),
        @ptrCast([*c]const u8, nonce)
    );
    return awriter;
}

test "authenticated encryptiion streams" {
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    try std.os.getrandom(&key);
    try std.os.getrandom(&nonce);

    var buffer: [512]u8 = undefined;
    var out = std.io.fixedBufferStream(&buffer);
    var in = std.io.fixedBufferStream(&buffer);
    var auth_out_stream = authenticatedWriter(out.writer(), 16, &key, &nonce);
    var auth_in_stream = authenticatedReader(in.reader(), 16, &key, &nonce);

    const original_string =
        \\This is a very long message that couldn't possibly fit in memory and
        \\be encrypted all at once."
    ;
    const original_text = @as(*const [original_string.len]u8, original_string);

    try auth_out_stream.writer().writeAll(original_text);

    var plaintext: [original_string.len]u8 = undefined;
    const amt_read = try auth_in_stream.reader().readAll(&plaintext);
    try expectEqual(amt_read, original_text.len);
    try expectEqualStrings(&plaintext, original_text);
}

pub fn blake2b(hash: []u8, message: []const u8) void {
    assert(hash.len <= 64);
    raw.crypto_blake2b(
        @ptrCast([*c]u8, hash),
        hash.len,
        @ptrCast([*c]const u8, message),
        message.len
    );
}

test "blake2b hash" {
    const original_string = "Shh, this is a secret.";
    const original_text = @as(*const [original_string.len]u8, original_string);
    var hash1: [64]u8 = undefined;
    var hash2: [64]u8 = undefined;

    blake2b(&hash1, original_text);
    blake2b(&hash2, original_text);
    try expectEqualSlices(u8, &hash1, &hash2);
}

pub fn blake2b_keyed(hash: []u8, key: []const u8, message: []const u8) void {
    assert(key.len <= 64);
    raw.crypto_blake2b_keyed(
        @ptrCast([*c]u8, hash),
        hash.len,
        @ptrCast([*c]const u8, key),
        key.len,
        @ptrCast([*c]const u8, message),
        message.len
    );
}

test "blake2b keyed hash" {
    var key: [32]u8 = undefined;
    const original_string = "Shh, this is a secret.";
    const original_text = @as(*const [original_string.len]u8, original_string);

    try std.os.getrandom(&key);

    var hash1: [64]u8 = undefined;
    var hash2: [64]u8 = undefined;

    blake2b_keyed(&hash1, &key, original_text);
    blake2b_keyed(&hash2, &key, original_text);
    try expectEqualSlices(u8, &hash1, &hash2);
}

pub const Blake2bHashStream = struct {
    const Self = @This();

    hash_size: usize,
    context: raw.crypto_blake2b_ctx,

    pub fn init(hash_size: usize) Self {
        assert(hash_size <= 64);
        var self = Self{
            .hash_size = hash_size,
            .context = undefined,
        };
        const ctx_ptr = @ptrCast([*c]raw.crypto_blake2b_ctx, &self.context);
        raw.crypto_blake2b_init(ctx_ptr, hash_size);
        return self;
    }

    pub fn keyed_init(key: []u8, hash_size: usize) Self {
        assert(key.len <= 64);
        var self = Self{
            .hash_size = hash_size,
            .context = undefined,
        };
        const ctx_ptr = @ptrCast([*c]raw.crypto_blake2b_ctx, &self.context);
        raw.crypto_blake2b_keyed_init(
            ctx_ptr,
            hash_size,
            @ptrCast([*c]const u8, key),
            key.len
        );
        return self;
    }

    pub fn update(self: *Self, message: []const u8) void {
        const ctx_ptr = @ptrCast([*c]raw.crypto_blake2b_ctx, &self.context);
        raw.crypto_blake2b_update(
            ctx_ptr,
            @ptrCast([*c]const u8, message),
            message.len
        );
    }

    pub fn final(self: *Self, hash: []u8) void {
        assert(hash.len >= self.hash_size);
        const ctx_ptr = @ptrCast([*c]raw.crypto_blake2b_ctx, &self.context);
        raw.crypto_blake2b_final(ctx_ptr, @ptrCast([*c]u8, hash));
    }
};

test "blake2b hash incremental" {
    var hash: [64]u8 = undefined;
    var hash_inc: [64]u8 = undefined;

    const original_string = 
        \\This is a very long message that couldn't possibly fit in memory and
        \\be hashed all at once."
    ;
    const original_text = @as(*const [original_string.len]u8, original_string);

    blake2b(&hash, original_text);

    var stream = Blake2bHashStream.init(hash_inc.len);
    stream.update(original_text);
    stream.final(&hash_inc);

    try expectEqualSlices(u8, &hash, &hash_inc);
}

test "blake2b keyed hash incremental" {
    var key: [32]u8 = undefined;
    try std.os.getrandom(&key);

    var hash: [64]u8 = undefined;
    var hash_inc: [64]u8 = undefined;

    const original_string = 
        \\This is a very long message that couldn't possibly fit in memory and
        \\be hashed all at once."
    ;
    const original_text = @as(*const [original_string.len]u8, original_string);

    blake2b_keyed(&hash, &key, original_text);

    var stream = Blake2bHashStream.keyed_init(&key, hash_inc.len);
    stream.update(original_text);
    stream.final(&hash_inc);

    try expectEqualSlices(u8, &hash, &hash_inc);
}

pub const Argon2 = struct {
    const Self = @This();
    const Allocator = std.mem.Allocator;

    const Block = struct {
        data: [1024]u8,
    };

    const Workspace = struct {
        blocks: []Block,
        config: raw.crypto_argon2_config,
    };

    workspace: ?Workspace,
    extras: raw.crypto_argon2_extras,

    pub const Argon2Error = error{NoWorkspace};

    pub const Algorithm = enum(u32) {
        Argon2d = 0,
        Argon2i = 1,
        Argon2id = 2,
    };

    pub fn init() Self {
        return Self{
            .workspace = null,
            .extras = raw.crypto_argon2_no_extras,
        };
    }

    pub fn make_workspace(
        self: *Self,
        allocator: Allocator,
        algorithm: Algorithm,
        blocks: u32,
        passes: u32
    ) !void {
        self.workspace = Workspace{
            .blocks = try allocator.alloc(Block, blocks),
            .config = raw.crypto_argon2_config{
                .algorithm = @enumToInt(algorithm),
                .nb_blocks = blocks,
                .nb_passes = passes,
                .nb_lanes = 1,
            },
        };
    }

    pub fn clear_workspace(self: *Self, allocator: Allocator) void {
        if (self.workspace == null) {
            return;
        }
        allocator.free(self.workspace.?.blocks);
        self.workspace = null;
    }

    pub fn set_key(self: *Self, key: []const u8) void {
        assert(key.len <= 64);
        self.extras.key = @ptrCast([*c]const u8, key);
        self.extras.key_size = @truncate(u32, key.len);
    }

    pub fn set_additional_data(self: *Self, ad: []const u8) void {
        self.extras.ad = @ptrCast([*c]const u8, ad);
        self.extras.ad_size = @truncate(u32, ad.len);
    }

    pub fn clear_extras(self: *Self) void {
        self.extras = raw.crypto_argon2_no_extras;
    }

    pub fn compute(
        self: *Self,
        hash: []u8,
        pass: []const u8,
        salt: []const u8
    ) Argon2Error!void {
        if (self.workspace == null) {
            return Argon2Error.NoWorkspace;
        }
        const inputs = raw.crypto_argon2_inputs{
            .pass = @ptrCast([*c]const u8, pass),
            .salt = @ptrCast([*c]const u8, salt),
            .pass_size = @truncate(u32, pass.len),
            .salt_size = @truncate(u32, salt.len),
        };
        raw.crypto_argon2(
            @ptrCast([*c]u8, hash),
            @truncate(u32, hash.len),
            @ptrCast([*c]u8, self.workspace.?.blocks),
            self.workspace.?.config, inputs,
            self.extras
        );
    }
};

test "argon2 password hashing" {
    var salt: [16]u8 = undefined;
    try std.os.getrandom(&salt);

    var key: [32]u8 = undefined;
    try std.os.getrandom(&key);

    const ad_string = "some other stuff";
    const ad_text = @as(*const [ad_string.len]u8, ad_string);

    const password_string = "abc123";
    const password_text = @as(*const [password_string.len]u8, password_string);

    var argon2 = Argon2.init();
    try argon2.make_workspace(std.testing.allocator, .Argon2d, 64, 1);
    defer argon2.clear_workspace(std.testing.allocator);
    argon2.set_key(&key);
    argon2.set_additional_data(ad_text);

    var hash1: [64]u8 = undefined;
    var hash2: [64]u8 = undefined;
    try argon2.compute(&hash1, password_text, &salt);
    try argon2.compute(&hash2, password_text, &salt);

    try expectEqualSlices(u8, &hash1, &hash2);
}

pub fn x25519_public_key(public_key: *[32]u8, secret_key: *const [32]u8) void {
    raw.crypto_x25519_public_key(
        @ptrCast([*c]u8, public_key),
        @ptrCast([*c]const u8, secret_key)
    );
}

pub fn x25519(
    shared_secret: *[32]u8,
    your_secret_key: *const [32]u8,
    their_public_key: *const [32]u8
) void {
    raw.crypto_x25519(
        @ptrCast([*c]u8, shared_secret),
        @ptrCast([*c]const u8, your_secret_key),
        @ptrCast([*c]const u8, their_public_key)
    );
}

test "x25519 key exchange" {
    var public_key1: [32]u8 = undefined;
    var secret_key1: [32]u8 = undefined;
    var public_key2: [32]u8 = undefined;
    var secret_key2: [32]u8 = undefined;
    var shared_key1: [32]u8 = undefined;
    var shared_key2: [32]u8 = undefined;

    try std.os.getrandom(&secret_key1);
    x25519_public_key(&public_key1, &secret_key1);

    try std.os.getrandom(&secret_key2);
    x25519_public_key(&public_key2, &secret_key2);

    x25519(&shared_key1, &secret_key1, &public_key2);
    x25519(&shared_key2, &secret_key2, &public_key1);
    try expectEqualSlices(u8, &shared_key1, &shared_key2);
}

pub fn eddsa_key_pair(
    secret_key: *[64]u8, public_key: *[32]u8, seed: *[32]u8
) void {
    raw.crypto_eddsa_key_pair(
        @ptrCast([*c]u8, secret_key),
        @ptrCast([*c]u8, public_key),
        @ptrCast([*c]u8, seed)
    );
}

pub fn eddsa_sign(
    signature: *[64]u8,
    secret_key: *const [64]u8,
    message: []const u8
) void {
    raw.crypto_eddsa_sign(
        @ptrCast([*c]u8, signature),
        @ptrCast([*c]const u8, secret_key),
        @ptrCast([*c]const u8, message),
        message.len
    );
}

pub fn eddsa_check(
    signature: *const [64]u8,
    public_key: *const [32]u8,
    message: []const u8
) bool {
    return 0 == raw.crypto_eddsa_check(
        @ptrCast([*c]const u8, signature),
        @ptrCast([*c]const u8, public_key),
        @ptrCast([*c]const u8, message),
        message.len
    );
}

test "eddsa signatures" {
    var secret_key: [64]u8 = undefined;
    var public_key: [32]u8 = undefined;
    var signature: [64]u8 = undefined;

    const original_string = "This was definitely sent by me.";
    const original_text = @as(*const [original_string.len]u8, original_string);

    var seed: [32]u8 = undefined;
    try std.os.getrandom(&seed);
    eddsa_key_pair(&secret_key, &public_key, &seed);

    eddsa_sign(&signature, &secret_key, original_text);
    try expectEqual(true, eddsa_check(&signature, &public_key, original_text));
}
