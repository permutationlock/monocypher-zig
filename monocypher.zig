const std = @import("std");

const testing = std.testing;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;
const expectEqualStrings = testing.expectEqualStrings;

const assert = std.debug.assert;

const mcraw = @import("monocypher_raw.zig");

pub const DecryptError = error{MessageCorrupted};

pub fn crypto_verify16(a: *const [16]u8, b: *const [16]u8) bool {
    return 0 == mcraw.crypto_verify16(@ptrCast([*c]const u8, a), @ptrCast([*c]const u8, b));
}

pub fn crypto_verify32(a: *const [32]u8, b: *const [32]u8) bool {
    return 0 == mcraw.crypto_verify32(@ptrCast([*c]const u8, a), @ptrCast([*c]const u8, b));
}

pub fn crypto_verify64(a: *const [64]u8, b: *const [64]u8) bool {
    return 0 == mcraw.crypto_verify64(@ptrCast([*c]const u8, a), @ptrCast([*c]const u8, b));
}

test "constant time comparison" {
    const a = [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const b = [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const c = [16]u8{ 1, 72, 3, 41, 15, 23, 7, 3, 9, 0, 1, 1, 3, 1, 5, 1 };

    try expectEqual(crypto_verify16(&a, &b), true);
    try expectEqual(crypto_verify16(&a, &c), false);
}

pub const crypto_wipe = mcraw.crypto_wipe;

test "memory wipe" {
    const MyData = struct {
        id: u64,
        blocks: [4]u16,
    };
    var data = MyData{
        .id = 72,
        .blocks = [4]u16{ 7, 2, 3, 1 },
    };
    crypto_wipe(&data, @sizeOf(MyData));
    try expectEqual(data.id, 0);
    const zeros = [4]u16{ 0, 0, 0, 0 };
    try expectEqualSlices(u16, &data.blocks, &zeros);
}

pub fn crypto_ae_lock(cipher_text: []u8, mac: *[16]u8, key: *const [32]u8, nonce: *const [24]u8, plain_text: []const u8) void {
    assert(cipher_text.len == plain_text.len);
    mcraw.crypto_aead_lock(@ptrCast([*c]u8, cipher_text), @ptrCast([*c]u8, mac), @ptrCast([*c]const u8, key), @ptrCast([*c]const u8, nonce), @intToPtr([*c]const u8, 0), 0, @ptrCast([*c]const u8, plain_text), plain_text.len);
}

pub fn crypto_ae_unlock(plain_text: []u8, mac: *const [16]u8, key: *const [32]u8, nonce: *const [24]u8, cipher_text: []const u8) DecryptError!void {
    assert(cipher_text.len == plain_text.len);
    if (0 != mcraw.crypto_aead_unlock(@ptrCast([*c]u8, plain_text), @ptrCast([*c]const u8, mac), @ptrCast([*c]const u8, key), @ptrCast([*c]const u8, nonce), @intToPtr([*c]const u8, 0), 0, @ptrCast([*c]const u8, cipher_text), cipher_text.len)) {
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
    crypto_ae_lock(&cipher_text, &mac, &key, &nonce, original_text);

    try crypto_ae_unlock(&plain_text, &mac, &key, &nonce, &cipher_text);

    try expectEqualStrings(original_text, &plain_text);
}

pub fn crypto_aead_lock(cipher_text: []u8, mac: *[16]u8, key: *const [32]u8, nonce: *const [24]u8, ad: []const u8, plain_text: []const u8) void {
    assert(cipher_text.len == plain_text.len);
    mcraw.crypto_aead_lock(@ptrCast([*c]u8, cipher_text), @ptrCast([*c]u8, mac), @ptrCast([*c]const u8, key), @ptrCast([*c]const u8, nonce), @ptrCast([*c]const u8, ad), ad.len, @ptrCast([*c]const u8, plain_text), plain_text.len);
}

pub fn crypto_aead_unlock(plain_text: []u8, mac: *const [16]u8, key: *const [32]u8, nonce: *const [24]u8, ad: []const u8, cipher_text: []const u8) DecryptError!void {
    assert(cipher_text.len == plain_text.len);
    if (0 != mcraw.crypto_aead_unlock(@ptrCast([*c]u8, plain_text), @ptrCast([*c]const u8, mac), @ptrCast([*c]const u8, key), @ptrCast([*c]const u8, nonce), @ptrCast([*c]const u8, ad), ad.len, @ptrCast([*c]const u8, cipher_text), cipher_text.len)) {
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
    crypto_aead_lock(&cipher_text, &mac, &key, &nonce, &ad, original_text);

    try crypto_aead_unlock(&plain_text, &mac, &key, &nonce, &ad, &cipher_text);

    try expectEqualStrings(original_text, &plain_text);
}

pub fn crypto_blake2b(hash: []u8, message: []const u8) void {
    mcraw.crypto_blake2b(@ptrCast([*c]u8, hash), hash.len, @ptrCast([*c]const u8, message), message.len);
}

test "blake2b hash" {
    const original_string = "Shh, this is a secret.";
    const original_text = @as(*const [original_string.len]u8, original_string);
    var hash1: [64]u8 = undefined;
    var hash2: [64]u8 = undefined;

    crypto_blake2b(&hash1, original_text);
    crypto_blake2b(&hash2, original_text);
    try expectEqualSlices(u8, &hash1, &hash2);
}

pub fn crypto_blake2b_keyed(hash: []u8, key: []const u8, message: []const u8) void {
    mcraw.crypto_blake2b_keyed(@ptrCast([*c]u8, hash), hash.len, @ptrCast([*c]const u8, key), key.len, @ptrCast([*c]const u8, message), message.len);
}

test "blake2b keyed hash" {
    var key: [32]u8 = undefined;
    const original_string = "Shh, this is a secret.";
    const original_text = @as(*const [original_string.len]u8, original_string);

    try std.os.getrandom(&key);

    var hash1: [64]u8 = undefined;
    var hash2: [64]u8 = undefined;

    crypto_blake2b_keyed(&hash1, &key, original_text);
    crypto_blake2b_keyed(&hash2, &key, original_text);
    try expectEqualSlices(u8, &hash1, &hash2);
}

pub fn crypto_x25519_public_key(public_key: *[32]u8, secret_key: *const [32]u8) void {
    mcraw.crypto_x25519_public_key(@ptrCast([*c]u8, public_key), @ptrCast([*c]const u8, secret_key));
}

pub fn crypto_x25519(shared_secret: *[32]u8, your_secret_key: *const [32]u8, their_public_key: *const [32]u8) void {
    mcraw.crypto_x25519(@ptrCast([*c]u8, shared_secret), @ptrCast([*c]const u8, your_secret_key), @ptrCast([*c]const u8, their_public_key));
}

test "x25519 key exchange" {
    var public_key1: [32]u8 = undefined;
    var secret_key1: [32]u8 = undefined;
    var public_key2: [32]u8 = undefined;
    var secret_key2: [32]u8 = undefined;
    var shared_key1: [32]u8 = undefined;
    var shared_key2: [32]u8 = undefined;

    try std.os.getrandom(&secret_key1);
    crypto_x25519_public_key(&public_key1, &secret_key1);

    try std.os.getrandom(&secret_key2);
    crypto_x25519_public_key(&public_key2, &secret_key2);

    crypto_x25519(&shared_key1, &secret_key1, &public_key2);
    crypto_x25519(&shared_key2, &secret_key2, &public_key1);
    try expectEqualSlices(u8, &shared_key1, &shared_key2);
}

pub fn crypto_eddsa_key_pair(secret_key: *[64]u8, public_key: *[32]u8, seed: *[32]u8) void {
    mcraw.crypto_eddsa_key_pair(@ptrCast([*c]u8, secret_key), @ptrCast([*c]u8, public_key), @ptrCast([*c]u8, seed));
}

pub fn crypto_eddsa_sign(signature: *[64]u8, secret_key: *const [64]u8, message: []const u8) void {
    mcraw.crypto_eddsa_sign(@ptrCast([*c]u8, signature), @ptrCast([*c]const u8, secret_key), @ptrCast([*c]const u8, message), message.len);
}

pub fn crypto_eddsa_check(signature: *const [64]u8, public_key: *const [32]u8, message: []const u8) bool {
    return 0 == mcraw.crypto_eddsa_check(@ptrCast([*c]const u8, signature), @ptrCast([*c]const u8, public_key), @ptrCast([*c]const u8, message), message.len);
}

test "eddsa signatures" {
    var secret_key: [64]u8 = undefined;
    var public_key: [32]u8 = undefined;
    var signature: [64]u8 = undefined;

    const original_string = "This was definitely sent by me.";
    const original_text = @as(*const [original_string.len]u8, original_string);

    {
        var seed: [32]u8 = undefined;
        try std.os.getrandom(&seed);
        crypto_eddsa_key_pair(&secret_key, &public_key, &seed);
    }

    crypto_eddsa_sign(&signature, &secret_key, original_text);
    try expectEqual(true, crypto_eddsa_check(&signature, &public_key, original_text));
}
