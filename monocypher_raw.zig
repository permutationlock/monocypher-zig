pub extern fn crypto_verify16(a: [*c]const u8, b: [*c]const u8) c_int;
pub extern fn crypto_verify32(a: [*c]const u8, b: [*c]const u8) c_int;
pub extern fn crypto_verify64(a: [*c]const u8, b: [*c]const u8) c_int;
pub extern fn crypto_wipe(secret: ?*anyopaque, size: usize) void;
pub extern fn crypto_aead_lock(cipher_text: [*c]u8, mac: [*c]u8, key: [*c]const u8, nonce: [*c]const u8, ad: [*c]const u8, ad_size: usize, plain_text: [*c]const u8, text_size: usize) void;
pub extern fn crypto_aead_unlock(plain_text: [*c]u8, mac: [*c]const u8, key: [*c]const u8, nonce: [*c]const u8, ad: [*c]const u8, ad_size: usize, cipher_text: [*c]const u8, text_size: usize) c_int;
pub const crypto_aead_ctx = extern struct {
    counter: u64,
    key: [32]u8,
    nonce: [8]u8,
};
pub extern fn crypto_aead_init_x(ctx: [*c]crypto_aead_ctx, key: [*c]const u8, nonce: [*c]const u8) void;
pub extern fn crypto_aead_init_djb(ctx: [*c]crypto_aead_ctx, key: [*c]const u8, nonce: [*c]const u8) void;
pub extern fn crypto_aead_init_ietf(ctx: [*c]crypto_aead_ctx, key: [*c]const u8, nonce: [*c]const u8) void;
pub extern fn crypto_aead_write(ctx: [*c]crypto_aead_ctx, cipher_text: [*c]u8, mac: [*c]u8, ad: [*c]const u8, ad_size: usize, plain_text: [*c]const u8, text_size: usize) void;
pub extern fn crypto_aead_read(ctx: [*c]crypto_aead_ctx, plain_text: [*c]u8, mac: [*c]const u8, ad: [*c]const u8, ad_size: usize, cipher_text: [*c]const u8, text_size: usize) c_int;
pub extern fn crypto_blake2b(hash: [*c]u8, hash_size: usize, message: [*c]const u8, message_size: usize) void;
pub extern fn crypto_blake2b_keyed(hash: [*c]u8, hash_size: usize, key: [*c]const u8, key_size: usize, message: [*c]const u8, message_size: usize) void;
pub const crypto_blake2b_ctx = extern struct {
    hash: [8]u64,
    input_offset: [2]u64,
    input: [16]u64,
    input_idx: usize,
    hash_size: usize,
};
pub extern fn crypto_blake2b_init(ctx: [*c]crypto_blake2b_ctx, hash_size: usize) void;
pub extern fn crypto_blake2b_keyed_init(ctx: [*c]crypto_blake2b_ctx, hash_size: usize, key: [*c]const u8, key_size: usize) void;
pub extern fn crypto_blake2b_update(ctx: [*c]crypto_blake2b_ctx, message: [*c]const u8, message_size: usize) void;
pub extern fn crypto_blake2b_final(ctx: [*c]crypto_blake2b_ctx, hash: [*c]u8) void;
pub const crypto_argon2_config = extern struct {
    algorithm: u32,
    nb_blocks: u32,
    nb_passes: u32,
    nb_lanes: u32,
};
pub const crypto_argon2_inputs = extern struct {
    pass: [*c]const u8,
    salt: [*c]const u8,
    pass_size: u32,
    salt_size: u32,
};
pub const crypto_argon2_extras = extern struct {
    key: [*c]const u8,
    ad: [*c]const u8,
    key_size: u32,
    ad_size: u32,
};
pub extern const crypto_argon2_no_extras: crypto_argon2_extras;
pub extern fn crypto_argon2(hash: [*c]u8, hash_size: u32, work_area: ?*anyopaque, config: crypto_argon2_config, inputs: crypto_argon2_inputs, extras: crypto_argon2_extras) void;
pub extern fn crypto_x25519_public_key(public_key: [*c]u8, secret_key: [*c]const u8) void;
pub extern fn crypto_x25519(raw_shared_secret: [*c]u8, your_secret_key: [*c]const u8, their_public_key: [*c]const u8) void;
pub extern fn crypto_x25519_to_eddsa(eddsa: [*c]u8, x25519: [*c]const u8) void;
pub extern fn crypto_x25519_inverse(blind_salt: [*c]u8, private_key: [*c]const u8, curve_point: [*c]const u8) void;
pub extern fn crypto_x25519_dirty_small(pk: [*c]u8, sk: [*c]const u8) void;
pub extern fn crypto_x25519_dirty_fast(pk: [*c]u8, sk: [*c]const u8) void;
pub extern fn crypto_eddsa_key_pair(secret_key: [*c]u8, public_key: [*c]u8, seed: [*c]u8) void;
pub extern fn crypto_eddsa_sign(signature: [*c]u8, secret_key: [*c]const u8, message: [*c]const u8, message_size: usize) void;
pub extern fn crypto_eddsa_check(signature: [*c]const u8, public_key: [*c]const u8, message: [*c]const u8, message_size: usize) c_int;
pub extern fn crypto_eddsa_to_x25519(x25519: [*c]u8, eddsa: [*c]const u8) void;
pub extern fn crypto_eddsa_trim_scalar(out: [*c]u8, in: [*c]const u8) void;
pub extern fn crypto_eddsa_reduce(reduced: [*c]u8, expanded: [*c]const u8) void;
pub extern fn crypto_eddsa_mul_add(r: [*c]u8, a: [*c]const u8, b: [*c]const u8, c: [*c]const u8) void;
pub extern fn crypto_eddsa_scalarbase(point: [*c]u8, scalar: [*c]const u8) void;
pub extern fn crypto_eddsa_check_equation(signature: [*c]const u8, public_key: [*c]const u8, h_ram: [*c]const u8) c_int;
pub extern fn crypto_chacha20_h(out: [*c]u8, key: [*c]const u8, in: [*c]const u8) void;
pub extern fn crypto_chacha20_djb(cipher_text: [*c]u8, plain_text: [*c]const u8, text_size: usize, key: [*c]const u8, nonce: [*c]const u8, ctr: u64) u64;
pub extern fn crypto_chacha20_ietf(cipher_text: [*c]u8, plain_text: [*c]const u8, text_size: usize, key: [*c]const u8, nonce: [*c]const u8, ctr: u32) u32;
pub extern fn crypto_chacha20_x(cipher_text: [*c]u8, plain_text: [*c]const u8, text_size: usize, key: [*c]const u8, nonce: [*c]const u8, ctr: u64) u64;
pub extern fn crypto_poly1305(mac: [*c]u8, message: [*c]const u8, message_size: usize, key: [*c]const u8) void;
pub const crypto_poly1305_ctx = extern struct {
    c: [16]u8,
    c_idx: usize,
    r: [4]u32,
    pad: [4]u32,
    h: [5]u32,
};
pub extern fn crypto_poly1305_init(ctx: [*c]crypto_poly1305_ctx, key: [*c]const u8) void;
pub extern fn crypto_poly1305_update(ctx: [*c]crypto_poly1305_ctx, message: [*c]const u8, message_size: usize) void;
pub extern fn crypto_poly1305_final(ctx: [*c]crypto_poly1305_ctx, mac: [*c]u8) void;
pub extern fn crypto_elligator_map(curve: [*c]u8, hidden: [*c]const u8) void;
pub extern fn crypto_elligator_rev(hidden: [*c]u8, curve: [*c]const u8, tweak: u8) c_int;
pub extern fn crypto_elligator_key_pair(hidden: [*c]u8, secret_key: [*c]u8, seed: [*c]u8) void;
