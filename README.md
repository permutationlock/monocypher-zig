# Monocypher Zig

Monocypher-zig aims to provide simple Zig bindings for the
[Monocypher](https://github.com/LoupVaillant/Monocypher) cryptography
library. It currently targets the Zig 10.1 release.

For most functions it is as simple as providing a casting
interface that allows Zig code to pass slices rather than pointers
and lengths.

The incremental interface for authenticated encryption
has a more involved
implementations, aiming to mimic the Zig Standard Library
Reader/Writer interface.

The Argon2 password derivation has a Zig interface using a passed
Allocator to allocate the workspace memory, rather than taking a void
pointer.
