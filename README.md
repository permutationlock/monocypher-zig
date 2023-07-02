# Monocypher-Zig

Monocypher-Zig aims to provide simple Zig bindings for the
[Monocypher](https://github.com/LoupVaillant/Monocypher) cryptography
library. It currently targets the Zig 10.1 release.

For most functions it simply provides a casting
interface to allow Zig code to pass slices rather than pointers
and sizes.

The incremental interface for authenticated encryption
has a more involved implementation that aims to be compatible
with the Zig Standard Library Reader/Writer interface.

The interface for Argon2 password derivation uses a passed
Allocator to allocate the workspace memory, rather than taking a void
pointer.
