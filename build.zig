const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("monocypher", "monocypher.zig");
    lib.addCSourceFile("Monocypher/src/monocypher.c", &[_][]const u8{
        "-fno-stack-protector",
    });
    lib.setBuildMode(mode);
    lib.install();

    var monocypher_tests = b.addTest("monocypher.zig");
    monocypher_tests.addCSourceFile("Monocypher/src/monocypher.c", &[_][]const u8{
        "-fno-stack-protector",
    });
    monocypher_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&monocypher_tests.step);
}
