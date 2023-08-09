const std = @import("std");

pub fn build(b: *std.Build) !void {
    var target = b.standardTargetOptions(.{});
    var optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "blind_rsa",
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);
    lib.linkLibC();
    lib.addIncludePath(.{ .path = "/opt/homebrew/opt/openssl/include" });
    lib.addLibraryPath(.{ .path = "/opt/homebrew/opt/openssl/lib" });
    lib.linkSystemLibrary("crypto");
    lib.addCSourceFiles(&.{"src/blind_rsa.c"}, &.{});
}
