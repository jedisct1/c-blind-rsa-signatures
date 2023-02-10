const std = @import("std");

pub fn build(b: *std.Build) !void {
    var target = b.standardTargetOptions(.{});
    var optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "blind_rsa",
        .target = target,
        .optimize = optimize,
    });
    lib.install();
    lib.linkLibC();
    lib.addIncludePath("/opt/homebrew/opt/openssl/include");
    lib.addLibraryPath("/opt/homebrew/opt/openssl/lib");
    lib.linkSystemLibrary("crypto");
    lib.addCSourceFile("src/blind_rsa.c", &.{});
}
