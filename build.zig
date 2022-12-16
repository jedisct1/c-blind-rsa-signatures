const std = @import("std");
const builtin = @import("builtin");
const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const mem = std.mem;
const LibExeObjStep = std.build.LibExeObjStep;
const Target = std.Target;

pub fn build(b: *std.build.Builder) !void {
    var target = b.standardTargetOptions(.{});
    var mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("blind_rsa", null);
    lib.setTarget(target);
    lib.setBuildMode(mode);
    lib.install();
    if (mode != .Debug) {
        lib.strip = true;
    }
    lib.linkLibC();
    lib.addIncludePath("/opt/homebrew/opt/openssl/include");
    lib.addLibraryPath("/opt/homebrew/opt/openssl/lib");
    lib.linkSystemLibrary("crypto");
    lib.addCSourceFile("src/blind_rsa.c", &.{});
}
