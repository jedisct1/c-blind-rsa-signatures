const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
    const source_files = &.{"src/blind_rsa.c"};
    if (@hasDecl(std.Build.Step.Compile, "AddCSourceFilesOptions")) {
        lib.addCSourceFiles(.{ .files = source_files });
    } else {
        lib.addCSourceFiles(source_files, &.{});
    }
}
