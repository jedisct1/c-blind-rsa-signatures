const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_options = b.addOptions();
    const with_boringssl = b.option([]const u8, "with-boringssl", "Path to BoringSSL install") orelse "";
    lib_options.addOption([]const u8, "with-boringssl", with_boringssl);

    const lib = b.addStaticLibrary(.{
        .name = "brsa",
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();
    if (with_boringssl.len > 0) {
        var buf_include: [std.posix.PATH_MAX]u8 = undefined;
        var buf_include_alloc = std.heap.FixedBufferAllocator.init(&buf_include);
        const path_include = try std.fs.path.join(buf_include_alloc.allocator(), &.{ with_boringssl, "include" });

        var buf_lib: [std.posix.PATH_MAX]u8 = undefined;
        var buf_lib_alloc = std.heap.FixedBufferAllocator.init(&buf_lib);
        const path_lib = try std.fs.path.join(buf_lib_alloc.allocator(), &.{ with_boringssl, "lib" });

        lib.addIncludePath(b.path(path_include));
        lib.addLibraryPath(b.path(path_lib));
    } else {
        lib.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        lib.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
    }
    lib.linkSystemLibrary("crypto");

    const lib_source_files = &.{"src/blind_rsa.c"};

    lib.addCSourceFiles(.{ .files = lib_source_files });
    b.installArtifact(lib);

    const exe_source_files = &.{"src/test_blind_rsa.c"};

    const exe = b.addExecutable(.{
        .name = "c-blind-rsa-signatures",
        .target = target,
        .optimize = optimize,
    });

    if (with_boringssl.len > 0) {
        var buf_include: [std.posix.PATH_MAX]u8 = undefined;
        var buf_include_alloc = std.heap.FixedBufferAllocator.init(&buf_include);
        const path_include = try std.fs.path.join(buf_include_alloc.allocator(), &.{ with_boringssl, "include" });

        var buf_lib: [std.posix.PATH_MAX]u8 = undefined;
        var buf_lib_alloc = std.heap.FixedBufferAllocator.init(&buf_lib);
        const path_lib = try std.fs.path.join(buf_lib_alloc.allocator(), &.{ with_boringssl, "lib" });

        exe.addIncludePath(b.path(path_include));
        exe.addLibraryPath(b.path(path_lib));
    } else {
        exe.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        exe.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
    }
    exe.addCSourceFiles(.{ .files = exe_source_files });
    exe.linkLibrary(lib);
    exe.linkLibC();

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_exe_unit_tests = b.addRunArtifact(exe);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
