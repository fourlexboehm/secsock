const std = @import("std");

const TlsImpl = enum {
    bearssl,
    s2n_tls,
};

pub fn build(b: *std.Build) void {
    const tls = b.option(
        TlsImpl,
        "tls",
        "Choose between bearssl and s2n_tls implementation",
    ) orelse .bearssl;

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const tls_option = b.addOptions();
    tls_option.addOption(TlsImpl, "tls", tls);

    const secsock = b.addModule("secsock", .{
        .root_source_file = b.path("src/Secsock.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tardy = b.dependency("tardy", .{
        .target = target,
        .optimize = optimize,
    }).module("tardy");

    secsock.addImport("tardy", tardy);
    secsock.addImport("options", tls_option.createModule());

    const check = b.step("check", "Check compilation errors");

    const options: Options = .{
        .optimize = optimize,
        .target = target,
        .tardy = tardy,
        .secsock = secsock,
    };

    switch (tls) {
        // bearssl is always enabled by default
        .bearssl => if (b.lazyDependency("bearssl", .{
            .target = target,
            .optimize = optimize,
            .BR_LE_UNALIGNED = false,
            .BR_BE_UNALIGNED = false,
        })) |bearssl| {
            const bearssl_h = bearssl.module("bearssl.h");
            secsock.addImport("bearssl.h", bearssl_h);

            const builder = bearssl.builder;
            const bearssl_check_step = &builder.top_level_steps.get(
                "check",
            ).?.step;
            check.dependOn(bearssl_check_step);

            const bearssl_lib = bearssl.artifact("bearssl");
            secsock.linkLibrary(bearssl_lib);

            add_example(b, "bearssl", options);
        },
        .s2n_tls => if (b.lazyDependency("s2n_tls", .{
            .target = target,
            .optimize = optimize,
        })) |s2n_tls| {
            const s2n_h = s2n_tls.module("s2n.h");
            secsock.addImport("s2n.h", s2n_h);

            const builder = s2n_tls.builder;
            const s2n_check_step = &builder.top_level_steps.get(
                "check",
            ).?.step;
            check.dependOn(s2n_check_step);

            const s2n_lib = s2n_tls.artifact("s2n");
            secsock.linkLibrary(s2n_lib);

            add_example(b, "s2n", options);
        },
    }
    add_example(b, "unsecured", options);
    add_example(b, "unix", options);
}

fn add_example(b: *std.Build, name: []const u8, options: Options) void {
    const mod = b.createModule(.{
        .root_source_file = b.path(b.fmt(
            "examples/{s}/main.zig",
            .{name},
        )),
        .target = options.target,
        .optimize = options.optimize,
        .strip = false,
    });
    mod.addImport("tardy", options.tardy);
    mod.addImport("secsock", options.secsock);

    const example = b.addExecutable(.{
        .name = b.fmt("{s}", .{name}),
        .root_module = mod,
    });

    const install_artifact = b.addInstallArtifact(
        example,
        .{},
    );
    b.getInstallStep().dependOn(&install_artifact.step);

    const build_step = b.step(
        b.fmt("{s}", .{name}),
        b.fmt("Build tardy example ({s})", .{name}),
    );
    build_step.dependOn(&install_artifact.step);

    const run_artifact = b.addRunArtifact(example);
    run_artifact.step.dependOn(&install_artifact.step);

    const run_step = b.step(
        b.fmt("run_{s}", .{name}),
        b.fmt("Run tardy example ({s})", .{name}),
    );
    run_step.dependOn(&install_artifact.step);
    run_step.dependOn(&run_artifact.step);
}

const Options = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    tardy: *std.Build.Module,
    secsock: *std.Build.Module,
};
