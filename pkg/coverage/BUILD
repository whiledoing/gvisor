load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "coverage",
    srcs = ["coverage.go"],
    # FIXME(b/160639712): Resolve :coverage_nogo build error.
    nogo = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sync",
        "//pkg/usermem",
        "@io_bazel_rules_go//go/tools/coverdata",
    ],
)
