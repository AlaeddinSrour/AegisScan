from src.scope import classify_code_role, load_ignore_patterns


def test_runtime_and_fixture_paths_are_distinguished():
    assert classify_code_role("routes/search.ts") == "RUNTIME"
    assert classify_code_role("data/static/codefixes/search_1.ts") == "FIXTURE"
    assert classify_code_role("tests/search.spec.ts") == "TEST"
    assert classify_code_role("dist/server.js") == "GENERATED"
    assert classify_code_role("frontend/src/assets/private/three.js") == "DEPENDENCY"
    assert classify_code_role("public/app.bundle.js") == "GENERATED"
    assert classify_code_role(".mvn/wrapper/MavenWrapperDownloader.java") == "DEPENDENCY"
    assert classify_code_role("src/it/java/example/BrowserTest.java") == "TEST"
    assert (
        classify_code_role("src/main/resources/webgoat/static/js/libs/ace.js")
        == "DEPENDENCY"
    )
    assert (
        classify_code_role("src/main/resources/webgoat/static/js/libs/jquery-ui-1.10.4.js")
        == "DEPENDENCY"
    )
    assert (
        classify_code_role(
            "src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/"
            "js/wysihtml5-0.3.0.js"
        )
        == "DEPENDENCY"
    )


def test_dot_prefixed_paths_keep_their_first_segment():
    assert classify_code_role("./.mvn/wrapper/Downloader.java") == "DEPENDENCY"


def test_versioned_openwrt_sdk_is_dependency_but_firmware_overlays_are_runtime():
    root = "OpenWrt/openwrt-18.06.2"
    assert (
        classify_code_role(f"{root}/package/boot/uboot-oxnas/src/common/spl/spl_block.c")
        == "DEPENDENCY"
    )
    assert classify_code_role(f"{root}/tools/m4/src/format.c") == "DEPENDENCY"
    assert classify_code_role(f"{root}/files/etc/rc.local") == "RUNTIME"
    assert (
        classify_code_role(f"{root}/files/usr/lib/lua/luci/controller/iotgoat/iotgoat.lua")
        == "RUNTIME"
    )
    assert (
        classify_code_role(f"{root}/package/base-files/files/etc/init.d/boot")
        == "DEPENDENCY"
    )
    assert classify_code_role("src/common/spl/spl_block.c") == "RUNTIME"


def test_aegisscanignore_patterns_override_runtime_role():
    assert classify_code_role("custom/training.ts", ["custom/**"]) == "IGNORED"


def test_ignore_file_supports_comments_and_repo_relative_patterns(tmp_path):
    (tmp_path / ".aegisscanignore").write_text(
        "# training data\ndata/static/codefixes/**\n\n",
        encoding="utf-8",
    )
    assert load_ignore_patterns(tmp_path) == ["data/static/codefixes/**"]


def test_negated_scope_pattern_can_force_runtime_role():
    patterns = ["generated/**", "!generated/runtime/**"]
    assert classify_code_role("generated/cache/file.py", patterns) == "IGNORED"
    assert classify_code_role("generated/runtime/server.py", patterns) == "RUNTIME"
