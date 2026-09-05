from src.related_context import build_related_context


def test_related_context_includes_imported_typescript_helper(tmp_path):
    routes = tmp_path / "routes"
    lib = tmp_path / "lib"
    routes.mkdir()
    lib.mkdir()
    (routes / "redirect.ts").write_text(
        "import * as security from '../lib/insecurity'\n"
        "export const redirect = (url: string) => {\n"
        "  if (security.isRedirectAllowed(url)) return url\n"
        "}\n",
        encoding="utf-8",
    )
    (lib / "insecurity.ts").write_text(
        "const allowlist = ['https://example.test']\n"
        "export const isRedirectAllowed = (url: string) => {\n"
        "  return allowlist.some((allowed) => url.includes(allowed))\n"
        "}\n",
        encoding="utf-8",
    )

    context = build_related_context(tmp_path, ["routes/redirect.ts"])

    assert "routes/redirect.ts -> lib/insecurity.ts" in context
    assert "Imported helper: isRedirectAllowed" in context
    assert "url.includes(allowed)" in context


def test_related_context_ignores_paths_outside_repository(tmp_path):
    assert build_related_context(tmp_path, ["../outside.ts"]) == ""


def test_related_context_rejects_external_symlinks_after_extension_resolution(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.ts"
    outside.write_text('export function helper() { return "PRIVATE_CONTENT"; }\n')
    (root / "helper.ts").symlink_to(outside)
    (root / "main.ts").write_text('import { helper } from "./helper";\nhelper();\n')

    assert build_related_context(root, ["main.ts"]) == ""


def test_related_context_rejects_external_index_symlink(tmp_path):
    root = tmp_path / "repo"
    (root / "helper").mkdir(parents=True)
    outside = tmp_path / "outside.ts"
    outside.write_text('export function helper() { return "PRIVATE_CONTENT"; }\n')
    (root / "helper" / "index.ts").symlink_to(outside)
    (root / "main.ts").write_text('import { helper } from "./helper";\nhelper();\n')

    assert build_related_context(root, ["main.ts"]) == ""


def test_related_context_allows_internal_symlink(tmp_path):
    (tmp_path / "real.ts").write_text('export function helper() { return 1; }\n')
    (tmp_path / "helper.ts").symlink_to(tmp_path / "real.ts")
    (tmp_path / "main.ts").write_text('import { helper } from "./helper";\nhelper();\n')

    assert "return 1" in build_related_context(tmp_path, ["main.ts"])
