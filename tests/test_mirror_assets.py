from crawler_common import extract_page_assets, rewrite_for_local_mirror


SAMPLE_CPANEL = """
<html><head>
<link href="/cPanel_magic_revision_1/unprotected/cpanel/style_v2_optimized.css" rel="stylesheet" />
<link href="/cPanel_magic_revision_1/unprotected/cpanel/fonts/open_sans/open_sans.min.css" rel="stylesheet" />
<script src="/cPanel_magic_revision_1/unprotected/cpanel/app.js"></script>
</head><body>
<img src="/cPanel_magic_revision_1/unprotected/cpanel/images/notice-error.png" alt="Error"/>
</body></html>
"""


def test_extract_cpanel_assets():
    assets = extract_page_assets(SAMPLE_CPANEL, "http://salacious.me/controlpanel/", "salacious.me")
    assert any(".css" in a for a in assets)
    assert any("notice-error.png" in a or "images/" in a for a in assets)
    assert all("salacious.me" in a for a in assets)


def test_extract_includes_cdn_components():
    html = """
    <html><head>
      <link rel="stylesheet" href="https://cdn.example.com/lib/app.css"/>
      <script src="https://cdn.example.com/lib/app.js"></script>
    </head><body>
      <img src="/static/logo.png"/>
    </body></html>
    """
    assets = extract_page_assets(html, "https://shop.example.com/", "shop.example.com", include_cdn=True)
    assert any("cdn.example.com" in a and a.endswith(".css") for a in assets)
    assert any("cdn.example.com" in a and a.endswith(".js") for a in assets)
    assert any(a.endswith("/static/logo.png") for a in assets)


def test_rewrite_root_relative_for_offline():
    rewritten = rewrite_for_local_mirror(
        SAMPLE_CPANEL,
        "http://salacious.me/controlpanel/",
        "salacious.me",
        "text/html",
    )
    assert 'href="../cPanel_magic_revision_1/unprotected/cpanel/style_v2_optimized.css"' in rewritten
    assert 'src="../cPanel_magic_revision_1/unprotected/cpanel/app.js"' in rewritten
    assert 'href="/cPanel_magic_revision_1/' not in rewritten
