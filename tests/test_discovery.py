import asyncio
from laravelhunter.discovery import extract_same_origin_links, summarize_features, discover_routes
from laravelhunter.models import HttpSnapshot


def snap(url: str, body: str, status: int = 200):
    return HttpSnapshot(url=url, status_code=status, headers={}, cookies={}, body_sample=body, elapsed_ms=1)


def test_extract_links_same_origin_and_skip_unsafe():
    s = snap("https://example.test/admin/login", '''
        <a href="/admin">Admin</a>
        <a href="/password/reset">Reset</a>
        <a href="/logout">Logout</a>
        <a href="https://evil.test/x">Offsite</a>
        <a href="/app.css">CSS</a>
    ''')
    links = extract_same_origin_links(s, ("https", "example.test"))
    assert "https://example.test/admin" in links
    assert "https://example.test/password/reset" in links
    assert all("logout" not in x for x in links)
    assert all("evil.test" not in x for x in links)


def test_summarize_features_livewire_and_auth():
    home = snap("https://example.test/admin/login", '<script data-update-uri="/livewire/update"></script>')
    from laravelhunter.models import RouteSurface
    routes = [
        RouteSurface(url="https://example.test/admin/login", path="/admin/login", kind="auth-login", source="entry", status_code=200, fetched=True),
        RouteSurface(url="https://example.test/livewire/update", path="/livewire/update", kind="livewire-update", source="html-marker", fetched=False),
    ]
    features = summarize_features(routes, [home])
    names = {f.name for f in features}
    assert "Authentication login surface" in names
    assert "Livewire update endpoint" in names


class FakeHttp:
    async def get(self, url):
        pages = {
            "https://example.test/reset": snap("https://example.test/reset", '<input type="email"><a href="/help">Help</a>'),
            "https://example.test/help": snap("https://example.test/help", 'ok'),
        }
        return pages[url]


def test_bounded_discovery_follows_visible_anchors_only():
    home = snap("https://example.test/login", '<a href="/reset">Reset</a><a href="/logout">Logout</a>')
    routes, pages, diagnostics = asyncio.run(discover_routes(FakeHttp(), home, max_pages=2))
    assert len(pages) == 2
    assert any(r.path == "/reset" for r in routes)
    assert any(r.path == "/help" for r in routes)
    assert all(r.path != "/logout" for r in routes)


def test_link_extraction_dedupes_query_variants_by_path():
    from laravelhunter.discovery import extract_same_origin_links
    page = snap('https://example.test/admin', '''
        <a href="/admin/accounts?page=1">one</a>
        <a href="/admin/accounts?page=2">two</a>
        <a href="/admin/users">users</a>
    ''')
    links = extract_same_origin_links(page, ('https', 'example.test'))
    assert len(links) == 2
    assert any('/admin/accounts' in x for x in links)
    assert any('/admin/users' in x for x in links)
