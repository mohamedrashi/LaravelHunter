from laravelhunter.fingerprint.laravel import detect_laravel, detect_components
from laravelhunter.edge.detect import detect_edge
from laravelhunter.models import HttpSnapshot


def snap(body="", headers=None, cookies=None, status=200):
    return HttpSnapshot(
        url="https://example.test",
        status_code=status,
        headers=headers or {},
        cookies=cookies or {},
        body_sample=body,
        elapsed_ms=1,
    )


def test_laravel_cookie_detection():
    s = snap(cookies={"laravel_session": "x", "XSRF-TOKEN": "y"})
    components = detect_components(s)
    result = detect_laravel(s, components)
    assert result.detected is True
    assert result.confidence >= 50


def test_livewire_detection():
    components = detect_components(snap(body='<div wire:id="abc">livewire</div>'))
    livewire = next(c for c in components if c.name == "Livewire")
    assert livewire.detected is True


def test_filament_livewire_correlation_detects_laravel():
    body = r'''
    <html class="fi">
      <meta name="csrf-token" content="secret">
      <link href="/fonts/filament/filament/inter/index.css?v=5.0.0.0" rel="stylesheet">
      <div class="fi-body" wire:id="abc" wire:snapshot="{}" wire:name="App\Filament\Pages\Auth\Login"></div>
      <script src="/livewire-667b9545/livewire.min.js"></script>
    </html>
    '''
    s = snap(body=body, cookies={"XSRF-TOKEN": "x", "app-session": "y"})
    components = detect_components(s)
    result = detect_laravel(s, components)
    assert next(c for c in components if c.name == "Filament").detected is True
    assert next(c for c in components if c.name == "Livewire").detected is True
    assert result.detected is True
    assert result.confidence >= 90


def test_cloudflare_detection():
    edge = detect_edge(snap(headers={"server": "cloudflare", "cf-ray": "abc"}, status=403))
    assert edge.cloudflare is True
    assert edge.waf_detected is True
