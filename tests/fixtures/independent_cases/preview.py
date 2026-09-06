"""Static-analysis cases; these functions are never run by the benchmark."""
import httpx


def unsafe_preview(request):
    destination = request.POST.get("preview_url")
    return httpx.post(destination, timeout=2)


def fixed_preview(request):
    return httpx.post("https://preview.example.test/render", json=request.get_json())
