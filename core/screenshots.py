import os
import asyncio

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

SCREENSHOTS_DIR = "ui/web/static/screenshots"

async def capture_screenshot(url, filename):
    if not PLAYWRIGHT_AVAILABLE:
        print("[WARN] Playwright not installed. Skipping screenshot.")
        return None

    if not os.path.exists(SCREENSHOTS_DIR):
        os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
        
    path = os.path.join(SCREENSHOTS_DIR, filename)
    
    try:
        async with async_playwright() as p:
            # Check if browser is installed (simplified check)
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.set_viewport_size({"width": 1280, "height": 720})
            
            # Wait for content to load, timeout 15s
            await page.goto(url, wait_until="networkidle", timeout=15000)
            await page.screenshot(path=path)
            await browser.close()
            return f"screenshots/{filename}"
    except Exception as e:
        print(f"[ERROR] Screenshot failed for {url}: {e}")
        return None

def take_service_screenshot(scan_id, port, target):
    """Sync wrapper for the async capture"""
    proto = "https" if port in [443, 8443] else "http"
    url = f"{proto}://{target}:{port}"
    filename = f"scan_{scan_id}_port_{port}.png"
    
    try:
        # Run in separate loop to avoid collision with Flask/other threads
        return asyncio.run(capture_screenshot(url, filename))
    except Exception as e:
        print(f"[ERROR] Sync screenshot wrapper failed: {e}")
        return None
