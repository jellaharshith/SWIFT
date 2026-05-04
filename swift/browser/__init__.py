"""Playwright-driven browser scanning for SWIFT."""
from browser.playwright_runner import scan_url, BrowserScanResult

__all__ = ["scan_url", "BrowserScanResult"]
