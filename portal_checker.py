"""Captive portal detection with HTTP redirect analysis."""

import requests
from urllib.parse import urlparse


def check_portal(test_url='http://example.com/', timeout=10):
    try:
        response = requests.get(test_url, timeout=timeout, allow_redirects=True)
        requested_host = urlparse(test_url).hostname or ''
        final_host = urlparse(response.url).hostname or ''

        if response.history:
            if requested_host != final_host:
                return 'RISKY'
            if response.url.startswith('https://'):
                return 'MODERATE'

        if response.status_code in (200, 204):
            if response.url.startswith('https://'):
                return 'SAFE'
            return 'MODERATE'

        return 'UNKNOWN'
    except requests.RequestException:
        return 'UNKNOWN'
