"""GitHub OAuth helpers using httpx — no external OAuth libraries required."""
from __future__ import annotations

import os
from typing import List
from urllib.parse import urlencode

import httpx

from log.logger import get_logger

logger = get_logger("web.oauth")

_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_TOKEN_URL = "https://github.com/login/oauth/access_token"
_REPOS_URL = "https://api.github.com/user/repos"


def _client_id() -> str:
    return os.environ.get("GITHUB_CLIENT_ID", "")


def _client_secret() -> str:
    return os.environ.get("GITHUB_CLIENT_SECRET", "")


def get_github_auth_url(redirect_uri: str) -> str:
    """Build the GitHub OAuth authorization URL.

    Args:
        redirect_uri: The callback URL GitHub will redirect the user to after
            authorization.

    Returns:
        Fully-qualified GitHub OAuth URL as a string.
    """
    params = {
        "client_id": _client_id(),
        "scope": "repo",
        "redirect_uri": redirect_uri,
    }
    return f"{_AUTHORIZE_URL}?{urlencode(params)}"


def exchange_code(code: str, redirect_uri: str) -> str:
    """Exchange a GitHub OAuth authorization code for an access token.

    Args:
        code: The one-time authorization code returned by GitHub's callback.
        redirect_uri: Must match the redirect_uri used in get_github_auth_url.

    Returns:
        The GitHub access token string.

    Raises:
        ValueError: If the exchange request fails or returns no access_token.
    """
    payload = {
        "client_id": _client_id(),
        "client_secret": _client_secret(),
        "code": code,
        "redirect_uri": redirect_uri,
    }
    response = httpx.post(
        _TOKEN_URL,
        data=payload,
        headers={"Accept": "application/json"},
        timeout=15,
    )

    if response.status_code != 200:
        logger.error(
            "GitHub token exchange failed: HTTP %s — %s",
            response.status_code,
            response.text,
        )
        raise ValueError(
            f"GitHub token exchange failed with status {response.status_code}."
        )

    data = response.json()
    token = data.get("access_token")
    if not token:
        error = data.get("error_description", data.get("error", "unknown error"))
        logger.error("GitHub token exchange returned no token: %s", error)
        raise ValueError(f"GitHub OAuth error: {error}")

    logger.info("Successfully exchanged GitHub OAuth code for access token.")
    return token


def list_repos(access_token: str) -> List[dict]:
    """List the authenticated user's GitHub repositories sorted by last update.

    Args:
        access_token: A valid GitHub OAuth access token.

    Returns:
        List of dicts each containing: name, full_name, html_url, private,
        description.

    Raises:
        ValueError: If the API request fails.
    """
    response = httpx.get(
        _REPOS_URL,
        params={"sort": "updated", "per_page": 50},
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=15,
    )

    if response.status_code != 200:
        logger.error(
            "GitHub repos list failed: HTTP %s — %s",
            response.status_code,
            response.text,
        )
        raise ValueError(
            f"GitHub API request failed with status {response.status_code}."
        )

    repos = response.json()
    logger.info("Listed %d GitHub repos for authenticated user.", len(repos))
    return [
        {
            "name": r.get("name"),
            "full_name": r.get("full_name"),
            "html_url": r.get("html_url"),
            "private": r.get("private"),
            "description": r.get("description"),
        }
        for r in repos
    ]
