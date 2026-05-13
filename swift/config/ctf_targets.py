"""Pre-configured CTF/training target templates."""
from typing import Any

CTF_TARGETS: dict[str, dict[str, Any]] = {
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "default_url": "http://localhost:3000",
        "docker_hint": "docker run -p 3000:3000 bkimminich/juice-shop",
        "techniques": ["xss", "sqli", "idor", "jwt", "ssrf"],
        "roe_template": {
            "scope": ["localhost:3000"],
            "allow_web_probes": True,
            "allow_chain_execution": True,
        },
    },
    "dvwa": {
        "name": "DVWA",
        "default_url": "http://localhost:80",
        "docker_hint": "docker run -p 80:80 vulnerables/web-dvwa",
        "techniques": ["sqli", "xss", "csrf", "lfi"],
        "roe_template": {
            "scope": ["localhost:80"],
            "allow_web_probes": True,
            "allow_chain_execution": True,
        },
    },
    "metasploitable": {
        "name": "Metasploitable2",
        "default_url": "http://localhost:80",
        "docker_hint": "docker run -p 80:80 tleemcjr/metasploitable2",
        "techniques": ["sqli", "xss", "rce"],
        "roe_template": {
            "scope": ["localhost"],
            "allow_web_probes": True,
            "allow_chain_execution": False,
        },
    },
}
