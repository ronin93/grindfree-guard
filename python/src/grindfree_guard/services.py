NETWORK = "eip155:8453"
PAY_TO = "0xe4b5827994B7B3Cd38F9830d9ECF58b51B77721b"

SERVICES = {
    "promptshield": {
        "origin": "https://promptshield.grindfree.net",
        "endpoints": {"screen": "/v1/screen", "clean": "/v1/clean"},
    },
    "crawlsafe": {"origin": "https://crawlsafe.grindfree.net", "endpoints": {"check": "/v1/check"}},
    "toolguard": {"origin": "https://toolguard.grindfree.net", "endpoints": {"evaluate": "/v1/evaluate"}},
    "commandguard": {
        "origin": "https://commandguard.grindfree.net",
        "endpoints": {"command": "/v1/command", "sql": "/v1/sql"},
    },
    "memoryguard": {"origin": "https://memoryguard.grindfree.net", "endpoints": {"screen": "/v1/screen"}},
    "wireshield": {"origin": "https://wireshield.grindfree.net", "endpoints": {"scan": "/v1/scan"}},
    "docshield": {"origin": "https://docshield.grindfree.net", "endpoints": {"scan": "/v1/scan"}},
}


def service_url(service: str, endpoint: str) -> str:
    spec = SERVICES[service]
    return f"{spec['origin']}{spec['endpoints'][endpoint]}"
