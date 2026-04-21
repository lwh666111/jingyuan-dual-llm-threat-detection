import json
from urllib import error as urlerror
from urllib import request as urlreq


BASE_URL = "http://127.0.0.1:3049"

ACCOUNTS = [
    {"username": "admin", "password": "admin", "role": "normal"},
    {"username": "admin", "password": "admin", "role": "pro"},
    {"username": "admin", "password": "admin", "role": "admin"},
]


def post_json(path: str, payload: dict, token: str = "") -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urlreq.Request(BASE_URL + path, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urlreq.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def get_text(path: str, token: str = "") -> tuple[int, str]:
    req = urlreq.Request(BASE_URL + path, method="GET")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urlreq.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def run_role_demo(account: dict) -> None:
    status, body = post_json(
        "/api/v2/auth/login",
        {"username": account["username"], "password": account["password"], "role": account["role"]},
    )
    if status != 200:
        raise RuntimeError(f"login failed: {status} {body}")
    token = json.loads(body)["token"]

    print(f"[{account['role']}] login ok")

    common_endpoints = [
        "/api/v2/common/system-status",
        "/api/v2/common/alerts/ticker?limit=3",
    ]
    for path in common_endpoints:
        s, t = get_text(path, token)
        print(f"[{account['role']}] {path} -> {s} {t[:100]}")

    if account["role"] == "normal":
        specific = [
            "/api/v2/user/dashboard/kpis",
            "/api/v2/user/dashboard/trend7d",
            "/api/v2/user/dashboard/top-attack-types",
        ]
    elif account["role"] == "pro":
        specific = [
            "/api/v2/pro/events?page=1&page_size=5&time_range=24h",
            "/api/v2/pro/model/performance",
            "/api/v2/pro/nodes/node-bj-01/detail",
        ]
    else:
        specific = [
            "/api/v2/admin/summary",
            "/api/v2/admin/machines",
            "/api/v2/admin/user-op-logs?page=1&page_size=5",
        ]
    for path in specific:
        s, t = get_text(path, token)
        print(f"[{account['role']}] {path} -> {s} {t[:100]}")


def main() -> None:
    try:
        status, body = get_text("/api/v1/screen/ping")
        if status != 200:
            raise RuntimeError(body)
        print("[ping] api online")
        for account in ACCOUNTS:
            run_role_demo(account)
        print("[demo] all checks passed")
    except urlerror.URLError as exc:
        raise RuntimeError("cannot connect api server on 3049, please start app.py first") from exc


if __name__ == "__main__":
    main()
