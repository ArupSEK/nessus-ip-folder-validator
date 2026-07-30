from __future__ import annotations

import argparse
import getpass

from backend.app.db.session import get_session_factory
from backend.app.services.auth import AuthError, bootstrap_admin


def bootstrap_admin_command(username: str, password: str) -> int:
    db = get_session_factory()()
    try:
        user = bootstrap_admin(db, username=username, password=password)
    except AuthError as exc:
        print(str(exc))
        return 1
    finally:
        db.close()
    print(f"Created administrator: {user.username}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    bootstrap_parser = subparsers.add_parser("bootstrap-admin")
    bootstrap_parser.add_argument("--username", required=True)
    bootstrap_parser.add_argument("--password")
    args = parser.parse_args()
    if args.command == "bootstrap-admin":
        password = args.password or getpass.getpass("Password: ")
        return bootstrap_admin_command(args.username, password)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
