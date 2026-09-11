"""Container entry points and host-admin recovery; normal work uses the GUI."""
import argparse
import getpass
import logging
import os
import sys
from sqlalchemy import select, delete
from . import __version__
from .config import Config
from .db import make_engine, initialize, transaction, User, LoginSession, State, now, audit
from .security import initialize_secrets, validate_password, PASSWORDS


def main():
    parser = argparse.ArgumentParser(prog="deepsnout")
    parser.add_argument("command", choices=["secrets", "init", "serve", "worker", "setup-token", "worker-health", "reset-password", "version"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--username")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if args.command == "version":
        print(__version__)
        return
    config = Config()
    initialize_secrets(config.data_dir)
    if args.command == "secrets":
        destination = os.getenv("DEEPSNOUT_DB_SECRET_EXPORT")
        if destination:
            from pathlib import Path
            target = Path(destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((config.data_dir / "db_password").read_text())
            target.chmod(0o444)
            import secrets
            from .security import create_secret
            admin = target.parent / "admin_password"
            create_secret(admin, secrets.token_urlsafe(36))
            admin.chmod(0o444)
        if os.geteuid() == 0 and os.getenv("DEEPSNOUT_CHOWN_UID"):
            uid = int(os.environ["DEEPSNOUT_CHOWN_UID"])
            os.chown(config.data_dir, uid, uid)
            for name in ["app_key", "setup_token", "db_password"]:
                os.chown(config.data_dir / name, uid, uid)
                (config.data_dir / name).chmod(0o600)
        return
    if args.command == "setup-token":
        print((config.data_dir / "setup_token").read_text().strip())
        return
    if args.command == "serve":
        import uvicorn
        from .web import create_app
        uvicorn.run(create_app(config), host=args.host, port=args.port,
                    proxy_headers=False, server_header=False, access_log=False)
        return
    engine = make_engine(config)
    if args.command == "init":
        initialize(engine)
        print("Database schema ready. Retrieve the setup token and open the GUI.")
    elif args.command == "worker":
        initialize(engine)
        from .worker import run
        run(engine, config)
    elif args.command == "worker-health":
        with transaction(engine) as db:
            row = db.get(State, "worker")
            healthy = row and now() - row.value.get("heartbeat", 0) < 600
        sys.exit(0 if healthy else 1)
    elif args.command == "reset-password":
        if not args.username:
            parser.error("reset-password requires --username")
        password = getpass.getpass("New password: ")
        if password != getpass.getpass("Repeat password: "):
            parser.error("Passwords differ")
        validate_password(password)
        with transaction(engine) as db:
            user = db.scalar(select(User).where(User.username == args.username.lower()))
            if not user:
                parser.error("User not found")
            user.password = PASSWORDS.hash(password)
            db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
            audit(db, "host-admin", "password.recovered", user.id)
        print("Password replaced; sessions invalidated.")


if __name__ == "__main__":
    main()
