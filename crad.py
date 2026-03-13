import os
import subprocess
import time
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.database import SessionLocal
from app.models import User
from app.auth import get_password_hash
from app.roles import UserRole


def run_migrations():
    print(">>> Applying Alembic migrations...")
    env = os.environ.copy()
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        env["DATABASE_URL"] = database_url
    else:
        env.pop("DATABASE_URL", None)
    subprocess.run(
        ["alembic", "-c", str(Path(__file__).with_name("alembic.ini")), "upgrade", "head"],
        check=True,
        cwd=Path(__file__).resolve().parent,
        env=env,
    )
    print(">>> Alembic migrations applied")

def init_db():
    print(">>> Waiting for database to be ready...")
    
    for i in range(30):
        try:
            db = SessionLocal()
            db.execute(text("SELECT 1"))
            db.close()
            print(">>> Database is ready!")
            break
        except OperationalError as e:
            print(f">>> Database not ready, waiting... ({i+1}/30)")
            time.sleep(2)
        except Exception as e:
            print(f">>> Error: {e}")
            time.sleep(2)
        finally:
            try:
                db.close()
            except:
                pass
    else:
        print(">>> Failed to connect to database after 30 attempts")
        return

    try:
        run_migrations()
    except Exception as e:
        print(f">>> Error applying migrations: {e}")
        return

    initial_admin_username = os.getenv("INITIAL_ADMIN_USERNAME")
    initial_admin_password = os.getenv("INITIAL_ADMIN_PASSWORD")
    if not initial_admin_username or not initial_admin_password:
        print(">>> Initial admin credentials are not set, skipping bootstrap user")
        return

    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == initial_admin_username).first():
            # bcrypt ограничивает пароль 72 байтами - обрезаем на всякий случай
            raw_password = initial_admin_password
            admin = User(
                username=initial_admin_username,
                hashed_password=get_password_hash(raw_password[:72]),
                role=UserRole.ADMIN.value
            )
            db.add(admin)
            db.commit()
            print(f">>> Initial admin user created: {initial_admin_username}")
        else:
            print(">>> Initial admin user already exists")
    except Exception as e:
        print(f">>> Error creating admin: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
