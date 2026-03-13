import time

from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError

from app.config import settings
from app.database import SessionLocal
from app.models import User
from app.auth import get_password_hash
from app.roles import UserRole

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

    if not settings.default_admin_username or not settings.default_admin_password:
        print(">>> DEFAULT_ADMIN_USERNAME or DEFAULT_ADMIN_PASSWORD is not set, skipping admin bootstrap")
        return

    db = SessionLocal()
    try:
        if not inspect(db.bind).has_table("users"):
            print(">>> users table does not exist, run migrations first")
            return

        if not db.query(User).filter(User.username == settings.default_admin_username).first():
            raw_password = settings.default_admin_password
            admin = User(
                username=settings.default_admin_username,
                hashed_password=get_password_hash(raw_password[:72]),
                role=UserRole.ADMIN.value,
                is_active=settings.default_admin_is_active,
            )
            db.add(admin)
            db.commit()
            print(f">>> Initial admin user created: {settings.default_admin_username}")
        else:
            print(">>> Initial admin user already exists")
    except Exception as e:
        print(f">>> Error creating admin: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
