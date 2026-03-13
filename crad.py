# init_admin.py
import os
import time
from sqlalchemy.exc import OperationalError
from sqlalchemy import text

from app.database import SessionLocal, engine, Base
from app.models import User
from app.auth import get_password_hash

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
        Base.metadata.create_all(bind=engine)
        print(">>> Database tables created")
    except Exception as e:
        print(f">>> Error creating tables: {e}")
        return
    
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            # bcrypt ограничивает пароль 72 байтами - обрезаем на всякий случай
            raw_password = "123"
            admin = User(
                username="admin",
                hashed_password=get_password_hash(raw_password[:72]),
                is_admin=True
            )
            db.add(admin)
            db.commit()
            print(">>> Admin user created: admin / 123")
        else:
            print(">>> Admin user already exists")
    except Exception as e:
        print(f">>> Error creating admin: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()