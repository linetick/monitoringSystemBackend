import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def read_source(relative_path: str) -> str:
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def load_module_from_path(module_name: str, relative_path: str, injected_modules=None):
    injected_modules = injected_modules or {}
    saved_modules = {name: sys.modules.get(name) for name in injected_modules}

    for name, module in injected_modules.items():
        sys.modules[name] = module

    spec = importlib.util.spec_from_file_location(module_name, PROJECT_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    loader = spec.loader
    if loader is None:
        raise RuntimeError(f"Unable to load module from {relative_path}")

    try:
        loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(module_name, None)
        for name, original_module in saved_modules.items():
            if original_module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module


class Day1SourceRegressionTests(unittest.TestCase):
    def test_role_model_replaces_is_admin_in_model_and_dependencies(self):
        model_source = read_source("app/models.py")
        dependency_source = read_source("app/dependencies.py")

        self.assertIn("role = Column(", model_source)
        self.assertNotIn("is_admin = Column(", model_source)
        self.assertIn("current_user.role != UserRole.ADMIN.value", dependency_source)
        self.assertNotIn("current_user.is_admin", dependency_source)

    def test_create_all_is_not_used_anymore(self):
        self.assertNotIn("create_all(", read_source("app/main.py"))
        self.assertNotIn("create_all(", read_source("crad.py"))

    def test_role_migration_contains_expected_upgrade_and_downgrade_steps(self):
        migration_source = read_source("alembic/versions/20260313_0002_user_role_model.py")

        self.assertIn('down_revision = "20260313_0001"', migration_source)
        self.assertIn('SET role = CASE WHEN is_admin THEN \'admin\' ELSE \'limited\' END', migration_source)
        self.assertIn('op.drop_column("users", "is_admin")', migration_source)
        self.assertIn('op.create_check_constraint(', migration_source)
        self.assertIn('SET is_admin = CASE WHEN role = \'admin\' THEN TRUE ELSE FALSE END;', migration_source)


class ConfigSettingsTests(unittest.TestCase):
    def test_default_admin_env_uses_initial_fallback(self):
        with mock.patch.dict(
            os.environ,
            {
                "INITIAL_ADMIN_USERNAME": "bootstrap-admin",
                "INITIAL_ADMIN_PASSWORD": "super-secret",
                "INITIAL_ADMIN_IS_ACTIVE": "false",
            },
            clear=True,
        ):
            config_module = load_module_from_path("test_day1_config_fallback", "app/config.py")
            settings = config_module.Settings()

        self.assertEqual(settings.default_admin_username, "bootstrap-admin")
        self.assertEqual(settings.default_admin_password, "super-secret")
        self.assertFalse(settings.default_admin_is_active)

    def test_default_admin_env_prefers_explicit_default_values(self):
        with mock.patch.dict(
            os.environ,
            {
                "DEFAULT_ADMIN_USERNAME": "default-admin",
                "DEFAULT_ADMIN_PASSWORD": "default-password",
                "INITIAL_ADMIN_USERNAME": "initial-admin",
                "INITIAL_ADMIN_PASSWORD": "initial-password",
            },
            clear=True,
        ):
            config_module = load_module_from_path("test_day1_config_default", "app/config.py")
            settings = config_module.Settings()

        self.assertEqual(settings.default_admin_username, "default-admin")
        self.assertEqual(settings.default_admin_password, "default-password")


class CradBootstrapTests(unittest.TestCase):
    @staticmethod
    def _load_crad_module(settings_obj, session_local_mock, hash_mock, has_users_table=True):
        sqlalchemy_module = types.ModuleType("sqlalchemy")
        sqlalchemy_exc_module = types.ModuleType("sqlalchemy.exc")

        class FakeOperationalError(Exception):
            pass

        sqlalchemy_exc_module.OperationalError = FakeOperationalError
        inspect_mock = mock.Mock(
            return_value=mock.Mock(has_table=mock.Mock(return_value=has_users_table))
        )
        sqlalchemy_module.inspect = inspect_mock
        sqlalchemy_module.text = lambda value: value

        app_package = types.ModuleType("app")
        app_package.__path__ = []

        config_module = types.ModuleType("app.config")
        config_module.settings = settings_obj

        database_module = types.ModuleType("app.database")
        database_module.SessionLocal = session_local_mock

        class FakeUser:
            username = "username"

            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        models_module = types.ModuleType("app.models")
        models_module.User = FakeUser

        auth_module = types.ModuleType("app.auth")
        auth_module.get_password_hash = hash_mock

        roles_module = types.ModuleType("app.roles")
        roles_module.UserRole = types.SimpleNamespace(
            ADMIN=types.SimpleNamespace(value="admin")
        )

        injected_modules = {
            "sqlalchemy": sqlalchemy_module,
            "sqlalchemy.exc": sqlalchemy_exc_module,
            "app": app_package,
            "app.config": config_module,
            "app.database": database_module,
            "app.models": models_module,
            "app.auth": auth_module,
            "app.roles": roles_module,
        }

        crad_module = load_module_from_path("test_day1_crad", "crad.py", injected_modules)
        return crad_module, FakeUser, inspect_mock

    def test_init_db_creates_admin_from_configured_credentials(self):
        probe_db = mock.Mock()
        admin_db = mock.Mock()
        admin_db.query.return_value.filter.return_value.first.return_value = None

        session_local_mock = mock.Mock(side_effect=[probe_db, admin_db])
        settings_obj = types.SimpleNamespace(
            default_admin_username="bootstrap-admin",
            default_admin_password="p" * 80,
            default_admin_is_active=False,
        )
        hash_mock = mock.Mock(return_value="hashed-password")

        crad_module, fake_user_class, inspect_mock = self._load_crad_module(
            settings_obj,
            session_local_mock,
            hash_mock,
        )

        with mock.patch("builtins.print"):
            crad_module.init_db()

        hash_mock.assert_called_once_with("p" * 72)
        created_user = admin_db.add.call_args[0][0]
        self.assertIsInstance(created_user, fake_user_class)
        self.assertEqual(created_user.username, "bootstrap-admin")
        self.assertEqual(created_user.role, "admin")
        self.assertFalse(created_user.is_active)
        self.assertEqual(created_user.hashed_password, "hashed-password")
        admin_db.commit.assert_called_once()
        inspect_mock.assert_called_once_with(admin_db.bind)

    def test_init_db_skips_bootstrap_without_credentials(self):
        probe_db = mock.Mock()
        session_local_mock = mock.Mock(return_value=probe_db)
        settings_obj = types.SimpleNamespace(
            default_admin_username=None,
            default_admin_password=None,
            default_admin_is_active=True,
        )
        hash_mock = mock.Mock()

        crad_module, _, inspect_mock = self._load_crad_module(
            settings_obj,
            session_local_mock,
            hash_mock,
        )

        with mock.patch("builtins.print"):
            crad_module.init_db()

        self.assertEqual(session_local_mock.call_count, 1)
        hash_mock.assert_not_called()
        inspect_mock.assert_not_called()


class RoleMigrationTests(unittest.TestCase):
    @staticmethod
    def _load_migration_module(inspector):
        class FakeColumn:
            def __init__(self, name, column_type, **kwargs):
                self.name = name
                self.column_type = column_type
                self.kwargs = kwargs

        class FakeString:
            def __init__(self, length=None):
                self.length = length

        class FakeBoolean:
            def __init__(self):
                self.length = None

        sqlalchemy_module = types.ModuleType("sqlalchemy")
        sqlalchemy_module.inspect = mock.Mock(return_value=inspector)
        sqlalchemy_module.Column = FakeColumn
        sqlalchemy_module.String = FakeString
        sqlalchemy_module.Boolean = FakeBoolean
        sqlalchemy_module.text = lambda value: value

        op_mock = mock.Mock()
        op_mock.get_bind.return_value = object()
        alembic_module = types.ModuleType("alembic")
        alembic_module.op = op_mock

        migration_module = load_module_from_path(
            "test_day1_migration",
            "alembic/versions/20260313_0002_user_role_model.py",
            {
                "sqlalchemy": sqlalchemy_module,
                "alembic": alembic_module,
            },
        )
        return migration_module, op_mock

    def test_upgrade_adds_role_and_drops_is_admin(self):
        inspector = mock.Mock()
        inspector.get_table_names.return_value = ["users"]
        inspector.get_columns.return_value = [{"name": "id"}, {"name": "is_admin"}]
        inspector.get_check_constraints.return_value = []

        migration_module, op_mock = self._load_migration_module(inspector)

        migration_module.upgrade()

        added_column = op_mock.add_column.call_args[0][1]
        self.assertEqual(added_column.name, "role")
        self.assertIn("CASE WHEN is_admin", op_mock.execute.call_args_list[0].args[0])
        op_mock.drop_column.assert_called_once_with("users", "is_admin")
        op_mock.alter_column.assert_called_once()
        op_mock.create_check_constraint.assert_called_once()

    def test_downgrade_restores_is_admin_and_removes_role(self):
        inspector = mock.Mock()
        inspector.get_table_names.return_value = ["users"]
        inspector.get_columns.return_value = [{"name": "id"}, {"name": "role"}]
        inspector.get_check_constraints.return_value = [{"name": "ck_users_role"}]

        migration_module, op_mock = self._load_migration_module(inspector)

        migration_module.downgrade()

        added_column = op_mock.add_column.call_args[0][1]
        self.assertEqual(added_column.name, "is_admin")
        self.assertIn("CASE WHEN role = 'admin'", op_mock.execute.call_args[0][0])
        op_mock.drop_constraint.assert_called_once_with(
            "ck_users_role",
            "users",
            type_="check",
        )
        op_mock.drop_column.assert_called_once_with("users", "role")


if __name__ == "__main__":
    unittest.main()
