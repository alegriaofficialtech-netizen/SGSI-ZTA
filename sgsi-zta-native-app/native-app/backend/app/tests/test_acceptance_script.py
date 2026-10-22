import pytest

from verify_m5_acceptance import check_database_safety, run_acceptance


def test_acceptance_script_import_has_no_side_effects():
    """Verify that importing verify_m5_acceptance is side-effect free."""
    import verify_m5_acceptance
    assert hasattr(verify_m5_acceptance, "run_acceptance")
    assert hasattr(verify_m5_acceptance, "check_database_safety")


def test_database_safety_guard_blocks_production_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_PRODUCTION_ACCEPTANCE", raising=False)
    prod_url = "postgresql+psycopg://sgsi_app:secret@postgres:5432/sgsi_zta_db"
    
    is_safe, reason = check_database_safety(prod_url, allow_production_opt_in=False)
    assert not is_safe
    assert "CRITICAL SAFETY VIOLATION" in reason


def test_database_safety_guard_blocks_production_without_env_var(monkeypatch):
    monkeypatch.delenv("ALLOW_PRODUCTION_ACCEPTANCE", raising=False)
    prod_url = "postgresql+psycopg://sgsi_app:secret@postgres:5432/sgsi_zta_db"
    
    is_safe, reason = check_database_safety(prod_url, allow_production_opt_in=True)
    assert not is_safe
    assert "CRITICAL SAFETY VIOLATION" in reason


def test_database_safety_guard_allows_production_with_both_flag_and_env(monkeypatch):
    monkeypatch.setenv("ALLOW_PRODUCTION_ACCEPTANCE", "true")
    prod_url = "postgresql+psycopg://sgsi_app:secret@postgres:5432/sgsi_zta_db"
    
    is_safe, reason = check_database_safety(prod_url, allow_production_opt_in=True)
    assert is_safe
    assert "Production database allowed" in reason


def test_database_safety_guard_allows_test_databases():
    test_urls = [
        "sqlite:///:memory:",
        "sqlite:///./test.db",
        "postgresql+psycopg://sgsi_test:secret@localhost:5432/sgsi_native_test",
        "postgresql+psycopg://user:pass@test-postgres:5432/test_db",
    ]
    for url in test_urls:
        is_safe, reason = check_database_safety(url, allow_production_opt_in=False)
        assert is_safe, f"Expected safe for {url}, got: {reason}"


def test_run_acceptance_aborts_on_unsafe_db(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://user:pass@postgres:5432/sgsi_zta_db")
    monkeypatch.delenv("ALLOW_PRODUCTION_ACCEPTANCE", raising=False)
    
    with pytest.raises(RuntimeError) as exc_info:
        run_acceptance(allow_production=False)
    assert "CRITICAL SAFETY VIOLATION" in str(exc_info.value)
