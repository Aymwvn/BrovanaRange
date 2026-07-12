from sqlalchemy import inspect, text

def add_column_if_missing(engine, table: str, column: str, ddl: str):
    inspector = inspect(engine)
    if table not in inspector.get_table_names():
        return
    columns = {item["name"] for item in inspector.get_columns(table)}
    if column in columns:
        return
    with engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))

def ensure_runtime_schema(engine):
    add_column_if_missing(engine, "users", "email_verified", "BOOLEAN DEFAULT FALSE NOT NULL")
    add_column_if_missing(engine, "users", "token_version", "INTEGER DEFAULT 0 NOT NULL")
    add_column_if_missing(engine, "users", "mfa_totp_enabled", "BOOLEAN DEFAULT FALSE NOT NULL")
    add_column_if_missing(engine, "users", "mfa_totp_secret", "VARCHAR(64)")
    add_column_if_missing(engine, "users", "mfa_email_enabled", "BOOLEAN DEFAULT FALSE NOT NULL")
    add_column_if_missing(engine, "submissions", "ip", "VARCHAR(64) DEFAULT '' NOT NULL")
    add_column_if_missing(engine, "submissions", "flagged", "BOOLEAN DEFAULT FALSE NOT NULL")
    add_column_if_missing(engine, "submissions", "anomaly_reason", "TEXT DEFAULT '' NOT NULL")
    add_column_if_missing(engine, "labs", "sandbox_runtime", "VARCHAR(40) DEFAULT 'runsc' NOT NULL")
