"""Idempotent schema migration for the Grant Intelligence stack.

`Base.metadata.create_all()` creates *missing tables only* - it will not add a
column to an existing table. So this script carries the changes that matter to
an already-populated `grants` table, and creates the new tables.

Safe to run repeatedly. Run it before starting the API or the scorer.

    python scripts/migrate_schema.py            # apply
    python scripts/migrate_schema.py --dry-run  # show what would change
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import inspect, text  # noqa: E402

from hunter.config import get_settings  # noqa: E402
from hunter.db import get_engine  # noqa: E402
from hunter.models import EMBEDDING_DIM, Base  # noqa: E402

# Importing these packages registers their tables on ``Base.metadata``. Without
# the imports, ``create_all`` would silently skip the SaaS tables because it
# only knows about the models that have been imported.
import accounts.models  # noqa: E402,F401
import billing.models  # noqa: E402,F401
import tracking.models  # noqa: E402,F401

VECTOR_TABLES = ("grants", "nonprofits")


def _vector_extension(conn) -> bool:
    return bool(
        conn.execute(
            text("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
        ).scalar()
    )


def _embedding_dim(conn, table: str) -> int | None:
    """Current declared dimension of <table>.embedding, or None if absent."""
    row = conn.execute(
        text(
            """
            SELECT atttypmod
            FROM pg_attribute
            WHERE attrelid = to_regclass(:t) AND attname = 'embedding'
            """
        ),
        {"t": table},
    ).scalar()
    if row is None:
        return None
    # pgvector stores the dimension directly in atttypmod.
    return int(row)


def migrate(engine, *, dry_run: bool = False) -> list[str]:
    actions: list[str] = []
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())

    with engine.begin() as conn:
        if not _vector_extension(conn):
            actions.append("CREATE EXTENSION vector")
            if not dry_run:
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))

        # 1. Resize grants.embedding if it was created at the old dimension.
        if "grants" in existing:
            current = _embedding_dim(conn, "grants")
            if current is not None and current != EMBEDDING_DIM:
                actions.append(
                    f"ALTER grants.embedding vector({current}) -> vector({EMBEDDING_DIM})"
                )
                if not dry_run:
                    # Existing values cannot survive a dimension change, and any
                    # rows present were written by a scorer that no longer
                    # matches the model. Drop and recreate the column.
                    conn.execute(text("ALTER TABLE grants DROP COLUMN embedding"))
                    conn.execute(
                        text(f"ALTER TABLE grants ADD COLUMN embedding vector({EMBEDDING_DIM})")
                    )
                    conn.execute(
                        text(
                            "CREATE INDEX IF NOT EXISTS ix_grants_embedding_hnsw "
                            "ON grants USING hnsw (embedding vector_cosine_ops)"
                        )
                    )
            elif current is None:
                actions.append(f"ADD grants.embedding vector({EMBEDDING_DIM})")
                if not dry_run:
                    conn.execute(
                        text(f"ALTER TABLE grants ADD COLUMN embedding vector({EMBEDDING_DIM})")
                    )

    # 2. Create any tables that do not exist yet (nonprofits, matches, drafts,
    #    and grants/hunter_runs on a fresh database).
    missing = [t for t in Base.metadata.tables if t not in existing]
    if missing:
        actions.append(f"CREATE TABLE {', '.join(sorted(missing))}")
        if not dry_run:
            Base.metadata.create_all(engine)

    with engine.begin() as conn:
        if _vector_extension(conn) and not dry_run:
            for table in VECTOR_TABLES:
                if table in set(inspect(engine).get_table_names()):
                    conn.execute(
                        text(
                            f"CREATE INDEX IF NOT EXISTS ix_{table}_embedding_hnsw "
                            f"ON {table} USING hnsw (embedding vector_cosine_ops)"
                        )
                    )

    return actions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate the Granted Agent schema")
    parser.add_argument("--dry-run", action="store_true", help="report without applying")
    args = parser.parse_args(argv)

    engine = get_engine()
    actions = migrate(engine, dry_run=args.dry_run)

    if not actions:
        print("schema is up to date; nothing to do")
        return 0
    for action in actions:
        print(("would " if args.dry_run else "") + action)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())