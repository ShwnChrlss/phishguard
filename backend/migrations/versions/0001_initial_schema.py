# =============================================================
#  Migration 0001 — Initial Schema
#  
#  WHY THIS FILE EXISTS:
#    Alembic couldn't auto-generate this because the SQLite DB
#    already had all tables. We write it manually so Docker can
#    create a fresh PostgreSQL database from scratch.
#
#  HOW MIGRATIONS WORK:
#    upgrade()   → runs when you do 'flask db upgrade'
#                  creates tables / adds columns
#    downgrade() → runs when you do 'flask db downgrade'
#                  reverses the changes (drops tables here)
#
#    Alembic tracks which migrations have run in the
#    'alembic_version' table — one row with the current
#    revision ID. On upgrade it runs all unapplied migrations
#    in order. On downgrade it reverses them.
# =============================================================

from alembic import op
import sqlalchemy as sa

# Unique ID for this migration — referenced by alembic_version table
revision  = '0001'
down_revision = None    # None = this is the very first migration
branch_labels = None
depends_on    = None


def upgrade():
    # ── USERS ──────────────────────────────────────────────
    op.create_table('users',
        sa.Column('id',                 sa.Integer(),      nullable=False),
        sa.Column('username',           sa.String(80),     nullable=False),
        sa.Column('email',              sa.String(120),    nullable=False),
        sa.Column('password_hash',      sa.String(255),    nullable=False),
        sa.Column('role',               sa.String(20),     nullable=False),
        sa.Column('department',         sa.String(100),    nullable=True),
        sa.Column('full_name',          sa.String(150),    nullable=True),
        sa.Column('is_active',          sa.Boolean(),      nullable=False),
        sa.Column('created_at',         sa.DateTime(),     nullable=False),
        sa.Column('last_login',         sa.DateTime(),     nullable=True),
        sa.Column('updated_at',         sa.DateTime(),     nullable=True),
        sa.Column('quiz_score',         sa.Integer(),      nullable=True),
        sa.Column('quiz_total',         sa.Integer(),      nullable=True),
        sa.Column('training_badges',    sa.Text(),         nullable=True),
        sa.Column('reset_token_hash',   sa.String(64),     nullable=True),
        sa.Column('reset_token_expiry', sa.DateTime(),     nullable=True),
        sa.Column('reset_token_used',   sa.Boolean(),      nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email'),
    )

    # ── EMAIL SCANS ────────────────────────────────────────
    op.create_table('email_scans',
        sa.Column('id',               sa.Integer(),      nullable=False),
        sa.Column('user_id',          sa.Integer(),      nullable=True),
        sa.Column('email_subject',    sa.String(500),    nullable=True),
        sa.Column('email_sender',     sa.String(200),    nullable=True),
        sa.Column('email_body',       sa.Text(),         nullable=False),
        sa.Column('email_preview',    sa.String(300),    nullable=True),
        sa.Column('is_phishing',      sa.Boolean(),      nullable=False),
        sa.Column('risk_score',       sa.Integer(),      nullable=False),
        sa.Column('confidence',       sa.Float(),        nullable=False),
        sa.Column('explanation_json', sa.Text(),         nullable=True),
        sa.Column('features_json',    sa.Text(),         nullable=True),
        sa.Column('status',           sa.String(20),     nullable=False),
        sa.Column('reviewed_by',      sa.String(80),     nullable=True),
        sa.Column('reviewed_at',      sa.DateTime(),     nullable=True),
        sa.Column('source',           sa.String(20),     nullable=True),
        sa.Column('scanned_at',       sa.DateTime(),     nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # ── ALERTS ─────────────────────────────────────────────
    op.create_table('alerts',
        sa.Column('id',                    sa.Integer(),     nullable=False),
        sa.Column('scan_id',               sa.Integer(),     nullable=True),
        sa.Column('alert_type',            sa.String(30),    nullable=False),
        sa.Column('severity',              sa.String(10),    nullable=False),
        sa.Column('title',                 sa.String(200),   nullable=False),
        sa.Column('message',               sa.Text(),        nullable=False),
        sa.Column('risk_score',            sa.Integer(),     nullable=False),
        sa.Column('target_email',          sa.String(200),   nullable=True),
        sa.Column('target_department',     sa.String(100),   nullable=True),
        sa.Column('status',                sa.String(20),    nullable=False),
        sa.Column('acknowledged_by',       sa.String(80),    nullable=True),
        sa.Column('resolved_by',           sa.String(80),    nullable=True),
        sa.Column('resolution_note',       sa.Text(),        nullable=True),
        sa.Column('notification_sent',     sa.Boolean(),     nullable=True),
        sa.Column('notification_sent_at',  sa.DateTime(),    nullable=True),
        sa.Column('created_at',            sa.DateTime(),    nullable=False),
        sa.Column('acknowledged_at',       sa.DateTime(),    nullable=True),
        sa.Column('resolved_at',           sa.DateTime(),    nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['email_scans.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # ── TRAINING RECORDS ───────────────────────────────────
    op.create_table('training_records',
        sa.Column('id',             sa.Integer(),     nullable=False),
        sa.Column('user_id',        sa.Integer(),     nullable=False),
        sa.Column('quiz_type',      sa.String(50),    nullable=False),
        sa.Column('score',          sa.Integer(),     nullable=False),
        sa.Column('total',          sa.Integer(),     nullable=False),
        sa.Column('time_seconds',   sa.Integer(),     nullable=True),
        sa.Column('badges_earned',  sa.Text(),        nullable=True),
        sa.Column('completed_at',   sa.DateTime(),    nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade():
    # Drop in reverse order — foreign keys must be dropped first
    op.drop_table('training_records')
    op.drop_table('alerts')
    op.drop_table('email_scans')
    op.drop_table('users')
