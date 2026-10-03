"""companies, locations and location-scoped users

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-03

* companies / locations tables (managed by Super Admin; never hard-deleted)
* servers.company_id / servers.location_id
* user_locations (which sites a non-Super-Admin user may see)
* default locations: Daman, Vapi, Pune, Surat, Indore, Bhopal, Other
* existing servers are matched to a location when their free-text location
  starts with a location name (e.g. "Pune DC, Rack 4" -> Pune); the rest stay
  unassigned (visible to Super Admin only) until assigned.
"""
from datetime import datetime

from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None

DEFAULT_LOCATIONS = [("Daman", "DMN"), ("Vapi", "VAP"), ("Pune", "PUN"), ("Surat", "SUR"),
                     ("Indore", "IDR"), ("Bhopal", "BPL"), ("Other", "OTH")]


def _audit_cols():
    return [sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('updated_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)]


def upgrade() -> None:
    op.create_table('companies',
                    sa.Column('id', sa.Integer(), primary_key=True),
                    sa.Column('name', sa.String(120), nullable=False, unique=True),
                    sa.Column('code', sa.String(16), nullable=False, unique=True),
                    sa.Column('description', sa.String(255), nullable=True),
                    sa.Column('is_active', sa.Boolean(), nullable=False),
                    *_audit_cols())
    op.create_table('locations',
                    sa.Column('id', sa.Integer(), primary_key=True),
                    sa.Column('name', sa.String(64), nullable=False, unique=True),
                    sa.Column('code', sa.String(16), nullable=False, unique=True),
                    sa.Column('description', sa.String(255), nullable=True),
                    sa.Column('is_active', sa.Boolean(), nullable=False),
                    *_audit_cols())
    op.create_table('user_locations',
                    sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
                    sa.Column('location_id', sa.Integer(), sa.ForeignKey('locations.id', ondelete='CASCADE'), primary_key=True))
    op.add_column('servers', sa.Column('company_id', sa.Integer(), nullable=True))
    op.add_column('servers', sa.Column('location_id', sa.Integer(), nullable=True))
    op.create_index('ix_servers_company_id', 'servers', ['company_id'])
    op.create_index('ix_servers_location_id', 'servers', ['location_id'])
    op.create_foreign_key('fk_servers_company', 'servers', 'companies', ['company_id'], ['id'], ondelete='RESTRICT')
    op.create_foreign_key('fk_servers_location', 'servers', 'locations', ['location_id'], ['id'], ondelete='RESTRICT')

    now = datetime.utcnow().replace(microsecond=0)
    loc = sa.table('locations', sa.column('id', sa.Integer), sa.column('name', sa.String), sa.column('code', sa.String),
                   sa.column('is_active', sa.Boolean), sa.column('created_at', sa.DateTime), sa.column('updated_at', sa.DateTime))
    op.bulk_insert(loc, [{"name": n, "code": c, "is_active": True, "created_at": now, "updated_at": now}
                         for n, c in DEFAULT_LOCATIONS])
    conn = op.get_bind()
    ids = {name.lower(): i for i, name in conn.execute(sa.text("SELECT id, name FROM locations"))}
    for sid, text_loc in conn.execute(sa.text("SELECT id, location FROM servers WHERE location IS NOT NULL")).fetchall():
        t = (text_loc or "").strip().lower()
        match = next((i for n, i in ids.items() if n != "other" and t.startswith(n)), None)
        if match:
            conn.execute(sa.text("UPDATE servers SET location_id=:l WHERE id=:s"), {"l": match, "s": sid})


def downgrade() -> None:
    op.drop_constraint('fk_servers_location', 'servers', type_='foreignkey')
    op.drop_constraint('fk_servers_company', 'servers', type_='foreignkey')
    op.drop_index('ix_servers_location_id', 'servers')
    op.drop_index('ix_servers_company_id', 'servers')
    op.drop_column('servers', 'location_id')
    op.drop_column('servers', 'company_id')
    op.drop_table('user_locations')
    op.drop_table('locations')
    op.drop_table('companies')
