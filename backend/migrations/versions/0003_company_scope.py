"""company-based access: user_companies

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-03

Non-Super-Admin users are now scoped by company (one or several). Locations become an
optional extra restriction: a user with no locations sees their companies at every site.
"""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('user_companies',
                    sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
                    sa.Column('company_id', sa.Integer(), sa.ForeignKey('companies.id', ondelete='CASCADE'), primary_key=True))


def downgrade() -> None:
    op.drop_table('user_companies')
