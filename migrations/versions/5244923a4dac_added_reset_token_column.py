"""Added reset_token column

Revision ID: 5244923a4dac
Revises: d0e3ed3f0de0
Create Date: 2025-03-21 12:59:23.613969

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5244923a4dac'
down_revision = 'd0e3ed3f0de0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reset_token', sa.String(length=32), nullable=True))
        batch_op.create_unique_constraint('uq_user_reset_token', ['reset_token'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_column('reset_token')

    # ### end Alembic commands ###
