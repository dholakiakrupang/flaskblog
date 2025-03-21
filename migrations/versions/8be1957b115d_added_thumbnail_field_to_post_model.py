"""Added thumbnail field to Post model

Revision ID: 8be1957b115d
Revises: 07e9e139fec6
Create Date: 2025-03-20 16:12:25.869441

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8be1957b115d'
down_revision = '07e9e139fec6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.add_column(sa.Column('thumbnail', sa.String(length=255), nullable=True))

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('profile_picture',
               existing_type=sa.VARCHAR(length=20),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('profile_picture',
               existing_type=sa.VARCHAR(length=20),
               nullable=True)

    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.drop_column('thumbnail')

    # ### end Alembic commands ###
