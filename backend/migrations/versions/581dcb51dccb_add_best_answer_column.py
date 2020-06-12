"""Add best_answer column

Revision ID: 581dcb51dccb
Revises: 9615c71d6713
Create Date: 2020-06-09 23:33:22.200943

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '581dcb51dccb'
down_revision = '9615c71d6713'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('questions', sa.Column('best_answer_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'questions', 'answers', ['best_answer_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'questions', type_='foreignkey')
    op.drop_column('questions', 'best_answer_id')
    # ### end Alembic commands ###
