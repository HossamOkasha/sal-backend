"""Remove foreignkey from Question

Revision ID: 0398aabca5eb
Revises: 3950d4964abe
Create Date: 2020-06-10 16:34:15.469672

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0398aabca5eb'
down_revision = '3950d4964abe'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('questions_best_answer_id_fkey', 'questions', type_='foreignkey')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key('questions_best_answer_id_fkey', 'questions', 'answers', ['best_answer_id'], ['id'])
    # ### end Alembic commands ###
