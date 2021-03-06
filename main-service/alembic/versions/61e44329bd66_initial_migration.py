"""initial migration

Revision ID: 61e44329bd66
Revises: 
Create Date: 2022-04-30 22:35:37.005731

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '61e44329bd66'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('company',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('created_ts', sa.DateTime(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('title', sa.String(length=32), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('company_id', sa.Integer(), nullable=True),
    sa.Column('company_role', sa.Enum('ADMIN', 'MANAGER', 'USER', name='companyuserrole'), nullable=True),
    sa.Column('created_ts', sa.DateTime(), nullable=False),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('first_name', sa.String(length=32), nullable=False),
    sa.Column('login', sa.String(length=32), nullable=False),
    sa.Column('password', sa.Text(), nullable=False),
    sa.Column('second_name', sa.String(length=32), nullable=False),
    sa.Column('service_role', sa.Enum('ADMIN', 'USER', name='serviceuserrole'), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['company.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('login')
    )
    op.create_table('project',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('company_id', sa.Integer(), nullable=False),
    sa.Column('created_ts', sa.DateTime(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('owner_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['company.id'], ),
    sa.ForeignKeyConstraint(['owner_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('project_user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.Column('role', sa.Enum('ADMIN', 'MANAGER', 'USER', name='projectuserrole'), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['project.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('project_user')
    op.drop_table('project')
    op.drop_table('user')
    op.drop_table('company')
    
    companyuserrole = postgresql.ENUM('ADMIN', 'MANAGER', 'USER', name='companyuserrole')
    companyuserrole.drop(op.get_bind())

    serviceuserrole = postgresql.ENUM('ADMIN', 'USER', name='serviceuserrole')
    serviceuserrole.drop(op.get_bind())

    projectuserrole = postgresql.ENUM('ADMIN', 'MANAGER', 'USER', name='projectuserrole')
    projectuserrole.drop(op.get_bind())
    # ### end Alembic commands ###
