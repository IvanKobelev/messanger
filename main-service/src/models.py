from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text

from src.database import Base
from src.enums import CompanyUserRole, ProjectUserRole, ServiceUserRole


class User(Base):

    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("company.id"))
    company_role = Column(Enum(CompanyUserRole, values_callable=lambda enum: [e.value for e in enum]))
    created_ts = Column(DateTime, default=datetime.utcnow, nullable=False)
    email = Column(String(), nullable=False, unique=True)
    first_name = Column(String(32), nullable=False)
    login = Column(String(32), nullable=False, unique=True)
    password = Column(Text, nullable=False)
    second_name = Column(String(32), nullable=False)
    service_role = Column(Enum(ServiceUserRole, values_callable=lambda enum: [e.value for e in enum]),
                          default=ServiceUserRole.user, nullable=False)


class Company(Base):

    __tablename__ = "company"

    id = Column(Integer, primary_key=True)
    created_ts = Column(DateTime, default=datetime.utcnow, nullable=False)
    description = Column(Text)
    title = Column(String(32), nullable=False)


class Project(Base):

    __tablename__ = "project"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("company.id"), nullable=False)
    created_ts = Column(DateTime, default=datetime.utcnow, nullable=False)
    description = Column(Text)
    owner_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    title = Column(String(32), nullable=False)


class ProjectUser(Base):

    __tablename__ = "project_user"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("project.id"), nullable=False)
    role = Column(Enum(ProjectUserRole, values_callable=lambda enum: [e.value for e in enum]),
                  default=ProjectUserRole.user, nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
