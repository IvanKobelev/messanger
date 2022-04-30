from enum import Enum


class ServiceUserRole(Enum):

    admin = "ADMIN"
    user = "USER"


class CompanyUserRole(Enum):

    admin = "ADMIN"
    manager = "MANAGER"
    user = "USER"


class ProjectUserRole(Enum):

    admin = "ADMIN"
    manager = "MANAGER"
    user = "USER"
