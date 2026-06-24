from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    Float,
    String,
    Text
)

from sqlalchemy.orm import (
    declarative_base,
    sessionmaker
)

Base = declarative_base()

engine = create_engine(
    "sqlite:///cves.db"
)

Session = sessionmaker(
    bind=engine
)


class CVE(Base):

    __tablename__ = "cves"

    id = Column(
        Integer,
        primary_key=True
    )

    cve_id = Column(
        String,
        nullable=False
    )

    port = Column(
        Integer,
        nullable=False
    )

    application = Column(
        String
    )

    cvss = Column(
        Float
    )
    classification = Column(
        String
    )

    description = Column(
        Text
    )


Base.metadata.create_all(engine)