from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    repo_name = Column(String, index=True)
    repo_url = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship(
        "Scan",
        back_populates="repository",
        cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    repo_id = Column(Integer, ForeignKey("repositories.id"))
    scan_date = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="PENDING")
    total_issues = Column(Integer, default=0)

    repository = relationship(
        "Repository",
        back_populates="scans"
    )

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    ai_chat_messages = relationship(
        "AIChatMessage",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="AIChatMessage.created_at"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    severity = Column(String)
    vulnerability_type = Column(String)
    file_path = Column(String)
    line_number = Column(Integer)
    suggestion = Column(String)

    vulnerable_code = Column(Text, nullable=True)
    secure_code = Column(Text, nullable=True)

    scan = relationship(
        "Scan",
        back_populates="vulnerabilities"
    )


class AIChatMessage(Base):
    __tablename__ = "ai_chat_messages"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False
    )

    role = Column(
        String,
        nullable=False
    )

    content = Column(
        Text,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    scan = relationship(
        "Scan",
        back_populates="ai_chat_messages"
    )