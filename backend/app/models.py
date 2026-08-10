from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    repo_name = Column(String(100), nullable=False)
    repo_url = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="repository")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    repo_id = Column(Integer, ForeignKey("repositories.id"))
    status = Column(String(20), default="PENDING")  # PENDING, IN_PROGRESS, COMPLETED
    total_issues = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    severity = Column(String(10), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    vulnerability_type = Column(String(50), nullable=False)
    file_path = Column(String(255), nullable=False)
    line_number = Column(Integer, nullable=False)
    suggestion = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")