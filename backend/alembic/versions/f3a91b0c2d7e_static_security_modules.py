"""static security modules

Revision ID: f3a91b0c2d7e
Revises: d08c9fa3ef24
Create Date: 2026-07-23 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f3a91b0c2d7e"
down_revision: Union[str, None] = "d08c9fa3ef24"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "apkid_results",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("analysis_id", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("value", sa.String(length=256), nullable=False),
        sa.Column("detected", sa.Boolean(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("file_path", sa.String(length=1024), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_apkid_results_analysis_id"), "apkid_results", ["analysis_id"])
    op.create_index("ix_apkid_analysis_category", "apkid_results", ["analysis_id", "category"])

    op.create_table(
        "behaviour_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("analysis_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("java_file", sa.String(length=1024), nullable=True),
        sa.Column("method_name", sa.String(length=256), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_behaviour_findings_analysis_id"), "behaviour_findings", ["analysis_id"])
    op.create_index("ix_behaviour_analysis_name", "behaviour_findings", ["analysis_id", "name"])
    op.create_index("ix_behaviour_analysis_severity", "behaviour_findings", ["analysis_id", "severity"])

    op.create_table(
        "abused_permissions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("analysis_id", sa.String(length=32), nullable=False),
        sa.Column("permission", sa.String(length=256), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("dangerous_reason", sa.Text(), nullable=True),
        sa.Column("malware_usage", sa.Text(), nullable=True),
        sa.Column("used_in_code", sa.Boolean(), nullable=False),
        sa.Column("files", sa.Text(), nullable=True),
        sa.Column("methods", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_abused_permissions_analysis_id"), "abused_permissions", ["analysis_id"])
    op.create_index("ix_abused_permissions_analysis_category", "abused_permissions", ["analysis_id", "category"])
    op.create_index("ix_abused_permissions_analysis_risk", "abused_permissions", ["analysis_id", "risk_level"])

    op.create_table(
        "code_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("analysis_id", sa.String(length=32), nullable=False),
        sa.Column("issue", sa.String(length=256), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cwe", sa.String(length=64), nullable=True),
        sa.Column("owasp", sa.String(length=64), nullable=True),
        sa.Column("masvs", sa.String(length=64), nullable=True),
        sa.Column("java_file", sa.String(length=1024), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_code_findings_analysis_id"), "code_findings", ["analysis_id"])
    op.create_index("ix_code_findings_analysis_severity", "code_findings", ["analysis_id", "severity"])
    op.create_index("ix_code_findings_analysis_category", "code_findings", ["analysis_id", "category"])

    op.create_table(
        "recon_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("analysis_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=1024), nullable=False),
        sa.Column("protocol", sa.String(length=32), nullable=True),
        sa.Column("indicator_type", sa.String(length=64), nullable=True),
        sa.Column("risk", sa.String(length=16), nullable=True),
        sa.Column("file_path", sa.String(length=1024), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("method_name", sa.String(length=256), nullable=True),
        sa.Column("context", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_recon_findings_analysis_id"), "recon_findings", ["analysis_id"])
    op.create_index("ix_recon_findings_analysis_kind", "recon_findings", ["analysis_id", "kind"])
    op.create_index("ix_recon_findings_analysis_value", "recon_findings", ["analysis_id", "value"])

    op.create_table(
        "domain_intel",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("analysis_id", sa.String(length=32), nullable=False),
        sa.Column("domain", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("resolved_ip", sa.String(length=64), nullable=True),
        sa.Column("country", sa.String(length=64), nullable=True),
        sa.Column("region", sa.String(length=128), nullable=True),
        sa.Column("city", sa.String(length=128), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("isp", sa.String(length=256), nullable=True),
        sa.Column("asn", sa.String(length=64), nullable=True),
        sa.Column("source_file", sa.String(length=1024), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_domain_intel_analysis_id"), "domain_intel", ["analysis_id"])
    op.create_index("ix_domain_intel_analysis_domain", "domain_intel", ["analysis_id", "domain"])


def downgrade() -> None:
    op.drop_index("ix_domain_intel_analysis_domain", table_name="domain_intel")
    op.drop_index(op.f("ix_domain_intel_analysis_id"), table_name="domain_intel")
    op.drop_table("domain_intel")
    op.drop_index("ix_recon_findings_analysis_value", table_name="recon_findings")
    op.drop_index("ix_recon_findings_analysis_kind", table_name="recon_findings")
    op.drop_index(op.f("ix_recon_findings_analysis_id"), table_name="recon_findings")
    op.drop_table("recon_findings")
    op.drop_index("ix_code_findings_analysis_category", table_name="code_findings")
    op.drop_index("ix_code_findings_analysis_severity", table_name="code_findings")
    op.drop_index(op.f("ix_code_findings_analysis_id"), table_name="code_findings")
    op.drop_table("code_findings")
    op.drop_index("ix_abused_permissions_analysis_risk", table_name="abused_permissions")
    op.drop_index("ix_abused_permissions_analysis_category", table_name="abused_permissions")
    op.drop_index(op.f("ix_abused_permissions_analysis_id"), table_name="abused_permissions")
    op.drop_table("abused_permissions")
    op.drop_index("ix_behaviour_analysis_severity", table_name="behaviour_findings")
    op.drop_index("ix_behaviour_analysis_name", table_name="behaviour_findings")
    op.drop_index(op.f("ix_behaviour_findings_analysis_id"), table_name="behaviour_findings")
    op.drop_table("behaviour_findings")
    op.drop_index("ix_apkid_analysis_category", table_name="apkid_results")
    op.drop_index(op.f("ix_apkid_results_analysis_id"), table_name="apkid_results")
    op.drop_table("apkid_results")
