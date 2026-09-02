"""Comprehensive E2E UI/UX & Route Audit Test Suite for MarlinSpike.
Tests all web pages, template variables, JSON data islands, CSRF protection, and audit endpoints.
"""

import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-ui")
os.environ.setdefault("MARLINSPIKE_ALLOW_NO_DATABASE_URL", "true")

import sys
import unittest
from marlinspike.app import create_app, db
from marlinspike.models import User, Project
import glob
import re


class TestMarlinSpikeE2E(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            # Create test user
            from werkzeug.security import generate_password_hash
            u = User.query.filter_by(username="admin").first()
            if u:
                u.password_hash = generate_password_hash("admin123")
                u.email = "admin@marlinspike.local"
                u.role = "admin"
            else:
                u = User()
                u.username = "admin"
                u.email = "admin@marlinspike.local"
                u.password_hash = generate_password_hash("admin123")
                u.role = "admin"
                db.session.add(u)
            db.session.commit()

            # Create test project
            p = Project()
            p.name = "Test Plant Audit Project"
            p.user_id = u.id
            db.session.add(p)
            db.session.commit()
            cls.test_user_id = u.id
            cls.test_project_id = p.id

            # Create dummy report for assets test
            import json
            from marlinspike import config
            d = os.path.join(config.REPORTS_DIR, str(u.id), str(p.id))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "test-report.json"), "w") as f:
                json.dump({"nodes": [], "edges": [], "risk_findings": [], "completed_stages": ["Risk Surface Report"]}, f)

    def login(self):
        with self.app.app_context():
            user = User.query.filter_by(username="admin").first()
            if not user:
                raise RuntimeError("Bootstrap admin user not found")
            user_username = user.username
            user_id = user.id
            user_role = user.role
            user_session_version = user.session_version or 1
        with self.client.session_transaction() as sess:
            sess["user"] = user_username
            sess["user_id"] = user_id
            sess["role"] = user_role
            sess["session_version"] = user_session_version
        return self.client

    def test_01_login_and_auth(self):
        c = self.login()
        res = c.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        self.assertIn("MarlinSpike", res.get_data(as_text=True))

    def test_02_dashboard_page(self):
        c = self.login()
        res = c.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Dashboard", text)
        self.assertIn("csrf-token", text)

    def test_03_asset_inventory_page(self):
        c = self.login()
        res = c.get(f"/api/reports/test-report.json/assets?project_id={self.test_project_id}")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Asset Inventory", text)
        # Check data island pattern
        self.assertIn('<script id="report-data" type="application/json">', text)

    def test_04_fleet_sensors_page(self):
        c = self.login()
        res = c.get("/fleet")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Fleet Sensors", text)

    def test_05_findings_page(self):
        c = self.login()
        res = c.get("/capabilities")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Catalog", text)

    def test_06_projects_page(self):
        c = self.login()
        res = c.get("/projects")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Projects", text)
        self.assertIn("Historical Audit Report", text)

    def test_07_project_audit_report_page(self):
        c = self.login()
        res = c.get(f"/projects/{self.test_project_id}/audit-report")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Project Audit Report", text)
        self.assertIn("Total Vulnerabilities Discovered", text)
        self.assertIn("Download CSV", text)
        self.assertIn("Download JSON", text)

    def test_08_project_audit_report_api(self):
        c = self.login()
        res = c.get(f"/api/projects/{self.test_project_id}/audit-report")
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertTrue(json_data["ok"])
        self.assertEqual(json_data["project_id"], self.test_project_id)
        self.assertIn("summary", json_data["audit"])

    def test_09_project_audit_report_csv_download(self):
        c = self.login()
        res = c.get(f"/api/projects/{self.test_project_id}/audit-report/download?format=csv")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")
        self.assertIn("attachment; filename=", res.headers.get("Content-Disposition", ""))

    def test_10_project_audit_report_json_download(self):
        c = self.login()
        res = c.get(f"/api/projects/{self.test_project_id}/audit-report/download?format=json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "application/json")
        self.assertIn("attachment; filename=", res.headers.get("Content-Disposition", ""))

    def test_12_new_export_endpoints(self):
        c = self.login()
        # Report level endpoints
        res_sbom = c.get(f"/api/reports/test-report.json/sbom?project_id={self.test_project_id}")
        self.assertEqual(res_sbom.status_code, 200)
        self.assertIn("CycloneDX", res_sbom.get_data(as_text=True))

        res_acl = c.get(f"/api/reports/test-report.json/switch-acl?project_id={self.test_project_id}")
        self.assertEqual(res_acl.status_code, 200)
        self.assertIn("Cisco Industrial Ethernet", res_acl.get_data(as_text=True))

        res_snort = c.get(f"/api/reports/test-report.json/snort?project_id={self.test_project_id}")
        self.assertEqual(res_snort.status_code, 200)
        self.assertIn("Snort 3", res_snort.get_data(as_text=True))

        # Project level download endpoints
        res_p_sbom = c.get(f"/api/projects/{self.test_project_id}/sbom/download")
        self.assertEqual(res_p_sbom.status_code, 200)
        self.assertIn("CycloneDX", res_p_sbom.get_data(as_text=True))

        res_p_acl = c.get(f"/api/projects/{self.test_project_id}/switch-acl/download")
        self.assertEqual(res_p_acl.status_code, 200)

        res_p_snort = c.get(f"/api/projects/{self.test_project_id}/snort/download")
        self.assertEqual(res_p_snort.status_code, 200)
        self.assertIn("Snort 3", res_p_snort.get_data(as_text=True))

        # Single consolidated findings download endpoints
        res_f_csv = c.get(f"/api/reports/test-report.json/findings/download?format=csv&project_id={self.test_project_id}")
        self.assertEqual(res_f_csv.status_code, 200)
        self.assertEqual(res_f_csv.mimetype, "text/csv")
        self.assertIn("Category,Severity,Description", res_f_csv.get_data(as_text=True))

        res_f_json = c.get(f"/api/reports/test-report.json/findings/download?format=json&project_id={self.test_project_id}")
        self.assertEqual(res_f_json.status_code, 200)
        self.assertEqual(res_f_json.mimetype, "application/json")
        self.assertIn("risk_findings", res_f_json.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
