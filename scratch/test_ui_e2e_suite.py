"""Comprehensive E2E UI/UX & Route Audit Test Suite for MarlinSpike.
Tests all web pages, template variables, JSON data islands, CSRF protection, and audit endpoints.
"""

import sys
import unittest
from marlinspike.app import create_app, db
from marlinspike.models import User, Project
import os
import glob
import re


class TestMarlinSpikeE2E(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            # Create test user
            u = User(username="admin", email="admin@marlinspike.local")
            u.set_password("admin123")
            db.session.add(u)
            db.session.commit()

            # Create test project
            p = Project(name="Test Plant Audit Project", user_id=u.id)
            db.session.add(p)
            db.session.commit()
            cls.test_user_id = u.id
            cls.test_project_id = p.id

    def login(self):
        with self.client as c:
            res = c.get("/login")
            self.assertEqual(res.status_code, 200)
            csrf_token = None
            for line in res.get_data(as_text=True).splitlines():
                if "csrf-token" in line:
                    m = re.search(r'content="([^"]+)"', line)
                    if m:
                        csrf_token = m.group(1)
                        break
            
            res = c.post(
                "/login",
                data={"username": "admin", "password": "admin123", "csrf_token": csrf_token},
                follow_redirects=True,
            )
            return c

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
        res = c.get("/assets")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Asset Inventory", text)
        # Check data island pattern
        self.assertIn('<script type="application/json" id="asset-report-data">', text)

    def test_04_fleet_sensors_page(self):
        c = self.login()
        res = c.get("/fleet")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Distributed Remote Sensors", text)

    def test_05_findings_page(self):
        c = self.login()
        res = c.get("/findings")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("Findings", text)

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

    def test_11_all_templates_compile_cleanly(self):
        """Check all Jinja2 HTML templates for syntax errors."""
        template_dir = os.path.join(os.path.dirname(__file__), "..", "marlinspike", "templates")
        templates = glob.glob(os.path.join(template_dir, "*.html"))
        self.assertGreater(len(templates), 0)
        with self.app.app_context():
            for t_path in templates:
                t_name = os.path.basename(t_path)
                try:
                    self.app.jinja_env.get_template(t_name)
                except Exception as e:
                    self.fail(f"Template compilation failed for {t_name}: {e}")


if __name__ == "__main__":
    unittest.main()
