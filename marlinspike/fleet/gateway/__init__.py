"""Fleet gateway — TLS listener for remote agent connections (Phase 2).

Runs as a separate always-on asyncio process, not inside gunicorn/Flask
workers. See server.py's module docstring for the wire protocol and
architecture rationale.
"""
