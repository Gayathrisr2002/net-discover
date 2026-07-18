"""Regression test for Finding #1 (stored XSS in the Users page → admin takeover).

The Users table was built client-side by concatenating the (attacker-controlled)
username into an HTML string, including into inline ``onclick="USR.showLimits('<username>')"``
handlers. The page's ``esc()`` helper escaped ``<``, ``>`` and ``&`` (via
``textContent`` → ``innerHTML``) but NOT quotes, so a username such as
``',alert(document.cookie),'`` broke out of the JS-string inside the onclick and
executed in an admin's session when the row was rendered/clicked — a stored XSS
that pivots to full admin takeover of a multi-tenant instance.

The XSS lives in template JavaScript, so this is a structural regression test:
it asserts the vulnerable pattern (interpolating the username into markup / inline
event handlers) is gone, and that the rows are now wired up with DOM APIs
(``createElement`` / ``textContent`` / ``addEventListener``) that never parse
user input as HTML.
"""

import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_HTML = os.path.join(REPO_ROOT, "marlinspike", "templates", "users.html")


def _template_source() -> str:
    with open(USERS_HTML, encoding="utf-8") as fh:
        return fh.read()


def test_username_not_interpolated_into_inline_onclick():
    """The three per-row action handlers took the username as an inline-onclick
    argument built by string concatenation. Those inline handlers must be gone.

    (The static modal buttons — ``USR.showAdd()``, ``USR.createUser()`` etc. —
    carry no user data and are unaffected; only the three that received a
    username were vulnerable.)
    """
    src = _template_source()
    for handler in ('onclick="USR.showLimits', 'onclick="USR.deleteUser', 'onclick="USR.showChpass'):
        assert handler not in src, (
            f"inline handler {handler!r} still present — the stored-XSS vector "
            "(username concatenated into an onclick JS-string) is not fixed"
        )


def test_no_esc_only_defense_for_action_buttons():
    """The row builder must not rely on esc() (which does not escape quotes)."""
    src = _template_source()
    assert "esc(u.username)" not in src


def test_rows_use_safe_dom_construction():
    """Rows are built with DOM APIs + addEventListener, not innerHTML of user data."""
    src = _template_source()
    assert "addEventListener('click'" in src, "action buttons should be wired via addEventListener"
    # username must reach the DOM via textContent, never via an HTML string.
    assert "textContent" in src
