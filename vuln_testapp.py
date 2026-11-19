#!/usr/bin/env python3
"""
Deliberately vulnerable Flask app for testing webscan locally.
Run:  python vuln_testapp.py   (listens on 127.0.0.1:5000 only)
Never deploy this anywhere.
"""
import os
from flask import Flask, request, redirect, make_response
from markupsafe import escape

app = Flask(__name__)
HERE = os.path.dirname(os.path.abspath(__file__))


@app.after_request
def leaky_headers(r):
    r.headers["Server"] = "Apache/2.4.29 (Ubuntu)"
    r.headers["X-Powered-By"] = "PHP/7.2.24"
    return r


@app.route("/")
def index():
    resp = make_response("""<h1>Test Shop</h1>
    <a href="/search?q=shoes">Search</a> | <a href="/safe?q=hello">Safe search</a> |
    <a href="/login?next=/account">Login</a> | <a href="/contact">Contact</a>""")
    resp.set_cookie("session", "abc123")          # no HttpOnly / SameSite
    return resp


@app.route("/search")
def search():                                       # VULN: reflected XSS
    return f"<p>Results for: {request.args.get('q', '')}</p>"


@app.route("/safe")
def safe():                                         # properly encoded
    return f"<p>Results for: {escape(request.args.get('q', ''))}</p>"


@app.route("/login")
def login():                                        # VULN: open redirect
    nxt = request.args.get("next")
    if nxt:
        return redirect(nxt)
    return "<form><input name=user><input type=password name=pw></form>"


@app.route("/contact", methods=["GET", "POST"])
def contact():                                      # VULN: XSS in POST form
    if request.method == "POST":
        return f"<p>Thanks {request.form.get('name')}, we got: {escape(request.form.get('msg', ''))}</p>"
    return """<form method=post action=/contact>
      <input name=name><textarea name=msg></textarea><input type=submit></form>"""


@app.route("/.git/HEAD")
def git_head():                                     # VULN: exposed git
    return "ref: refs/heads/main\n"


@app.route("/.env")
def env():                                          # VULN: exposed env
    return "DB_PASSWORD=supersecret\nAPI_KEY=xyz\n"


@app.route("/uploads/")
def uploads():                                      # VULN: directory listing
    return "<title>Index of /uploads</title><h1>Index of /uploads</h1><a href=a.pdf>a.pdf</a>"


@app.errorhandler(404)
def nf(_):
    return "Not found", 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
