"""Intentionally vulnerable Flask target for scanner integration tests.

Contains BOTH public (`/search`) and authenticated (`/dashboard/search`) endpoints so
authenticated-scan behaviour can be exercised end-to-end. Never expose to the internet.
"""
from flask import Flask, request, make_response, redirect
from markupsafe import escape

app = Flask(__name__)

VALID_SESSIONS = {"authed-session-token-abc123"}

INDEX = """<!doctype html>
<html><body>
<h1>Test Target</h1>
<ul>
  <li><a href="/html?q=hello">/html?q=hello</a> (HTML context reflection)</li>
  <li><a href='/attr?name=hello'>/attr?name=hello</a> (attribute context reflection)</li>
  <li><a href='/js?msg=hello'>/js?msg=hello</a> (javascript context reflection)</li>
  <li><a href='/encoded?q=hello'>/encoded?q=hello</a> (encoded, safe)</li>
  <li><a href='/safe'>/safe</a> (no reflection)</li>
  <li><a href='/form'>/form</a> (POST form)</li>
  <li><a href='/search?q=hello'>/search?q=hello</a> (public search)</li>
  <li><a href='/login'>/login</a> · <a href='/dashboard'>/dashboard</a> (authed area)</li>
</ul>
</body></html>"""


def _authed():
    tok = request.cookies.get("session", "")
    return tok in VALID_SESSIONS


def _login_page(msg=""):
    return f"""<!doctype html><html><body>
    <h1>Sign in</h1>
    <form method='POST' action='/login'>
      <input name='username' value='alice'>
      <input name='password' type='password' value='secret'>
      <button>Sign in</button>
    </form>
    <p>{msg}</p>
    </body></html>"""


@app.get("/")
def index():
    return INDEX


# --- Public reflection endpoints ---
@app.get("/html")
def html_reflect():
    return f"<html><body>Hello, {request.args.get('q','')}!</body></html>"


@app.get("/attr")
def attr_reflect():
    return f'<html><body><input type="text" value="{request.args.get("name","")}"></body></html>'


@app.get("/js")
def js_reflect():
    return f"<html><body><script>var m = '{request.args.get('msg','')}';</script></body></html>"


@app.get("/encoded")
def encoded_reflect():
    return f"<html><body>Hello, {escape(request.args.get('q',''))}!</body></html>"


@app.get("/safe")
def safe_no_reflect():
    _ = request.args.get("q", "")
    return "<html><body>Static content, no reflection.</body></html>"


@app.route("/form", methods=["GET", "POST"])
def form():
    if request.method == "POST":
        return f"<html><body>You said: {request.form.get('comment','')}</body></html>"
    return """<html><body>
      <form method="POST" action="/form">
        <input name="comment" value="hi"><button>Send</button>
      </form></body></html>"""


@app.get("/search")
def public_search():
    return f"<html><body>Public results for: {request.args.get('q','')}</body></html>"


# --- Auth flow ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == "alice" and request.form.get("password") == "secret":
            resp = make_response(redirect("/dashboard"))
            resp.set_cookie("session", "authed-session-token-abc123", httponly=True, samesite="Lax")
            return resp
        return _login_page("Invalid credentials")
    return _login_page()


@app.get("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.set_cookie("session", "", expires=0)
    return resp


# --- Authenticated area ---
@app.get("/dashboard")
def dashboard():
    if not _authed():
        return redirect("/login")
    return """<html><body>
      <h1>Dashboard</h1><a href='/logout'>Sign out</a>
      <ul><li><a href='/dashboard/search?q=hello'>/dashboard/search?q=hello</a></li>
          <li><a href='/dashboard/profile?name=alice'>/dashboard/profile?name=alice</a></li></ul>
    </body></html>"""


@app.get("/dashboard/search")
def dashboard_search():
    if not _authed():
        return redirect("/login")
    q = request.args.get("q", "")
    return f"<html><body>Authenticated results for: {q}<br><a href='/logout'>Sign out</a></body></html>"


@app.get("/dashboard/profile")
def dashboard_profile():
    if not _authed():
        return redirect("/login")
    name = request.args.get("name", "")
    return f'<html><body><input value="{name}"><a href="/logout">Sign out</a></body></html>'


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
