"""Intentionally vulnerable Flask target for scanner integration tests.

Do NOT expose to the internet. Run only inside docker-compose or localhost.
"""
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

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
</ul>
</body></html>"""


@app.get("/")
def index():
    return INDEX


@app.get("/html")
def html_reflect():
    q = request.args.get("q", "")
    return f"<html><body>Hello, {q}!</body></html>"  # UNSAFE - reflected in HTML


@app.get("/attr")
def attr_reflect():
    name = request.args.get("name", "")
    return f'<html><body><input type="text" value="{name}"></body></html>'  # UNSAFE - reflected in attribute


@app.get("/js")
def js_reflect():
    msg = request.args.get("msg", "")
    return f"<html><body><script>var m = '{msg}'; console.log(m);</script></body></html>"


@app.get("/encoded")
def encoded_reflect():
    q = request.args.get("q", "")
    return f"<html><body>Hello, {escape(q)}!</body></html>"  # SAFE - encoded


@app.get("/safe")
def safe_no_reflect():
    _ = request.args.get("q", "")
    return "<html><body>Static content, no reflection.</body></html>"


@app.route("/form", methods=["GET", "POST"])
def form():
    if request.method == "POST":
        comment = request.form.get("comment", "")
        return f"<html><body>You said: {comment}</body></html>"  # UNSAFE POST reflection
    return """<html><body>
      <form method="POST" action="/form">
        <input name="comment" value="hi">
        <button>Send</button>
      </form></body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
