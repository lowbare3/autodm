import os
import hmac
import hashlib
import sqlite3
import requests
from flask import Flask, request, jsonify, redirect, render_template

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

APP_ID = os.environ["APP_ID"]
APP_SECRET = os.environ["APP_SECRET"]
VERIFY_TOKEN = os.environ["VERIFY_TOKEN"]
REDIRECT_URI = os.environ["REDIRECT_URI"]
DB_PATH = "accounts.db"

GRAPH_BASE = "https://graph.instagram.com"
SCOPES = "instagram_business_basic,instagram_manage_messages,instagram_manage_comments,instagram_business_manage_messages"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ig_user_id TEXT UNIQUE NOT NULL,
                username TEXT,
                access_token TEXT NOT NULL,
                dm_message TEXT DEFAULT 'Hey! Here''s the link: https://yourlink.com',
                comment_reply TEXT DEFAULT 'Sent you a link! Check your DMs 📩',
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


init_db()


@app.route("/")
def index():
    with get_db() as conn:
        accounts = conn.execute(
            "SELECT * FROM accounts WHERE active = 1 ORDER BY created_at DESC"
        ).fetchall()
    error = request.args.get("error")
    return render_template("index.html", accounts=accounts, error=error)


@app.route("/auth/login")
def auth_login():
    return redirect(
        f"https://api.instagram.com/oauth/authorize"
        f"?client_id={APP_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={SCOPES}"
        f"&response_type=code"
    )


@app.route("/auth/callback")
def auth_callback():
    code = request.args.get("code")
    if not code:
        return redirect("/?error=auth_failed")

    # Exchange code for short-lived token
    resp = requests.post("https://api.instagram.com/oauth/access_token", data={
        "client_id": APP_ID,
        "client_secret": APP_SECRET,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code": code
    })
    if not resp.ok:
        print(f"[auth] short token failed: {resp.text}")
        return redirect("/?error=token_failed")

    short_token = resp.json()["access_token"]
    ig_user_id = str(resp.json()["user_id"])

    # Exchange for long-lived token (60 days)
    ll = requests.get(f"{GRAPH_BASE}/access_token", params={
        "grant_type": "ig_exchange_token",
        "client_secret": APP_SECRET,
        "access_token": short_token
    })
    if not ll.ok:
        print(f"[auth] long-lived token failed: {ll.text}")
        return redirect("/?error=token_failed")

    long_token = ll.json()["access_token"]

    # Get username
    me = requests.get(f"{GRAPH_BASE}/me", params={
        "fields": "id,username",
        "access_token": long_token
    })
    username = me.json().get("username", "unknown") if me.ok else "unknown"

    with get_db() as conn:
        conn.execute("""
            INSERT INTO accounts (ig_user_id, username, access_token)
            VALUES (?, ?, ?)
            ON CONFLICT(ig_user_id) DO UPDATE SET
                access_token = excluded.access_token,
                username = excluded.username,
                active = 1
        """, (ig_user_id, username, long_token))
        conn.commit()

    return redirect("/")


@app.route("/settings", methods=["POST"])
def update_settings():
    account_id = request.form.get("account_id")
    dm_message = request.form.get("dm_message", "").strip()
    comment_reply = request.form.get("comment_reply", "").strip()
    if account_id and dm_message and comment_reply:
        with get_db() as conn:
            conn.execute(
                "UPDATE accounts SET dm_message = ?, comment_reply = ? WHERE id = ?",
                (dm_message, comment_reply, account_id)
            )
            conn.commit()
    return redirect("/")


@app.route("/disconnect", methods=["POST"])
def disconnect():
    account_id = request.form.get("account_id")
    if account_id:
        with get_db() as conn:
            conn.execute("UPDATE accounts SET active = 0 WHERE id = ?", (account_id,))
            conn.commit()
    return redirect("/")


@app.route("/health")
def health():
    return "OK", 200


@app.route("/webhook", methods=["GET"])
def verify_webhook():
    if request.args.get("hub.verify_token") == VERIFY_TOKEN:
        return request.args.get("hub.challenge"), 200
    return "Forbidden", 403


@app.route("/webhook", methods=["POST"])
def handle_webhook():
    sig = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(APP_SECRET.encode(), request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return "Invalid signature", 403

    data = request.get_json()
    for entry in data.get("entry", []):
        account = get_account(entry.get("id"))
        if not account:
            continue
        for change in entry.get("changes", []):
            if change.get("field") == "comments":
                handle_comment(change["value"], account)

    return jsonify({"status": "ok"}), 200


def get_account(ig_user_id):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM accounts WHERE ig_user_id = ? AND active = 1",
            (ig_user_id,)
        ).fetchone()


def handle_comment(comment_data, account):
    commenter_id = comment_data.get("from", {}).get("id")
    commenter_username = comment_data.get("from", {}).get("username", "")
    comment_id = comment_data.get("id")

    if not commenter_id or not comment_id:
        return
    if commenter_username == account["username"]:
        return

    reply_to_comment(comment_id, account["comment_reply"], account["access_token"])
    send_dm(account["ig_user_id"], commenter_id, account["dm_message"], account["access_token"])


def reply_to_comment(comment_id, message, token):
    resp = requests.post(
        f"{GRAPH_BASE}/{comment_id}/replies",
        params={"access_token": token},
        json={"message": message}
    )
    print(f"[reply] comment={comment_id} status={resp.status_code} body={resp.text}")


def send_dm(ig_user_id, recipient_id, message, token):
    resp = requests.post(
        f"{GRAPH_BASE}/{ig_user_id}/messages",
        params={"access_token": token},
        json={"recipient": {"id": recipient_id}, "message": {"text": message}}
    )
    print(f"[dm] recipient={recipient_id} status={resp.status_code} body={resp.text}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
