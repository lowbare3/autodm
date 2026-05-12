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

GRAPH_BASE = "https://graph.facebook.com/v19.0"
SCOPES = "instagram_basic,instagram_manage_messages,instagram_manage_comments,pages_read_engagement,pages_show_list"


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
        f"https://www.facebook.com/dialog/oauth"
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

    # Exchange code for user access token
    resp = requests.get("https://graph.facebook.com/v19.0/oauth/access_token", params={
        "client_id": APP_ID,
        "client_secret": APP_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": code
    })
    if not resp.ok:
        print(f"[auth] token exchange failed: {resp.text}")
        return redirect("/?error=token_failed")

    user_token = resp.json()["access_token"]

    # Get linked Instagram Business Account
    pages = requests.get("https://graph.facebook.com/v19.0/me/accounts", params={
        "access_token": user_token
    })
    if not pages.ok or not pages.json().get("data"):
        print(f"[auth] no pages found: {pages.text}")
        return redirect("/?error=no_page")

    # Use the first page's token to get the Instagram account
    page = pages.json()["data"][0]
    page_token = page["access_token"]
    page_id = page["id"]

    ig_resp = requests.get(f"https://graph.facebook.com/v19.0/{page_id}", params={
        "fields": "instagram_business_account",
        "access_token": page_token
    })
    ig_data = ig_resp.json().get("instagram_business_account", {})
    ig_user_id = ig_data.get("id")

    if not ig_user_id:
        print(f"[auth] no instagram account linked: {ig_resp.text}")
        return redirect("/?error=no_instagram")

    long_token = page_token

    # Get Instagram username
    me = requests.get(f"https://graph.facebook.com/v19.0/{ig_user_id}", params={
        "fields": "username",
        "access_token": page_token
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
