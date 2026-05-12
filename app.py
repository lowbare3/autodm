import os
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

VERIFY_TOKEN = os.environ["VERIFY_TOKEN"]
PAGE_ACCESS_TOKEN = os.environ["PAGE_ACCESS_TOKEN"]
APP_SECRET = os.environ["APP_SECRET"]
DM_MESSAGE = os.environ.get("DM_MESSAGE", "Hey! Here's the link you asked for: https://yourlink.com")
COMMENT_REPLY = os.environ.get("COMMENT_REPLY", "Sent you a link! Check your DMs 📩")
MY_USERNAME = os.environ.get("MY_USERNAME", "")


def verify_signature(payload: bytes, signature: str) -> bool:
    expected = "sha256=" + hmac.new(APP_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.route("/")
def health():
    return "OK", 200


@app.route("/webhook", methods=["GET"])
def verify_webhook():
    if request.args.get("hub.verify_token") == VERIFY_TOKEN:
        return request.args.get("hub.challenge"), 200
    return "Forbidden", 403


@app.route("/webhook", methods=["POST"])
def handle_webhook():
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(request.data, signature):
        return "Invalid signature", 403

    data = request.get_json()

    for entry in data.get("entry", []):
        for change in entry.get("changes", []):
            if change.get("field") == "comments":
                handle_comment(change["value"])

    return jsonify({"status": "ok"}), 200


def handle_comment(comment_data: dict):
    commenter_id = comment_data.get("from", {}).get("id")
    commenter_username = comment_data.get("from", {}).get("username", "")
    comment_id = comment_data.get("id")

    if not commenter_id or not comment_id:
        return

    # Prevent replying to your own comments and triggering a loop
    if commenter_username == MY_USERNAME:
        return

    reply_to_comment(comment_id)
    send_dm(commenter_id)


def reply_to_comment(comment_id: str):
    url = f"https://graph.facebook.com/v19.0/{comment_id}/replies"
    resp = requests.post(url, json={
        "message": COMMENT_REPLY,
        "access_token": PAGE_ACCESS_TOKEN
    })
    print(f"[reply] comment={comment_id} status={resp.status_code} body={resp.text}")


def send_dm(user_id: str):
    url = "https://graph.facebook.com/v19.0/me/messages"
    resp = requests.post(url, json={
        "recipient": {"id": user_id},
        "message": {"text": DM_MESSAGE},
        "access_token": PAGE_ACCESS_TOKEN
    })
    print(f"[dm] user={user_id} status={resp.status_code} body={resp.text}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
