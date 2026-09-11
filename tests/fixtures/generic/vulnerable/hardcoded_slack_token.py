# Fixture vulnérable : token Slack hardcodé
import requests

SLACK_TOKEN = "xoxb-1234567890-abcdefghijklm"

requests.post("https://slack.com/api/chat.postMessage", json={
    "channel": "#general",
    "text": "Hello",
    "token": SLACK_TOKEN
})
