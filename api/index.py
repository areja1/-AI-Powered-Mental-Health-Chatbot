# Vercel Python Serverless entrypoint for your Flask app.
# It imports `app` defined in app.py so Vercel can serve it.
from app import app # Flask WSGI app
