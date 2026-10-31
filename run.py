"""
Start TRACE X locally:

    python run.py

then open http://127.0.0.1:5000 in your browser.
The database and sample data are created automatically on the first run.
"""

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=debug)
