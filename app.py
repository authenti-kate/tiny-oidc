#!/usr/bin/env -S uv run
from app import create_app
from config import Config

if __name__ == '__main__':
    app = create_app(Config)
    app.run(
        host=Config.FLASK_HOST, port=Config.FLASK_PORT,
        debug=Config.FLASK_DEBUG
    )
