from flask import Flask
from flask_cors import CORS
import os
import mail
import ChatController

app = Flask(__name__)
cors = CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
app.secret_key = os.environ.get('SECRET_KEY', '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')  # Move to a secure place or use environment variables
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True

mail.setup_mail_routes(app)
ChatController.setup_chat_routes(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)

