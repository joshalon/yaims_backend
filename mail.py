import json
import os
import logging
import base64
from flask_cors import CORS
from flask import session, make_response
from email.mime.text import MIMEText
from flask import jsonify, redirect, request, session, url_for
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError



# Remove app initialization from here
SCOPES = [
    'https://mail.google.com/',            # Full access to the mail service
    'https://www.googleapis.com/auth/gmail.modify'  # Read, compose, and send emails from your Gmail account
]
CLIENT_SECRETS_FILE = 'credentials.json'

def setup_mail_routes(app):

    @app.route('/login')
    def login():
        # Create a flow instance to manage the OAuth 2.0 Authorization Grant Flow steps
        flow = Flow.from_client_secrets_file(
            'credentials.json', SCOPES)
        
        flow.redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')
        authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'  # Ensures that the user is prompted for consent which is necessary to receive a refresh token
        )

        
        session['state'] = state
        return redirect(authorization_url)

    @app.route('/oauth2callback', methods=['GET'])
    def oauth2callback():
    # Attempt to retrieve the state from the session first
        try:
            state = session.get('state')
            if not state:
                app.logger.error('Session state is missing')
                return 'Session state missing', 400
        
            # Initialize the flow object using the state from the session
            flow = Flow.from_client_secrets_file(
            'credentials.json', 
            SCOPES, 
            state=state
            )
            flow.redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')

            # Fetch the token using the response from the authorization server
            authorization_response = request.url
            flow.fetch_token(authorization_response=authorization_response)

            if not flow.credentials:
                return 'Authentication failed', 401
            
             # Convert credentials to JSON and store them in a secure, HttpOnly cookie
            creds_json = flow.credentials.to_json()
            
            response = app.response_class(
                response=json.dumps({'success': True}),
                status=200,
                mimetype='application/json'
            )
            response.set_cookie('credentials', value=creds_json, httponly=False, secure=True, samesite='None', max_age=3600)  # Set max_age as needed
            
            # Clear the state from the session
            session.pop('state', None)
            
            # Set the Location header for redirect
            response.headers['Location'] = 'http://localhost:3000/inbox'
            response.status_code = 302  # Set status code for redirect
            
            app.logger.info(f"Setting cookie: {response.headers.get('Set-Cookie')}")
            return response
        except Exception as e:
            app.logger.error(f'Error in oauth2callback: {str(e)}')
        return jsonify({'error': str(e)}), 500
    
    @app.route('/getSessionToken', methods=['GET'])
    def get_token():
        try:
            app.logger.info(f"All cookies received: {request.cookies}")
            credentials = request.cookies.get('credentials')
            if not credentials:
                app.logger.error('No credentials found in cookie')
                return jsonify({'error': 'No credentials found'}), 401
            
            app.logger.info(f"Credentials found: {credentials}")
            
            try:
                creds_dict = json.loads(credentials)
            except json.JSONDecodeError:
                app.logger.error('Invalid JSON in credentials cookie')
                return jsonify({'error': 'Invalid credentials format'}), 401
            
            token = creds_dict.get('token')
            if not token:
                app.logger.error('No token found in credentials')
                return jsonify({'error': 'No token found in credentials'}), 401
            
            # You might want to validate the token here
            # For example, check if it's expired and refresh if necessary
            
            return jsonify({'token': token}), 200
        except Exception as e:
            app.logger.error(f'Error in get_token: {str(e)}')
            return jsonify({'error': str(e)}), 500
            
    @app.route('/get_emails', methods=['GET'])
    def get_emails():
        creds_json = session.get('credentials')
        if not creds_json:
            return jsonify({'error': 'No credentials, authentication required'}), 401

        creds = Credentials.from_authorized_user_info(json.loads(creds_json))

        try:
            service = build('gmail', 'v1', credentials=creds)
            results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
            messages = results.get('messages', [])

            return jsonify(messages)
        except HttpError as error:
            return jsonify({'error': str(error)}), 500

    @app.route('/send_email', methods=['GET', 'POST'])
    def send_email():
        token_info = request.json
        access_token = token_info['access_token']
        message_text = token_info['message']
        subject_text = token_info['subject']
        
        
        creds= Credentials(access_token=access_token)
        
        app.logger.info('Received send_email request')
        creds_json = session.get('credentials')
        if not creds_json:
            return redirect(url_for('index'))

        #creds = Credentials.from_authorized_user_info(json.loads(creds_json))
        service = build('gmail', 'v1', credentials=creds)
        message = MIMEText(message_text)
        message['to'] = 'j.alon@aol.com'
        message['subject'] = subject_text  # Set subject from provided data
        
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        create_message = {'raw': encoded_message}

        try:
            sent_message = service.users().messages().send(userId='me', body=create_message).execute()
            return f'Sent message to {sent_message["id"]}'
        except HttpError as error:
            return f'An error occurred: {error}', 500


