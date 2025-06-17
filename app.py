from flask import Flask, render_template, request, redirect, session, jsonify
from msal import ConfidentialClientApplication
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
from dotenv import load_dotenv
import os
import requests
from flask_session import Session
import secrets

# Load environment variables
load_dotenv()

app = Flask(__name__ , static_folder='static')
app.secret_key = os.getenv('secret_key')  # Secret key for session management
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Session(app)

# Azure AD app credentials
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
TENANT_ID = os.getenv('TENANT_ID')
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["User.Read"]
REDIRECT_URI = "http://localhost:5000/callback"  # Update with your Flask app's redirect URI

# Kerberos-protected resource URL
KERBEROS_PROTECTED_URL = "https://hsdes-api.intel.com/rest/article/16027238568"

# Initialize MSAL Confidential Client Application
app_msal = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

@app.route('/')
def index():
    """
    Render the main page.
    """
    print("Rendering index page. Session State:", session)  # Debugging
    user_data = session.get('user_data', {})
    logged_in = user_data.get('logged_in', False)
    kerberos_authenticated = user_data.get('kerberos_authenticated', False)
    kerberos_user = user_data.get('kerberos_user', None)
    return render_template(
        'index.html',
        logged_in=logged_in,
        kerberos_authenticated=kerberos_authenticated,
        kerberos_user=kerberos_user
    )

@app.route('/login')
def login():
    """
    Generate the MSAL login URL and redirect the user to it.
    """
    login_url = app_msal.get_authorization_request_url(SCOPE, redirect_uri=REDIRECT_URI)
    return redirect(login_url)

@app.route('/callback')
def callback():
    """
    Handle the OAuth 2.0 callback and acquire an access token.
    """
    auth_code = request.args.get('code')
    if auth_code:
        result = app_msal.acquire_token_by_authorization_code(
            auth_code,
            scopes=SCOPE,
            redirect_uri=REDIRECT_URI
        )
        if "access_token" in result:
            session['user_data'] = {
                'access_token': result['access_token'],
                'logged_in': True,
                'kerberos_authenticated': False,
                'kerberos_user': None
            }
            print("Access Token:", session['user_data']['access_token'])  # Debugging
            print("Session State after login:", session)  # Debugging
            return redirect('/')
    return "Login failed", 400

@app.route('/kerberos-auth', methods=['POST'])
def kerberos_auth():
    """
    Authenticate the user using Kerberos and access the protected resource.
    """
    print("Kerberos authentication endpoint triggered.")  # Debugging
    print("Session State: ", session)
    try:
        kerberos_user = os.getenv("USER") or os.getenv("USERNAME")
        if kerberos_user:
            print("Kerberos User:", kerberos_user)  # Debugging

            # Update session with Kerberos authentication details
            session['user_data']['kerberos_authenticated'] = True
            session['user_data']['kerberos_user'] = kerberos_user

            # Access the Kerberos-protected resource
            kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
            headers = {'Content-Type': 'application/json'}
            response = requests.get(KERBEROS_PROTECTED_URL, auth=kerberos_auth, headers=headers)

            print("Request Headers:", response.request.headers)  # Debugging
            print("Response Status Code:", response.status_code)  # Debugging
            print("Response Text:", response.text)  # Debugging
            
            if response.status_code == 200:
                print("Successfully accessed the Kerberos-protected resource.")  # Debugging
                resource_data = response.json()
                return jsonify({
                    "message": f"Authenticated as: {kerberos_user}",
                    "resource_data": resource_data
                }), 200
            else:
                print(f"Failed to access the resource. Status code: {response.status_code}")  # Debugging
                return jsonify({
                    "message": f"Authenticated as: {kerberos_user}",
                    "error": f"Failed to access the resource. Status code: {response.status_code}"
                }), 400
        else:
            return jsonify({"message": "Could not determine the authenticated Kerberos user."}), 400
    except Exception as e:
        print("Kerberos Authentication Error:", str(e))  # Debugging
        return jsonify({"message": f"Kerberos authentication failed: {str(e)}"}), 500

@app.route('/access-resource', methods=['POST'])
def access_resource():
    """
    Access the Kerberos-protected resource.
    """
    print("Accessing Kerberos-protected resource...")
    print("Session State: ", session)
    
    user_data = session.get('user_data')
    if not user_data or not user_data.get('kerberos_authenticated'):
        return jsonify({"message": "You must authenticate with Kerberos first!"}), 400

    try:
        # Recreate the HTTPKerberosAuth object when needed
        kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
        response = requests.get(KERBEROS_PROTECTED_URL, auth=kerberos_auth)
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"message": f"Failed to access the resource. Status code: {response.status_code}"}), 400
    except Exception as e:
        return jsonify({"message": f"An error occurred while accessing the resource: {str(e)}"}), 500    

if __name__ == '__main__':
    app.run(host = "0.0.0.0", port = 5000, debug=True)