from flask import Flask, render_template, request, redirect, session, jsonify
from msal import ConfidentialClientApplication
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
from dotenv import load_dotenv
import os
import requests
from flask_session import Session
import secrets
from hsd import HsdConnector
import base64
import keyring
import json
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
SCOPE = [
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/profile",
]
REDIRECT_URI = "https://bagapp1083.gar.corp.intel.com:5000/callback"  # Update with your Flask app's redirect URI

# Kerberos-protected resource URL
KERBEROS_PROTECTED_URL = "https://hsdes-api.intel.com/rest/article/16027238568"
KERBEROS_MAP_FILE = "kerberos_alias_map.json"

# Initialize MSAL Confidential Client Application
app_msal = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

def get_graph_profile(access_token):
    url = "https://graph.microsoft.com/v1.0/me"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()  # This is the user's full profile
    else:
        print("Graph API error:", response.text)
        return None

def get_kerberos_alias(email):
    if not os.path.exists(KERBEROS_MAP_FILE):
        return None
    with open(KERBEROS_MAP_FILE, "r") as f:
        mapping = json.load(f)
    return mapping.get(email)

def save_kerberos_alias(email, alias):
    if os.path.exists(KERBEROS_MAP_FILE):
        with open(KERBEROS_MAP_FILE, "r") as f:
            mapping = json.load(f)
    else:
        mapping = {}
    mapping[email] = alias
    with open(KERBEROS_MAP_FILE, "w") as f:
        json.dump(mapping, f)

@app.route('/')
def index():
    """
    Render the main page. Show session state if present.
    """
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
            #print(f"Result is : {result}")
            # Extract claims from the id_token
            user_claims = result.get("id_token_claims", {})
            #print(f"User claims are :{user_claims}")  # Shows all claims, including oid, sid, name, preferred_username, etc.

            # Save useful claims in session (customize as needed)
            session['user_data'] = {
                'access_token': result['access_token'],
                'logged_in': True,
                'kerberos_authenticated': False,
                'kerberos_user': None,
                'name': user_claims.get('name'),
                'oid': user_claims.get('oid'),
                'sid': user_claims.get('sid'),
                'idsid': user_claims.get('IDSID')
                #'upn': user_claims.get('upn'),
                #'acct': user_claims.get('acct'),
                #'acrs': user_claims.get('acrs'),
                #'given_name': user_claims.get('given_name'),
                #'login_hint': user_claims.get('login_hint'),
                #'preferred_username': user_claims.get('preferred_username'),
                #'vnet': user_claims.get('vnet')
            }
            
            profile = get_graph_profile(result['access_token'])
            #print("Full profile from Graph:", profile)
            # Optionally, store profile in session for later use:
            session['user_data']['profile'] = profile
            print(f"Session data : {session}")
            return redirect('/')
    return "Login failed", 400

@app.route('/kerberos-auth', methods=['POST'])
def kerberos_auth():
    """
    Authenticate the user using Kerberos and access the protected resource.
    Use the kerberos_user value from the session (set via alias input), not os.getenv().
    """
    try:
        user_data = session.get('user_data', {})
        kerberos_user = user_data.get('kerberos_user')
        if kerberos_user:
            print("Kerberos User:", kerberos_user)  # Debugging

            # Update session with Kerberos authentication details
            session['user_data']['kerberos_authenticated'] = True
            session['user_data']['kerberos_user'] = kerberos_user

            # Access the Kerberos-protected resource
            kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
            headers = {'Content-Type': 'application/json'}
            response = requests.get(KERBEROS_PROTECTED_URL, auth=kerberos_auth, headers=headers)

            if response.status_code == 200:
                resource_data = response.json()
                return jsonify({
                    "message": f"Authenticated as: {kerberos_user}",
                    "resource_data": resource_data
                }), 200
            else:
                app.logger.error(f"Kerberos resource access failed: {response.status_code} {response.text}")
                return jsonify({
                    "message": f"Authenticated as: {kerberos_user}",
                    "error": f"Failed to access the resource. Status code: {response.status_code}",
                    "details": response.text
                }), 400
        else:
            return jsonify({"message": "Kerberos user not set. Please provide your alias first."}), 400
    except Exception as e:
        app.logger.exception("Kerberos authentication failed")
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

@app.route('/hsd-data', methods=['GET'])
def hsd_data():
    """
    Endpoint to extract HSD data using the current Kerberos user from the session.
    """
    user_data = session.get('user_data')
    if not user_data or not user_data.get('kerberos_authenticated'):
        return jsonify({'error': 'Kerberos authentication required.'}), 401
    kerberos_user = user_data.get('kerberos_user')
    hsd_id = request.args.get('hsd_id', '16027238568')  # Default/test HSD ID
    fields = request.args.getlist('fields') or None
    connector = HsdConnector(kerberos_user=kerberos_user)
    try:
        data = connector.get_hsd(hsd_id, fields)
        return jsonify({'data': data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/kerberos-alias', methods=['GET', 'POST'])
def kerberos_alias():
    user_data = session.get('user_data', {})
    profile = user_data.get('profile', {})
    email = profile.get('mail') or profile.get('userPrincipalName')
    if not user_data.get('logged_in') or not email:
        return redirect('/login')
    if request.method == 'POST':
        alias = request.form.get('alias')
        if not alias:
            return "Alias required", 400
        save_kerberos_alias(email, alias)
        session['user_data']['kerberos_user'] = alias
        session['user_data']['kerberos_authenticated'] = True
        return redirect('/')
    # GET: show form if alias not set, else redirect
    alias = get_kerberos_alias(email)
    if alias:
        session['user_data']['kerberos_user'] = alias
        session['user_data']['kerberos_authenticated'] = True
        return redirect('/')
    return '''
        <form method="post">
            <label>Enter your Kerberos alias:</label>
            <input type="text" name="alias" required />
            <input type="submit" value="Save" />
        </form>
    '''

@app.route('/logout')
def logout():
    """
    Clear the session and redirect to the home page.
    """
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(host = "0.0.0.0", port = 5000, debug=True, ssl_context = ('cert.crt', 'key.pem'))