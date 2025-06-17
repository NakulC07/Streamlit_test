import streamlit as st
from msal import ConfidentialClientApplication
import requests
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Azure AD app credentials
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
TENANT_ID = os.getenv('TENANT_ID')
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["User.Read"]
REDIRECT_URI = "https://10.224.248.131:8507"  # Local redirect URI

# Kerberos-protected resource URL
KERBEROS_PROTECTED_URL = "https://hsdes-api.intel.com/rest/article/16027238568"

# Initialize MSAL Confidential Client Application
app = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

def get_login_url():
    """
    Generate the login URL for MSAL authentication.
    """
    return app.get_authorization_request_url(SCOPE, redirect_uri=REDIRECT_URI)

def acquire_token_by_authorization_code(auth_code):
    """
    Acquire an access token using the authorization code.
    """
    result = app.acquire_token_by_authorization_code(
        auth_code,
        scopes=SCOPE,
        redirect_uri=REDIRECT_URI
    )
    return result

def authenticate_with_kerberos():
    """
    Authenticate the user using Kerberos.
    """
    try:
        st.session_state["kerberos_auth"] = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
        st.success("Kerberos authentication successful!")
        # Assuming the Kerberos principal is available in the session or environment
        kerberos_user = os.getenv("USER") or os.getenv("USERNAME")  # Fetch the current user
        if kerberos_user:
            st.info(f"Authenticated as: {kerberos_user}")
        else:
            st.warning("Could not determine the authenticated Kerberos user.")
    except Exception as e:
        st.error(f"Kerberos authentication failed: {str(e)}")

def access_kerberos_protected_resource():
    """
    Access the Kerberos-protected resource.
    """
    if "kerberos_auth" not in st.session_state or st.session_state["kerberos_auth"] is None:
        st.error("You must authenticate with Kerberos first!")
        return

    try:
        response = requests.get(KERBEROS_PROTECTED_URL, auth=st.session_state["kerberos_auth"])
        if response.status_code == 200:
            st.success("Access to the protected resource successful!")
            st.json(response.json())
        else:
            st.error(f"Failed to access the resource. Status code: {response.status_code}")
            st.text(response.text)
    except Exception as e:
        st.error(f"An error occurred while accessing the resource: {str(e)}")

def main():
    st.title("Local Streamlit App with MSAL and Kerberos Authentication")

    # Parse query parameters
    query_params = st.experimental_get_query_params()
    auth_code = query_params.get('code', [None])[0]

    # Step 1: MSAL Authentication
    if 'access_token' not in st.session_state:
        if auth_code:
            result = acquire_token_by_authorization_code(auth_code)
            if "access_token" in result:
                st.session_state['access_token'] = result['access_token']
                st.success("Login successful!")

                # Display user information
                access_token = st.session_state['access_token']
                headers = {'Authorization': f'Bearer {access_token}'}
                user_info = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers).json()
                st.write("User Info:", user_info)

                # Step 2: Kerberos Authentication
                st.write("Kerberos Authentication")
                if st.button("Authenticate with Kerberos"):
                    authenticate_with_kerberos()

                # Step 3: Access Kerberos-Protected Resource
                st.write("Access Kerberos-Protected Resource")
                if st.button("Access Protected Resource"):
                    access_kerberos_protected_resource()

                # Logout button
                if st.button("Logout"):
                    del st.session_state['access_token']
                    st.success("Logged out successfully!")
        else:
            st.write("You are not logged in.")
            login_url = get_login_url()
            st.markdown(f"[Login here]({login_url})")
    else:
        st.write("You are already logged in.")
        st.write("Kerberos Authentication")
        if st.button("Authenticate with Kerberos"):
            authenticate_with_kerberos()

        st.write("Access Kerberos-Protected Resource")
        if st.button("Access Protected Resource"):
            access_kerberos_protected_resource()

if __name__ == "__main__":
    main()