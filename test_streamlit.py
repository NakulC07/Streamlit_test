import streamlit as st
from msal import ConfidentialClientApplication
import requests
from dotenv import load_dotenv
import os

load_dotenv()

# Azure AD app credentials
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
TENANT_ID = os.getenv('TENANT_ID')
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_PATH = "http://localhost:8501/getAToken"  # Used for forming an absolute URL to your redirect URI
SCOPE = ["User.Read"]  # Add other scopes as needed

# Initialize MSAL Confidential Client Application
app = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

# Function to get login URL
def get_login_url():
    return app.get_authorization_request_url(SCOPE, redirect_uri="http://localhost:8501")

# Function to acquire token by authorization code
def acquire_token_by_authorization_code(auth_code):
    result = app.acquire_token_by_authorization_code(
        auth_code,
        scopes=SCOPE,
        redirect_uri="http://localhost:8501"
    )
    return result

# Streamlit app
def main():
    st.title("Streamlit App with MSAL Authentication")

    # Parse query parameters
    query_params = st.experimental_get_query_params()
    auth_code = query_params.get('code', [None])[0]

    # Check if user is logged in
    if 'access_token' not in st.session_state:
        if auth_code:
            result = acquire_token_by_authorization_code(auth_code)
            if "access_token" in result:
                st.session_state['access_token'] = result['access_token']
                st.success("Login successful!")
            else:
                st.error("Login failed. Please try again.")
                st.write(result)
        else:
            st.write("You are not logged in.")
            login_url = get_login_url()
            st.markdown(f"[Login here]({login_url})")
    else:
        st.write("You are logged in!")
        access_token = st.session_state['access_token']
        headers = {'Authorization': f'Bearer {access_token}'}
        user_info = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers).json()
        st.write("User Info:", user_info)

        # Logout button
        if st.button("Logout"):
            del st.session_state['access_token']
            st.success("Logged out successfully!")

if __name__ == "__main__":
    main()
