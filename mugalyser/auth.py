"""
A simple authentication framework for injecting authentication into requests.
"""

from datetime import datetime, timedelta

import requests

class ProOAuthProvider:
    """
        Implements "Server auth with user credentials", as described at
        https://www.meetup.com/meetup_api/auth/#oauth2servercredentials
    """

    authorize_uri = "https://secure.meetup.com/oauth2/authorize"
    access_uri = "https://secure.meetup.com/oauth2/access"
    sessions_uri = "https://api.meetup.com/sessions"

    def __init__(self, consumer_id, consumer_secret, consumer_redirect_uri, user_email, user_password):
        self._consumer_id = consumer_id
        self._consumer_secret = consumer_secret
        self._consumer_redirect_uri = consumer_redirect_uri
        self._user_email = user_email
        self._user_password = user_password

        # This gets set by a successful authentication.
        self._access_token = None
        self._refresh_token = None
        self._expiry = None

    def __call__(self, request):
        token = self._get_token()
        request.headers["Authorization"] = "Bearer " + token

    def _get_token(self):
        if self._access_token is None:
            self._authenticate()
        if datetime.now() >= self._expiry:
            self._refresh_token()
        return self._access_token

    def _authenticate(self):
        response = requests.get(
            self.authorize_uri,
            params={
                "client_id": self._consumer_id,
                "response_type": "anonymous_code",
                "redirect_uri": self._consumer_redirect_uri,  # This is ignored, but must be supplied.
            },
            headers={"accept": "application/json"},
        )
        code = response.json()["code"]

        response = requests.post(
            self.access_uri,
            data={
                "client_id": self._consumer_id,
                "client_secret": self._consumer_secret,
                "grant_type": "anonymous_code",
                "redirect_uri": self._consumer_redirect_uri,  # This is ignored, but must be supplied.
                "code": code,
            },
            headers={"accept": "application/json"},
        )
        response_data = response.json()
        consumer_access_token = response_data["access_token"]

        # TODO: Set expiry datetime, so can refresh when required.
        response = requests.post(
            self.sessions_uri,
            data={"email": self._user_email, "password": self._user_password,},
            headers={
                "Authorization": f"Bearer {consumer_access_token}",
                "accept": "application/json",
            },
        )
        response_data = response.json()
        print(response_data)    # FIXME

        account_access_token = response_data["oauth_token"]
        account_refresh_token = response_data["refresh_token"]
        expiry = (
            datetime.now() 
            + timedelta(seconds=response_data["expires_in"]) 
            - timedelta(seconds=10) # We'll refresh the token a little earlier than necessary, just in case.
        )
        self._access_token = account_access_token
        self._refresh_token = account_refresh_token
        self._expiry = expiry

    def refresh_token(self):
        response = requests.post(
            self.access_uri,
            data={
                "client_id": self._consumer_id,
                "client_secret": self._consumer_secret,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            headers={"accept": "application/json",},
        )
        response_data = response.json()
        access_token = response_data["access_token"]
        refresh_token = response_data["refresh_token"]
        expiry = (
            datetime.now() 
            + timedelta(seconds=response_data["expires_in"]) 
            - timedelta(seconds=10) # We'll refresh the token a little earlier than necessary, just in case.
        )

        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expiry = expiry