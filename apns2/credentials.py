import time
import ssl
from typing import Optional

import httpx
import jwt

DEFAULT_TOKEN_LIFETIME = 2700
DEFAULT_TOKEN_ENCRYPTION_ALGORITHM = 'ES256'


# Abstract Base class. This should not be instantiated directly.
class Credentials(object):
    def __init__(self, ssl_context: Optional[ssl.SSLContext] = None) -> None:
        super().__init__()
        self.__ssl_context = ssl_context

    # Creates a connection with the credentials, if available or necessary.
    def create_connection(
        self, server: str, port: int, proto: Optional[str],
        proxy_host: Optional[str] = None, proxy_port: Optional[int] = None
    ) -> httpx.Client:
        # self.__ssl_context may be none, and that's fine.
        proxies = None
        if proxy_host and proxy_port:
            proxies = {
                'http://': f'http://{proxy_host}:{proxy_port}',
                'https://': f'http://{proxy_host}:{proxy_port}'
            }
        
        return httpx.Client(
            http2=True,
            verify=self.__ssl_context,
            proxies=proxies,
            headers={'accept': 'application/json'}
        )

    def get_authorization_header(self, topic: Optional[str]) -> Optional[str]:
        return None


# Credentials subclass for certificate authentication
class CertificateCredentials(Credentials):
    def __init__(
        self, cert_file: Optional[str] = None,
        password: Optional[str] = None,
        cert_chain: Optional[str] = None
    ) -> None:
        ssl_context = ssl.create_default_context()
        if cert_file:
            try:
                ssl_context.load_cert_file(cert_file, password=password)
                if cert_chain:
                    ssl_context.load_verify_locations(cert_chain)
            except ssl.SSLError as e:
                raise ValueError(f"Failed to load certificate: {e}")
        super(CertificateCredentials, self).__init__(ssl_context)


# Credentials subclass for JWT token based authentication
class TokenCredentials(Credentials):
    def __init__(
        self,
        auth_key_path: str,
        auth_key_id: str,
        team_id: str,
        encryption_algorithm: str = DEFAULT_TOKEN_ENCRYPTION_ALGORITHM,
        token_lifetime: int = DEFAULT_TOKEN_LIFETIME
    ) -> None:
        self.__auth_key = self._get_signing_key(auth_key_path)
        self.__auth_key_id = auth_key_id
        self.__team_id = team_id
        self.__encryption_algorithm = encryption_algorithm
        self.__token_lifetime = token_lifetime

        self.__jwt_token = None  # type: Optional[tuple[float, str]]

        # Use the default constructor because we don't have an SSL context
        super(TokenCredentials, self).__init__()

    def get_authorization_header(self, topic: Optional[str]) -> str:
        token = self._get_or_create_topic_token()
        return 'bearer %s' % token

    def _is_expired_token(self, issue_date: float) -> bool:
        return time.time() > issue_date + self.__token_lifetime

    @staticmethod
    def _get_signing_key(key_path: str) -> str:
        secret = ''
        if key_path:
            with open(key_path) as f:
                secret = f.read()
        return secret

    def _get_or_create_topic_token(self) -> str:
        if (
            self.__jwt_token is None or
            self._is_expired_token(self.__jwt_token[0])
        ):
            issue_date = time.time()
            token = jwt.encode(
                {
                    'iss': self.__team_id,
                    'iat': issue_date
                },
                self.__auth_key,
                algorithm=self.__encryption_algorithm,
                headers={
                    'kid': self.__auth_key_id,
                }
            )
            # In PyJWT >= 2.0.0 jwt.encode returns string instead of bytes
            if not isinstance(token, str):
                token = token.decode('ascii')
            self.__jwt_token = (issue_date, token)

        return self.__jwt_token[1]
