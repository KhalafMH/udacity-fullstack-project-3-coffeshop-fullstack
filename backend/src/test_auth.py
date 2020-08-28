import json
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from jose import jwt, JWSError, JWTError

from auth.auth import check_permissions, get_token_auth_header, AuthError, verify_decode_jwt, requires_auth

JWT_WITH_MANAGER_ROLE_PERMISSIONS = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxEN0w3cnc5cEFBaEpnWjRXWUdSOCJ9.eyJpc3MiOiJodHRwczovL2Rldi03dnN4OGI1Zi51cy5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWYxY2VhNzAyOGRkYmEwMDM3NDNhYTI5IiwiYXVkIjoiZGV2IiwiaWF0IjoxNTk4NDk3NTAzLCJleHAiOjE1OTg1MDQ3MDMsImF6cCI6IlFVdllNVG5xWnRMNDQ3dVlPdkpxc2dYSHA1Y0ZpOHh1Iiwic2NvcGUiOiIiLCJwZXJtaXNzaW9ucyI6WyJkZWxldGU6ZHJpbmtzIiwiZ2V0OmRyaW5rcy1kZXRhaWwiLCJwYXRjaDpkcmlua3MiLCJwb3N0OmRyaW5rcyJdfQ.epCb8Av7NFl491e3gQ-gsrh3_icfC4eMIrea37jKIvp_4TpcpntTt_3StIudcwQNjaKrzjNnfRzVTbPRPSWMeqotOsQEr_45fCrJ7G7tNmIZpCOQ5Ym1YK2NjHFMy6OsfjqG3KKyEjO8ThSnR9ra7Xttpw4E0WSB4q9bfJniJjJwY_6jeZ86pVwnQY2sLcm4YyrK0mNTLzjPrCF0nhp0D-wgw12aWBcgm7IFy-aPrScu1HAaFUXxyacGmnm1DpXvTAOgId1VZFSs55-ojFE9yhiVGMNA6Bjct47djQgoP8SNlP6Ql6iqF7AuL37i1XmM01YfyEauzD616YFM4vu9Lw'
original_jwt_decode = jwt.decode


def jwt_decode_mock(token, algorithms, audience, key):
    if token == JWT_WITH_MANAGER_ROLE_PERMISSIONS and algorithms == ['RS256'] and audience == 'dev':
        if key == json.loads(
                '{"alg": "RS256", "kty": "RSA", "use": "sig", "n": "uEgk3LAHhSpsUiUCtZKFMm1QZy5gX8nMly0tlHCMoD_gDc2lU_iBxoUismOpxiBKGcNvMlP46JRUAeC0uYhHQS6VsB6DuKRNc5be9TXWDjxZ3wVlBY3OU3agsvEpVJosPZ1ODHBSygmJXxDRZvogvghZSCjg3LCEWxEkYkc2g8dvwTY0wTv6Jc8Pi3A7xfH1jKvTeCp6HOYkIkYAWI-ooKoPSdU_r1_zITwPoDWjaNTvvAcLslZiP0e-71-XnEmJkc0rWKv_OR5CrdVhIp0BM-KGRblrsh0ovmS0KAArU4aSMA5_Fb9zEO8XUxDP93LFkWi93aYx6KPoDE3B65QCAw", "e": "AQAB", "kid": "lD7L7rw9pAAhJgZ4WYGR8", "x5t": "PtBmr9pJrg7dXuUxBX2kDyaBStA", "x5c": ["MIIDDTCCAfWgAwIBAgIJaRR3AVeGlGgZMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi03dnN4OGI1Zi51cy5hdXRoMC5jb20wHhcNMjAwNzI2MDIyMzU2WhcNMzQwNDA0MDIyMzU2WjAkMSIwIAYDVQQDExlkZXYtN3ZzeDhiNWYudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuEgk3LAHhSpsUiUCtZKFMm1QZy5gX8nMly0tlHCMoD/gDc2lU/iBxoUismOpxiBKGcNvMlP46JRUAeC0uYhHQS6VsB6DuKRNc5be9TXWDjxZ3wVlBY3OU3agsvEpVJosPZ1ODHBSygmJXxDRZvogvghZSCjg3LCEWxEkYkc2g8dvwTY0wTv6Jc8Pi3A7xfH1jKvTeCp6HOYkIkYAWI+ooKoPSdU/r1/zITwPoDWjaNTvvAcLslZiP0e+71+XnEmJkc0rWKv/OR5CrdVhIp0BM+KGRblrsh0ovmS0KAArU4aSMA5/Fb9zEO8XUxDP93LFkWi93aYx6KPoDE3B65QCAwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSGQcuwZ0XEVF6ogtxiVr5voJkReTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKFMIHs5CBDrgIGDyu9Ta6RtA5TzfqhG4VOIEJ4p9worMGg+JrBKOiLbpB7umxp/rYEwIkUDlYJYIa89NFnfDQNldY939DNoQHTrTPCHbIVCUxm/DcY/AVfVJb/ntp48pg/ujDxNezxbJTaybdFJfr39vCdjMS8MLSuWwIem7qPXMcxTfbh80dNzUu2L2nTo0bxyvyBWtXjYnbCmZAYNshy+I1xlSVidr84AN+jVSymtsPWAUoeBWWaeGSxjNSWzLMYIqGi8v1DHtpIwC3J8jqL7R7q5sjoLiW/onhzPeJapMzsYgynHsVST4/S3A7utybn5m/DAPreb7L+1GnKF/mk="]}'):
            return json.loads(
                '{"iss": "https://dev-7vsx8b5f.us.auth0.com/", "sub": "auth0|5f1cea7028ddba003743aa29", "aud": "dev", "iat": 1598497503, "exp": 1598504703, "azp": "QUvYMTnqZtL447uYOvJqsgXHp5cFi8xu", "scope": "", "permissions": ["delete:drinks", "get:drinks-detail", "patch:drinks", "post:drinks"]}')
        if key == json.loads(
                '{"alg": "RS256", "kty": "RSA", "use": "sig", "n": "wZt3uxqsGgMHgHCz7mxZEPXIhjzWHusZYxUAmN3AWcWIukplkoM5ojxJpmUVeIua46QA-h0s5ciUjE8iIvkMU-RnBQZBn1X_jlyR66pFCEocLuo8AOIxnQHw7qFJVaT4n1cTnhYr9MZHgZICERIQRLdsaAZXD-scYCwCEV4W0eET-IQ95BQ3gYbrg12KjsUeOMHwbDEGVkX19K-O1beSGaR946j5NZasp0GPx-QFX1Rf-1G83jHBLhCKCDt6prwtfAbnv6vb2Ya0YLtq9CyFS7uAuHOySsfJ82HAbABmvFTrVnCa7tx5WtXCL62j-yWiek-yzFKixwid_2MNxzPbmw", "e": "AQAB", "kid": "WMrOKOmPctihL2zOmJaTB", "x5t": "0caCo2GZejAdxWYsOv95bqMg-Js", "x5c": ["MIIDDTCCAfWgAwIBAgIJIyqWzeq95nHkMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi03dnN4OGI1Zi51cy5hdXRoMC5jb20wHhcNMjAwNzI2MDIyMzU2WhcNMzQwNDA0MDIyMzU2WjAkMSIwIAYDVQQDExlkZXYtN3ZzeDhiNWYudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwZt3uxqsGgMHgHCz7mxZEPXIhjzWHusZYxUAmN3AWcWIukplkoM5ojxJpmUVeIua46QA+h0s5ciUjE8iIvkMU+RnBQZBn1X/jlyR66pFCEocLuo8AOIxnQHw7qFJVaT4n1cTnhYr9MZHgZICERIQRLdsaAZXD+scYCwCEV4W0eET+IQ95BQ3gYbrg12KjsUeOMHwbDEGVkX19K+O1beSGaR946j5NZasp0GPx+QFX1Rf+1G83jHBLhCKCDt6prwtfAbnv6vb2Ya0YLtq9CyFS7uAuHOySsfJ82HAbABmvFTrVnCa7tx5WtXCL62j+yWiek+yzFKixwid/2MNxzPbmwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRwbfh1Upn18b2L9eT6nv6NDsLS2DAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBADan7ilnUlEEL0KfKzPFy6cgUexxAL11UK5vyw3DWDPpVRSvN3KZ/zNfiknNpJ44qJ5YrblsCqtIMcszMQf0oUOMsIQsSvKaQVe8UL22uQSIvEvwKCVmiNzWJCI+8GDKrdU/Wv4Y86p9WGQDB8VP30buCL3RyEUmw68tpTE39yllLfencMIoMIENMhuUrZozA2jQGc8myvGounhmEG5pfy15xk+XyQYnEXCxSeqAbC1lmiTvT9na+sJcbUqRVyQnX0imgn2PnNO+yLduw2480JkobrZVzgWg18/uSy+I4Xz8K+81KMeGK6LH1s00vH7q70xfhiaat3qwp+qVGvBb+5c="]}'):
            raise JWTError(JWSError('Signature verification failed.'))
    return original_jwt_decode(token, algorithms=algorithms, audience=audience, key=key)


class AuthTest(unittest.TestCase):
    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_check_permissions_fails_when_permission_is_not_included_in_payload(self):
        payload = {
            "permissions": []
        }
        permissions = 'get:drinks-detail'
        with self.assertRaises(ValueError):
            check_permissions(permissions, payload)

    def test_check_permissions_succeeds_when_permission_is_included_in_payload(self):
        payload = {
            "permissions": [
                'get:drinks-detail'
            ]
        }
        permissions = 'get:drinks-detail'
        result = check_permissions(permissions, payload)
        self.assertTrue(result)

    def test_get_token_auth_header_returns_the_token(self):
        request_mock = MagicMock()
        request_mock.headers = {'Authorization': f'Bearer {JWT_WITH_MANAGER_ROLE_PERMISSIONS}'}
        with patch('auth.auth.request', request_mock):
            token = get_token_auth_header()
            self.assertEqual(token, JWT_WITH_MANAGER_ROLE_PERMISSIONS)

    def test_get_token_auth_header_fails_when_token_not_present(self):
        request_mock = MagicMock()
        request_mock.headers = {}
        with patch('auth.auth.request', request_mock):
            with self.assertRaises(AuthError):
                get_token_auth_header()

    def test_verify_decode_jwt(self):
        mock = MagicMock(side_effect=jwt_decode_mock)
        with patch('auth.auth.jwt.decode', mock):
            result = verify_decode_jwt(JWT_WITH_MANAGER_ROLE_PERMISSIONS)
            self.assertIn('get:drinks-detail', result['permissions'])

    def test_requires_auth_annotation_passes_when_the_request_has_the_required_permissions(self):
        decode_mock = MagicMock(side_effect=jwt_decode_mock)
        request_mock = MagicMock()
        request_mock.headers = {'Authorization': f'Bearer {JWT_WITH_MANAGER_ROLE_PERMISSIONS}'}

        with patch('auth.auth.jwt.decode', decode_mock):
            with patch('auth.auth.request', request_mock):
                @requires_auth('get:drinks-detail')
                def test_function(token_payload):
                    if 'get:drinks-detail' in token_payload['permissions']:
                        return 'passes'
                    else:
                        return 'fails'

                result = test_function()
                self.assertEqual('passes', result)

    def test_requires_auth_annotation_fails_when_the_request_does_not_have_the_required_permissions(self):
        decode_mock = MagicMock(side_effect=jwt_decode_mock)
        request_mock = MagicMock()
        request_mock.headers = {}

        with patch('auth.auth.jwt.decode', decode_mock):
            with patch('auth.auth.request', request_mock):
                @requires_auth('get:drinks-detail')
                def test_function(token_payload):
                    if 'get:drinks-detail' in token_payload['permissions']:
                        return 'passes'
                    else:
                        return 'fails'

                with self.assertRaises(AuthError):
                    test_function()
                    self.fail("Shouldn't reach here")
