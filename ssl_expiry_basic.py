#!/usr/bin/python3
#
# Description: A simple script to test the expiration of SSL certficates.
# Author: Devin Miller
#
# Sources / Credits:
#   Author: Lucas Roelser <roesler.lucas@gmail.com>
#   Modified from https://serverlesscode.com/post/ssl-expiration-alerts-with-lambda/

import datetime
import socket
import ssl

def test_host(hostname: str, buffer_days: int=30) -> str:
    """Return test message for hostname cert expiration."""

    def ssl_expiry_datetime(hostname: str) -> datetime.datetime:
        """Parses the datetime from the SSL certificate."""
        conn = ssl.create_default_context().wrap_socket(socket.socket(
            socket.AF_INET), server_hostname=hostname)
        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        return datetime.datetime.strptime(ssl_info['notAfter'], r'%b %d %H:%M:%S %Y %Z')

    try:
        expires = ssl_expiry_datetime(hostname)
        will_expire_in = expires - datetime.datetime.utcnow()
    except (ssl.CertificateError, ssl.SSLError) as e:
        return f'{hostname} cert error {e}'
    except socket.timeout as e:
        return f'{hostname} could not connect'
    else:
        if will_expire_in < datetime.timedelta(days=0):
            return f'{hostname} cert is expired!'
        elif will_expire_in < datetime.timedelta(days=buffer_days):
            return f'{hostname} cert will expire in {will_expire_in}'
        else:
            return f'{hostname} cert is fine'

HOSTS = ("google.com", "facebook.com", "expired.badssl.com", "wrong.host.badssl.com")
for (idx, host) in enumerate(HOSTS, start=1):
    print("{}: {}\n".format(idx, test_host(host, buffer_days=60)))
