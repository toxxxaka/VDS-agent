"""Small network utilities for the authenticated WebUI.

Targets must resolve to a public address; browser input cannot be used to reach
localhost, RFC1918, link-local or other private server networks.
"""
import ipaddress
import json
import secrets
import socket
import ssl
import string
import urllib.parse
import urllib.request
from datetime import datetime, timezone

SAFE = string.ascii_letters + string.digits + '!_)(*&^%$#@/+-\\`":?><'


def password():
    return '-'.join(''.join(secrets.choice(SAFE) for _ in range(n)) for n in (5, 6, 7))


def host(value):
    v = str(value).strip().lower().split('://')[-1].split('/')[0]
    if not v or len(v) > 253 or any(c not in string.ascii_lowercase + string.digits + '.:-' for c in v):
        raise ValueError('invalid host')
    name, _, raw_port = v.rpartition(':')
    if raw_port and name:
        if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
            raise ValueError('invalid port')
        v = f'{name}:{int(raw_port)}'
    return v


def _public_target(value):
    target = host(value)
    name, sep, raw_port = target.rpartition(':')
    hostname = name if sep else target
    port = int(raw_port) if sep else 443
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError('DNS lookup failed') from exc
    public = sorted(address for address in addresses if ipaddress.ip_address(address).is_global)
    if not public:
        raise ValueError('host must resolve to a public address')
    return hostname, port, public[0]


def ssl_check(value):
    name, port, address = _public_target(value)
    ctx = ssl.create_default_context()
    with socket.create_connection((address, port), 5) as raw:
        with ctx.wrap_socket(raw, server_hostname=name) as c:
            cert = c.getpeercert()
            exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            return {'host': name, 'address': address, 'port': port, 'protocol': c.version(), 'cipher': c.cipher()[0], 'issuer': dict(x[0] for x in cert.get('issuer', [])).get('commonName', '—'), 'expires_at': exp.isoformat(), 'days_left': int((exp-datetime.now(timezone.utc)).total_seconds()//86400)}


def checkhost(value, kind='http'):
    name, port, _address = _public_target(value)
    kind = kind if kind in {'http', 'ping', 'tcp', 'dns'} else 'http'
    target = f'{name}:{port}' if port != 443 else name
    url = 'https://check-host.net/check-' + kind + '?' + urllib.parse.urlencode({'host': target, 'max_nodes': '5'})
    req = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': 'Monitoringbot/4'})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def cheburcheck_url(value):
    name, port, _address = _public_target(value)
    target = f'{name}:{port}' if port != 443 else name
    return 'https://cheburcheck.ru/?q=' + urllib.parse.quote(target, safe='')
