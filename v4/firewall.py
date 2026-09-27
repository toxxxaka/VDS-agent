"""Client for the constrained firewall bridge; no firewall command runs in WebUI."""
from __future__ import annotations
import ipaddress, json, socket
SOCKET = '/run/monitorbot/infrastructure.sock'
PROFILES = {
    'none': 'Remove only Monitoring-managed filtering; preserve Docker and existing nftables tables.',
    'standard': 'Permit established traffic, loopback, ICMP, SSH, HTTP and HTTPS; deny other new inbound traffic.',
    'hard': 'Permit SSH only for the trusted address. WebUI is optional and restricted to that address.',
}
def _bridge(payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.settimeout(20); c.connect(SOCKET); c.sendall((json.dumps(payload)+'\n').encode()); data=b''
        while b'\n' not in data:
            part=c.recv(65536)
            if not part: break
            data += part
    response=json.loads(data.decode())
    if not response.get('ok'): raise RuntimeError(response.get('error','firewall bridge failed'))
    return response
def state(): return _bridge({'action':'firewall_state'})
def preview(profile, source_ip, keep_webui):
    if profile not in PROFILES: raise ValueError('unknown firewall profile')
    ipaddress.ip_address(source_ip)
    return _bridge({'action':'firewall_preview','profile':profile,'source_ip':source_ip,'keep_webui':bool(keep_webui)})
def request_apply(profile, source_ip, keep_webui):
    return _bridge({'action':'firewall_request','profile':profile,'source_ip':source_ip,'keep_webui':bool(keep_webui)})
def confirm(token):
    if not isinstance(token,str) or len(token) < 20: raise ValueError('invalid confirmation')
    return _bridge({'action':'firewall_confirm','token':token})
def rollback(): return _bridge({'action':'firewall_rollback'})
