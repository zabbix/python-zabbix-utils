import ssl
from zabbix_utils import ZabbixSender

# Try importing sslpsk3, fall back to sslpsk2 if not available
try:
    import sslpsk3 as sslpsk
except ImportError:
    # Import sslpsk2 if sslpsk3 is not available
    import sslpsk2 as sslpsk


# PSK wrapper function for SSL connection
def psk_wrapper(sock, tls):
    psk = None
    psk_identity = tls.get('tlspskidentity')
    psk_file = tls.get('tlspskfile')

    # Read PSK from file if specified
    if psk_file:
        with open(psk_file, encoding='utf-8') as f:
            psk = f.read()

    # Check if both PSK and PSK identity are available
    if psk and psk_identity:
        return sslpsk.wrap_socket(
            sock,
            ssl_version=ssl.PROTOCOL_TLSv1_2,
            ciphers='ECDHE-PSK-AES128-CBC-SHA256',
            psk=(psk, psk_identity)
        )

    # Return original socket if PSK or PSK identity is missing
    return sock


# Create a ZabbixSender instance with PSK support
sender = ZabbixSender(use_config=True, socket_wrapper=psk_wrapper)

# Send a value to a Zabbix server/proxy with specified parameters
# Parameters: (host, key, value, clock, ns)
resp = sender.send_value('host', 'item.key', 'value', 1695713666, 30)

# Check if the value sending was successful
if resp.failed == 0:
    # Print a success message along with the response time
    print(f"Value sent successfully in {resp.time}")
else:
    # Print a failure message
    print("Failed to send value")
