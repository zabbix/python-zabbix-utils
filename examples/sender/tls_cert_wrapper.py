import ssl
from zabbix_utils import ZabbixSender

# Zabbix server details
ZABBIX_SERVER = "zabbix-server.example.com"
ZABBIX_PORT = 10051

# Path to the CA bundle file for verifying the server's certificate
SERT_PATH = 'path/to/cabundle.pem'


# Define a function for wrapping the socket with TLS
def tls_wrapper(sock, *args, **kwargs):
    # Create an SSL context for TLS client
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Load the CA bundle file for server certificate verification
    context.load_verify_locations(SERT_PATH)

    # Wrap the socket with TLS using the created context
    return context.wrap_socket(sock, server_hostname=ZABBIX_SERVER)


# Create an instance of ZabbixSender with TLS configuration
sender = ZabbixSender(
    server=ZABBIX_SERVER,
    port=ZABBIX_PORT,
    # Use the defined tls_wrapper function for socket wrapping
    socket_wrapper=tls_wrapper
)

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
