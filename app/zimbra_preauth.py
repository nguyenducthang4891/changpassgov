import hmac
import hashlib
import time



def compute_preauth_token(account, preauth_key, timestamp=None, expires=0):
    """
    Compute Zimbra preauth token theo spec của Zimbra

    Formula: HMAC-SHA1(account|by|expires|timestamp, preauth_key)

    Args:
        account: Full email address
        preauth_key: zimbraPreAuthKey from domain
        timestamp: Unix timestamp in milliseconds (default: current time)
        expires: Expiration in milliseconds (0 = no expiry)

    Returns:
        (preauth_token, timestamp)
    """
    if timestamp is None:
        timestamp = int(time.time() * 1000)  # Current time in ms

    by = "name"

    # Message format: account|by|expires|timestamp
    message = f"{account}|{by}|{expires}|{timestamp}"

    # Compute HMAC-SHA1
    preauth_token = hmac.new(
        preauth_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha1
    ).hexdigest()

    return preauth_token, timestamp