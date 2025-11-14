import aiohttp
import ssl
import re
from loguru import logger


def create_ssl_context() -> ssl.SSLContext:
    """Tạo SSL context không verify certificate"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def build_auth_xml(email: str, password: str) -> str:
    """Tạo SOAP XML request cho authentication"""
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <context xmlns="urn:zimbra"/>
  </soap:Header>
  <soap:Body>
    <AuthRequest xmlns="urn:zimbraAccount">
      <account by="name">{email}</account>
      <password>{password}</password>
    </AuthRequest>
  </soap:Body>
</soap:Envelope>"""


def parse_auth_response(response_text: str) -> dict:
    """
    Parse SOAP response và extract authToken + resetPassword

    Returns:
        dict: {"authToken": str, "mustChangePassword": bool} hoặc {"error": str}
    """
    # Check SOAP Fault
    if "<soap:Fault" in response_text:
        return {"error": "Email hoặc mật khẩu không đúng"}

    # Compile regex patterns
    pattern_auth_token = re.compile(r"<authToken>(.*?)</authToken>", re.DOTALL)
    pattern_reset_password = re.compile(r"<resetPassword>(.*?)</resetPassword>")

    # Extract values
    auth_token_match = pattern_auth_token.search(response_text)
    reset_password_match = pattern_reset_password.search(response_text)

    if not auth_token_match:
        return {
            "success": False,
            "error": "Không thể lấy mã xác thực"
        }

    auth_token = auth_token_match.group(1).strip()
    is_reset_password = reset_password_match.group(1) if reset_password_match else "false"

    return {
        "success": True,
        "authToken": auth_token,
        "mustChangePassword": is_reset_password.lower() == "true"
    }


async def send_soap_request(url: str,xml_body: str,ssl_context: ssl.SSLContext,timeout: float = 30.0) -> tuple[int, str]:
    """
    Gửi SOAP request và trả về status code + response text

    Returns:
        tuple: (status_code, response_text)
    """
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
        async with session.post(
                url,
                data=xml_body.encode("utf-8"),
                headers={"Content-Type": "application/soap+xml; charset=utf-8"}
        ) as resp:
            return resp.status, await resp.text()


async def authenticate_aiohttp(host: str, email: str, password: str) -> dict:
    """
    Authenticate với Zimbra SOAP API

    Args:
        host: Domain của Zimbra server (vd: example.com)
        email: Email đăng nhập
        password: Password
        debug: Bật debug logs

    Returns:
        dict: {
            "success": bool,
            "authToken": str (nếu success=True),
            "mustChangePassword": bool (nếu success=True),
            "error": str (nếu success=False)
        }
    """
    url = f"https://mail.{host}/service/soap"
    xml_body = build_auth_xml(email, password)


    logger.info(f"[AUTH] URL: {url}")
    logger.info(f"[AUTH] XML:\n{xml_body}")

    try:
        ssl_context = create_ssl_context()
        status_code, response_text = await send_soap_request(url, xml_body, ssl_context)


        logger.info(f"[AUTH] Response Status: {status_code}")
        logger.info(f"[AUTH] Response:\n{response_text}\n")

        # Parse response
        result = parse_auth_response(response_text)

        if "error" in result:
            return {"success": False, "error": result["error"]}

        # Log thông tin
        logger.info(f"authToken: {result['authToken']}")
        logger.info(f"resetPassword: {result['mustChangePassword']}")

        return {
            "success": True,
            "authToken": result["authToken"],
            "mustChangePassword": result["mustChangePassword"]
        }

    except aiohttp.ClientError as e:
        logger.error(f"HTTP request failed: {e}")
        return {"success": False, "error": f"Network error: {str(e)}"}
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def build_change_password_xml(email: str, old_password: str, new_password: str, auth_token: str, must_change=True) -> str:
    """Tạo SOAP XML request cho change password"""
    if must_change:
        return f"""<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
          <soap:Body>
            <ChangePasswordRequest xmlns="urn:zimbraAccount">
              <account by="name">{email}</account>
              <oldPassword>{old_password}</oldPassword>
              <password>{new_password}</password>
              <authToken>{auth_token}</authToken>
            </ChangePasswordRequest>
          </soap:Body>
        </soap:Envelope>"""
    else:
        return f"""<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
          <soap:Header>
            <context xmlns="urn:zimbra">
              <authToken>{auth_token}</authToken>
            </context>
          </soap:Header>
          <soap:Body>
            <ChangePasswordRequest xmlns="urn:zimbraAccount">
              <account by="name">{email}</account>
              <oldPassword>{old_password}</oldPassword>
              <password>{new_password}</password>
            </ChangePasswordRequest>
          </soap:Body>
        </soap:Envelope>"""



def parse_change_password_response(response_text: str) -> dict:
    """
    Parse SOAP response cho change password

    Returns:
        dict: {"success": bool, "error": str (nếu failed)}
    """
    if "<soap:Fault" in response_text:
        fault_match = re.search(r'<soap:Text>([^<]+)</soap:Text>', response_text)
        error = fault_match.group(1) if fault_match else "Unknown error"
        return {"success": False, "error": error}

    return {"success": True}


async def change_password_with_auth_aiohttp(host: str,email: str,old_password: str,new_password: str,must_change=False) -> dict:
    """
    Đổi mật khẩu Zimbra (authenticate trước, sau đó change password)

    Args:
        host: Domain của Zimbra server
        email: Email đăng nhập
        old_password: Mật khẩu cũ
        new_password: Mật khẩu mới
        debug: Bật debug logs

    Returns:
        dict: {
            "success": bool,
            "message": str (nếu success=True),
            "error": str (nếu success=False),
            "body": str (response body, chỉ khi debug=True)
        }
    """
    # Step 1: Authenticate
    auth_result = await authenticate_aiohttp(host, email, old_password, debug=debug)
    if not auth_result["success"]:
        return {
            "success": False,
            "error": f"Auth failed: {auth_result.get('error')}"
        }

    auth_token = auth_result["authToken"]
    mustChangePassword = auth_result["mustChangePassword"]
    # Step 2: Change password với authToken
    url = f"https://mail.{host}/service/soap"
    xml_body = build_change_password_xml(email, old_password, new_password, auth_token,mustChangePassword)

    logger.infot(f"[CHANGE_PW] URL: {url}")
    logger.info(f"[CHANGE_PW] XML:\n{xml_body}")

    try:
        ssl_context = create_ssl_context()
        status_code, response_text = await send_soap_request(url, xml_body, ssl_context)

        logger.info(f"[CHANGE_PW] Response Status: {status_code}")
        logger.info(f"[CHANGE_PW] Response:\n{response_text}\n")

        # Parse response
        result = parse_change_password_response(response_text)

        if not result["success"]:
            response = {
                "success": False,
                "error": result["error"]
            }
            logger.debug(response_text)
            return response

        response = {
            "success": True,
            "message": "Đã thay đổi mật khẩu thành công"
        }
        logger.debug(response_text)

        logger.info(f"Password changed successfully for {email}")
        return response

    except aiohttp.ClientError as e:
        logger.error(f"HTTP request failed: {e}")
        return {"success": False, "error": f"Network error: {str(e)}"}
    except Exception as e:
        logger.error(f"Change password failed: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}