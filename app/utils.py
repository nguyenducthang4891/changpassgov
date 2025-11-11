import os
import re
import asyncio
import ssl

import aiohttp
from lxml import etree
import httpx
import logging

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Lấy IP của client"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def extract_domain(email):
    """Trích xuất domain từ email"""
    match = re.match(r'^[^@]+@(.+)$', email)
    if match:
        return match.group(1)
    return None


async def call_soap_api(host, email, old_password, new_password):
    """
    Gọi SOAP API để đổi mật khẩu
    """
    soap_url = f"https://mail.{host}/soap/api"
    logger.info(f"Calling SOAP API: {soap_url} for email: {email}")

    # SOAP envelope template
    soap_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:urn="urn:zimbraAccount">
    <soap:Header>
        <context xmlns="urn:zimbra">
            <userAgent name="Django-PasswordChange" version="1.0"/>
        </context>
    </soap:Header>
    <soap:Body>
        <urn:ChangePasswordRequest>
            <urn:account by="name">{email}</urn:account>
            <urn:oldPassword>{old_password}</urn:oldPassword>
            <urn:password>{new_password}</urn:password>
        </urn:ChangePasswordRequest>
    </soap:Body>
</soap:Envelope>"""

    headers = {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        'SOAPAction': 'urn:zimbraAccount#ChangePasswordRequest'
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                    soap_url,
                    data=soap_body,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False  # Trong production nên set True
            ) as response:
                response_text = await response.text()
                logger.debug(f"SOAP response status: {response.status}")

                if response.status == 200:
                    try:
                        root = etree.fromstring(response_text.encode('utf-8'))
                        fault = root.find('.//{http://www.w3.org/2003/05/soap-envelope}Fault')
                        if fault:
                            fault_string = fault.find(
                                './/{http://www.w3.org/2003/05/soap-envelope}Reason/{http://www.w3.org/2003/05/soap-envelope}Text')
                            error_msg = fault_string.text if fault_string is not None else "Lỗi không xác định từ server"
                            logger.error(f"SOAP fault for {email}: {error_msg}")
                            return {
                                'success': False,
                                'error': error_msg
                            }

                        logger.info(f"Password changed successfully for {email}")
                        return {
                            'success': True,
                            'message': 'Đổi mật khẩu thành công'
                        }
                    except etree.XMLSyntaxError as e:
                        logger.error(f"XML parse error for {email}: {str(e)}")
                        return {
                            'success': False,
                            'error': f'Phản hồi không hợp lệ: {str(e)}'
                        }
                else:
                    logger.error(f"HTTP error {response.status} for {email}")
                    return {
                        'success': False,
                        'error': f'Lỗi HTTP: {response.status}'
                    }

    except asyncio.TimeoutError:
        logger.error(f"Timeout error for {email} at {soap_url}")
        return {
            'success': False,
            'error': 'Timeout - Server không phản hồi'
        }
    except aiohttp.ClientError as e:
        logger.error(f"Connection error for {email}: {str(e)}")
        return {
            'success': False,
            'error': f'Lỗi kết nối: {str(e)}'
        }
    except Exception as e:
        logger.exception(f"Unexpected error for {email}: {str(e)}")
        return {
            'success': False,
            'error': f'Lỗi không xác định: {str(e)}'
        }


async def authenticate(host: str, email: str, password: str) -> dict:
    """
    Authenticate và lấy authToken
    """
    url = f"https://mail.{host}/service/soap"

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
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

    print(f"[AUTH] URL: {url}")
    print(f"[AUTH] XML:\n{xml}")

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with httpx.AsyncClient(verify=ssl_context, timeout=30.0) as client:
        resp = await client.post(
            url,
            content=xml.encode("utf-8"),
            headers={"Content-Type": "application/soap+xml; charset=utf-8"}
        )

        print(f"[AUTH] Response Status: {resp.status_code}")
        print(f"[AUTH] Response:\n{resp.text}\n")

        if "<soap:Fault" in resp.text:
            return {"success": False, "error": "Authentication failed"}

        # Parse authToken và accountId

        pattern_auth_token = re.compile(r"<authToken>(.*?)</authToken>")
        authToken = pattern_auth_token.findall(resp.text)[0]

        if authToken:
            return {
                "success": True,
                "authToken": authToken
            }

        return {"success": False, "error": "Could not extract auth token"}


async def change_password_with_auth(
        host: str,
        email: str,
        old_password: str,
        new_password: str
) -> dict:
    """
    Đổi mật khẩu sau khi authenticate (RECOMMENDED)
    """
    # Step 1: Authenticate
    auth_result = await authenticate(host, email, old_password)
    if not auth_result["success"]:
        return {"success": False, "error": f"Auth failed: {auth_result.get('error')}"}

    authToken = auth_result["authToken"]

    # Step 2: Change password với authToken
    url = f"https://mail.{host}/service/soap"

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <context xmlns="urn:zimbra">
      <authToken>{authToken}</authToken>
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

    print(f"[CHANGE_PW] URL: {url}")
    print(f"[CHANGE_PW] XML:\n{xml}")

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with httpx.AsyncClient(verify=ssl_context, timeout=30.0) as client:
        resp = await client.post(
            url,
            content=xml.encode("utf-8"),
            headers={"Content-Type": "application/soap+xml; charset=utf-8"}
        )

        print(f"[CHANGE_PW] Response Status: {resp.status_code}")
        print(f"[CHANGE_PW] Response:\n{resp.text}\n")

        if "<soap:Fault" in resp.text:
            fault_match = re.search(r'<soap:Text>([^<]+)</soap:Text>', resp.text)
            error = fault_match.group(1) if fault_match else "Unknown error"
            return {"success": False, "error": error, "body": resp.text}

        return {"success": True, "message": "Password changed successfully", "body": resp.text}
