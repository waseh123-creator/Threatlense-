
import os
import time
import base64
import logging
import requests
import whois

from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger("threatlens.sources")

REQUEST_TIMEOUT_SECONDS = 8
MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.5


def _error(source, message):
    return {
        "source": source,
        "status": "error",
        "error": message
    }


def _iso(value):
    if value is None:
        return None

    if isinstance(value, (list, tuple)):
        value = value[0] if value else None

    if value is None:
        return None

    if isinstance(value, datetime):
        return value.isoformat()

    return str(value)


def _extract_hostname(target):
    try:
        parsed = urlparse(target)

        if parsed.scheme not in ("http", "https"):
            return None

        return parsed.hostname

    except Exception:
        return None


def get_virustotal(target_type: str, target: str) -> dict:

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return _error(
            "VirusTotal",
            "VirusTotal API key is not configured."
        )

    headers = {
        "x-apikey": api_key
    }

    target_type = target_type.lower()

    if target_type == "ip":

        endpoint = (
            "https://www.virustotal.com/api/v3/ip_addresses/"
            + target
        )

    elif target_type == "domain":

        endpoint = (
            "https://www.virustotal.com/api/v3/domains/"
            + target
        )

    elif target_type == "url":

        url_id = (
            base64.urlsafe_b64encode(
                target.encode()
            )
            .decode()
            .strip("=")
        )

        endpoint = (
            "https://www.virustotal.com/api/v3/urls/"
            + url_id
        )

    else:

        return _error(
            "VirusTotal",
            "Unsupported target type."
        )

    last_error = None

    for attempt in range(MAX_RETRIES + 1):

        try:

            response = requests.get(
                endpoint,
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code == 429:

                retry_after = response.headers.get(
                    "Retry-After",
                    "unknown"
                )

                return _error(
                    "VirusTotal",
                    f"VirusTotal rate limit reached. Retry-After: {retry_after}"
                )

            if 400 <= response.status_code < 500:

                if response.status_code == 401:
                    message = "VirusTotal API key is unauthorized."

                elif response.status_code == 404:
                    message = "Target was not found in VirusTotal."

                else:
                    message = (
                        f"VirusTotal rejected the request "
                        f"(HTTP {response.status_code})."
                    )

                return _error(
                    "VirusTotal",
                    message
                )

            if response.status_code >= 500:

                last_error = (
                    f"VirusTotal server error "
                    f"(HTTP {response.status_code})."
                )

                if attempt < MAX_RETRIES:

                    time.sleep(
                        RETRY_BACKOFF_SECONDS * (2 ** attempt)
                    )

                    continue

                return _error(
                    "VirusTotal",
                    last_error
                )

            try:

                payload = response.json()

            except ValueError:

                return _error(
                    "VirusTotal",
                    "VirusTotal returned malformed JSON."
                )

            attributes = (
                payload
                .get("data", {})
                .get("attributes", {})
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            data = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attributes.get("reputation")
            }

            return {
                "source": "VirusTotal",
                "status": "success",
                "data": data,
                "fetched_at": datetime.utcnow().isoformat() + "Z"
            }

        except requests.Timeout:

            last_error = "VirusTotal request timed out."

            if attempt < MAX_RETRIES:

                time.sleep(
                    RETRY_BACKOFF_SECONDS * (2 ** attempt)
                )

                continue

        except requests.ConnectionError:

            last_error = "Could not connect to VirusTotal."

            if attempt < MAX_RETRIES:

                time.sleep(
                    RETRY_BACKOFF_SECONDS * (2 ** attempt)
                )

                continue

        except requests.RequestException:

            logger.exception(
                "VirusTotal request failed"
            )

            return _error(
                "VirusTotal",
                "VirusTotal network request failed."
            )

        except Exception:

            logger.exception(
                "Unexpected VirusTotal error"
            )

            return _error(
                "VirusTotal",
                "Unexpected VirusTotal error."
            )

    return _error(
        "VirusTotal",
        last_error or "VirusTotal lookup failed."
    )


def get_whois(target_type: str, target: str) -> dict:

    try:

        target_type = target_type.lower()

        if target_type == "url":

            hostname = _extract_hostname(target)

            if not hostname:

                return _error(
                    "WHOIS",
                    "Could not extract a valid hostname from the URL."
                )

            lookup_target = hostname

        elif target_type in ("domain", "ip"):

            lookup_target = target

        else:

            return _error(
                "WHOIS",
                "Unsupported target type."
            )

        result = whois.whois(
            lookup_target
        )

        if result is None:

            return _error(
                "WHOIS",
                "WHOIS returned no information."
            )

        data = {
            "domain": _iso(
                getattr(result, "domain_name", None)
            ),

            "registrar": _iso(
                getattr(result, "registrar", None)
            ),

            "creation_date": _iso(
                getattr(result, "creation_date", None)
            ),

            "expiration_date": _iso(
                getattr(result, "expiration_date", None)
            ),

            "name_servers": getattr(
                result,
                "name_servers",
                None
            ),

            "country": _iso(
                getattr(result, "country", None)
            ),

            "organization": _iso(
                getattr(result, "org", None)
            )
        }

        return {
            "source": "WHOIS",
            "status": "success",
            "data": data,
            "fetched_at": datetime.utcnow().isoformat() + "Z"
        }

    except Exception:

        logger.exception(
            "WHOIS lookup failed"
        )

        return _error(
            "WHOIS",
            "WHOIS lookup failed or returned unavailable data."
        )


SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
