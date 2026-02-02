import logging
import time
import httpx
from typing import List, Dict, Any, Optional
from urllib.parse import quote

try:
    from src.core.config import settings
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from src.core.config import settings

logger = logging.getLogger(__name__)


ZAP_BASE_URL = settings.zap_base_url
ZAP_TIMEOUT = settings.zap_timeout
SPIDER_POLL_INTERVAL = settings.zap_spider_poll_interval
ACTIVE_SCAN_POLL_INTERVAL = settings.zap_active_scan_poll_interval
RATE_LIMIT_DELAY = settings.zap_rate_limit_delay
MAX_ZAP_RETRIES = 3
RETRY_BACKOFF_BASE = 2


def zap_api_request(endpoint: str, timeout: int = 10, max_retries: int = MAX_ZAP_RETRIES) -> Optional[Dict[str, Any]]:
    url = f"{ZAP_BASE_URL}{endpoint}"
    
    for attempt in range(max_retries):
        try:
            response = httpx.get(url, timeout=timeout, verify=False)
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException:
            if attempt < max_retries - 1:
                backoff = RETRY_BACKOFF_BASE ** attempt
                time.sleep(backoff)
            else:
                logger.error(f"[ZAP] Timeout accessing {url} after {max_retries} attempts")
                return None
        except httpx.HTTPError as e:
            if attempt < max_retries - 1:
                backoff = RETRY_BACKOFF_BASE ** attempt
                time.sleep(backoff)
            else:
                logger.error(f"[ZAP] HTTP error accessing {url} after {max_retries} attempts: {e}")
                return None
        except Exception as e:
            logger.error(f"[ZAP] Unexpected error accessing {url}: {e}")
            return None
    
    return None


def map_zap_risk_to_severity(risk: str) -> str:
    risk_map = {
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Informational": "info",
    }
    return risk_map.get(risk, "low")


def map_zap_confidence(confidence: str) -> int:
    confidence_map = {
        "High": 95,
        "Medium": 70,
        "Low": 50,
    }
    return confidence_map.get(confidence, 70)


def zap_baseline_scan(target_url: str, verification_id: Optional[int] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    scan_start_time = time.time()
    
    try:
        version_response = zap_api_request("/JSON/core/view/version/")
        
        if not version_response:
            raise RuntimeError("ZAP is not accessible. Ensure ZAP container is running on port 8090.")
        
        time.sleep(RATE_LIMIT_DELAY)
        
        encoded_url = quote(target_url, safe='')
        access_response = zap_api_request(f"/JSON/core/action/accessUrl/?url={encoded_url}")
        
        if not access_response:
             logger.error(f"[ZAP] Access URL failed. No response.")
             raise RuntimeError(f"Failed to access URL: {target_url}")
             
        is_success = (
            access_response.get("Result") == "OK" or 
            access_response.get("result") == "OK" or
            "accessUrl" in access_response 
        )
             
        if not is_success:
            logger.error(f"[ZAP] Access URL failed. Response: {access_response}")
            raise RuntimeError(f"Failed to access URL: {target_url}")
        
        time.sleep(RATE_LIMIT_DELAY)
        
        spider_response = zap_api_request(f"/JSON/spider/action/scan/?url={encoded_url}")
        
        if not spider_response:
            raise RuntimeError("Failed to start spider")
        
        spider_scan_id = spider_response.get("scan")
        time.sleep(RATE_LIMIT_DELAY)
        
        spider_timeout = 60
        spider_start = time.time()
        
        while True:
            if time.time() - scan_start_time > ZAP_TIMEOUT:
                logger.warning(f"[ZAP] Timeout after {ZAP_TIMEOUT}s")
                break
            
            if time.time() - spider_start > spider_timeout:
                logger.warning(f"[ZAP] Spider timeout after {spider_timeout}s")
                break
            
            status_response = zap_api_request(f"/JSON/spider/view/status/?scanId={spider_scan_id}", timeout=20)
            
            if not status_response:
                time.sleep(2)
                status_response = zap_api_request(f"/JSON/spider/view/status/?scanId={spider_scan_id}", timeout=20)
                
                if not status_response:
                    time.sleep(SPIDER_POLL_INTERVAL)
                    continue
            
            status = int(status_response.get("status", "0"))
            
            if status >= 100:
                break
            
            time.sleep(SPIDER_POLL_INTERVAL)
        
        time.sleep(RATE_LIMIT_DELAY)
        
        results_response = zap_api_request(f"/JSON/spider/view/results/?scanId={spider_scan_id}")
        urls_found = results_response.get("results", []) if results_response else []
        
        time.sleep(RATE_LIMIT_DELAY)
        
        threads_per_host = settings.zap_threads_per_host
        thread_config = zap_api_request(
            f"/JSON/ascan/action/setOptionThreadPerHost/?Integer={threads_per_host}",
            timeout=10
        )
        
        strength_config = zap_api_request(
            f"/JSON/ascan/action/setOptionDefaultPolicy/?String=Low",
            timeout=10
        )
        
        delay_config = zap_api_request(
            f"/JSON/ascan/action/setOptionDelayInMs/?Integer=500",
            timeout=10
        )
        
        time.sleep(RATE_LIMIT_DELAY)
        
        ascan_response = zap_api_request(f"/JSON/ascan/action/scan/?url={encoded_url}")
        
        if not ascan_response:
            raise RuntimeError("Failed to start active scan")
        
        ascan_scan_id = ascan_response.get("scan")
        time.sleep(RATE_LIMIT_DELAY)
        
        ascan_timeout = ZAP_TIMEOUT - (time.time() - scan_start_time)
        ascan_start = time.time()
        consecutive_failures = 0
        max_consecutive_failures = 3
        
        while True:
            if time.time() - scan_start_time > ZAP_TIMEOUT:
                logger.warning(f"[ZAP] Global timeout ({ZAP_TIMEOUT}s) reached - stopping scan")
                zap_api_request(f"/JSON/ascan/action/stop/?scanId={ascan_scan_id}", timeout=10, max_retries=1)
                break
            
            if time.time() - ascan_start > ascan_timeout:
                logger.warning(f"[ZAP] Active scan timeout ({ascan_timeout:.1f}s) reached - stopping")
                zap_api_request(f"/JSON/ascan/action/stop/?scanId={ascan_scan_id}", timeout=10, max_retries=1)
                break
            
            status_response = zap_api_request(
                f"/JSON/ascan/view/status/?scanId={ascan_scan_id}", 
                timeout=45,
                max_retries=2
            )
            
            if not status_response:
                consecutive_failures += 1
                
                if consecutive_failures >= max_consecutive_failures:
                    logger.error("[ZAP] Too many consecutive failures, stopping scan")
                    zap_api_request(f"/JSON/ascan/action/stop/?scanId={ascan_scan_id}", timeout=10, max_retries=1)
                    break
                
                backoff = min(ACTIVE_SCAN_POLL_INTERVAL * (2 ** consecutive_failures), 30)
                time.sleep(backoff)
                continue
            
            consecutive_failures = 0
            status = int(status_response.get("status", "0"))
            
            if status >= 100:
                break
            
            time.sleep(ACTIVE_SCAN_POLL_INTERVAL)
        
        duration = time.time() - scan_start_time
        time.sleep(RATE_LIMIT_DELAY)
        
        alerts_response = zap_api_request(
            f"/JSON/core/view/alerts/?baseurl={encoded_url}", 
            timeout=60,
            max_retries=3
        )
        
        if not alerts_response:
            logger.warning("[ZAP] Failed to fetch alerts after retries")
            return findings
        
        alerts = alerts_response.get("alerts", [])
        
        for alert in alerts:
            try:
                severity = map_zap_risk_to_severity(alert.get("risk", "Low"))
                confidence = map_zap_confidence(alert.get("confidence", "Medium"))
                
                finding = {
                    "title": alert.get("name", "Unknown ZAP Alert"),
                    "severity": severity,
                    "remediation": alert.get("solution", "Review ZAP documentation for remediation guidance."),
                    "confidence": confidence,
                    "path": alert.get("url", target_url),
                    "details": {
                        "alert_id": alert.get("alertId"),
                        "description": alert.get("description", ""),
                        "risk": alert.get("risk", "Low"),
                        "cwe_id": alert.get("cweid"),
                        "wasc_id": alert.get("wascid"),
                        "evidence": alert.get("evidence", ""),
                        "attack": alert.get("attack", ""),
                        "param": alert.get("param", ""),
                        "reference": alert.get("reference", ""),
                        "scan_type": "zap_baseline_active",
                    }
                }
                
                if verification_id:
                    finding["details"]["verification_id"] = verification_id
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"[ZAP] Error processing alert: {e}")
                continue
        
    except RuntimeError as e:
        logger.error(f"[ZAP] Scan failed: {e}")
        findings.append({
            "title": "ZAP baseline scan failed",
            "severity": "info",
            "remediation": f"Could not complete ZAP baseline scan: {str(e)}",
            "confidence": 100,
            "path": target_url,
            "details": {
                "error": str(e),
                "scan_type": "zap_baseline_active",
            }
        })
        
    except Exception as e:
        logger.error(f"[ZAP] Unexpected error during scan: {e}")
        findings.append({
            "title": "ZAP baseline scan error",
            "severity": "info",
            "remediation": f"Unexpected error during ZAP scan: {str(e)}",
            "confidence": 100,
            "path": target_url,
            "details": {
                "error": str(e),
                "scan_type": "zap_baseline_active",
            }
        })
    
    return findings


def is_zap_available() -> bool:
    try:
        response = zap_api_request("/JSON/core/view/version/", timeout=5)
        return response is not None
    except Exception:
        return False
