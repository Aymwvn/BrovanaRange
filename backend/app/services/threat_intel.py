from datetime import datetime, timedelta
import ipaddress
import json
import urllib.error
import urllib.request

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import BlockedIpWatchlist, IpReputationCache
from app.services.alerts import create_alert

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return parsed.is_global


def empty_reputation(ip: str, error: str = "") -> IpReputationCache:
    return IpReputationCache(
        ip=ip,
        malicious=0,
        suspicious=0,
        harmless=0,
        undetected=0,
        reputation=0,
        country="",
        as_owner="",
        blocked=False,
        error=error,
        checked_at=datetime.utcnow(),
    )


def lookup_virustotal_ip(ip: str) -> dict:
    request = urllib.request.Request(
        VT_IP_URL.format(ip=ip),
        headers={
            "x-apikey": settings.VIRUSTOTAL_API_KEY,
            "accept": "application/json",
            "user-agent": "BrovanaRange/1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))


def upsert_watchlist_entry(db: Session, reputation: IpReputationCache) -> None:
    if not reputation.blocked:
        return
    entry = db.query(BlockedIpWatchlist).filter_by(ip=reputation.ip).first()
    if not entry:
        entry = BlockedIpWatchlist(ip=reputation.ip, first_seen_at=datetime.utcnow())
        db.add(entry)
    entry.source = reputation.provider
    entry.reason = f"VirusTotal malicious detections >= {settings.VIRUSTOTAL_MALICIOUS_THRESHOLD}"
    entry.malicious = reputation.malicious
    entry.suspicious = reputation.suspicious
    entry.as_owner = reputation.as_owner
    entry.country = reputation.country
    entry.last_seen_at = datetime.utcnow()
    entry.active = True
    create_alert(
        db,
        severity="critical",
        source="virustotal",
        title="Malicious IP added to watchlist",
        message=f"{reputation.ip} has {reputation.malicious} malicious and {reputation.suspicious} suspicious VirusTotal detections.",
        target=reputation.ip,
    )


def get_ip_reputation(db: Session, ip: str, *, force: bool = False) -> IpReputationCache:
    cached = db.query(IpReputationCache).filter_by(ip=ip).first()
    fresh_after = datetime.utcnow() - timedelta(hours=settings.VIRUSTOTAL_CACHE_HOURS)
    if cached and not force and cached.checked_at >= fresh_after:
        return cached

    if not is_public_ip(ip):
        record = cached or empty_reputation(ip)
        record.error = "not_public_ip"
        record.checked_at = datetime.utcnow()
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    if not settings.VIRUSTOTAL_API_KEY:
        record = cached or empty_reputation(ip)
        record.error = "virustotal_api_key_not_configured"
        record.checked_at = datetime.utcnow()
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    record = cached or empty_reputation(ip)
    try:
        payload = lookup_virustotal_ip(ip)
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        record.malicious = int(stats.get("malicious") or 0)
        record.suspicious = int(stats.get("suspicious") or 0)
        record.harmless = int(stats.get("harmless") or 0)
        record.undetected = int(stats.get("undetected") or 0)
        record.reputation = int(attrs.get("reputation") or 0)
        record.country = (attrs.get("country") or "")[:8]
        record.as_owner = (attrs.get("as_owner") or "")[:255]
        record.blocked = record.malicious >= settings.VIRUSTOTAL_MALICIOUS_THRESHOLD
        record.error = ""
    except urllib.error.HTTPError as exc:
        record.error = f"virustotal_http_{exc.code}"
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        record.error = f"virustotal_error:{str(exc)[:200]}"
    record.checked_at = datetime.utcnow()
    db.add(record)
    upsert_watchlist_entry(db, record)
    db.commit()
    db.refresh(record)
    return record
