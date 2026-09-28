import hashlib
import random
from datetime import datetime

from models import db, Event

EVENT_IDS = [4625, 4624, 4720, 1102, 4672]

EVENT_TYPES = {
    4625: "Failed Logon",
    4624: "Successful Logon",
    4720: "User Account Created",
    1102: "Audit Log Cleared",
    4672: "Special Privileges Assigned",
}

USERS = ["admin", "jdoe", "svc_backup", "guest", "root",
         "service_account", "alice", "bob"]

HOSTS = ["WIN-DC01", "WIN-WS01", "WIN-WS02", "SRV-FILE01"]


def _random_ip():
    if random.random() < 0.3:
        return "10.0.{0}.{1}".format(random.randint(0, 255), random.randint(1, 254))
    return "{0}.{1}.{2}.{3}".format(
        random.randint(1, 223),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(1, 254),
    )


def _random_hash():
    return hashlib.sha256(str(random.random()).encode()).hexdigest()


def generate_event():
    event_id = random.choice(EVENT_IDS)
    ip = _random_ip()
    user = random.choice(USERS)
    host = random.choice(HOSTS)

    ts = datetime.utcnow()
    if random.random() < 0.2:
        ts = ts.replace(hour=random.choice([2, 3, 4, 23]))

    file_hash = _random_hash() if random.random() < 0.15 else None

    event = Event(
        timestamp=ts,
        event_id=event_id,
        source_ip=ip,
        username=user,
        hostname=host,
        event_type=EVENT_TYPES.get(event_id, "Unknown"),
        file_hash=file_hash,
        raw="EventID={0} User={1} IP={2} Host={3} Hash={4}".format(
            event_id, user, ip, host, file_hash or "-"
        ),
    )
    db.session.add(event)
    db.session.commit()
    return event