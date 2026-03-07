#!/usr/bin/env python3
# =============================================================
#  scripts/export_report.py
#  Exports a security summary report to JSON (and optionally PDF)
#
#  RUN:  cd backend && python ../scripts/export_report.py
# =============================================================

import sys, os, json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app import create_app
from app.models.email_scan import EmailScan
from app.models.alert import Alert
from app.models.user import User

app = create_app()

def export_json():
    with app.app_context():
        total   = EmailScan.query.count()
        phish   = EmailScan.query.filter_by(is_phishing=True).count()
        safe    = EmailScan.query.filter_by(is_phishing=False).count()
        alerts  = Alert.query.count()
        pending = Alert.query.filter_by(status="pending").count()
        users   = User.query.filter_by(is_active=True).count()

        report = {
            "generated_at":   datetime.utcnow().isoformat(),
            "period":         "all time",
            "summary": {
                "total_scans":    total,
                "phishing":       phish,
                "safe":           safe,
                "detection_rate": round((phish/total*100) if total else 0, 1),
                "total_alerts":   alerts,
                "pending_alerts": pending,
                "active_users":   users,
            },
            "recent_scans": [
                s.to_dict(include_body=False)
                for s in EmailScan.query.order_by(EmailScan.scanned_at.desc()).limit(20).all()
            ],
        }

        filename = f"phishguard_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n✅ Report exported: {filename}")
        print(f"   Total scans: {total}")
        print(f"   Phishing:    {phish} ({report['summary']['detection_rate']}%)")
        print(f"   Alerts:      {alerts} ({pending} pending)")
        return filename

if __name__ == "__main__":
    print("\n🛡️  PhishGuard — Report Exporter")
    print("=" * 50)
    export_json()