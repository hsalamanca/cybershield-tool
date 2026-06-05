"""
CyberShield report API.

Vercel's @vercel/python runtime exposes a single `handler(request, response)`
function (or an `app = Flask(...)` object). We use the WSGI-style `app`
variable since Flask works on Vercel out of the box.
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)


def local_generate(answers):
    score = 100
    risks = []
    actions = []
    wins = []

    if answers.get('wifiPass') == 'never':
        score -= 20
        risks.append('Default or unchanged WiFi password - entry point for brute-force attacks.')
        actions.append('Change your WiFi password to a 16+ character passphrase. Use a password manager to store it.')
    elif answers.get('wifiPass') == 'yearly':
        score -= 10
        risks.append('Annual password rotation is below modern best practice for high-value networks.')
        actions.append('Rotate your WiFi password every 90 days and after any guests have had access.')
    else:
        wins.append('Strong WiFi password hygiene.')

    if answers.get('passReuse') == 'yes':
        score -= 25
        risks.append('Password reuse means one breach exposes all your accounts.')
        actions.append('Adopt a password manager (Bitwarden free tier is excellent) and generate unique passwords for every account.')
    elif answers.get('passReuse') == 'some':
        score -= 12
        risks.append('Password variation is still predictable to attackers.')
        actions.append('Move fully to unique, generated passwords for email, banking, and work accounts first.')
    elif answers.get('passReuse') == 'manager':
        wins.append('Password manager usage - top 1% of users.')

    if answers.get('twofa') == 'none':
        score -= 20
        risks.append('No two-factor authentication means password leaks become account takeovers.')
        actions.append('Enable 2FA on email, banking, and any account with payment info. Use an authenticator app, not SMS.')
    elif answers.get('twofa') == 'some':
        score -= 10
        risks.append('Partial 2FA leaves your most-valuable accounts exposed.')
        actions.append('Identify your crown-jewel accounts (email, banking, password manager) and confirm 2FA is on each.')
    else:
        wins.append('2FA enabled broadly.')

    if answers.get('vlan') == 'no':
        score -= 15
        risks.append('Single network means a compromised smart bulb can reach your laptop.')
        actions.append('Enable guest WiFi isolation on your router, OR upgrade to a Firewalla / UniFi / eero for full network segmentation.')
    elif answers.get('vlan') == 'guest':
        score -= 7
        actions.append('Good start. Next step: separate your IoT devices onto their own VLAN so they cannot reach your work devices.')
    else:
        wins.append('Network segmentation in place - significant risk reduction.')

    devices = answers.get('devices', [])
    if 'cameras' in devices or 'doorbell' in devices:
        score -= 5
        actions.append('Confirm your cameras run the latest firmware and use unique credentials (not the default admin/admin). Disable remote access if not needed.')
    if 'smart-locks' in devices:
        score -= 3
        actions.append('Smart locks: enable 2FA on the companion app and keep physical key backup. Disable remote unlock if you do not need it.')
    if answers.get('deviceCount') == '30+':
        score -= 8
        risks.append('30+ devices dramatically expands your attack surface.')
        actions.append('Inventory all devices. Anything you no longer use should be removed from the network entirely.')

    if answers.get('envType') in ('home-office', 'hybrid'):
        score -= 5
        actions.append('Working from home: confirm your work traffic is on a separate VLAN from personal devices. Many compliance frameworks (HIPAA, PCI) require this.')

    score = max(15, min(100, score))

    if score < 50:
        verdict = 'Critical gaps - fix the top 3 items this week.'
    elif score < 70:
        verdict = 'Moderate risk - solid foundation, a few key improvements needed.'
    elif score < 85:
        verdict = 'Good security posture - small refinements would harden it further.'
    else:
        verdict = 'Excellent - your setup is well-defended.'

    if answers.get('concerns'):
        snippet = answers['concerns'][:80] + ('...' if len(answers['concerns']) > 80 else '')
        actions.append('Specific to your concern ("' + snippet + '"): schedule a free 15-minute consult with HoustonSecureIT.')

    return {
        'score': score,
        'verdict': verdict,
        'risks': risks,
        'actions': actions,
        'wins': wins,
        'generatedAt': datetime.utcnow().isoformat() + 'Z',
        'source': 'local',
    }


@app.route('/api/report', methods=['POST'])
def report():
    answers = request.get_json(force=True, silent=True) or {}
    return jsonify(local_generate(answers))


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'cybershield'})
