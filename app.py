from flask import Flask, request, jsonify, render_template_string
from main import create_acc
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time

app = Flask(__name__)

VALID_REGIONS = ['IND', 'ID', 'BR', 'ME', 'VN', 'TH', 'CIS', 'BD', 'PK', 'SG', 'NA', 'SAC', 'EU', 'TW']
TOTAL_ACCOUNTS = 0
START_TIME = datetime.now()

@app.route('/gen', methods=['GET'])
def generate_accounts():
    """Generate accounts via API - returns JSON"""
    global TOTAL_ACCOUNTS
    start_time = time.time()
    
    region = request.args.get('region', '').upper()
    amount = request.args.get('amount', '10')
    
    # Validate region
    if region not in VALID_REGIONS:
        return jsonify({
            'error': 'Invalid region',
            'valid_regions': VALID_REGIONS
        }), 400
    
    # Validate amount
    try:
        amount = int(amount)
        if amount < 1 or amount > 100:
            return jsonify({
                'error': 'Amount must be between 1 and 100'
            }), 400
    except ValueError:
        return jsonify({
            'error': 'Invalid amount parameter. Must be a number.'
        }), 400
    
    accounts = []
    max_workers = min(40, amount * 2)
    
    def generate_single_account():
        try:
            max_attempts = 50  # Try up to 50 times to find rare UID
            for _ in range(max_attempts):
                result = create_acc(region, 'NAV')
                if result and result.get('status_code') == 200:
                    account_id = result.get('account_id')
                    is_rare = result.get('is_rare', False)
                    
                    if is_rare and account_id:
                        return {
                            'accountId': account_id,
                            'password': result['password'],
                            'uid': result['uid']
                        }
        except Exception as e:
            print(f"Error: {e}")
        return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit more tasks to account for filtering
        futures = [executor.submit(generate_single_account) for _ in range(amount * 3)]
        for future in as_completed(futures, timeout=600):
            acc = future.result()
            if acc:
                accounts.append(acc)
                if len(accounts) >= amount:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break
    
    TOTAL_ACCOUNTS += len(accounts)
    elapsed = round(time.time() - start_time, 2)
    
    return jsonify({
        'region': region,
        'requested': amount,
        'generated': len(accounts),
        'time_taken_sec': elapsed,
        'accounts': accounts
    })

@app.route('/')
def home():
    """HTML homepage with docs"""
    html = f"""
    <html>
    <head>
        <title>Account Generator API</title>
        <style>
            body {{ font-family: Arial; background: #111; color: #eee; padding: 40px; }}
            h1 {{ color: #00ff88; }}
            code {{ background: #222; padding: 4px 6px; border-radius: 4px; }}
            a {{ color: #00ffcc; }}
            .box {{ background: #1b1b1b; padding: 20px; border-radius: 8px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <h1>🔥 Account Generator API</h1>
        <p>Welcome to the <b>FreeFire Account Generator</b> service.</p>

        <div class="box">
            <h2>🧩 Endpoints:</h2>
            <ul>
                <li><b>/gen</b> → Generate accounts (API JSON response)</li>
                <li><b>/total</b> → View total generated accounts (HTML)</li>
                <li><b>/health</b> → View API status (HTML)</li>
            </ul>
        </div>

        <div class="box">
            <h2>⚙️ Usage Example:</h2>
            <p>Use a simple GET request:</p>
            <code>/gen?region=IND&amount=10</code>
            <p>👉 Returns JSON with 10 new accounts from region <b>IND</b>.</p>
        </div>

        <div class="box">
            <h2>🌍 Valid Regions:</h2>
            <p>{', '.join(VALID_REGIONS)}</p>
        </div>

        <div class="box">
            <h2>📊 API Summary</h2>
            <p>Total Accounts Generated: <b>{TOTAL_ACCOUNTS}</b></p>
            <p>Uptime: <b>{(datetime.now() - START_TIME).seconds // 60} minutes</b></p>
        </div>
    </body>
    </html>
    """
    return html

@app.route('/total')
def total_generated():
    """HTML summary of generated accounts"""
    uptime = datetime.now() - START_TIME
    html = f"""
    <html><head><title>Total Generated</title></head>
    <body style="background:#111;color:#eee;font-family:Arial;padding:30px">
        <h1>📊 Total Generation Stats</h1>
        <p>Total Accounts Generated: <b style="color:#00ff88">{TOTAL_ACCOUNTS}</b></p>
        <p>Service Uptime: <b>{uptime}</b></p>
        <p>Valid Regions: {', '.join(VALID_REGIONS)}</p>
        <p><a href="/" style="color:#00ffcc">⬅ Back to Home</a></p>
    </body></html>
    """
    return html

@app.route('/health')
def health_check():
    """HTML health status"""
    uptime = datetime.now() - START_TIME
    html = f"""
    <html><head><title>Health Check</title></head>
    <body style="background:#111;color:#eee;font-family:Arial;padding:30px">
        <h1>💚 API Health Status</h1>
        <p>Status: ✅ Running</p>
        <p>Service: Account Generator API</p>
        <p>Uptime: <b>{uptime}</b></p>
        <p>Valid Regions: {', '.join(VALID_REGIONS)}</p>
        <p><a href="/" style="color:#00ffcc">⬅ Back to Home</a></p>
    </body></html>
    """
    return html

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
