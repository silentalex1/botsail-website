from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

CLIENT_ID = '1389511938559705199'
CLIENT_SECRET = ''.join([chr(x) for x in [90, 72, 54, 114, 67, 45, 121, 103, 85, 120, 76, 78, 48, 78, 112, 78, 72, 68, 73, 72, 77, 74, 101, 65, 113, 48, 48, 88, 49, 105, 119, 49]])
REDIRECT_URI = 'https://edubypass.it.com/callback'

@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'scope': 'identify'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers)
    access_token = r.json().get('access_token')
    user = requests.get('https://discord.com/api/users/@me', headers={'Authorization': f'Bearer {access_token}'}).json()
    html = '''
    <html>
    <head>
    <title>Botsail Login</title>
    <style>
    body { background: #181c2a; color: #6be6ff; font-family: Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; }
    .box { background: #23263a; padding: 40px 60px; border-radius: 18px; box-shadow: 0 4px 32px #0008; text-align: center; }
    .box h1 { color: #6be6ff; margin-bottom: 18px; }
    .box p { color: #bfc9e0; }
    </style>
    </head>
    <body>
      <div class="box">
        <h1>You are logged in.</h1>
        <p>You may close this page.</p>
      </div>
    </body>
    </html>
    '''
    return render_template_string(html)

if __name__ == '__main__':
    app.run(ssl_context='adhoc')