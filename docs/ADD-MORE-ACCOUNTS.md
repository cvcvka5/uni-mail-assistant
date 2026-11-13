# Adding Gmail and Matrix / Element groups

Everything is built in. You only add your private login (stored in the **Keychain**, never in a file) and switch the account on in `config.json`.
Afterwards, run this in the project folder:
```bash
python3 helper.py check
```

---

## Gmail (as many accounts as you like)

You sign in with Google in your browser, so there are no app passwords. The assistant gets read-only access, and you can disconnect an account whenever you want.

### One-time setup (about 5 minutes)
1. Go to console.cloud.google.com, create a project, and turn on the Gmail API (APIs & Services → Library).
2. Open the OAuth consent screen, choose *External*, and add your Gmail addresses as test users. Then publish the app ("In production"). Google will say the app is unverified, which is expected for a personal app. In "Testing" mode your tokens expire after 7 days.
3. Under Credentials, create an OAuth client ID of type *Desktop app*.
4. Put the client ID in `config.json` and the client secret in the Keychain:
   ```json
   "google_oauth": {"clients": [{"client_id": "123-abc.apps.googleusercontent.com", "keychain": "unimail-google-client-secret"}]}
   ```
   ```bash
   security add-generic-password -s unimail-google-client-secret -a google -w
   ```
   If your accounts belong to different Google Cloud projects, add one entry to `clients` per project, each with its own Keychain name.

### Link, list, disconnect
In the chat window, open **Gmail accounts** and use *Link a Gmail account* or *Disconnect*. In Terminal:
```bash
python3 gmail_oauth.py add [CLIENT_ID]   # opens the browser; repeat for each account
python3 gmail_oauth.py list
python3 gmail_oauth.py remove you@gmail.com
```
`remove` revokes access at Google, deletes the stored token and wipes the saved mail content (message ids stay, so linking the account again won't repeat old reminders).

Then run `python3 helper.py check` and `python3 helper.py sync`. The first sync downloads up to 300 recent messages per inbox and can take a few minutes.

Every reminder, digest entry and chat answer names the inbox it came from. The refresh token of each account sits in the Keychain as `unimail-gmail-oauth:<address>`; access tokens only live in memory. If Google ever revokes access, the log tells you to link that account again.

### Outlook / Hotmail
Microsoft no longer allows simple passwords for outlook.com. The easiest way: in Outlook.com → Settings → Mail → **Forwarding**, forward to one of your Gmail accounts.

---

## Matrix / Element groups (e.g. course or student groups)

The assistant reads new messages in your groups (**read-only, it never posts**), keeps only announcements, deadlines, events and anything addressed to you, and turns them into reminders with a link that opens the message in Element.

1. Log in to your Matrix account at **app.element.io** (Element Web). If your group uses its own server, choose that server when logging in.
2. Avatar → **All settings** → **Help & About** → **Advanced** → **Access Token** → copy it.
   ⚠️ This token works like your password. **Never share it or post it anywhere.**
3. Save it in the Keychain and paste the token when asked:
   ```bash
   security add-generic-password -s unimail-matrix -a matrix -w
   ```
4. In `config.json`, under `"matrix"`:
   - `"enabled": true`
   - `"server"`: your Matrix server (e.g. `matrix.org` or your university's server)
   - `"rooms": []` reads all your groups. To limit it, list room names: `["My Course Group"]`
5. Run `python3 helper.py check`, then `python3 helper.py sync`.

Notes:
- **Don't click "Sign out"** in that Element Web session. Signing out makes the token stop working; just close the tab. If it stops working, delete the old one (`security delete-generic-password -s unimail-matrix`) and repeat steps 2–3.
- **End-to-end encrypted** rooms (🔒) can't be read; the log will say so. Most announcement groups aren't encrypted.
