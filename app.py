import sqlite3
from flask import Flask, render_template, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from analyzer import evaluate_password, generate_suggestion

app = Flask(__name__)
app.secret_key = 'some_secret_key'  # Required for flashing messages


# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    # We store the HASH, not the actual password
    c.execute('CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, hash TEXT)')
    conn.commit()
    conn.close()


init_db()


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    suggestion = None
    warning = None

    if request.method == 'POST':
        pwd = request.form.get('password')

        # 1. Check uniqueness (Database integration)
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('SELECT hash FROM history')
        old_hashes = c.fetchall()

        is_reused = False
        for h in old_hashes:
            if check_password_hash(h[0], pwd):
                is_reused = True
                break

        if is_reused:
            warning = "⚠️ You have used this password before! Please choose a unique one."
        else:
            # 2. If unique, analyze it
            strength, checks = evaluate_password(pwd)
            result = {"strength": strength, "checks": checks}

            if strength != "Strong":
                suggestion = generate_suggestion()
            else:
                # 3. Store the new unique password (as a hash)
                new_hash = generate_password_hash(pwd)
                c.execute('INSERT INTO history (hash) VALUES (?)', (new_hash,))
                conn.commit()

        conn.close()

    return render_template('index.html', result=result, suggestion=suggestion, warning=warning)


if __name__ == '__main__':
    app.run(debug=True)