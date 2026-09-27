from flask import Flask, request, jsonify, render_template
from database.database import initialize_database, get_connection

app = Flask(__name__)

# Initialize the database when the application starts
initialize_database()

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    connection = get_connection()

    result = connection.execute(
        "SELECT COUNT(*) AS count FROM users"
    ).fetchone()

    connection.close()

    return {
        "status": "ok",
        "database": "connected",
        "users": result["count"]
    }


@app.route("/vulnerable-login", methods=["GET", "POST"])
def vulnerable_login():
    if request.method == "GET":
        return render_template("vulnerable_login.html")
        return """
        <h2>Vulnerable Login</h2>

        <form method="POST">
            <label>Username:</label>
            <input type="text" name="username">

            <br><br>
    
            <label>Password:</label>
            <input type="password" name="password">

            <br><br>

            <button type="submit">Login</button>
        </form>
        """

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    connection = get_connection()

    # INTENTIONALLY VULNERABLE:
    # User input is directly inserted into the SQL query.
    query = f"""
        SELECT id, username, role
        FROM users
        WHERE username = '{username}'
        AND password = '{password}'
    """

    result = connection.execute(query).fetchone()

    connection.close()

    if result:
        return jsonify({
            "login": "successful",
            "username": result["username"],
            "role": result["role"]
        })

    return jsonify({
        "login": "failed"
    }), 401
@app.route("/secure-login", methods=["GET", "POST"])
def secure_login():
    if request.method == "GET":
        return render_template("secure_login.html")
        return """
        <h2>Secure Login</h2>

        <form method="POST">
            <label>Username:</label>
            <input type="text" name="username">

            <br><br>

            <label>Password:</label>
            <input type="password" name="password">

            <br><br>

            <button type="submit">Login</button>
        </form>
        """

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    connection = get_connection()

    # SECURE:
    # User input is passed separately from the SQL statement.
    query = """
        SELECT id, username, role
        FROM users
        WHERE username = ?
        AND password = ?
    """

    result = connection.execute(
        query,
        (username, password)
    ).fetchone()

    connection.close()

    if result:
        return jsonify({
            "login": "successful",
            "username": result["username"],
            "role": result["role"]
        })

    return jsonify({
        "login": "failed"
    }), 401

if __name__ == "__main__":
    app.run(debug=True)