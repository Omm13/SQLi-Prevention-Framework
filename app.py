from flask import Flask
from database.database import initialize_database, get_connection

app = Flask(__name__)

# Initialize the database when the application starts
initialize_database()


@app.route("/")
def home():
    return "SQL Injection Prevention Framework"


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


if __name__ == "__main__":
    app.run(debug=True)