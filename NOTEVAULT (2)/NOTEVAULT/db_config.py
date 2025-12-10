from flask import Flask
from flask_mysqldb import MySQL

app = Flask(__name__)
app.secret_key = "supersecretkey"

# MySQL config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'notevault_db'

mysql = MySQL(app)

def get_db_connection():
    return mysql.connection
