# install mysql-connector-python == 8.0.29
import mysql.connector

database = mysql.connector.connect(
    host=DB_HOST,
    port=DB_PORT,
    user=DB_USER,
    password=DB_PASS,
    database=DB,
)

cursor = database.cursor()

cursor.execute("SELECT * FROM users")

result = cursor.fetchall()

print(result)
