# install mysql-connector-python == 8.0.29
import mysql.connector

database = mysql.connector.connect(
    host="viaduct.proxy.rlwy.net",
    port=58214,
    user="root",
    password="uEdDoyhBohALDxWuMLJRnXgURbLIUnFu",
    database="railway",
)

cursor = database.cursor()

cursor.execute("SELECT * FROM users")

result = cursor.fetchall()

print(result)
