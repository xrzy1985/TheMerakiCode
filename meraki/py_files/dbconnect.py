import MySQLdb

# if you're using python anywhere, this is the MySQL set you can use 
def connection():
    conn = MySQLdb.connect(host="username.mysql.pythonanywhere-services.com",
                            user="username",
                            passwd = "password",
                            db = "db"
                            )
    curse = conn.cursor()

    return curse, conn
