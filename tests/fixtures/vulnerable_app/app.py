from flask import request


def search(db):
    term = request.args["q"]
    query = f"SELECT * FROM users WHERE name = '{term}'"
    return db.execute(query)


def profile():
    return "<div id='name'></div><script>name.innerHTML = location.hash</script>"


def download():
    path = request.args["path"]
    return open(path).read()

