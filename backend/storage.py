import sqlite3, os, uuid
DB=os.getenv("CASE_DB","/data/phishlens.db")
def init():
    os.makedirs(os.path.dirname(DB),exist_ok=True)
    with sqlite3.connect(DB) as c:
        c.execute("create table if not exists cases(id text primary key, title text, notes text, created text default current_timestamp)")
def save_case(title,notes):
    cid=str(uuid.uuid4())[:8].upper()
    with sqlite3.connect(DB) as c: c.execute("insert into cases(id,title,notes) values(?,?,?)",(cid,title,notes))
    return cid
def list_cases():
    with sqlite3.connect(DB) as c:
        return [{"id":r[0],"title":r[1],"notes":r[2],"created":r[3]} for r in c.execute("select id,title,notes,created from cases order by created desc")]
