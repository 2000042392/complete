import argparse
from app.database import init_db, connection

parser=argparse.ArgumentParser(description="Promote an existing Zaalima account to administrator.")
parser.add_argument("username")
args=parser.parse_args()
init_db()
with connection() as db:
    cursor=db.execute("UPDATE users SET role='admin' WHERE username=?",(args.username,))
    if cursor.rowcount != 1:
        raise SystemExit("No account found with that username. Register the account first.")
print(f"Administrator role granted to {args.username!r}.")
