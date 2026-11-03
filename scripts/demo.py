"""Safe in-process demonstration; no external host contacted."""
import json
from fastapi.testclient import TestClient
from app.main import create_app

def run(vulnerable):
    c = TestClient(create_app(vulnerable=vulnerable))
    login = c.post('/login', json={'username': 'alice', 'password': 'alice-demo'})
    h = {'Authorization': 'Bearer ' + login.json()['access_token']}
    access = c.get('/users/bob', headers=h).status_code
    mass = c.patch('/users/alice', headers=h, json={'display_name': 'Alice', 'role': 'admin'}).status_code
    rates = [c.post('/login', headers={'X-Forwarded-For': f'203.0.113.{i+1}'}, json={'username': 'bob', 'password': 'invalid'}).status_code for i in range(5)]
    return {'mode': 'vulnerable' if vulnerable else 'hardened', 'cross_user_read': access, 'mass_assignment': mass, 'login_attempts': rates}

if __name__ == '__main__':
    print(json.dumps([run(True), run(False)], indent=2))
