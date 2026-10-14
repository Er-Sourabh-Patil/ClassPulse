import os
import tempfile
import unittest
from app import app, seed_demo
from database import init_db, get_db

class ClassPulseTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, 'test.db')
        app.config.update(TESTING=True, DATABASE=self.db_path, WTF_CSRF_ENABLED=False)
        with app.app_context():
            init_db()
            seed_demo()
        self.client = app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def token(self):
        with self.client.session_transaction() as sess:
            return sess.get('csrf_token')

    def login(self, login_id, password):
        self.client.get('/login')
        return self.client.post('/login', data={
            'csrf_token': self.token(), 'login_id': login_id, 'password': password
        }, follow_redirects=False)

    def create_student(self, prn='260840325001', name='Test Student'):
        self.login('admin', 'Admin@12345')
        response = self.client.post('/admin/students', data={
            'csrf_token': self.token(), 'action': 'create', 'prn': prn,
            'full_name': name, 'batch': 'BDA-2026'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def create_activity(self, title='Team SQL Task'):
        response = self.client.post('/admin/activities', data={
            'csrf_token': self.token(), 'action': 'create', 'title': title,
            'description': 'Test activity', 'category': 'Technical',
            'difficulty': 'Beginner', 'max_marks': '20', 'deadline': '2099-12-31'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with app.app_context():
            return get_db().execute('SELECT id FROM activities WHERE title=?', (title,)).fetchone()['id']

    def test_fresh_database_has_no_demo_records(self):
        with app.app_context():
            db = get_db()
            self.assertEqual(db.execute('SELECT COUNT(*) n FROM students').fetchone()['n'], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) n FROM teams').fetchone()['n'], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) n FROM activities').fetchone()['n'], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) n FROM users WHERE role="admin"').fetchone()['n'], 1)

    def test_admin_login_and_role_redirect(self):
        response = self.login('admin', 'Admin@12345')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/admin/dashboard')

    def test_student_prn_login_and_default_password(self):
        self.create_student()
        self.client.post('/logout', data={'csrf_token': self.token()})
        response = self.login('260840325001', 'Welcome@123')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/student/dashboard')

    def test_team_name_login_default_password_and_dashboard(self):
        self.login('admin', 'Admin@12345')
        response = self.client.post('/admin/teams', data={
            'csrf_token': self.token(), 'action': 'create', 'team_name': 'Team Alpha'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.client.post('/logout', data={'csrf_token': self.token()})
        response = self.login('Team Alpha', 'Team@123')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/team/dashboard')
        self.assertEqual(self.client.get('/team/dashboard').status_code, 200)

    def test_admin_can_assign_activity_to_team(self):
        self.login('admin', 'Admin@12345')
        self.client.post('/admin/teams', data={
            'csrf_token': self.token(), 'action': 'create', 'team_name': 'Team Beta'
        }, follow_redirects=True)
        activity_id = self.create_activity()
        with app.app_context():
            team_id = get_db().execute('SELECT id FROM teams WHERE team_name=?', ('Team Beta',)).fetchone()['id']
        response = self.client.post('/admin/assignments', data={
            'csrf_token': self.token(), 'activity_id': str(activity_id),
            'target_type': 'team', 'target_id': str(team_id)
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with app.app_context():
            count = get_db().execute('SELECT COUNT(*) n FROM activity_assignments WHERE activity_id=? AND team_id=?', (activity_id, team_id)).fetchone()['n']
            self.assertEqual(count, 1)

    def test_all_activity_categories_are_supported(self):
        self.login('admin', 'Admin@12345')
        for category in ('Technical', 'Communication', 'Cultural', 'Sports'):
            response = self.client.post('/admin/activities', data={
                'csrf_token': self.token(), 'action': 'create', 'title': category,
                'description': 'Test', 'category': category, 'difficulty': 'Beginner',
                'max_marks': '10', 'deadline': '2099-12-31'
            }, follow_redirects=True)
            self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
