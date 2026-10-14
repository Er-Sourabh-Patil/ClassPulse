import csv, io, os, secrets, string, json, re
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, make_response, g
from werkzeug.security import generate_password_hash, check_password_hash
from config import DATABASE, SECRET_KEY, ADMIN_LOGIN, ADMIN_PASSWORD, DEMO_MODE
from database import get_db, close_db, init_db
from analytics import rows_for_target, summarize
from recommendations import refresh_recommendations

app=Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, DATABASE=DATABASE, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
app.teardown_appcontext(close_db)

# Flask's default cookie session is shared by every tab in one browser. ClassPulse
# uses an opaque per-tab token (stored in sessionStorage and propagated on links/forms)
# to load each tab's authentication state independently from SQLite.
_TAB_TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{32,100}$')

@app.before_request
def load_tab_session():
    if request.endpoint == 'static':
        return None
    token = request.values.get('tab_session') or request.headers.get('X-ClassPulse-Tab')
    if not token or not _TAB_TOKEN_RE.fullmatch(token):
        token = secrets.token_urlsafe(32)
        g.tab_session_token = token
        session.clear()
        session['csrf_token'] = secrets.token_urlsafe(24)
        # Redirect before a view runs so even the very first page request is isolated.
        query = [(k, v) for k, v in request.args.items() if k != 'tab_session']
        query.append(('tab_session', token))
        location = request.path + (('?' + urlencode(query)) if query else '')
        if request.method not in ('GET', 'HEAD'):
            # Forms rendered by the app always carry the token; this is a safe fallback.
            return make_response('Missing tab session. Please reload the page and try again.', 400)
        return redirect(location)
    g.tab_session_token = token
    row = get_db().execute('SELECT session_data FROM tab_sessions WHERE token=?', (token,)).fetchone()
    session.clear()
    if row:
        try:
            data = json.loads(row['session_data'])
            if isinstance(data, dict): session.update(data)
        except (TypeError, ValueError):
            pass
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(24)

@app.after_request
def save_tab_session(response):
    token = getattr(g, 'tab_session_token', None)
    if token:
        try:
            data = json.dumps(dict(session), separators=(',', ':'))
            db = get_db()
            db.execute('INSERT INTO tab_sessions(token,session_data,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) '
                       'ON CONFLICT(token) DO UPDATE SET session_data=excluded.session_data, updated_at=CURRENT_TIMESTAMP',
                       (token, data))
            db.commit()
            # Preserve the tab token through Flask redirects, including post/redirect/get.
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location', '')
                parts = urlsplit(location)
                if location.startswith('/') and not location.startswith('//'):
                    params = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != 'tab_session']
                    params.append(('tab_session', token))
                    response.headers['Location'] = urlunsplit(('', '', parts.path, urlencode(params), parts.fragment))
        except Exception:
            app.logger.exception('Could not persist tab session')
    return response

@app.before_request
def csrf_setup():
    if 'csrf_token' not in session: session['csrf_token']=secrets.token_urlsafe(24)
    # Keep overdue status in sync with deadline and resolution state.
    if request.endpoint and request.endpoint not in ('static','login'):
        try:
            db=get_db(); db.execute("UPDATE activity_assignments SET status='Overdue' WHERE status IN ('Assigned','In Progress') AND id IN (SELECT aa.id FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id WHERE a.deadline IS NOT NULL AND date(a.deadline)<date('now','localtime'))")
            db.commit()
        except Exception: pass

@app.context_processor
def inject_globals():
    return {'csrf_token':session.get('csrf_token',''), 'current_user':session.get('user'), 'current_year':datetime.now().year, 'tab_session_token':getattr(g,'tab_session_token','')}

@app.before_request
def csrf_validate():
    if request.method=='POST':
        supplied=request.form.get('csrf_token','')
        if not supplied or not secrets.compare_digest(supplied,session.get('csrf_token','')):
            abort(400, description='Security token expired or invalid. Refresh the page and try again.')

def login_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if not session.get('user'): return redirect(url_for('login',next=request.path))
        return fn(*args,**kwargs)
    return wrapper

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args,**kwargs):
            if not session.get('user'): return redirect(url_for('login'))
            if session['user']['role'] not in roles: abort(403)
            return fn(*args,**kwargs)
        return wrapper
    return decorator

def audit(action, entity_type, entity_id=None):
    u=session.get('user'); db=get_db()
    db.execute('INSERT INTO audit_logs(user_id,action,entity_type,entity_id) VALUES(?,?,?,?)',(u['id'] if u else None,action,entity_type,entity_id)); db.commit()

def notify(user_id,message):
    if user_id: get_db().execute('INSERT INTO notifications(user_id,message) VALUES(?,?)',(user_id,message))

def make_login_id(name, prefix='STU'):
    base=''.join(c for c in name.upper() if c.isalnum())[:7] or 'USER'
    db=get_db(); candidate=f'{prefix}{base}'
    n=1
    while db.execute('SELECT 1 FROM users WHERE login_id=?',(candidate,)).fetchone():
        n+=1; candidate=f'{prefix}{base}{n}'
    return candidate

def random_password():
    chars=string.ascii_letters+string.digits+'@#$%'
    return ''.join(secrets.choice(chars) for _ in range(12))

def create_user(login_id,password,role):
    db=get_db(); cur=db.execute('INSERT INTO users(login_id,password_hash,role) VALUES(?,?,?)',(login_id,generate_password_hash(password),role)); return cur.lastrowid

def seed_demo():
    """Initialize only the configured admin account; no demo records are seeded."""
    db = get_db()
    if not db.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
        create_user(ADMIN_LOGIN, ADMIN_PASSWORD, 'admin')
        db.commit()


with app.app_context():
    init_db(); seed_demo()

@app.route('/')
def index():
    if not session.get('user'): return redirect(url_for('login'))
    role=session['user']['role']; return redirect(url_for({'admin':'admin_dashboard','student':'student_dashboard','team':'team_dashboard'}[role]))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        login_id=request.form.get('login_id','').strip(); password=request.form.get('password','')
        user=get_db().execute('SELECT * FROM users WHERE login_id=? AND is_active=1',(login_id,)).fetchone()
        # PRN lookup also supports legacy rows until the startup migration is applied.
        if not user:
            user=get_db().execute('SELECT u.* FROM users u JOIN students s ON s.user_id=u.id WHERE s.prn=? AND u.is_active=1',(login_id,)).fetchone()
        if user and check_password_hash(user['password_hash'],password):
            session.clear(); session['csrf_token']=secrets.token_urlsafe(24); session['user']={'id':user['id'],'login_id':user['login_id'],'role':user['role']}
            audit('login','user',user['id'])
            return redirect(url_for({'admin':'admin_dashboard','student':'student_dashboard','team':'team_dashboard'}[user['role']]))
        flash('Invalid login ID or password, or the account is inactive.','danger')
    return render_template('login.html')

@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password','')
        new = request.form.get('new_password','')
        confirm = request.form.get('confirm_password','')
        db = get_db()
        user = db.execute('SELECT password_hash FROM users WHERE id=? AND is_active=1',(session['user']['id'],)).fetchone()
        if not user or not check_password_hash(user['password_hash'], current):
            flash('Current password is incorrect.','danger')
        elif len(new) < 8:
            flash('New password must be at least 8 characters.','danger')
        elif new != confirm:
            flash('New password and confirmation do not match.','danger')
        else:
            db.execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(new),session['user']['id']))
            db.commit(); audit('change_password','user',session['user']['id'])
            flash('Password changed successfully.','success')
            return redirect(url_for('index'))
    return render_template('change_password.html')

@app.post('/logout')
@login_required
def logout():
    audit('logout','user',session['user']['id']); session.clear(); flash('You have been logged out.','success'); return redirect(url_for('login'))

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    db=get_db(); stats={
      'students':db.execute('SELECT COUNT(*) n FROM students s JOIN users u ON u.id=s.user_id WHERE u.is_active=1').fetchone()['n'],
      'teams':db.execute('SELECT COUNT(*) n FROM teams g JOIN users u ON u.id=g.user_id WHERE u.is_active=1').fetchone()['n'],
      'activities':db.execute('SELECT COUNT(*) n FROM activities WHERE is_active=1').fetchone()['n'],
      'pending':db.execute("SELECT COUNT(*) n FROM activity_assignments aa LEFT JOIN evaluations e ON e.assignment_id=aa.id WHERE e.id IS NULL AND aa.status='Submitted'").fetchone()['n'],
      'assigned':db.execute('SELECT COUNT(*) n FROM activity_assignments').fetchone()['n'],
      'completed':db.execute("SELECT COUNT(*) n FROM activity_assignments WHERE status='Completed'").fetchone()['n']}
    stats['completion']=round(stats['completed']/stats['assigned']*100,1) if stats['assigned'] else 0
    recent=db.execute('''SELECT aa.id, a.title, aa.status, aa.assigned_at, aa.target_type, COALESCE(st.full_name,g.team_name) target
      FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id LEFT JOIN students s ON s.id=aa.student_id
      LEFT JOIN users su ON su.id=s.user_id LEFT JOIN students st ON st.id=s.id LEFT JOIN teams g ON g.id=aa.team_id
      ORDER BY aa.assigned_at DESC LIMIT 8''').fetchall()
    cats=db.execute('SELECT category,COUNT(*) n FROM activities WHERE is_active=1 GROUP BY category').fetchall()
    return render_template('admin/dashboard.html',stats=stats,recent=recent,cats=cats)

@app.route('/admin/students',methods=['GET','POST'])
@role_required('admin')
def admin_students():
    db=get_db(); creds=None
    if request.method=='POST':
        action=request.form.get('action','create')
        try:
            if action=='create':
                name=request.form.get('full_name','').strip(); prn=request.form.get('prn','').strip(); batch=request.form.get('batch','').strip()
                if not name or not prn or not batch: raise ValueError('Name, PRN, and batch are required.')
                login_id=prn; password='Welcome@123'; uid=create_user(login_id,password,'student')
                cur=db.execute('INSERT INTO students(user_id,prn,full_name,batch) VALUES(?,?,?,?)',(uid,prn,name,batch)); db.commit(); creds={'login_id':login_id,'password':password,'name':name}; audit('create','student',cur.lastrowid); flash('Student created. Copy the credentials now; the temporary password is shown only once.','success')
            elif action=='edit':
                student_id=int(request.form['student_id']); new_prn=request.form['prn'].strip(); name=request.form['full_name'].strip(); batch_value=request.form['batch'].strip()
                if not new_prn or not name or not batch_value: raise ValueError('Name, PRN and batch are required.')
                student=db.execute('SELECT user_id FROM students WHERE id=?',(student_id,)).fetchone()
                if not student: raise ValueError('Student not found.')
                db.execute('UPDATE students SET full_name=?,prn=?,batch=? WHERE id=?',(name,new_prn,batch_value,student_id))
                db.execute('UPDATE users SET login_id=? WHERE id=?',(new_prn,student['user_id']))
                db.commit(); flash('Student details updated. Login ID now matches the PRN.','success')
            elif action=='toggle':
                db.execute('UPDATE users SET is_active=CASE is_active WHEN 1 THEN 0 ELSE 1 END WHERE id=(SELECT user_id FROM students WHERE id=?)',(request.form['student_id'],)); db.commit(); flash('Student account status updated.','success')
        except Exception as e: db.rollback(); flash('Could not save student: '+str(e),'danger')
    q=request.args.get('q','').strip(); batch=request.args.get('batch','').strip()
    sql='SELECT s.*,u.login_id,u.is_active FROM students s JOIN users u ON u.id=s.user_id WHERE (s.full_name LIKE ? OR s.prn LIKE ? OR u.login_id LIKE ?)'; params=[f'%{q}%',f'%{q}%',f'%{q}%']
    if batch: sql+=' AND s.batch=?'; params.append(batch)
    sql+=' ORDER BY s.full_name'
    students=db.execute(sql,params).fetchall(); batches=db.execute('SELECT DISTINCT batch FROM students ORDER BY batch').fetchall()
    return render_template('admin/students.html',students=students,batches=batches,q=q,batch=batch,credentials=creds)

@app.route('/admin/students/import', methods=['GET', 'POST'])
@role_required('admin')
def admin_students_import():
    """Import student records from CSV and create matching login accounts."""
    result = None
    credentials = []
    if request.method == 'POST':
        uploaded = request.files.get('csv_file')
        default_batch = request.form.get('batch', 'BDA-2026').strip() or 'BDA-2026'
        if not uploaded or not uploaded.filename:
            flash('Choose a CSV file to import.', 'danger')
            return redirect(url_for('admin_students_import'))
        if not uploaded.filename.lower().endswith('.csv'):
            flash('Please upload a .csv file.', 'danger')
            return redirect(url_for('admin_students_import'))
        try:
            content = uploaded.stream.read(2 * 1024 * 1024 + 1)
            if len(content) > 2 * 1024 * 1024:
                raise ValueError('CSV file is too large (maximum 2 MB).')
            text_data = content.decode('utf-8-sig')
            sample = text_data[:4096]
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=',;\t')
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(io.StringIO(text_data), dialect=dialect)
            if not reader.fieldnames:
                raise ValueError('The CSV file is empty or has no header row.')
            headers = {h.strip().lower(): h for h in reader.fieldnames if h}
            prn_col = next((headers[k] for k in ('prn', 'prn number', 'student prn') if k in headers), None)
            name_col = next((headers[k] for k in ('student name', 'full_name', 'full name', 'name') if k in headers), None)
            batch_col = next((headers[k] for k in ('batch', 'batch name') if k in headers), None)
            if not prn_col or not name_col:
                raise ValueError('CSV must contain PRN and Student Name columns. A Batch column is optional.')
            rows = list(reader)
            if len(rows) > 1000:
                raise ValueError('A maximum of 1,000 students can be imported at once.')
            db = get_db()
            seen_prns = set()
            prepared = []
            skipped = []
            for line_no, row in enumerate(rows, start=2):
                prn = (row.get(prn_col) or '').strip()
                name = ' '.join((row.get(name_col) or '').split())
                batch_value = ((row.get(batch_col) or '').strip() if batch_col else '') or default_batch
                if not prn and not name:
                    continue
                if not prn or not name:
                    skipped.append(f'Row {line_no}: PRN or student name is missing.')
                    continue
                if len(prn) > 64 or len(name) > 120 or len(batch_value) > 80:
                    skipped.append(f'Row {line_no}: one or more fields exceed the allowed length.')
                    continue
                if prn in seen_prns:
                    skipped.append(f'Row {line_no}: duplicate PRN {prn} within the CSV.')
                    continue
                seen_prns.add(prn)
                if db.execute('SELECT 1 FROM students WHERE prn=?', (prn,)).fetchone():
                    skipped.append(f'Row {line_no}: PRN {prn} already exists; skipped.')
                    continue
                prepared.append((prn, name, batch_value))
            # All inserts happen in one transaction. A database failure rolls back the batch.
            try:
                for prn, name, batch_value in prepared:
                    login_id = prn
                    password = 'Welcome@123'
                    uid = create_user(login_id, password, 'student')
                    cur = db.execute('INSERT INTO students(user_id,prn,full_name,batch) VALUES(?,?,?,?)',
                                      (uid, prn, name, batch_value))
                    credentials.append({'prn': prn, 'name': name, 'login_id': login_id, 'password': password})
                    db.execute('INSERT INTO audit_logs(user_id,action,entity_type,entity_id) VALUES(?,?,?,?)',
                               (session['user']['id'], 'csv_import', 'student', cur.lastrowid))
                db.commit()
            except Exception:
                db.rollback()
                raise
            result = {'imported': len(credentials), 'skipped': len(skipped), 'messages': skipped}
            if credentials:
                flash(f"Successfully imported {len(credentials)} student(s). Download or copy the generated credentials shown below now.", 'success')
            else:
                flash('No new students were imported. Review the skipped-row details below.', 'warning')
        except (UnicodeDecodeError, csv.Error, ValueError) as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash('Import failed and changes were rolled back. Check for duplicate PRNs or login IDs. Details: ' + str(e), 'danger')
    return render_template('admin/students_import.html', result=result, credentials=credentials)

@app.route('/admin/teams', methods=['GET', 'POST'])
@role_required('admin')
def admin_teams():
    db = get_db()
    credentials = None
    if request.method == 'POST':
        action = request.form.get('action', 'create')
        try:
            if action == 'create':
                name = ' '.join(request.form.get('team_name', '').split())
                if not name:
                    raise ValueError('Team name is required.')
                if len(name) > 100:
                    raise ValueError('Team name must be 100 characters or fewer.')
                if db.execute('SELECT 1 FROM teams WHERE lower(team_name)=lower(?)', (name,)).fetchone():
                    raise ValueError('A team with this name already exists.')
                password = 'Team@123'
                uid = create_user(name, password, 'team')
                cur = db.execute('INSERT INTO teams(team_name, user_id) VALUES(?, ?)', (name, uid))
                team_id = cur.lastrowid
                for sid in request.form.getlist('student_ids'):
                    student = db.execute('SELECT s.id FROM students s JOIN users u ON u.id=s.user_id WHERE s.id=? AND u.is_active=1', (sid,)).fetchone()
                    if not student:
                        raise ValueError('One of the selected students is not active.')
                    already = db.execute('SELECT id FROM team_members WHERE student_id=? AND is_active=1', (sid,)).fetchone()
                    if already:
                        raise ValueError(f'Student ID {sid} already belongs to an active team.')
                    db.execute('INSERT INTO team_members(team_id, student_id) VALUES(?, ?)', (team_id, sid))
                db.commit()
                credentials = {'login_id': name, 'password': password, 'name': name}
                audit('create', 'team', team_id)
                flash('Team created. Login ID is the team name. Copy the default password now.', 'success')
            elif action == 'edit':
                team_id = int(request.form['team_id'])
                name = ' '.join(request.form.get('team_name', '').split())
                if not name:
                    raise ValueError('Team name is required.')
                team = db.execute('SELECT user_id FROM teams WHERE id=?', (team_id,)).fetchone()
                if not team:
                    raise ValueError('Team not found.')
                if db.execute('SELECT 1 FROM teams WHERE lower(team_name)=lower(?) AND id<>?', (name, team_id)).fetchone():
                    raise ValueError('Another team already uses this name.')
                if db.execute('SELECT 1 FROM users WHERE login_id=? AND id<>?', (name, team['user_id'])).fetchone():
                    raise ValueError('This team name is already used by another login.')
                db.execute('UPDATE teams SET team_name=? WHERE id=?', (name, team_id))
                db.execute('UPDATE users SET login_id=? WHERE id=?', (name, team['user_id']))
                db.commit()
                flash('Team updated. Login ID now matches the team name.', 'success')
            elif action == 'members':
                team_id = int(request.form['team_id'])
                if not db.execute('SELECT id FROM teams WHERE id=?', (team_id,)).fetchone():
                    raise ValueError('Team not found.')
                selected = set(request.form.getlist('student_ids'))
                current = db.execute('SELECT student_id FROM team_members WHERE team_id=? AND is_active=1', (team_id,)).fetchall()
                current_ids = {str(r['student_id']) for r in current}
                for sid in current_ids - selected:
                    db.execute('UPDATE team_members SET is_active=0 WHERE team_id=? AND student_id=?', (team_id, sid))
                for sid in selected - current_ids:
                    already = db.execute('SELECT id FROM team_members WHERE student_id=? AND is_active=1', (sid,)).fetchone()
                    if already:
                        raise ValueError(f'Student ID {sid} already belongs to an active team.')
                    db.execute('INSERT INTO team_members(team_id, student_id) VALUES(?, ?)', (team_id, sid))
                db.commit()
                flash('Team membership updated.', 'success')
            elif action == 'delete':
                team_id = int(request.form['team_id'])
                team = db.execute('SELECT user_id FROM teams WHERE id=?', (team_id,)).fetchone()
                if not team:
                    raise ValueError('Team not found.')
                db.execute('UPDATE users SET is_active=0 WHERE id=?', (team['user_id'],))
                db.execute('UPDATE team_members SET is_active=0 WHERE team_id=?', (team_id,))
                db.commit()
                flash('Team deactivated; historical records have been preserved.', 'success')
            else:
                raise ValueError('Unknown team action.')
        except Exception as exc:
            db.rollback()
            flash('Could not save team: ' + str(exc), 'danger')
    teams = db.execute('''SELECT t.*, u.login_id, u.is_active,
        (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id=t.id AND tm.is_active=1) AS member_count
        FROM teams t JOIN users u ON u.id=t.user_id ORDER BY t.team_name''').fetchall()
    students = db.execute('''SELECT s.id,s.full_name,s.prn,s.batch,tm.team_id FROM students s
        JOIN users u ON u.id=s.user_id LEFT JOIN team_members tm ON tm.student_id=s.id AND tm.is_active=1
        WHERE u.is_active=1 ORDER BY s.full_name''').fetchall()
    members = {t['id']: db.execute('''SELECT s.id,s.full_name,s.prn FROM team_members tm
        JOIN students s ON s.id=tm.student_id WHERE tm.team_id=? AND tm.is_active=1 ORDER BY s.full_name''', (t['id'],)).fetchall() for t in teams}
    return render_template('admin/teams.html', teams=teams, students=students, members=members, credentials=credentials)

@app.route('/admin/activities',methods=['GET','POST'])
@role_required('admin')
def admin_activities():
    db=get_db()
    if request.method=='POST':
        try:
            action=request.form.get('action','create')
            if action=='create':
                title=request.form.get('title','').strip(); desc=request.form.get('description','').strip(); cat=request.form.get('category'); diff=request.form.get('difficulty'); marks=float(request.form.get('max_marks','0')); deadline=request.form.get('deadline') or None
                if not title or cat not in ('Technical','Communication','Cultural','Sports') or marks<=0: raise ValueError('Enter a title, valid category, and positive maximum marks.')
                db.execute('INSERT INTO activities(title,description,category,difficulty,max_marks,deadline,created_by) VALUES(?,?,?,?,?,?,?)',(title,desc,cat,diff,marks,deadline,session['user']['id'])); db.commit(); flash('Activity created.','success')
            elif action=='edit':
                marks=float(request.form['max_marks']); category=request.form.get('category',''); title=request.form.get('title','').strip()
                if marks<=0 or not title: raise ValueError('Title and positive maximum marks are required.')
                if category not in ('Technical','Communication','Cultural','Sports'): raise ValueError('Choose a valid activity category.')
                db.execute('UPDATE activities SET title=?,description=?,category=?,difficulty=?,max_marks=?,deadline=? WHERE id=?',(title,request.form.get('description','').strip(),category,request.form.get('difficulty','Beginner'),marks,request.form.get('deadline') or None,request.form['activity_id'])); db.commit(); flash('Activity updated.','success')
            elif action=='toggle':
                db.execute('UPDATE activities SET is_active=CASE is_active WHEN 1 THEN 0 ELSE 1 END WHERE id=?',(request.form['activity_id'],)); db.commit(); flash('Activity status updated.','success')
        except Exception as e: db.rollback(); flash('Could not save activity: '+str(e),'danger')
    activities=db.execute('SELECT * FROM activities ORDER BY created_at DESC').fetchall()
    return render_template('admin/activities.html',activities=activities)

@app.route('/admin/assignments',methods=['GET','POST'])
@role_required('admin')
def admin_assignments():
    db=get_db()
    if request.method=='POST':
        try:
            aid=int(request.form['activity_id']); target=request.form['target_type']; tid=int(request.form['target_id'])
            activity=db.execute('SELECT id FROM activities WHERE id=? AND is_active=1',(aid,)).fetchone()
            if not activity: raise ValueError('Select an active activity.')
            if target=='student':
                target_row=db.execute('SELECT s.user_id FROM students s JOIN users u ON u.id=s.user_id WHERE s.id=? AND u.is_active=1',(tid,)).fetchone()
                if not target_row: raise ValueError('Select an active student.')
                db.execute("INSERT INTO activity_assignments(activity_id,target_type,student_id,status) VALUES(?,'student',?,'Assigned')",(aid,tid))
                notify(target_row['user_id'],'A new activity has been assigned to you.')
            elif target=='team':
                target_row=db.execute('SELECT g.user_id FROM teams g JOIN users u ON u.id=g.user_id WHERE g.id=? AND u.is_active=1',(tid,)).fetchone()
                if not target_row: raise ValueError('Select an active team.')
                db.execute("INSERT INTO activity_assignments(activity_id,target_type,team_id,status) VALUES(?,'team',?,'Assigned')",(aid,tid))
                notify(target_row['user_id'],'A new activity has been assigned to your team.')
            else: raise ValueError('Choose a valid assignment target.')
            db.commit(); flash('Activity assigned successfully.','success'); audit('assign','activity',aid)
        except Exception as e: db.rollback(); flash('Assignment failed (it may already exist): '+str(e),'danger')
    assignments=db.execute('''SELECT aa.*,a.title,a.category,a.deadline,COALESCE(s.full_name,g.team_name) target_name,
      e.id evaluation_id,sub.id submission_id FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id
      LEFT JOIN students s ON s.id=aa.student_id LEFT JOIN teams g ON g.id=aa.team_id
      LEFT JOIN evaluations e ON e.assignment_id=aa.id LEFT JOIN submissions sub ON sub.assignment_id=aa.id ORDER BY aa.assigned_at DESC''').fetchall()
    activities=db.execute('SELECT id,title,category FROM activities WHERE is_active=1 ORDER BY title').fetchall(); students=db.execute('SELECT s.id AS id, s.full_name AS full_name, s.prn AS prn FROM students AS s JOIN users AS u ON u.id=s.user_id WHERE u.is_active=1 ORDER BY s.full_name').fetchall(); teams=db.execute('SELECT g.id,g.team_name FROM teams g JOIN users u ON u.id=g.user_id WHERE u.is_active=1 ORDER BY g.team_name').fetchall()
    return render_template('admin/assignments.html',assignments=assignments,activities=activities,students=students,teams=teams)

@app.route('/admin/evaluations',methods=['GET','POST'])
@role_required('admin')
def admin_evaluations():
    db=get_db()
    if request.method=='POST':
        try:
            aid=int(request.form['assignment_id']); assignment=db.execute('SELECT aa.*,a.max_marks,a.title FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id WHERE aa.id=?',(aid,)).fetchone()
            if not assignment: raise ValueError('Assignment not found.')
            score=float(request.form['score']); max_marks=float(assignment['max_marks'])
            if score<0 or score>max_marks: raise ValueError(f'Marks must be between 0 and {max_marks}.')
            feedback=request.form.get('feedback','').strip(); existing=db.execute('SELECT id FROM evaluations WHERE assignment_id=?',(aid,)).fetchone()
            if assignment['target_type']=='team':
                if existing: db.execute('UPDATE evaluations SET team_score=?,individual_score=NULL,feedback=?,evaluated_by=?,updated_at=CURRENT_TIMESTAMP,evaluated_at=CURRENT_TIMESTAMP WHERE assignment_id=?',(score,feedback,session['user']['id'],aid))
                else: db.execute('INSERT INTO evaluations(assignment_id,team_score,feedback,evaluated_by) VALUES(?,?,?,?)',(aid,score,feedback,session['user']['id']))
                team= db.execute('SELECT user_id FROM teams WHERE id=?',(assignment['team_id'],)).fetchone(); notify(team['user_id'],'Your team activity has been evaluated.')
            else:
                if existing: db.execute('UPDATE evaluations SET student_id=?,individual_score=?,team_score=NULL,feedback=?,evaluated_by=?,updated_at=CURRENT_TIMESTAMP,evaluated_at=CURRENT_TIMESTAMP WHERE assignment_id=?',(assignment['student_id'],score,feedback,session['user']['id'],aid))
                else: db.execute('INSERT INTO evaluations(assignment_id,student_id,individual_score,feedback,evaluated_by) VALUES(?,?,?,?,?)',(aid,assignment['student_id'],score,feedback,session['user']['id']))
                uid=db.execute('SELECT user_id FROM students WHERE id=?',(assignment['student_id'],)).fetchone()['user_id']; notify(uid,'Your activity has been evaluated. Check your feedback.')
            db.execute("UPDATE activity_assignments SET status='Completed' WHERE id=?",(aid,)); db.execute("UPDATE submissions SET status='Reviewed' WHERE assignment_id=?",(aid,)); db.commit(); flash('Evaluation saved.','success'); audit('evaluate','assignment',aid)
        except Exception as e: db.rollback(); flash('Could not save evaluation: '+str(e),'danger')
    rows=db.execute('''SELECT aa.id assignment_id,aa.target_type,aa.status,a.title,a.category,a.max_marks,a.deadline,
      COALESCE(st.full_name,g.team_name) target_name,sub.submission_text,sub.submission_url,sub.submitted_at,
      e.team_score,e.individual_score,e.feedback,e.updated_at FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id
      LEFT JOIN students st ON st.id=aa.student_id LEFT JOIN teams g ON g.id=aa.team_id LEFT JOIN submissions sub ON sub.assignment_id=aa.id
      LEFT JOIN evaluations e ON e.assignment_id=aa.id ORDER BY CASE WHEN sub.id IS NOT NULL AND e.id IS NULL THEN 0 ELSE 1 END,aa.assigned_at DESC''').fetchall()
    return render_template('admin/evaluations.html',rows=rows)

@app.route('/admin/analytics')
@role_required('admin')
def admin_analytics():
    period=request.args.get('period','weekly'); period='monthly' if period=='monthly' else 'weekly'; data=summarize(rows_for_target('admin',session['user']['id'],period))
    db=get_db(); team_rows=db.execute('''SELECT g.team_name,COUNT(aa.id) assigned,SUM(CASE WHEN aa.status='Completed' THEN 1 ELSE 0 END) completed,
      ROUND(AVG(COALESCE(e.team_score,0)),2) average FROM teams g LEFT JOIN activity_assignments aa ON aa.team_id=g.id
      LEFT JOIN evaluations e ON e.assignment_id=aa.id GROUP BY g.id ORDER BY g.team_name''').fetchall()
    batch_rows=db.execute('''SELECT s.batch,COUNT(DISTINCT s.id) students,ROUND(AVG(COALESCE(e.individual_score,0)),2) average FROM students s
      LEFT JOIN activity_assignments aa ON aa.student_id=s.id LEFT JOIN evaluations e ON e.assignment_id=aa.id GROUP BY s.batch''').fetchall()
    return render_template('admin/analytics.html',data=data,period=period,team_rows=team_rows,batch_rows=batch_rows)

@app.route('/admin/recommendations')
@role_required('admin')
def admin_recommendations():
    refresh_recommendations(); db=get_db()
    rows=db.execute('''SELECT r.*,u.login_id,s.full_name,g.team_name FROM recommendations r LEFT JOIN users u ON u.id=r.user_id
      LEFT JOIN students s ON s.user_id=r.user_id LEFT JOIN teams g ON g.id=r.team_id ORDER BY r.created_at DESC''').fetchall()
    return render_template('admin/recommendations.html',rows=rows)

@app.post('/recommendations/<int:rid>/<action>')
@login_required
def update_recommendation(rid,action):
    if action not in ('Completed','Dismissed'): abort(404)
    db=get_db(); rec=db.execute('SELECT * FROM recommendations WHERE id=?',(rid,)).fetchone()
    if not rec: abort(404)
    user=session['user']
    if user['role']!='admin' and rec['user_id']!=user['id'] and not (user['role']=='team' and rec['team_id'] and db.execute('SELECT id FROM teams WHERE id=? AND user_id=?',(rec['team_id'],user['id'])).fetchone()): abort(403)
    db.execute('UPDATE recommendations SET status=? WHERE id=?',(action,rid)); db.commit(); flash('Recommendation updated.','success')
    return redirect(request.referrer or url_for('index'))

@app.route('/admin/reports')
@role_required('admin')
def admin_reports():
    db=get_db(); counts={'students':db.execute('SELECT COUNT(*) n FROM students').fetchone()['n'],'assignments':db.execute('SELECT COUNT(*) n FROM activity_assignments').fetchone()['n'],'evaluations':db.execute('SELECT COUNT(*) n FROM evaluations').fetchone()['n']}
    return render_template('admin/reports.html',counts=counts)

@app.route('/admin/reports/export.csv')
@role_required('admin')
def export_csv():
    db=get_db(); rows=db.execute('''SELECT aa.id assignment_id,aa.target_type,COALESCE(s.full_name,g.team_name) target,a.title activity,a.category,a.max_marks,
      aa.status,aa.assigned_at,a.deadline,sub.submitted_at,COALESCE(e.team_score,e.individual_score) score,e.feedback,e.evaluated_at
      FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id LEFT JOIN students s ON s.id=aa.student_id LEFT JOIN teams g ON g.id=aa.team_id
      LEFT JOIN submissions sub ON sub.assignment_id=aa.id LEFT JOIN evaluations e ON e.assignment_id=aa.id ORDER BY aa.assigned_at DESC''').fetchall()
    output=io.StringIO(); writer=csv.writer(output); writer.writerow(rows[0].keys() if rows else ['assignment_id','target_type','target','activity','category','max_marks','status','assigned_at','deadline','submitted_at','score','feedback','evaluated_at'])
    for row in rows: writer.writerow([row[k] for k in row.keys()])
    response=make_response(output.getvalue()); response.headers['Content-Type']='text/csv; charset=utf-8'; response.headers['Content-Disposition']='attachment; filename=classpulse_report.csv'; return response

# Shared personal/team activity pages

def get_student_id(user_id):
    row=get_db().execute('SELECT id FROM students WHERE user_id=?',(user_id,)).fetchone(); return row['id'] if row else None

def get_team_id(user_id):
    row=get_db().execute('SELECT id FROM teams WHERE user_id=?',(user_id,)).fetchone(); return row['id'] if row else None

def role_activity_rows(role,user_id,only_team=False):
    db=get_db()
    if role=='student':
        sid=get_student_id(user_id)
        if not sid:return []
        condition='aa.team_id IN (SELECT team_id FROM team_members WHERE student_id=? AND is_active=1)' if only_team else '(aa.student_id=? OR aa.team_id IN (SELECT team_id FROM team_members WHERE student_id=? AND is_active=1))'
        params=(sid,) if only_team else (sid,sid)
        return db.execute(f'''SELECT aa.*,a.title,a.description,a.category,a.difficulty,a.max_marks,a.deadline,
          sub.submission_text,sub.submission_url,sub.submitted_at,e.individual_score,e.team_score,e.feedback,e.evaluated_at,
          COALESCE(g.team_name,'') team_name FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id
          LEFT JOIN submissions sub ON sub.assignment_id=aa.id LEFT JOIN evaluations e ON e.assignment_id=aa.id
          LEFT JOIN teams g ON g.id=aa.team_id WHERE {condition} ORDER BY aa.assigned_at DESC''',params).fetchall()
    gid=get_team_id(user_id)
    if not gid:return []
    return db.execute('''SELECT aa.*,a.title,a.description,a.category,a.difficulty,a.max_marks,a.deadline,sub.submission_text,sub.submission_url,
      sub.submitted_at,e.team_score,e.feedback,e.evaluated_at,g.team_name FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id
      LEFT JOIN submissions sub ON sub.assignment_id=aa.id LEFT JOIN evaluations e ON e.assignment_id=aa.id LEFT JOIN teams g ON g.id=aa.team_id
      WHERE aa.team_id=? ORDER BY aa.assigned_at DESC''',(gid,)).fetchall()

def render_role_dashboard(role):
    user=session['user']; period=request.args.get('period','weekly'); period='monthly' if period=='monthly' else 'weekly'
    data=summarize(rows_for_target(role,user['id'],period)); db=get_db()
    rows=role_activity_rows(role,user['id'])
    if role=='student':
        recommendations= db.execute("SELECT * FROM recommendations WHERE user_id=? AND status='Active' ORDER BY created_at DESC",(user['id'],)).fetchall()
        student_id=get_student_id(user['id']); profile=db.execute('SELECT * FROM students WHERE id=?',(student_id,)).fetchone() if student_id else None
        team_members=[]
    else:
        gid=get_team_id(user['id']); recommendations=db.execute("SELECT * FROM recommendations WHERE team_id=? AND status='Active' ORDER BY created_at DESC",(gid,)).fetchall()
        profile=db.execute('SELECT * FROM teams WHERE id=?',(gid,)).fetchone() if gid else None
        team_members=db.execute('SELECT s.full_name,s.prn,s.batch FROM team_members gm JOIN students s ON s.id=gm.student_id WHERE gm.team_id=? AND gm.is_active=1 ORDER BY s.full_name',(gid,)).fetchall() if gid else []
    return render_template(f'{role}/dashboard.html',data=data,period=period,rows=rows,recommendations=recommendations,profile=profile,team_members=team_members)

@app.route('/student/dashboard')
@role_required('student')
def student_dashboard(): return render_role_dashboard('student')
@app.route('/team/dashboard')
@role_required('team')
def team_dashboard(): return render_role_dashboard('team')

@app.route('/student/activities')
@role_required('student')
def student_activities():
    rows=role_activity_rows('student',session['user']['id']); return render_template('student/activities.html',rows=rows,title='My Activities',team_only=False)
@app.route('/student/team-activities')
@role_required('student')
def student_team_activities():
    rows=role_activity_rows('student',session['user']['id'],True); return render_template('student/activities.html',rows=rows,title='team Activities',team_only=True)
@app.route('/student/history')
@role_required('student')
def student_history():
    rows=role_activity_rows('student',session['user']['id']); return render_template('student/activities.html',rows=rows,title='Activity History',history=True)
@app.route('/student/performance')
@role_required('student')
def student_performance():
    period=request.args.get('period','weekly'); period='monthly' if period=='monthly' else 'weekly'; data=summarize(rows_for_target('student',session['user']['id'],period)); return render_template('student/performance.html',data=data,period=period)
@app.route('/student/recommendations')
@role_required('student')
def student_recommendations():
    refresh_recommendations(); rows=get_db().execute("SELECT * FROM recommendations WHERE user_id=? ORDER BY created_at DESC",(session['user']['id'],)).fetchall(); return render_template('student/recommendations.html',rows=rows)
@app.route('/team/members')
@role_required('team')
def team_members_page():
    gid=get_team_id(session['user']['id']); rows=get_db().execute('SELECT s.full_name,s.prn,s.batch,gm.joined_at FROM team_members gm JOIN students s ON s.id=gm.student_id WHERE gm.team_id=? AND gm.is_active=1 ORDER BY s.full_name',(gid,)).fetchall(); return render_template('team/members.html',rows=rows)
@app.route('/team/activities')
@role_required('team')
def team_activities(): return render_template('student/activities.html',rows=role_activity_rows('team',session['user']['id']),title='Assigned team Activities')
@app.route('/team/history')
@role_required('team')
def team_history(): return render_template('student/activities.html',rows=role_activity_rows('team',session['user']['id']),title='team Activity History',history=True)
@app.route('/team/performance')
@role_required('team')
def team_performance():
    period=request.args.get('period','weekly'); period='monthly' if period=='monthly' else 'weekly'; data=summarize(rows_for_target('team',session['user']['id'],period)); return render_template('student/performance.html',data=data,period=period)
@app.route('/team/recommendations')
@role_required('team')
def team_recommendations():
    refresh_recommendations(); gid=get_team_id(session['user']['id']); rows=get_db().execute('SELECT * FROM recommendations WHERE team_id=? ORDER BY created_at DESC',(gid,)).fetchall(); return render_template('student/recommendations.html',rows=rows)

@app.post('/assignment/<int:assignment_id>/submit')
@login_required
def submit_assignment(assignment_id):
    user=session['user']; db=get_db(); assignment=db.execute('SELECT * FROM activity_assignments WHERE id=?',(assignment_id,)).fetchone()
    if not assignment: abort(404)
    allowed=False
    if user['role']=='student':
        sid=get_student_id(user['id']); allowed=bool(sid and ((assignment['target_type']=='student' and assignment['student_id']==sid) or (assignment['target_type']=='team' and db.execute('SELECT id FROM team_members WHERE student_id=? AND team_id=? AND is_active=1',(sid,assignment['team_id'])).fetchone())))
    elif user['role']=='team': allowed=bool(assignment['target_type']=='team' and assignment['team_id']==get_team_id(user['id']))
    if not allowed: abort(403)
    if db.execute('SELECT id FROM evaluations WHERE assignment_id=?',(assignment_id,)).fetchone(): flash('This activity has already been evaluated; submissions are closed.','warning')
    else:
        text=request.form.get('submission_text','').strip(); link=request.form.get('submission_url','').strip()
        if not text and not link: flash('Add a short submission note or a URL before submitting.','danger')
        elif link and not (link.startswith('https://') or link.startswith('http://')): flash('Submission URL must start with http:// or https://.','danger')
        else:
            db.execute('''INSERT INTO submissions(assignment_id,submitted_by,submission_text,submission_url,status) VALUES(?,?,?,?, 'Submitted')
              ON CONFLICT(assignment_id) DO UPDATE SET submitted_by=excluded.submitted_by,submission_text=excluded.submission_text,submission_url=excluded.submission_url,submitted_at=CURRENT_TIMESTAMP,status='Submitted' ''',(assignment_id,user['id'],text,link))
            db.execute("UPDATE activity_assignments SET status='Submitted' WHERE id=?",(assignment_id,)); db.commit(); flash('Submission sent for review.','success'); audit('submit','assignment',assignment_id)
    return redirect(request.referrer or url_for('index'))

@app.post('/assignment/<int:assignment_id>/start')
@login_required
def start_assignment(assignment_id):
    user=session['user']; db=get_db(); a=db.execute('SELECT * FROM activity_assignments WHERE id=?',(assignment_id,)).fetchone()
    if not a: abort(404)
    allowed=False
    if user['role']=='student':
        sid=get_student_id(user['id']); allowed=bool(sid and ((a['target_type']=='student' and a['student_id']==sid) or (a['target_type']=='team' and db.execute('SELECT id FROM team_members WHERE student_id=? AND team_id=? AND is_active=1',(sid,a['team_id'])).fetchone())))
    elif user['role']=='team': allowed=bool(a['target_type']=='team' and a['team_id']==get_team_id(user['id']))
    if not allowed: abort(403)
    if a['status']=='Assigned': db.execute("UPDATE activity_assignments SET status='In Progress' WHERE id=?",(assignment_id,)); db.commit(); flash('Activity marked as in progress.','success')
    return redirect(request.referrer or url_for('index'))

@app.route('/notifications')
@login_required
def notifications_page():
    db=get_db(); rows=db.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100',(session['user']['id'],)).fetchall(); db.execute('UPDATE notifications SET is_read=1 WHERE user_id=?',(session['user']['id'],)); db.commit(); return render_template('notifications.html',rows=rows)

@app.errorhandler(403)
def forbidden(_): return render_template('error.html',code=403,message='You do not have permission to access this page.'),403
@app.errorhandler(404)
def not_found(_): return render_template('error.html',code=404,message='The page or record could not be found.'),404
@app.errorhandler(400)
def bad_request(err): return render_template('error.html',code=400,message=getattr(err,'description','Invalid request.')),400


if __name__ == '__main__':
    app.run(
        debug=os.environ.get('FLASK_DEBUG', '0') == '1',
        host=os.environ.get('HOST', '0.0.0.0'),  # Changed '127.0.0.1' to '0.0.0.0'
        port=int(os.environ.get('PORT', '5000'))
    )