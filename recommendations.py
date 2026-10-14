from database import get_db


def refresh_recommendations():
    db=get_db()
    # Keep only one active recommendation per recipient/reason; use recent evaluated records.
    students=db.execute('SELECT s.id,s.user_id,s.full_name FROM students s JOIN users u ON u.id=s.user_id WHERE u.is_active=1').fetchall()
    for st in students:
        rows=db.execute('''SELECT a.category,e.individual_score,a.max_marks,aa.status,a.deadline FROM activity_assignments aa
          JOIN activities a ON a.id=aa.activity_id LEFT JOIN evaluations e ON e.assignment_id=aa.id
          WHERE aa.student_id=? ORDER BY aa.assigned_at DESC LIMIT 12''',(st['id'],)).fetchall()
        technical=[r for r in rows if r['category']=='Technical' and r['individual_score'] is not None]
        comm=[r for r in rows if r['category']=='Communication' and r['individual_score'] is not None]
        ideas=[]
        if technical and sum(r['individual_score']/r['max_marks'] for r in technical)/len(technical)<.65:
            ideas.append(('Technical practice','Recent technical scores suggest that short coding or SQL exercises could help reinforce fundamentals.'))
        if comm and sum(r['individual_score']/r['max_marks'] for r in comm)/len(comm)<.65:
            ideas.append(('Communication practice','Try a short presentation or structured team discussion to practise clear communication.'))
        if sum(1 for r in rows if r['status']=='Overdue') >= 2:
            ideas.append(('Time management','Break upcoming work into smaller time-boxed steps and submit an early draft.'))
        if not ideas and len(rows)>=3:
            ideas.append(('Stretch activity','Build on recent participation with an advanced challenge or a short peer-teaching activity.'))
        for title,reason in ideas:
            exists=db.execute("SELECT id FROM recommendations WHERE user_id=? AND team_id IS NULL AND reason=? AND status='Active'",(st['user_id'],reason)).fetchone()
            if not exists: db.execute('INSERT INTO recommendations(user_id,reason,status) VALUES(?,?,\'Active\')',(st['user_id'],reason))
    teams=db.execute('SELECT id,team_name FROM teams').fetchall()
    for gr in teams:
        count=db.execute("SELECT COUNT(*) n FROM activity_assignments WHERE team_id=? AND status IN ('Assigned','In Progress','Overdue')",(gr['id'],)).fetchone()['n']
        if count>=2:
            reason='Try a structured collaborative task with rotating roles so every member has a clear contribution.'
            exists=db.execute("SELECT id FROM recommendations WHERE team_id=? AND reason=? AND status='Active'",(gr['id'],reason)).fetchone()
            if not exists: db.execute('INSERT INTO recommendations(team_id,reason,status) VALUES(?,?,\'Active\')',(gr['id'],reason))
    db.commit()
