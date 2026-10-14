from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from database import get_db


def period_start(period):
    now = datetime.now()
    if period == 'monthly':
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).strftime('%Y-%m-%d %H:%M:%S')
    return (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y-%m-%d %H:%M:%S')


def rows_for_target(role, entity_id, period='weekly'):
    db = get_db()
    start = period_start(period)
    if role == 'admin':
        rows = db.execute('''SELECT aa.id assignment_id, aa.status, aa.assigned_at, a.category, a.max_marks, a.deadline,
          e.team_score, e.individual_score, e.evaluated_at, s.submitted_at, st.batch, st.full_name,
          g.team_name, aa.target_type FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id
          LEFT JOIN evaluations e ON e.assignment_id=aa.id LEFT JOIN submissions s ON s.assignment_id=aa.id
          LEFT JOIN students st ON st.id=aa.student_id LEFT JOIN teams g ON g.id=aa.team_id
          WHERE aa.assigned_at >= ? ORDER BY aa.assigned_at''', (start,)).fetchall()
    elif role == 'student':
        student = db.execute('SELECT id FROM students WHERE user_id=?', (entity_id,)).fetchone()
        if not student: return []
        rows = db.execute('''SELECT aa.id assignment_id, aa.status, aa.assigned_at, a.category, a.max_marks, a.deadline,
          CASE WHEN aa.target_type='student' THEN e.individual_score ELSE NULL END AS individual_score, NULL AS team_score, e.evaluated_at, sub.submitted_at, st.batch, st.full_name, g.team_name, aa.target_type
          FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id
          LEFT JOIN evaluations e ON e.assignment_id=aa.id LEFT JOIN submissions sub ON sub.assignment_id=aa.id
          LEFT JOIN students st ON st.id=aa.student_id LEFT JOIN teams g ON g.id=aa.team_id
          WHERE (aa.student_id=? OR aa.team_id IN (SELECT team_id FROM team_members WHERE student_id=? AND is_active=1))
          AND aa.assigned_at >= ? ORDER BY aa.assigned_at''', (student['id'], student['id'], start)).fetchall()
    else:
        grp = db.execute('SELECT id FROM teams WHERE user_id=?', (entity_id,)).fetchone()
        if not grp: return []
        rows = db.execute('''SELECT aa.id assignment_id, aa.status, aa.assigned_at, a.category, a.max_marks, a.deadline,
          e.team_score, e.evaluated_at, sub.submitted_at, g.team_name, aa.target_type
          FROM activity_assignments aa JOIN activities a ON a.id=aa.activity_id LEFT JOIN evaluations e ON e.assignment_id=aa.id
          LEFT JOIN submissions sub ON sub.assignment_id=aa.id LEFT JOIN teams g ON g.id=aa.team_id
          WHERE aa.team_id=? AND aa.assigned_at >= ? ORDER BY aa.assigned_at''', (grp['id'], start)).fetchall()
    return [dict(r) for r in rows]


def summarize(rows):
    if not rows:
        return {'assigned':0,'completed':0,'pending':0,'overdue':0,'completion':0,'average':0,'technical':0,'communication':0,'cultural':0,'sports':0,'trend_labels':[],'trend_values':[],'category_labels':['Technical','Communication','Cultural','Sports'],'category_values':[0,0,0,0]}
    df = pd.DataFrame(rows)
    status = df['status'].fillna('Assigned')
    assigned = len(df)
    completed = int(status.isin(['Completed']).sum())
    now = datetime.now()
    overdue = int(sum(1 for _, r in df.iterrows() if r.get('deadline') and str(r.get('deadline')) < now.strftime('%Y-%m-%d') and r.get('status') != 'Completed'))
    pending = assigned - completed
    team_scores = pd.to_numeric(df['team_score'], errors='coerce') if 'team_score' in df else pd.Series(np.nan, index=df.index)
    individual_scores = pd.to_numeric(df['individual_score'], errors='coerce') if 'individual_score' in df else pd.Series(np.nan, index=df.index)
    df['_score'] = team_scores.combine_first(individual_scores)
    scores = df['_score'].dropna()
    average = round(float(np.mean(scores)), 2) if len(scores) else 0
    category_values=[]
    for cat in ['Technical','Communication','Cultural','Sports']:
        vals = df.loc[df['category']==cat, '_score'].dropna()
        category_values.append(round(float(vals.mean()),2) if len(vals) else 0)
    by_day = df.copy()
    by_day['day'] = pd.to_datetime(by_day['assigned_at'], errors='coerce').dt.strftime('%d %b')
    trend = by_day.groupby('day', dropna=True).size().tail(7)
    return {'assigned':assigned,'completed':completed,'pending':pending,'overdue':overdue,
      'completion':round(completed/assigned*100,1) if assigned else 0,'average':average,
      'technical':category_values[0],'communication':category_values[1], 'cultural':category_values[2], 'sports':category_values[3], 'trend_labels':trend.index.tolist(),
      'trend_values':trend.astype(int).tolist(),'category_labels':['Technical','Communication','Cultural','Sports'],'category_values':category_values}
