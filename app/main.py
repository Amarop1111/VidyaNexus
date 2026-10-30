import os, sqlite3, csv, io, json, hmac, hashlib, secrets, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB = os.getenv('DATABASE_PATH', str(ROOT.parent / 'vidyanexus.db'))
SECRET = os.getenv('APP_SECRET', 'CHANGE-ME-LOCAL-DEMO-SECRET')
app = FastAPI(title='VidyaNexus API', version='1.0.0', description='APAAR-linked student data management prototype; external integrations are adapter stubs until authorized.')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=False, allow_methods=['*'], allow_headers=['*'])

def conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def now(): return datetime.now(timezone.utc).isoformat()
def hashpw(p,s): return hashlib.pbkdf2_hmac('sha256',p.encode(),s.encode(),180000).hex()
def token_for(user):
    payload=json.dumps({'u':user['username'],'r':user['role'],'exp':int(time.time())+8*3600},separators=(',',':')).encode(); sig=hmac.new(SECRET.encode(),payload,hashlib.sha256).hexdigest()
    import base64
    return base64.urlsafe_b64encode(payload).decode().rstrip('=')+'.'+sig

def init():
    c=conn(); q=c.cursor()
    q.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, salt TEXT, role TEXT, institution_id INTEGER);
    CREATE TABLE IF NOT EXISTS institutions(id INTEGER PRIMARY KEY, code TEXT UNIQUE, name TEXT, approved_intake INTEGER NOT NULL DEFAULT 0, supernumerary_intake INTEGER NOT NULL DEFAULT 0, active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, student_name TEXT NOT NULL, apaar_ref TEXT, institution_id INTEGER NOT NULL, programme TEXT, category TEXT DEFAULT 'General', status TEXT DEFAULT 'Pending', created_at TEXT, updated_at TEXT, FOREIGN KEY(institution_id) REFERENCES institutions(id));
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, student_id INTEGER, institution_id INTEGER, type TEXT, severity TEXT, reason TEXT, status TEXT DEFAULT 'Open', created_at TEXT, reviewed_by TEXT, reviewed_at TEXT, FOREIGN KEY(student_id) REFERENCES students(id));
    CREATE TABLE IF NOT EXISTS verifications(id INTEGER PRIMARY KEY, apaar_ref TEXT, requester TEXT, purpose TEXT, consent INTEGER, result TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, actor TEXT, action TEXT, entity TEXT, entity_id TEXT, details TEXT, created_at TEXT);
    ''')
    if q.execute('SELECT COUNT(*) FROM institutions').fetchone()[0]==0:
        q.executemany('INSERT INTO institutions(code,name,approved_intake,supernumerary_intake) VALUES(?,?,?,?)',[
          ('DEMO-AI-01','Amrita Institute',350,20),('DEMO-NV-02','North Valley Engineering College',250,10),('DEMO-CT-03','Coastal Technical University',240,15),('DEMO-MP-04','Metro Polytechnic',180,0)])
    if q.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0:
        salt=secrets.token_hex(16); q.execute('INSERT INTO users(username,password_hash,salt,role) VALUES(?,?,?,?)',('admin',hashpw('Vidya@123',salt),salt,'AICTE_ADMIN'))
        salt=secrets.token_hex(16); q.execute('INSERT INTO users(username,password_hash,salt,role,institution_id) VALUES(?,?,?,?,?)',('college',hashpw('College@123',salt),salt,'INSTITUTION_ADMIN',1))
    if q.execute('SELECT COUNT(*) FROM students').fetchone()[0]==0:
        demo=[('Aarav Menon','DEMO-APAAR-1001',1,'B.Tech CSE','General'),('Diya Sharma','DEMO-APAAR-1002',1,'B.Tech ECE','General'),('Kabir Rao','DEMO-APAAR-1003',2,'B.Tech IT','General'),('Meera Nair','',3,'B.Tech CSE','General'),('Ishaan Patel','DEMO-APAAR-1005',4,'Diploma CSE','General'),('Ananya Das','DEMO-APAAR-1001',3,'B.Tech ME','General'),('Rohan Iyer','DEMO-APAAR-1007',1,'B.Tech EEE','General'),('Sara Khan','DEMO-APAAR-1008',2,'B.Tech CSE','General')]
        q.executemany('INSERT INTO students(student_name,apaar_ref,institution_id,programme,category,status,created_at,updated_at) VALUES(?,?,?,?,? ,?,?,?)',[(a,b,d,e,f,'Pending',now(),now()) for a,b,d,e,f in demo])
    c.commit(); c.close()
init()

def audit(c,actor,action,entity='',entity_id='',details=''):
    c.execute('INSERT INTO audit_logs(actor,action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?,?)',(actor,action,entity,str(entity_id),details,now()))

def current_user(authorization: Optional[str]=Header(None)):
    if not authorization or not authorization.startswith('Bearer '): raise HTTPException(401,'Sign in required')
    raw=authorization[7:]
    try:
        import base64
        p,s=raw.split('.',1); payload=base64.urlsafe_b64decode(p+'='*((4-len(p)%4)%4)); expected=hmac.new(SECRET.encode(),payload,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(s,expected): raise ValueError()
        data=json.loads(payload)
        if data['exp']<time.time(): raise ValueError()
        return data
    except Exception: raise HTTPException(401,'Session expired or invalid; sign in again')

def require_admin(u=Depends(current_user)):
    if u['r'] not in ('AICTE_ADMIN','INSTITUTION_ADMIN'): raise HTTPException(403,'Insufficient role')
    return u

class Login(BaseModel): username:str; password:str
class StudentIn(BaseModel): student_name:str=Field(min_length=2); apaar_ref:Optional[str]=None; institution_id:int; programme:str=''; category:str='General'
class ReviewIn(BaseModel): note:str='Reviewed by authorized user'
class VerifyIn(BaseModel): apaar_ref:str; purpose:str; consent:bool=False

@app.get('/api/health')
def health(): return {'status':'ok','service':'VidyaNexus API','database':'connected','external_integrations':'not_configured','time':now()}
@app.post('/api/auth/login')
def login(body:Login):
    c=conn(); row=c.execute('SELECT * FROM users WHERE username=?',(body.username,)).fetchone(); c.close()
    if not row or not hmac.compare_digest(hashpw(body.password,row['salt']),row['password_hash']): raise HTTPException(401,'Incorrect username or password')
    return {'access_token':token_for(row),'token_type':'bearer','user':{'username':row['username'],'role':row['role'],'institution_id':row['institution_id']}}
@app.get('/api/auth/me')
def me(u=Depends(current_user)): return u
@app.get('/api/institutions')
def institutions(u=Depends(current_user)):
    c=conn(); rows=[dict(x) for x in c.execute('SELECT i.*,COUNT(s.id) AS enrolled FROM institutions i LEFT JOIN students s ON s.institution_id=i.id GROUP BY i.id ORDER BY i.name')]; c.close(); return rows
@app.post('/api/institutions')
def add_institution(body:dict,u=Depends(require_admin)):
    if u['r']!='AICTE_ADMIN': raise HTTPException(403,'Only AICTE administrators can create institutions')
    try:
        c=conn(); cur=c.execute('INSERT INTO institutions(code,name,approved_intake,supernumerary_intake) VALUES(?,?,?,?)',(body['code'],body['name'],int(body.get('approved_intake',0)),int(body.get('supernumerary_intake',0)))); audit(c,u['u'],'CREATE','institution',cur.lastrowid,body['name']); c.commit(); out=cur.lastrowid; c.close(); return {'id':out,'created':True}
    except sqlite3.IntegrityError: raise HTTPException(409,'Institution code already exists')
@app.get('/api/students')
def students(q:str='',institution_id:Optional[int]=None,status:str='',u=Depends(current_user)):
    c=conn(); sql='SELECT s.*,i.name AS institution FROM students s JOIN institutions i ON i.id=s.institution_id WHERE 1=1'; args=[]
    if q: sql+=' AND (s.student_name LIKE ? OR s.apaar_ref LIKE ? OR s.programme LIKE ?)'; args += [f'%{q}%']*3
    if institution_id: sql+=' AND s.institution_id=?'; args.append(institution_id)
    if status: sql+=' AND s.status=?'; args.append(status)
    if u['r']=='INSTITUTION_ADMIN': sql+=' AND s.institution_id=?'; args.append(u.get('institution_id'))
    sql+=' ORDER BY s.id DESC'; rows=[dict(x) for x in c.execute(sql,args)]; c.close(); return rows
@app.post('/api/students')
def add_student(b:StudentIn,u=Depends(require_admin)):
    if u['r']=='INSTITUTION_ADMIN' and b.institution_id!=u.get('institution_id'): raise HTTPException(403,'Cannot add records for another institution')
    c=conn(); inst=c.execute('SELECT id FROM institutions WHERE id=?',(b.institution_id,)).fetchone()
    if not inst: c.close(); raise HTTPException(404,'Institution not found')
    cur=c.execute('INSERT INTO students(student_name,apaar_ref,institution_id,programme,category,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(b.student_name,b.apaar_ref or '',b.institution_id,b.programme,b.category,'Pending',now(),now())); audit(c,u['u'],'CREATE','student',cur.lastrowid,b.student_name); c.commit(); sid=cur.lastrowid; c.close(); return {'id':sid,'created':True}
@app.post('/api/students/upload')
async def upload(file:UploadFile=File(...),u=Depends(require_admin)):
    if not file.filename.lower().endswith('.csv'): raise HTTPException(400,'Upload a CSV file')
    raw=(await file.read()).decode('utf-8-sig'); reader=csv.DictReader(io.StringIO(raw)); required={'student_name','institution_code'}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)): raise HTTPException(400,'CSV must include student_name and institution_code. Optional: apaar_ref, programme, category.')
    c=conn(); inserted=0; errors=[]
    for line,row in enumerate(reader,start=2):
        code=(row.get('institution_code') or '').strip(); inst=c.execute('SELECT id FROM institutions WHERE code=?',(code,)).fetchone()
        if not inst: errors.append({'line':line,'reason':f'Unknown institution_code: {code}'}); continue
        if u['r']=='INSTITUTION_ADMIN' and inst['id']!=u.get('institution_id'): errors.append({'line':line,'reason':'Institution scope violation'}); continue
        name=(row.get('student_name') or '').strip()
        if not name: errors.append({'line':line,'reason':'Missing student_name'}); continue
        c.execute('INSERT INTO students(student_name,apaar_ref,institution_id,programme,category,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(name,(row.get('apaar_ref') or '').strip(),inst['id'],(row.get('programme') or '').strip(),(row.get('category') or 'General').strip(),'Pending',now(),now())); inserted+=1
    audit(c,u['u'],'CSV_UPLOAD','students','',f'{file.filename}: inserted={inserted}, errors={len(errors)}'); c.commit(); c.close(); return {'inserted':inserted,'errors':errors,'message':'Upload completed; run validation to generate review alerts.'}
@app.post('/api/validation/run')
def run_validation(u=Depends(require_admin)):
    c=conn(); scope=' AND institution_id=?' if u['r']=='INSTITUTION_ADMIN' else ''; params=(u.get('institution_id'),) if scope else (); c.execute("DELETE FROM alerts WHERE status='Open'"+scope,params)
    records=c.execute('SELECT * FROM students WHERE 1=1'+scope,params).fetchall(); created=0
    for s in records:
        if not (s['apaar_ref'] or '').strip(): c.execute('INSERT INTO alerts(student_id,institution_id,type,severity,reason,created_at) VALUES(?,?,?,?,?,?)',(s['id'],s['institution_id'],'Missing APAAR reference','Medium','APAAR reference is blank; verify source data and update if available.',now())); created+=1
        if s['apaar_ref']:
            dup=c.execute('SELECT id,institution_id FROM students WHERE apaar_ref=? AND id<>?',(s['apaar_ref'],s['id'])).fetchall()
            if dup: c.execute('INSERT INTO alerts(student_id,institution_id,type,severity,reason,created_at) VALUES(?,?,?,?,?,?)',(s['id'],s['institution_id'],'Potential duplicate reference','High',f"Reference occurs on {len(dup)} other record(s); authorized review required.",now())); created+=1
    insts=c.execute('SELECT * FROM institutions').fetchall()
    for i in insts:
        if u['r']=='INSTITUTION_ADMIN' and i['id']!=u.get('institution_id'): continue
        count=c.execute('SELECT COUNT(*) FROM students WHERE institution_id=?',(i['id'],)).fetchone()[0]; allowed=i['approved_intake']+i['supernumerary_intake']
        if count>allowed: c.execute('INSERT INTO alerts(institution_id,type,severity,reason,created_at) VALUES(?,?,?,?,?)',(i['id'],'Intake threshold review','High',f'Submitted records ({count}) exceed configured approved plus supernumerary intake ({allowed}). Confirm applicable category and approval rules.',now())); created+=1
    audit(c,u['u'],'RUN_VALIDATION','validation','',f'alerts_created={created}'); c.commit(); c.close(); return {'alerts_created':created,'records_checked':len(records),'note':'Flags require human review; this is not a determination of fraud or ineligibility.'}
@app.get('/api/alerts')
def get_alerts(status:str='',u=Depends(current_user)):
    c=conn(); sql='SELECT a.*,s.student_name,s.apaar_ref,i.name AS institution FROM alerts a LEFT JOIN students s ON s.id=a.student_id LEFT JOIN institutions i ON i.id=a.institution_id WHERE 1=1'; args=[]
    if status: sql+=' AND a.status=?'; args.append(status)
    if u['r']=='INSTITUTION_ADMIN': sql+=' AND a.institution_id=?'; args.append(u.get('institution_id'))
    sql+=' ORDER BY a.created_at DESC'; rows=[dict(x) for x in c.execute(sql,args)]; c.close(); return rows
@app.patch('/api/alerts/{alert_id}/review')
def review(alert_id:int,b:ReviewIn,u=Depends(require_admin)):
    c=conn(); a=c.execute('SELECT * FROM alerts WHERE id=?',(alert_id,)).fetchone()
    if not a: c.close(); raise HTTPException(404,'Alert not found')
    if u['r']=='INSTITUTION_ADMIN' and a['institution_id']!=u.get('institution_id'): c.close(); raise HTTPException(403,'Cannot review another institution alert')
    c.execute("UPDATE alerts SET status='Reviewed',reviewed_by=?,reviewed_at=?,reason=reason||? WHERE id=?",(u['u'],now(),' | Review note: '+b.note,alert_id)); audit(c,u['u'],'REVIEW_ALERT','alert',alert_id,b.note); c.commit(); c.close(); return {'reviewed':True}
@app.post('/api/verification/request')
def verify(b:VerifyIn,u=Depends(current_user)):
    c=conn()
    if not b.consent:
        c.execute('INSERT INTO verifications(apaar_ref,requester,purpose,consent,result,created_at) VALUES(?,?,?,?,?,?)',(b.apaar_ref,u['u'],b.purpose,0,'DENIED_NO_CONSENT',now())); audit(c,u['u'],'VERIFICATION_DENIED','student',b.apaar_ref,'Consent not confirmed'); c.commit(); c.close(); raise HTTPException(403,'Verification requires documented consent/authorization')
    s=c.execute('SELECT s.*,i.name AS institution FROM students s JOIN institutions i ON i.id=s.institution_id WHERE s.apaar_ref=?',(b.apaar_ref,)).fetchone()
    result='DEMO_MATCH_FOUND' if s else 'NO_MATCH_IN_LOCAL_DEMO_DATA'
    c.execute('INSERT INTO verifications(apaar_ref,requester,purpose,consent,result,created_at) VALUES(?,?,?,?,?,?)',(b.apaar_ref,u['u'],b.purpose,1,result,now())); audit(c,u['u'],'VERIFICATION_REQUEST','student',b.apaar_ref,f'purpose={b.purpose}; consent=true'); c.commit(); c.close()
    return {'result':result,'record':({'student_name':s['student_name'],'institution':s['institution'],'programme':s['programme'],'status':s['status']} if s else None),'disclaimer':'Local synthetic demo lookup only. This is not live APAAR, ABC, NAD or degree verification.'}
@app.get('/api/dashboard/overview')
def dashboard(u=Depends(current_user)):
    c=conn(); scope=' WHERE institution_id=?' if u['r']=='INSTITUTION_ADMIN' else ''; args=(u.get('institution_id'),) if scope else ()
    total=c.execute('SELECT COUNT(*) FROM students'+scope,args).fetchone()[0]
    missing=c.execute("SELECT COUNT(*) FROM students"+scope+(' AND' if scope else ' WHERE')+" (apaar_ref IS NULL OR TRIM(apaar_ref)='')",args).fetchone()[0]
    open_alerts=c.execute("SELECT COUNT(*) FROM alerts WHERE status='Open'"+(' AND institution_id=?' if scope else ''),args).fetchone()[0]
    inst_count=c.execute('SELECT COUNT(*) FROM institutions'+(' WHERE id=?' if scope else ''),args).fetchone()[0]
    byinst=[dict(x) for x in c.execute('SELECT i.name,i.approved_intake,i.supernumerary_intake,COUNT(s.id) AS enrolled FROM institutions i LEFT JOIN students s ON s.institution_id=i.id '+('WHERE i.id=? ' if scope else '')+'GROUP BY i.id ORDER BY i.name',args)]
    recent=[dict(x) for x in c.execute('SELECT action,entity,details,created_at,actor FROM audit_logs ORDER BY id DESC LIMIT 8')]
    c.close(); return {'students':total,'institutions':inst_count,'missing_apaar':missing,'open_alerts':open_alerts,'enrolment_by_institution':byinst,'recent_activity':recent}
@app.get('/api/reports/students.csv')
def report(u=Depends(current_user)):
    rows=students(u=u); buf=io.StringIO(); w=csv.DictWriter(buf,fieldnames=['id','student_name','apaar_ref','institution','programme','category','status']); w.writeheader()
    for r in rows: w.writerow({k:r.get(k,'') for k in w.fieldnames})
    return StreamingResponse(iter([buf.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=vidyanexus_student_report.csv'})
@app.get('/api/audit')
def audit_list(u=Depends(require_admin)):
    c=conn(); rows=[dict(x) for x in c.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200')]; c.close(); return rows
@app.get('/api/integrations/status')
def integrations(u=Depends(current_user)):
    return [{'name':'APAAR / ABC','status':'Not configured','mode':'Adapter placeholder','required':'Official partner onboarding, API specification and credentials'},{'name':'AICTE','status':'Not configured','mode':'Adapter placeholder','required':'Authorized integration endpoint and institutional approval data access'},{'name':'NAD / DigiLocker','status':'Not configured','mode':'Adapter placeholder','required':'Verifier onboarding, consent workflow and approved credentials'}]

app.mount('/',StaticFiles(directory=str(ROOT/'static'),html=True),name='static')
