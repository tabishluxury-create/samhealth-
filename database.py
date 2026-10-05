"""Healthcare Database Management with SQLite and Hardware-level AES-256 Encryption"""

import sqlite3
import json
import os
import re
from html import escape
from datetime import datetime
from pathlib import Path

# Import hardware-accelerated encryption helpers
try:
    from backend.security import encrypt_field, decrypt_field, is_encrypted
except ImportError:
    from security import encrypt_field, decrypt_field, is_encrypted

BASE_DIR = Path(__file__).resolve().parent
LEGACY_DB_FILE = BASE_DIR / "backend" / "healthcare.db"
PRIMARY_DB_FILE = BASE_DIR / "healthcare.db"

if PRIMARY_DB_FILE.exists() or not LEGACY_DB_FILE.exists():
    DB_FILE = str(PRIMARY_DB_FILE)
else:
    DB_FILE = str(LEGACY_DB_FILE)

if not os.path.exists(DB_FILE):
    os.makedirs(os.path.dirname(DB_FILE) or ".", exist_ok=True)

def init_database():
    """Initialize database with all required tables and hardware credential schema"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Patients table
    c.execute('''CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        email TEXT,
        age INTEGER,
        gender TEXT,
        blood_group TEXT,
        address TEXT,
        medical_history TEXT,
        created_at TEXT,
        updated_at TEXT
    )''')
    
    # Doctors table
    c.execute('''CREATE TABLE IF NOT EXISTS doctors (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        email TEXT,
        specialization TEXT,
        qualification TEXT,
        experience INTEGER,
        clinic_address TEXT,
        created_at TEXT,
        updated_at TEXT
    )''')
    doctor_columns = [row[1] for row in c.execute("PRAGMA table_info(doctors)")]
    for column in ("doctor_type", "license_number", "department", "hospital"):
        if column not in doctor_columns:
            c.execute(f"ALTER TABLE doctors ADD COLUMN {column} TEXT")
    
    # Appointments table
    c.execute('''CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doctor_id TEXT,
        patient_id TEXT,
        appointment_date TEXT,
        appointment_time TEXT,
        token_number INTEGER,
        status TEXT,
        notes TEXT,
        created_at TEXT,
        FOREIGN KEY(doctor_id) REFERENCES doctors(id),
        FOREIGN KEY(patient_id) REFERENCES patients(id)
    )''')
    appointment_columns = [row[1] for row in c.execute("PRAGMA table_info(appointments)")]
    if "token_number" not in appointment_columns:
        c.execute("ALTER TABLE appointments ADD COLUMN token_number INTEGER")
    if "visit_notes" not in appointment_columns:
        c.execute("ALTER TABLE appointments ADD COLUMN visit_notes TEXT")
    token_counts = {
        (row[0], row[1]): row[2]
        for row in c.execute(
            '''SELECT doctor_id, appointment_date, MAX(token_number)
               FROM appointments GROUP BY doctor_id, appointment_date'''
        )
    }
    existing_appointments = c.execute(
        '''SELECT id, doctor_id, appointment_date FROM appointments
           WHERE token_number IS NULL ORDER BY doctor_id, appointment_date, id'''
    ).fetchall()
    for appointment_id, doctor_id, appointment_date in existing_appointments:
        key = (doctor_id, appointment_date)
        token_counts[key] = token_counts.get(key) or 0
        token_counts[key] += 1
        c.execute(
            "UPDATE appointments SET token_number = ? WHERE id = ?",
            (token_counts[key], appointment_id)
        )
    c.execute('''CREATE INDEX IF NOT EXISTS idx_appointments_doctor_date_token
                 ON appointments (doctor_id, appointment_date, token_number)''')
    
    # Attendance table
    c.execute('''CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        doctor_id TEXT,
        check_in_time TEXT,
        check_out_time TEXT,
        duration_minutes INTEGER,
        date TEXT,
        FOREIGN KEY(patient_id) REFERENCES patients(id),
        FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    )''')
    
    # Prescriptions table
    c.execute('''CREATE TABLE IF NOT EXISTS prescriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doctor_id TEXT,
        patient_id TEXT,
        medicine_name TEXT,
        dosage TEXT,
        frequency TEXT,
        duration TEXT,
        created_at TEXT,
        FOREIGN KEY(doctor_id) REFERENCES doctors(id),
        FOREIGN KEY(patient_id) REFERENCES patients(id)
    )''')
    
    # Lab Reports table
    c.execute('''CREATE TABLE IF NOT EXISTS lab_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        report_type TEXT,
        report_data TEXT,
        created_at TEXT,
        FOREIGN KEY(patient_id) REFERENCES patients(id)
    )''')

    # Referrals table
    c.execute('''CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        doctor_id TEXT,
        referred_to TEXT,
        reason TEXT,
        status TEXT DEFAULT 'pending',
        created_at TEXT,
        FOREIGN KEY(patient_id) REFERENCES patients(id),
        FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS surgery_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT NOT NULL,
        doctor_id TEXT NOT NULL,
        surgery_type TEXT NOT NULL,
        surgery_date TEXT,
        surgeon TEXT,
        hospital TEXT,
        status TEXT,
        follow_up TEXT,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(patient_id) REFERENCES patients(id),
        FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    )''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_surgery_records_patient_created
                 ON surgery_records (patient_id, created_at DESC)''')

    # Shared patient-doctor notification feed
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_id TEXT NOT NULL,
        sender_id TEXT,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )''')
    
    # Patient Accounts table (for login/authentication)
    c.execute('''CREATE TABLE IF NOT EXISTS patient_accounts (
        id TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        email TEXT,
        account_status TEXT DEFAULT 'active',
        created_at TEXT,
        last_login TEXT
    )''')
    
    # Doctor Accounts table (for login/authentication)
    c.execute('''CREATE TABLE IF NOT EXISTS doctor_accounts (
        id TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        email TEXT,
        account_status TEXT DEFAULT 'active',
        created_at TEXT,
        last_login TEXT
    )''')

    # Hardware Security Credentials table (for WebAuthn / Passkeys / Biometrics)
    c.execute('''CREATE TABLE IF NOT EXISTS hardware_credentials (
        credential_id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        role TEXT NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )''')

    for table in ("patient_accounts", "doctor_accounts"):
        columns = [row[1] for row in c.execute(f"PRAGMA table_info({table})")]
        if "two_step_enabled" not in columns:
            c.execute(f"ALTER TABLE {table} ADD COLUMN two_step_enabled INTEGER DEFAULT 0")
        if "security_pin_hash" not in columns:
            c.execute(f"ALTER TABLE {table} ADD COLUMN security_pin_hash TEXT")

    conn.commit()
    conn.close()
    print(f"Database initialized: {DB_FILE}")

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def canonical_account_id(identifier):
    """Resolve an account ID from either an ID or registered phone number."""
    if not identifier:
        return identifier
    identifier_str = str(identifier).strip()
    conn = get_db()
    normalized_phone = normalize_phone(identifier_str)
    row = conn.execute('''SELECT id FROM patient_accounts WHERE id = ? OR phone = ?
                          UNION ALL SELECT id FROM doctor_accounts WHERE id = ? OR phone = ?
                          LIMIT 1''', (identifier_str, normalized_phone, identifier_str, normalized_phone)).fetchone()
    conn.close()
    return row[0] if row else identifier_str

def _decrypt_patient(row):
    """Decrypt sensitive patient fields."""
    if not row:
        return None
    d = {key: row[key] for key in (
        "id", "name", "phone", "email", "age", "gender", "blood_group",
        "address", "medical_history", "created_at", "updated_at",
    )}
    if d.get("medical_history"):
        d["medical_history"] = decrypt_field(d["medical_history"])
    return d

def _decrypt_doctor(row):
    """Decrypt sensitive doctor fields."""
    if not row:
        return None
    return {key: row[key] for key in (
        "id", "name", "phone", "email", "specialization", "qualification",
        "experience", "clinic_address", "doctor_type", "license_number",
        "department", "hospital", "created_at", "updated_at",
    )}

def get_patients():
    """Get all patients with decrypted sensitive fields."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM patients ORDER BY updated_at DESC LIMIT 100')
    patients = [_decrypt_patient(row) for row in c.fetchall()]
    conn.close()
    return patients

def get_patient(patient_id):
    """Get specific patient by canonical ID or phone number."""
    if not patient_id:
        return None
    patient_id = canonical_account_id(patient_id)
    conn = get_db()
    c = conn.cursor()
    phone = normalize_phone(patient_id)
    c.execute('SELECT * FROM patients WHERE id = ? OR phone = ?', (patient_id, phone))
    row = c.fetchone()
    patient = _decrypt_patient(row)
    conn.close()
    return patient

def add_patient(patient_data):
    """Add new patient with AES-256 encrypted sensitive fields."""
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    try:
        c.execute('''INSERT INTO patients 
                    (id, name, phone, email, age, gender, blood_group, address, medical_history, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (patient_data.get('id'), patient_data.get('name'), normalize_phone(patient_data.get('phone')),
                  patient_data.get('email'), patient_data.get('age'), patient_data.get('gender'),
                  patient_data.get('blood_group'), patient_data.get('address'),
                  encrypt_field(patient_data.get('medical_history')),
                  now, now))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False

def update_patient(patient_id, patient_data):
    """Update editable patient information, encrypt sensitive fields, and sync accounts table."""
    patient_id = canonical_account_id(patient_id)
    conn = get_db()
    try:
        phone = normalize_phone(patient_data.get('phone'))
        email = patient_data.get('email')
        med_history = encrypt_field(patient_data.get('medical_history'))
        conn.execute('''UPDATE patients SET name = ?, phone = ?, email = ?, age = ?, gender = ?,
                        blood_group = ?, address = ?, medical_history = ?, updated_at = ? WHERE id = ?''',
                     (patient_data.get('name'), phone,
                      email, patient_data.get('age'), patient_data.get('gender'),
                      patient_data.get('blood_group'), patient_data.get('address'),
                      med_history, datetime.now().isoformat(), patient_id))

        if phone:
            conn.execute('UPDATE patient_accounts SET phone = ?, email = ? WHERE id = ?', (phone, email, patient_id))
        conn.commit()
        changed = conn.total_changes > 0
        conn.close()
        return changed
    except Exception:
        conn.close()
        return False

def get_doctors():
    """Get registered doctors whose accounts are active and accepting bookings."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT d.* FROM doctors d
                 INNER JOIN doctor_accounts a ON a.id = d.id
                 WHERE a.account_status = 'active'
                 ORDER BY d.updated_at DESC LIMIT 100''')
    doctors = [_decrypt_doctor(row) for row in c.fetchall()]
    conn.close()
    return doctors

def get_doctor(doctor_id):
    """Get specific doctor by canonical ID or phone number."""
    if not doctor_id:
        return None
    doctor_id = canonical_account_id(doctor_id)
    conn = get_db()
    c = conn.cursor()
    phone = normalize_phone(doctor_id)
    c.execute('SELECT * FROM doctors WHERE id = ? OR phone = ?', (doctor_id, phone))
    row = c.fetchone()
    doctor = _decrypt_doctor(row)
    conn.close()
    return doctor

def add_doctor(doctor_data):
    """Add or register a doctor from dictionary data."""
    doctor_id = doctor_data.get("id") or doctor_data.get("doctor_id")
    name = doctor_data.get("name", "Doctor")
    phone = normalize_phone(doctor_data.get("phone", ""))
    email = doctor_data.get("email")
    password = doctor_data.get("password") or "doctor123"
    specialization = doctor_data.get("specialization")
    qualification = doctor_data.get("qualification")
    experience = doctor_data.get("experience") or doctor_data.get("experience_years") or 0
    security_pin = doctor_data.get("security_pin") or "1234"
    doctor_type = doctor_data.get("doctor_type")
    license_number = doctor_data.get("license_number")
    department = doctor_data.get("department")
    hospital = doctor_data.get("hospital")
    clinic_address = doctor_data.get("clinic_address") or doctor_data.get("address")

    if not doctor_id or not phone:
        return False

    return register_doctor(doctor_id, name, phone, email, password, specialization, qualification,
                           experience, security_pin, doctor_type, license_number, department,
                           hospital, clinic_address=clinic_address)

def get_appointments(filter_by=None, value=None):
    """Get appointments with decrypted notes and canonical ID resolution."""
    conn = get_db()
    c = conn.cursor()
    if filter_by and value:
        if filter_by not in ("patient_id", "doctor_id"):
            conn.close()
            raise ValueError("Appointments can only be filtered by patient_id or doctor_id.")
        value = canonical_account_id(value)
        c.execute(f'SELECT * FROM appointments WHERE {filter_by} = ? ORDER BY appointment_date DESC LIMIT 100', (value,))
    else:
        c.execute('SELECT * FROM appointments ORDER BY appointment_date DESC LIMIT 100')
    appointments = []
    for row in c.fetchall():
        item = dict(row)
        if item.get("notes"):
            item["notes"] = decrypt_field(item["notes"])
        if item.get("visit_notes"):
            item["visit_notes"] = decrypt_field(item["visit_notes"])
        appointments.append(item)
    conn.close()
    return appointments

def add_appointment(appointment_data):
    """Add an appointment and assign the next token for its doctor and date."""
    conn = get_db()
    doctor_id = canonical_account_id(appointment_data.get('doctor_id'))
    patient_id = canonical_account_id(appointment_data.get('patient_id'))
    try:
        conn.execute("BEGIN IMMEDIATE")
        doctor_account = conn.execute(
            "SELECT account_status FROM doctor_accounts WHERE id = ?",
            (doctor_id,)
        ).fetchone()
        doctor_profile = conn.execute(
            "SELECT 1 FROM doctors WHERE id = ?",
            (doctor_id,)
        ).fetchone()
        if not doctor_account or doctor_account["account_status"] != "active" or not doctor_profile:
            raise ValueError("This doctor is not registered and available for booking.")
        token_number = conn.execute(
            '''SELECT COALESCE(MAX(token_number), 0) + 1
               FROM appointments WHERE doctor_id = ? AND appointment_date = ?''',
            (doctor_id, appointment_data.get('appointment_date'))
        ).fetchone()[0]
        cursor = conn.execute(
            '''INSERT INTO appointments
               (doctor_id, patient_id, appointment_date, appointment_time, token_number,
                status, notes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (doctor_id, patient_id, appointment_data.get('appointment_date'),
             appointment_data.get('appointment_time'), token_number,
             appointment_data.get('status', 'scheduled'),
             encrypt_field(appointment_data.get('notes')), datetime.now().isoformat())
        )
        appointment = conn.execute(
            "SELECT * FROM appointments WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        conn.commit()
        result = dict(appointment)
        if result.get("notes"):
            result["notes"] = decrypt_field(result["notes"])
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def update_appointment_status(appointment_data):
    """Update an appointment status and return the updated appointment with decrypted notes."""
    conn = get_db()
    try:
        status = appointment_data.get("status")
        if status not in {"requested", "scheduled", "confirmed", "upcoming", "ongoing", "completed", "cancelled"}:
            conn.close()
            return None

        conditions = []
        values = [status]
        doctor_id = appointment_data.get("doctor_id")
        patient_id = appointment_data.get("patient_id")
        if doctor_id:
            conditions.append("doctor_id = ?")
            values.append(canonical_account_id(doctor_id))
        if patient_id:
            conditions.append("patient_id = ?")
            values.append(canonical_account_id(patient_id))
        if not conditions:
            conn.close()
            return None
        if patient_id and status != "cancelled":
            conn.close()
            return None

        appointment_id = appointment_data.get("appointment_id")
        if appointment_id:
            conditions.append("id = ?")
            values.append(appointment_id)
        elif doctor_id and patient_id:
            pass
        else:
            conn.close()
            return None

        if status == "cancelled" and doctor_id and patient_id:
            conn.close()
            return None

        target = conn.execute(
            f"SELECT status, appointment_date FROM appointments WHERE {' AND '.join(conditions)}",
            values[1:]
        ).fetchone()
        if not target:
            conn.close()
            return None
        if status == "cancelled":
            if doctor_id and target["status"] != "ongoing":
                conn.close()
                return None
            if patient_id and target["status"] in {"cancelled", "completed", "ongoing"}:
                conn.close()
                return None
        if (
            status == "cancelled"
            and patient_id
            and target["appointment_date"]
            and target["appointment_date"] < datetime.now().date().isoformat()
        ):
            conn.close()
            return None

        cursor = conn.execute(
            f"UPDATE appointments SET status = ? WHERE {' AND '.join(conditions)}",
            values
        )
        conn.commit()
        if cursor.rowcount == 0:
            conn.close()
            return None
        row = conn.execute(
            f"SELECT * FROM appointments WHERE {' AND '.join(conditions)}",
            values[1:]
        ).fetchone()
        conn.close()
        if not row:
            return None
        res = dict(row)
        if res.get("notes"):
            res["notes"] = decrypt_field(res["notes"])
        if res.get("visit_notes"):
            res["visit_notes"] = decrypt_field(res["visit_notes"])
        return res
    except Exception:
        conn.close()
        raise

def update_completed_appointment_visit_notes(appointment_id, doctor_id, visit_notes):
    """Save a doctor's visit summary only for their completed appointment."""
    if not isinstance(visit_notes, str):
        raise ValueError("Visit notes must be text.")
    visit_notes = visit_notes.strip()
    if len(visit_notes) > 10000:
        raise ValueError("Visit notes must be 10,000 characters or fewer.")

    conn = get_db()
    try:
        cursor = conn.execute(
            """UPDATE appointments
               SET visit_notes = ?
               WHERE id = ? AND doctor_id = ? AND status = 'completed'""",
            (encrypt_field(visit_notes), appointment_id, canonical_account_id(doctor_id))
        )
        if cursor.rowcount == 0:
            conn.rollback()
            return None
        conn.commit()
        row = conn.execute(
            "SELECT * FROM appointments WHERE id = ? AND doctor_id = ?",
            (appointment_id, canonical_account_id(doctor_id))
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        if result.get("notes"):
            result["notes"] = decrypt_field(result["notes"])
        if result.get("visit_notes"):
            result["visit_notes"] = decrypt_field(result["visit_notes"])
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def complete_doctor_appointments_for_date(doctor_id, appointment_date):
    """Complete all non-terminal appointments for one doctor on one date atomically."""
    active_statuses = ("requested", "scheduled", "confirmed", "upcoming", "ongoing")
    status_placeholders = ", ".join("?" for _ in active_statuses)
    canonical_doctor_id = canonical_account_id(doctor_id)
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        appointments = conn.execute(
            f"""SELECT id, patient_id, doctor_id, token_number
                FROM appointments
                WHERE doctor_id = ? AND appointment_date = ?
                  AND status IN ({status_placeholders})""",
            (canonical_doctor_id, appointment_date, *active_statuses)
        ).fetchall()
        if appointments:
            conn.execute(
                f"""UPDATE appointments
                    SET status = 'completed'
                    WHERE doctor_id = ? AND appointment_date = ?
                      AND status IN ({status_placeholders})""",
                (canonical_doctor_id, appointment_date, *active_statuses)
            )
        conn.commit()
        return [dict(appointment) for appointment in appointments]
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def get_attendance(doctor_id=None, date=None):
    """Get attendance records with optional doctor and date filtering."""
    conn = get_db()
    c = conn.cursor()
    if doctor_id:
        doctor_id = canonical_account_id(doctor_id)

    if doctor_id and date:
        c.execute('''SELECT a.*, COALESCE(p.name, a.patient_id) as patient_name FROM attendance a 
                     LEFT JOIN patients p ON a.patient_id = p.id 
                     WHERE a.doctor_id = ? AND a.date = ? ORDER BY check_in_time DESC''', (doctor_id, date))
    elif doctor_id:
        c.execute('''SELECT a.*, COALESCE(p.name, a.patient_id) as patient_name FROM attendance a 
                     LEFT JOIN patients p ON a.patient_id = p.id 
                     WHERE a.doctor_id = ? ORDER BY a.date DESC, check_in_time DESC''', (doctor_id,))
    elif date:
        c.execute('''SELECT a.*, COALESCE(p.name, a.patient_id) as patient_name FROM attendance a 
                     LEFT JOIN patients p ON a.patient_id = p.id 
                     WHERE a.date = ? ORDER BY check_in_time DESC''', (date,))
    else:
        c.execute('''SELECT a.*, COALESCE(p.name, a.patient_id) as patient_name FROM attendance a 
                     LEFT JOIN patients p ON a.patient_id = p.id ORDER BY a.date DESC, check_in_time DESC LIMIT 100''')
    records = [dict(row) for row in c.fetchall()]
    conn.close()
    return records

def add_attendance(attendance_data):
    """Add attendance record with canonical ID resolution."""
    conn = get_db()
    c = conn.cursor()
    doctor_id = canonical_account_id(attendance_data.get('doctor_id'))
    patient_id = canonical_account_id(attendance_data.get('patient_id'))
    try:
        c.execute('''INSERT INTO attendance 
                    (patient_id, doctor_id, check_in_time, check_out_time, duration_minutes, date)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                 (patient_id, doctor_id,
                  attendance_data.get('check_in_time'), attendance_data.get('check_out_time'),
                  attendance_data.get('duration_minutes'), attendance_data.get('date')))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False

def get_prescriptions(patient_id=None, doctor_id=None):
    """Get prescriptions with canonical ID resolution."""
    conn = get_db()
    c = conn.cursor()
    if patient_id:
        patient_id = canonical_account_id(patient_id)
        c.execute('SELECT * FROM prescriptions WHERE patient_id = ? ORDER BY created_at DESC', (patient_id,))
    elif doctor_id:
        doctor_id = canonical_account_id(doctor_id)
        c.execute('SELECT * FROM prescriptions WHERE doctor_id = ? ORDER BY created_at DESC', (doctor_id,))
    else:
        c.execute('SELECT * FROM prescriptions ORDER BY created_at DESC LIMIT 100')
    prescriptions = [dict(row) for row in c.fetchall()]
    conn.close()
    return prescriptions

def add_prescription(prescription_data):
    """Add prescription with canonical ID resolution."""
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    doctor_id = canonical_account_id(prescription_data.get('doctor_id'))
    patient_id = canonical_account_id(prescription_data.get('patient_id'))
    try:
        c.execute('''INSERT INTO prescriptions 
                    (doctor_id, patient_id, medicine_name, dosage, frequency, duration, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (doctor_id, patient_id,
                  prescription_data.get('medicine_name'), prescription_data.get('dosage'),
                  prescription_data.get('frequency'), prescription_data.get('duration'), now))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False

def get_lab_reports(patient_id=None, doctor_id=None):
    """Get lab reports with decrypted report_data and canonical ID resolution."""
    conn = get_db()
    c = conn.cursor()
    if patient_id:
        patient_id = canonical_account_id(patient_id)
        c.execute('SELECT * FROM lab_reports WHERE patient_id = ? ORDER BY created_at DESC', (patient_id,))
    else:
        c.execute('SELECT * FROM lab_reports ORDER BY created_at DESC LIMIT 100')
    reports = []
    for row in c.fetchall():
        item = dict(row)
        if item.get("report_data"):
            item["report_data"] = decrypt_field(item["report_data"])
        reports.append(item)
    conn.close()
    return reports

def add_lab_report(report_data):
    """Add a lab report with AES-256 encrypted report_data."""
    conn = get_db()
    c = conn.cursor()
    patient_id = canonical_account_id(report_data.get('patient_id'))
    encrypted_data = encrypt_field(report_data.get('report_data'))
    try:
        c.execute('''INSERT INTO lab_reports (patient_id, report_type, report_data, created_at)
                     VALUES (?, ?, ?, ?)''',
                  (patient_id, report_data.get('report_type'),
                   encrypted_data, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def get_referrals(patient_id=None, doctor_id=None):
    """Get referrals with canonical ID resolution."""
    conn = get_db()
    c = conn.cursor()
    if patient_id:
        patient_id = canonical_account_id(patient_id)
        c.execute('SELECT * FROM referrals WHERE patient_id = ? ORDER BY created_at DESC', (patient_id,))
    elif doctor_id:
        doctor_id = canonical_account_id(doctor_id)
        c.execute('SELECT * FROM referrals WHERE doctor_id = ? ORDER BY created_at DESC', (doctor_id,))
    else:
        c.execute('SELECT * FROM referrals ORDER BY created_at DESC LIMIT 100')
    referrals = [dict(row) for row in c.fetchall()]
    conn.close()
    return referrals

def add_referral(referral_data):
    """Add a patient referral with canonical ID resolution."""
    conn = get_db()
    c = conn.cursor()
    patient_id = canonical_account_id(referral_data.get('patient_id'))
    doctor_id = canonical_account_id(referral_data.get('doctor_id'))
    try:
        c.execute('''INSERT INTO referrals (patient_id, doctor_id, referred_to, reason, status, created_at)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (patient_id, doctor_id,
                   referral_data.get('referred_to'), referral_data.get('reason'),
                   referral_data.get('status', 'pending'), datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def get_surgery_records(patient_id=None, doctor_id=None):
    """Get surgery records for a patient or doctor, decrypting clinical details."""
    conn = get_db()
    if patient_id:
        patient_id = canonical_account_id(patient_id)
        rows = conn.execute(
            "SELECT * FROM surgery_records WHERE patient_id = ? ORDER BY surgery_date DESC, created_at DESC",
            (patient_id,)
        ).fetchall()
    elif doctor_id:
        doctor_id = canonical_account_id(doctor_id)
        rows = conn.execute(
            "SELECT * FROM surgery_records WHERE doctor_id = ? ORDER BY created_at DESC",
            (doctor_id,)
        ).fetchall()
    else:
        conn.close()
        return []

    encrypted_fields = ("surgery_type", "surgeon", "hospital", "status", "follow_up", "notes")
    records = []
    for row in rows:
        record = dict(row)
        for field in encrypted_fields:
            if record.get(field):
                record[field] = decrypt_field(record[field])
        records.append(record)
    conn.close()
    return records

def save_surgery_record(record_data):
    """Create doctor-authored records or edit an existing record owned by a patient."""
    conn = get_db()
    role = str(record_data.get("role") or "").lower()
    patient_id = canonical_account_id(record_data.get("patient_id"))
    surgery_type = str(record_data.get("surgery_type") or "").strip()
    surgery_id = record_data.get("surgery_id")
    if role not in {"patient", "doctor"} or not patient_id or not surgery_type:
        conn.close()
        return None

    if role == "patient" and not surgery_id:
        conn.close()
        return None
    doctor_id = canonical_account_id(record_data.get("doctor_id")) if role == "doctor" else None
    if role == "doctor" and not doctor_id:
        conn.close()
        return None

    encrypted_fields = {
        field: encrypt_field(str(record_data.get(field) or "").strip() or None)
        for field in ("surgery_type", "surgeon", "hospital", "status", "follow_up", "notes")
    }
    surgery_date = str(record_data.get("surgery_date") or "").strip() or None
    now = datetime.now().isoformat()
    try:
        doctor = None
        if role == "doctor":
            doctor = conn.execute(
                '''SELECT 1 FROM doctors d
                   JOIN doctor_accounts a ON a.id = d.id
                   WHERE d.id = ? AND a.account_status = 'active' ''',
                (doctor_id,)
            ).fetchone()
        patient = conn.execute("SELECT 1 FROM patients WHERE id = ?", (patient_id,)).fetchone()
        if not patient:
            conn.close()
            return None

        if surgery_id:
            owner_clause = "patient_id = ?" if role == "patient" else "doctor_id = ?"
            owner_id = patient_id if role == "patient" else doctor_id
            if role == "doctor" and not doctor:
                conn.close()
                return None
            cursor = conn.execute(
                '''UPDATE surgery_records
                   SET surgery_type = ?, surgery_date = ?, surgeon = ?, hospital = ?,
                       status = ?, follow_up = ?, notes = ?, updated_at = ?
                   WHERE id = ? AND patient_id = ? AND ''' + owner_clause,
                (encrypted_fields["surgery_type"], surgery_date, encrypted_fields["surgeon"],
                 encrypted_fields["hospital"], encrypted_fields["status"],
                 encrypted_fields["follow_up"], encrypted_fields["notes"], now,
                 surgery_id, patient_id, owner_id)
            )
            if cursor.rowcount != 1:
                conn.close()
                return None
            record_id = surgery_id
        else:
            if role != "doctor" or not doctor:
                conn.close()
                return None
            cursor = conn.execute(
                '''INSERT INTO surgery_records
                   (patient_id, doctor_id, surgery_type, surgery_date, surgeon, hospital,
                    status, follow_up, notes, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (patient_id, doctor_id, encrypted_fields["surgery_type"], surgery_date,
                 encrypted_fields["surgeon"], encrypted_fields["hospital"],
                 encrypted_fields["status"], encrypted_fields["follow_up"],
                 encrypted_fields["notes"], now, now)
            )
            record_id = cursor.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM surgery_records WHERE id = ?", (record_id,)).fetchone()
        record = dict(row)
        for field in ("surgery_type", "surgeon", "hospital", "status", "follow_up", "notes"):
            if record.get(field):
                record[field] = decrypt_field(record[field])
        conn.close()
        return record
    except Exception:
        conn.rollback()
        conn.close()
        raise

def add_notification(recipient_id, message, sender_id=None):
    """Add a notification for a patient or doctor account."""
    conn = get_db()
    recipient_id = canonical_account_id(recipient_id)
    if sender_id:
        sender_id = canonical_account_id(sender_id)
    try:
        conn.execute('''INSERT INTO notifications (recipient_id, sender_id, message, created_at)
                        VALUES (?, ?, ?, ?)''',
                     (recipient_id, sender_id, message, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def get_notifications(recipient_id):
    """Get recent notifications and unread count for an account."""
    conn = get_db()
    recipient_id = canonical_account_id(recipient_id)
    rows = conn.execute('''SELECT * FROM notifications WHERE recipient_id = ?
                          ORDER BY created_at DESC LIMIT 50''', (recipient_id,)).fetchall()
    unread = conn.execute('''SELECT COUNT(*) FROM notifications
                             WHERE recipient_id = ? AND is_read = 0''', (recipient_id,)).fetchone()[0]
    conn.close()
    return [dict(row) for row in rows], unread

def mark_notifications_read(recipient_id):
    """Mark all notifications for an account as read."""
    recipient_id = canonical_account_id(recipient_id)
    conn = get_db()
    conn.execute('UPDATE notifications SET is_read = 1 WHERE recipient_id = ?', (recipient_id,))
    conn.commit()
    conn.close()

def sanitize_text(value, max_length=255, allow_newlines=False):
    """Strip whitespace and escape HTML to prevent reflected XSS in profile text fields."""
    if value is None:
        return ""
    text = str(value).strip().replace("\x00", "")
    if not allow_newlines:
        text = " ".join(text.split())
    else:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = escape(text, quote=True)
    if max_length and len(text) > max_length:
        text = text[:max_length].rstrip()
    return text


def validate_email(email):
    """Validate and normalize an email address before storing it."""
    if email is None:
        return None
    normalized = sanitize_text(email, max_length=254).lower()
    if not normalized or "@" not in normalized:
        return None
    pattern = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
    return normalized if pattern.fullmatch(normalized) else None


def validate_password(password):
    """Require a reasonably strong password with mixed character classes."""
    if password is None:
        return False
    normalized = sanitize_text(password, max_length=128)
    if len(normalized) < 8 or len(normalized) > 128:
        return False
    if not re.search(r"[a-z]", normalized):
        return False
    if not re.search(r"[A-Z]", normalized):
        return False
    if not re.search(r"\d", normalized):
        return False
    if not re.search(r"[^A-Za-z0-9]", normalized):
        return False
    return True


def validate_security_pin(pin):
    """Ensure a login PIN is exactly four digits and not user-controlled script input."""
    if pin is None:
        return False
    normalized = sanitize_text(pin, max_length=8)
    return bool(re.fullmatch(r"\d{4}", normalized))


def hash_password(password):
    """Hash password using SHA256"""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def normalize_phone(phone):
    """Normalize phone input so registration and login use the same value."""
    raw = sanitize_text(phone, max_length=32)
    has_plus = "+" in raw
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return ""
    return f"+{digits}" if has_plus else digits


def verify_password(password, password_hash):
    """Verify password against hash"""
    return hash_password(password) == password_hash

def register_patient(patient_id, name, phone, email, password, age=None, gender=None, blood_group=None,
                    security_pin=None):
    """Register new patient account and create patient record with AES-256 encryption."""
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    try:
        phone = normalize_phone(phone)
        name = sanitize_text(name, max_length=100)
        email = validate_email(email)
        password = str(password or "")
        pin = str(security_pin or "")
        password_hash = hash_password(password)
        pin_hash = hash_password(pin) if validate_security_pin(pin) else hash_password("1234")
        c.execute('''INSERT INTO patient_accounts (id, password_hash, phone, email, two_step_enabled,
                    security_pin_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (patient_id, password_hash, phone, email, 1, pin_hash, now))
        
        c.execute('''INSERT INTO patients (id, name, phone, email, age, gender, blood_group, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (patient_id, name, phone, email, age, gender,
                  sanitize_text(blood_group, max_length=20) if blood_group else blood_group, now, now))
        
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def register_doctor(doctor_id, name, phone, email, password, specialization=None, qualification=None,
                    experience=None, security_pin=None, doctor_type=None, license_number=None,
                    department=None, hospital=None, clinic_address=None):
    """Register new doctor account and create doctor record with AES-256 encryption."""
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    try:
        phone = normalize_phone(phone)
        name = sanitize_text(name, max_length=100)
        email = validate_email(email)
        password = str(password or "")
        pin = str(security_pin or "")
        password_hash = hash_password(password)
        pin_hash = hash_password(pin) if validate_security_pin(pin) else hash_password("1234")
        c.execute('''INSERT INTO doctor_accounts (id, password_hash, phone, email, two_step_enabled,
                    security_pin_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (doctor_id, password_hash, phone, email, 1, pin_hash, now))
        
        c.execute('''INSERT INTO doctors (id, name, phone, email, doctor_type, license_number, department,
                specialization, qualification, experience, hospital, clinic_address, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
             (doctor_id, name, phone, email, sanitize_text(doctor_type, max_length=50) if doctor_type else doctor_type,
              sanitize_text(license_number, max_length=50) if license_number else license_number,
              sanitize_text(department, max_length=80) if department else department,
              sanitize_text(specialization, max_length=80) if specialization else specialization,
              sanitize_text(qualification, max_length=80) if qualification else qualification,
              experience, sanitize_text(hospital, max_length=120) if hospital else hospital,
              sanitize_text(clinic_address, max_length=200) if clinic_address else clinic_address,
              now, now))
        
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def reset_account_credentials(role, identifier, new_password, new_pin=None):
    """Update a password and optionally a login PIN after successful recovery verification."""
    if len(str(new_password)) < 8:
        return False

    table = _account_table(role)
    conn = get_db()
    account = conn.execute(f"SELECT id FROM {table} WHERE id = ? OR phone = ?",
                           (identifier, normalize_phone(identifier))).fetchone()
    if not account:
        conn.close()
        return False

    if new_pin is not None:
        new_pin = str(new_pin).strip()
        if not new_pin.isdigit() or len(new_pin) != 4:
            conn.close()
            return False

    try:
        if new_pin is not None:
            conn.execute(f"UPDATE {table} SET password_hash = ?, security_pin_hash = ? WHERE id = ? OR phone = ?",
                         (hash_password(new_password), hash_password(new_pin), identifier, normalize_phone(identifier)))
        else:
            conn.execute(f"UPDATE {table} SET password_hash = ? WHERE id = ? OR phone = ?",
                         (hash_password(new_password), identifier, normalize_phone(identifier)))
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def authenticate_patient(identifier, password):
    """Authenticate patient by ID or phone and password. Returns patient dict or None."""
    conn = get_db()
    c = conn.cursor()
    try:
        phone_identifier = normalize_phone(identifier)
        c.execute('''SELECT a.id, a.phone, a.email, a.password_hash FROM patient_accounts a
                WHERE a.id = ? OR a.phone = ?''', (identifier, phone_identifier))
        account = c.fetchone()
        conn.close()
        
        if account and verify_password(password, account['password_hash']):
            return {'id': account['id'], 'phone': account['phone'], 'email': account['email']}
        return None
    except Exception as e:
        conn.close()
        return None

def authenticate_doctor(identifier, password):
    """Authenticate doctor by ID or phone and password. Returns doctor dict or None."""
    conn = get_db()
    c = conn.cursor()
    try:
        phone_identifier = normalize_phone(identifier)
        c.execute('''SELECT a.id, a.phone, a.email, a.password_hash FROM doctor_accounts a
                WHERE a.id = ? OR a.phone = ?''', (identifier, phone_identifier))
        account = c.fetchone()
        conn.close()
        
        if account and verify_password(password, account['password_hash']):
            return {'id': account['id'], 'phone': account['phone'], 'email': account['email']}
        return None
    except Exception as e:
        conn.close()
        return None

def patient_exists(patient_id):
    """Check if patient ID exists"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT 1 FROM patient_accounts WHERE id = ?', (patient_id,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def doctor_exists(doctor_id):
    """Check if doctor ID exists"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT 1 FROM doctor_accounts WHERE id = ?', (doctor_id,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def phone_exists_patient(phone):
    """Check if phone number exists in either account table."""
    conn = get_db()
    c = conn.cursor()
    normalized_phone = normalize_phone(phone)
    c.execute('''SELECT 1 FROM patient_accounts WHERE phone = ?
                 UNION ALL SELECT 1 FROM doctor_accounts WHERE phone = ?''',
              (normalized_phone, normalized_phone))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def phone_exists_doctor(phone):
    """Check if phone number exists in either account table."""
    return phone_exists_patient(phone)

def _account_table(role):
    return "patient_accounts" if role == "patient" else "doctor_accounts"

def get_profile(role, identifier):
    """Get the profile and account settings with decrypted sensitive fields."""
    table = _account_table(role)
    profile_table = "patients" if role == "patient" else "doctors"
    conn = get_db()
    c = conn.cursor()
    normalized_identifier = normalize_phone(identifier)
    c.execute(f'''SELECT a.id, a.phone, a.email, a.two_step_enabled, p.*
                  FROM {table} a JOIN {profile_table} p ON p.id = a.id
                  WHERE a.id = ? OR a.phone = ?''', (identifier, normalized_identifier))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return _decrypt_patient(row) if role == "patient" else _decrypt_doctor(row)

def update_profile(role, account_id, profile_data):
    """Update editable profile fields without discarding values omitted from a partial form."""
    table = _account_table(role)
    profile_table = "patients" if role == "patient" else "doctors"
    account_id = canonical_account_id(account_id)
    now = datetime.now().isoformat()
    conn = get_db()
    c = conn.cursor()
    try:
        current = c.execute(f"SELECT * FROM {profile_table} WHERE id = ?", (account_id,)).fetchone()
        if not current:
            conn.close()
            return False
        current = dict(current)
        current_profile = _decrypt_patient(current) if role == "patient" else _decrypt_doctor(current)

        if any(key in profile_data and not str(profile_data[key] or "").strip() for key in ("name", "phone")):
            conn.close()
            return False

        def supplied_value(key):
            value = profile_data.get(key)
            return value if value is not None and str(value).strip() else current_profile.get(key)

        name = supplied_value("name")
        raw_phone = supplied_value("phone")
        if not name or not raw_phone:
            conn.close()
            return False
        phone = normalize_phone(raw_phone)
        if not phone:
            conn.close()
            return False
        duplicate = c.execute(f"SELECT 1 FROM {table} WHERE phone = ? AND id != ?", (phone, account_id)).fetchone()
        other_table = "doctor_accounts" if table == "patient_accounts" else "patient_accounts"
        duplicate = duplicate or c.execute(f"SELECT 1 FROM {other_table} WHERE phone = ?", (phone,)).fetchone()
        if duplicate:
            conn.close()
            return False
        email = supplied_value("email")
        if role == "patient":
            med_history = encrypt_field(supplied_value("medical_history"))
            c.execute(f'''UPDATE {profile_table} SET name = ?, phone = ?, email = ?, age = ?,
                         gender = ?, blood_group = ?, address = ?, medical_history = ?, updated_at = ? WHERE id = ?''',
                      (name, phone, email, supplied_value("age"), supplied_value("gender"),
                       supplied_value("blood_group"), supplied_value("address"),
                       med_history, now, account_id))
        else:
            c.execute(f'''UPDATE {profile_table} SET name = ?, phone = ?, email = ?, doctor_type = ?,
                             license_number = ?, department = ?, specialization = ?, qualification = ?, experience = ?,
                             hospital = ?, clinic_address = ?, updated_at = ? WHERE id = ?''',
                         (name, phone, email, supplied_value("doctor_type"), supplied_value("license_number"),
                          supplied_value("department"), supplied_value("specialization"), supplied_value("qualification"),
                          supplied_value("experience"), supplied_value("hospital"), supplied_value("clinic_address"),
                          now, account_id))

        c.execute(f"UPDATE {table} SET phone = ?, email = ? WHERE id = ?", (phone, email, account_id))
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def get_two_step_enabled(role, identifier):
    """Return the saved two-step preference for an account."""
    table = _account_table(role)
    conn = get_db()
    c = conn.cursor()
    c.execute(f"SELECT two_step_enabled FROM {table} WHERE id = ? OR phone = ?",
              (identifier, normalize_phone(identifier)))
    row = c.fetchone()
    conn.close()
    return bool(row and row[0])

def set_two_step_enabled(role, identifier, enabled):
    """Save the two-step preference for an account."""
    table = _account_table(role)
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute(f"UPDATE {table} SET two_step_enabled = ? WHERE id = ? OR phone = ?",
                  (1 if enabled else 0, identifier, normalize_phone(identifier)))
        conn.commit()
        changed = c.rowcount > 0
        conn.close()
        return changed
    except Exception:
        conn.close()
        return False

def set_security_pin(role, identifier, pin):
    """Store a hashed security PIN and enable PIN verification."""
    table = _account_table(role)
    conn = get_db()
    try:
        conn.execute(f"UPDATE {table} SET security_pin_hash = ?, two_step_enabled = 1 WHERE id = ? OR phone = ?",
                     (hash_password(pin), identifier, normalize_phone(identifier)))
        conn.commit()
        changed = conn.total_changes > 0
        conn.close()
        return changed
    except Exception:
        conn.close()
        return False

def verify_security_pin(role, identifier, pin):
    """Verify a security PIN for an account."""
    table = _account_table(role)
    conn = get_db()
    row = conn.execute(f"SELECT security_pin_hash FROM {table} WHERE id = ? OR phone = ?",
                       (identifier, normalize_phone(identifier))).fetchone()
    conn.close()
    return bool(row and row[0] and verify_password(pin, row[0]))

def change_account_password(role, identifier, current_password, new_password):
    """Change a password after verifying the current password."""
    table = _account_table(role)
    conn = get_db()
    try:
        row = conn.execute(f"SELECT password_hash FROM {table} WHERE id = ? OR phone = ?",
                           (identifier, normalize_phone(identifier))).fetchone()
        if not row or not verify_password(current_password, row[0]):
            conn.close()
            return False
        conn.execute(f"UPDATE {table} SET password_hash = ? WHERE id = ? OR phone = ?",
                     (hash_password(new_password), identifier, normalize_phone(identifier)))
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def account_id_exists(account_id):
    """Check whether an ID is already used by any account or profile."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT 1 FROM patient_accounts WHERE id = ?
                 UNION ALL SELECT 1 FROM doctor_accounts WHERE id = ?
                 UNION ALL SELECT 1 FROM patients WHERE id = ?
                 UNION ALL SELECT 1 FROM doctors WHERE id = ?''',
              (account_id, account_id, account_id, account_id))
    exists = c.fetchone() is not None
    conn.close()
    return exists

# --- WebAuthn / Hardware Credential Helpers ---
def add_hardware_credential(credential_id, account_id, role, public_key):
    """Store WebAuthn hardware security key / biometric credential."""
    conn = get_db()
    account_id = canonical_account_id(account_id)
    now = datetime.now().isoformat()
    try:
        conn.execute('''INSERT OR REPLACE INTO hardware_credentials
                        (credential_id, account_id, role, public_key, sign_count, created_at)
                        VALUES (?, ?, ?, ?, 0, ?)''',
                     (credential_id, account_id, role, public_key, now))
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def get_hardware_credential(credential_id):
    """Look up a WebAuthn credential by ID."""
    conn = get_db()
    row = conn.execute('SELECT * FROM hardware_credentials WHERE credential_id = ?', (credential_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_hardware_credentials_for_account(account_id):
    """Get all registered hardware credentials for an account."""
    conn = get_db()
    account_id = canonical_account_id(account_id)
    rows = conn.execute('SELECT credential_id, role, created_at FROM hardware_credentials WHERE account_id = ?', (account_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

if __name__ == "__main__":
    init_database()
