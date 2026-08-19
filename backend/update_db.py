import sqlite3

# 1. Database နဲ့ ချိတ်ဆက်မည်
conn = sqlite3.connect('app.db')
cursor = conn.cursor()

print("Updating database schema without deleting data...")

# 2. Column အသစ်များ ပေါင်းထည့်မည်
try:
    cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN vulnerable_code TEXT;")
    print("✅ Added 'vulnerable_code' column successfully.")
except sqlite3.OperationalError as e:
    print("⚠️ Column 'vulnerable_code' might already exist.")

try:
    cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN secure_code TEXT;")
    print("✅ Added 'secure_code' column successfully.")
except sqlite3.OperationalError as e:
    print("⚠️ Column 'secure_code' might already exist.")

# 3. Save & Close
conn.commit()
conn.close()

print("\n🎉 Database update complete! Your existing scan data is safe.")