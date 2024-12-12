from flask import Flask, render_template, request, redirect, url_for, session
import os
import numpy as np
from prediction import predict_res
import pandas as pd
import yagmail
import mysql.connector
from mitigation import get_mitigation_for_attack

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "intrusionn"

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Rishika123',
    'database': 'intrusion',
}

# Database connection
conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    gender ENUM('Male', 'Female') NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    city VARCHAR(255),
    country VARCHAR(255)
)
''')

# Routes
@app.route("/index")
def index():
    return render_template("index.html")


@app.route('/predict', methods=['POST', 'GET'])
def predict():
    try:
        if request.method == 'POST':
            file = request.files['file_path']
            file_path = 'upload/' + file.filename
            file.save(file_path)

            # Call the prediction function
            prediction_data = predict_res(file_path)

            # Extract attack type and normalize to lowercase
            attack_type = prediction_data[1].split(":")[1].strip().lower()

            # Fetch mitigation measures dynamically
            mitigation = get_mitigation_for_attack(attack_type)

            # Send email if attack type is one of the specified types
            if attack_type in ['ddos', 'password', 'scanning']:
                try:
                    # Use Yagmail to send an email alert
                    user = yagmail.SMTP(
                        user='alertname23@gmail.com',  # Replace with your Gmail address
                        password='uufbvzxpmrwjueez'  # Replace with your Gmail App Password
                    )
                    user.send(
                        to='oitsme04@gmail.com',  # Replace with recipient's email
                        subject='$$ALERT$$',
                        contents=f"An intrusion of type {attack_type.upper()} has been detected! Please take immediate action."
                    )
                    print("Email sent successfully!")
                except Exception as e:
                    print(f"Error sending email: {e}")

            return render_template(
                'index.html',
                lb=attack_type,  # Attack type for display
                ip=prediction_data[0],  # IP address for display
                mitigation=mitigation  # Mitigation measures as a list
            )

        return render_template('index.html')

    except Exception as e:
        # Log error for debugging
        print(f"Error in predict route: {str(e)}")
        return render_template('index.html', u=str(e))


def read_excel():
    try:
        df = pd.read_csv('LOG.csv')

        if df.empty:
            return ['IP Address', 'Block Reason'], []

        cols = list(df.columns)
        df1 = np.asarray(df)
        length = len(df1)
        df2 = []

        count = length
        for i in range(length):
            df2.append(df1[count - 1])
            count -= 1

        return cols, df2
    except FileNotFoundError:
        print("Error: File not found.")
        return ['IP Address', 'Block Reason'], []
    except Exception as e:
        print("Error:", e)
        return ['IP Address', 'Block Reason'], []


@app.route("/blocked_ip", methods=['GET', 'POST'])
def blocked_ip():
    data = read_excel()
    cols = data[0]
    values = data[1]
    title = "List of Blocked Clients"
    return render_template("result1.html", title=title, cols=cols, values=values)


@app.route("/clear_data", methods=['GET', 'POST'])
def clear_data():
    df = pd.read_csv("LOG.csv")
    df.drop(df.index, inplace=True)
    df.to_csv("LOG.csv", index=False)

    return redirect(url_for('blocked_ip'))


@app.route('/register', methods=['POST', 'GET'])
def register():
    try:
        if request.method == 'POST':
            userDetails = request.form
            name = userDetails['name']
            email = userDetails['Email']
            password = userDetails['Password']
            last_name = userDetails['Last_name']
            sex = userDetails['gender']
            city = userDetails['city']
            country = userDetails['country']

            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()

            cur.execute("INSERT INTO users(name, last_name, gender, email, password, city, country) VALUES(%s, %s, %s, %s, %s, %s, %s)",
                        (name, last_name, sex, email, password, city, country))

            conn.commit()
            cur.close()
            conn.close()

            if sex == 'Male':
                msg = "Hello Mr. {} !! You can login Here !!!".format(name)
            else:
                msg = "Hello Ms. {} !! You can login Here !!!".format(name)
            return render_template('login.html', msg=msg, email=email)

        return render_template('register.html')
    except Exception as e:
        return render_template('register.html', msg=e)


@app.route('/')
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form["email"]
        password = request.form["password"]

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user:
            return redirect(url_for('index'))
        else:
            msg = 'Invalid Login Details. Please Try Again.'
            return render_template('login.html', msg=msg, email=email)
    return render_template('login.html')


@app.route('/password', methods=['POST', 'GET'])
def password():
    if request.method == 'POST':
        current_pass = request.form['current']
        new_pass = request.form['new']
        verify_pass = request.form['verify']
        email = request.form['email']

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            if user[5] == current_pass:
                if new_pass == verify_pass:
                    cursor.execute(
                        "UPDATE users SET password = %s WHERE email = %s", (new_pass, email))
                    conn.commit()
                    cursor.close()
                    conn.close()
                    msg = 'Password changed successfully'
                    return render_template('password.html', msg=msg)
                else:
                    cursor.close()
                    conn.close()
                    msg = 'Re-entered password does not match'
                    return render_template('password.html', msg=msg)
            else:
                cursor.close()
                conn.close()
                msg = 'Incorrect current password'
                return render_template('password.html', msg=msg)
        else:
            cursor.close()
            conn.close()
            msg = 'User not found'
            return render_template('password.html', msg=msg)

    return render_template('password.html')


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == '__main__':
    app.run(port=5015, debug=True)
