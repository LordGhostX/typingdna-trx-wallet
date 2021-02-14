import hashlib
from datetime import datetime
from functools import wraps
import requests
from flask import *
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from tronapi import Tron
from typingdna import TypingDNA

app = Flask(__name__)
app.config["SECRET_KEY"] = "SECRET_KEY"
app.config["ENCRYPTION_SALT"] = "ENCRYPTION_SALT"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///wallet.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
Bootstrap(app)
db = SQLAlchemy(app)
tdna = TypingDNA("apiKey", "apiSecret")


full_node = "https://api.trongrid.io"
solidity_node = "https://api.trongrid.io"
event_server = "https://api.trongrid.io"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=False)
    private_key = db.Column(db.String(255), unique=True, nullable=False)
    address = db.Column(db.String(255), unique=True, nullable=False)
    typingdna_secured = db.Column(db.Boolean, nullable=False, default=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


def encrypt_password(password):
    return hashlib.sha512((password + app.config["ENCRYPTION_SALT"]).encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def hexfilter(hex):
    tron = Tron(full_node=full_node, solidity_node=solidity_node,
                event_server=event_server)
    return tron.address.from_hex(hex).decode("utf-8")


def timefilter(timestamp):
    return datetime.fromtimestamp(timestamp / 1000).strftime("%c")


app.jinja_env.filters["hexfilter"] = hexfilter
app.jinja_env.filters["timefilter"] = timefilter


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/auth/register/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip().lower()
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            flash("The account you are trying to create already exists", "danger")
            return redirect(url_for("register"))

        tron = Tron(full_node=full_node, solidity_node=solidity_node,
                    event_server=event_server)
        account = tron.create_account
        private_key = account.private_key
        address = account.address.base58
        db.session.add(User(username=username, password=encrypt_password(password),
                            private_key=private_key, address=address))
        db.session.commit()
        flash("You have successfully registered your account", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/auth/login/", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username").strip().lower()
        password = request.form.get("password")

        user = User.query.filter_by(
            username=username, password=encrypt_password(password)).first()
        if user:
            session["user"] = {
                "username": user.username,
                "address": user.address
            }
            if user.typingdna_secured:
                return redirect(url_for("dashboard"))
            else:
                return redirect(url_for("enroll_typingdna"))
        else:
            flash("You have supplied invalid login credentials", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/auth/typingdna/enroll/", methods=["GET", "POST"])
@login_required
def enroll_typingdna():
    if request.method == "POST":
        tp = request.form.get("tp")
        username = session["user"]["username"]
        r = tdna.auto(tdna.hash_text(username), tp)
        if r.status_code == 200:
            User.query.filter_by(username=username).update(
                dict(typingdna_secured=True))
            db.session.commit()
            flash("You have successfully registered TypingDNA 2FA", "success")
            return redirect(url_for("dashboard"))
        else:
            flash(r.json()["message"], "danger")
            return redirect(url_for("enroll_typingdna"))
    return render_template("typingdna-enroll.html")


@app.route("/dashboard/", methods=["GET", "POST"])
@login_required
def dashboard():
    user = User.query.filter_by(username=session["user"]["username"]).first()
    if not user.typingdna_secured:
        return redirect(url_for("enroll_typingdna"))

    tron = Tron(full_node=full_node, solidity_node=solidity_node,
                event_server=event_server)
    tron.private_key = user.private_key
    tron.default_address = session["user"]["address"]
    balance = tron.trx.get_balance() / 1000000

    if request.method == "POST":
        amount = request.form.get("amount").strip()
        address = request.form.get("address").strip()
        password = request.form.get("password")

        try:
            amount = float(amount)
        except:
            flash("You have supplied an invalid withdrawal amount", "danger")
            return redirect(url_for("dashboard"))
        if amount > balance:
            flash("You cannot withdraw more than your account balance", "danger")
            return redirect(url_for("dashboard"))
        if not tron.isAddress(address):
            flash("The withdrawal address provided is not valid", "danger")
            return redirect(url_for("dashboard"))
        if address == session["user"]["address"]:
            flash("You cannot withdraw to your own wallet", "danger")
            return redirect(url_for("dashboard"))
        if encrypt_password(password) != user.password:
            flash("The account password provided is not valid", "danger")
            return redirect(url_for("dashboard"))
        try:
            transaction = tron.trx.send(address, amount)
            if transaction["result"]:
                flash(
                    f"Your withdrawal was successfully created, you can track your transaction <a href='https://tronscan.org/#/transaction/{transaction['txid']}' target='_blank'>here</a>", "success")
                return redirect(url_for("dashboard"))
            else:
                raise Exception()
        except:
            flash("An error occured when processing your withdrawal", "danger")
            return redirect(url_for("dashboard"))

    transactions = requests.get(
        f"https://api.trongrid.io/v1/accounts/{session['user']['address']}/transactions").json()["data"]
    return render_template("dashboard.html", balance=balance, transactions=transactions)


@app.route("/dashboard/logout/")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
