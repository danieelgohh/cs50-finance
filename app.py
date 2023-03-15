import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True, nullable=False)
#     username = db.Column(db.String(20), unique=True, nullable=False)
#     password = db.Column(db.String(60), nullable=False)
#     cash = db.Column(db.Float(precision=2), default=10000.00)
#     history = db.relationship('History', backref='buyer', lazy=True)

# class History(db.Model):
#     id = db.Column(db.Integer, primary_key=True, nullable=False)
#     name = db.Column(db.String, nullable=False)
#     symbol = db.Column(db.String, nullable=False)
#     price_per_share = db.Column(db.Float(precision=2), nullable=False)
#     date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    id = session.get("user_id")
    currprice = 0
    symbol = db.execute("SELECT symbol FROM purchases WHERE user_id = ? GROUP BY symbol", id)
    name = db.execute("SELECT name FROM purchases WHERE id = ? GROUP BY name", id)
    cash = round(db.execute("SELECT cash FROM users WHERE id = ?", id)[0]['cash'], 2)
    for symb in symbol:
        x = lookup(symb['symbol'])
        tshares = db.execute("SELECT SUM(shares) FROM purchases WHERE user_id = ? and symbol = ?", id, symb['symbol'])
        total_price = float(tshares[0]['SUM(shares)']) * x["price"]
        currprice += total_price
    return render_template("index.html", symbol=symbol, name=name, cash=cash, float=float, currprice=currprice, lookup=lookup, db=db)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = lookup(request.form.get("symbol"))
        if not symbol:
            return apology("Symbol not found!")
        shares = request.form.get("shares")
        try:
            float(shares)
        except:
            return apology("Invalid number of shares!")
        current_user = session.get("user_id")
        cost = symbol["price"] * float(shares)
        if not shares or float(shares) < 0 or float(shares) % 1 != 0:
            return apology("Invalid number of shares!")
        if float(db.execute("SELECT cash FROM users WHERE id = ?", current_user)[0]['cash']) > cost:
            balance = float(db.execute("SELECT cash FROM users WHERE id = ?", current_user)[0]['cash']) - cost
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, current_user)
            db.execute("INSERT INTO purchases (name, symbol, 'price per share', shares, 'total price', user_id) VALUES (?, ?, ?, ?, ?, ?)", symbol["name"], symbol["symbol"], symbol["price"], shares, (symbol["price"] * float(shares)), session.get("user_id"))
            db.execute("INSERT INTO history (name, symbol, type, shares, 'price per share', date, user_id) VALUES (?, ?, ?, ?, ?, DateTime('now'), ?)", symbol["name"], symbol["symbol"], "Purchased", shares, symbol["price"], session.get("user_id"))
            return redirect("/")
        else:
            return apology("Insufficient funds!")
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute('SELECT name, symbol, type, shares, "price per share", date FROM history WHERE user_id = ? ORDER BY date DESC', session.get("user_id"))
    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # /quote page without Javascript
    # q = request.args.get("q")
    # if q:
    #     symbol = lookup(q)
    #     if symbol == None:
    #         symbol = {}
    #     print(symbol)
    # else:
    #     symbol = {}
    # return render_template("quote.html", symbol=symbol["symbol"])
    # if request.method == "POST":
    #     symbol = lookup(request.form.get("symbol"))
    #     if not symbol:
    #         return apology("Symbol not found!")
    #     else:
    #         return render_template("quoted.html", symbol=symbol["symbol"], name=symbol["name"], price=symbol["price"])
    # else:
    #     return render_template("quote.html", api_key=os.environ.get("API_KEY"))

    # /quote page with Javascript
    return render_template("quote.html", api_key=os.environ.get("API_KEY"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("Username field is empty!")
        elif (db.execute("SELECT username FROM users WHERE username = ?", username)):
            return apology("Username is taken!")
        elif not password:
            return apology("Password field is empty!")
        elif password != confirmation:
            return apology("Password does not match!")
        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    curruser = session.get("user_id")
    symbol = db.execute("SELECT symbol FROM purchases WHERE user_id = ? GROUP BY symbol", curruser)
    if request.method == "POST":
        target_symbol = lookup(request.form.get("symbol"))
        shares = int(request.form.get("shares"))
        owned_shares = db.execute("SELECT SUM(shares) FROM purchases WHERE user_id = ? and symbol = ?", curruser, target_symbol['symbol'])[0]['SUM(shares)']
        if shares <= owned_shares:
            total_price = shares * target_symbol['price']
            balance = float(db.execute("SELECT cash FROM users WHERE id = ?", curruser)[0]['cash']) + total_price
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, curruser)
            shares_balance = owned_shares - shares
            db.execute("INSERT INTO history (name, symbol, type, shares, 'price per share', date, user_id) VALUES (?, ?, ?, ?, ?, DateTime('now'), ?)", target_symbol["name"], target_symbol["symbol"], "Sold", shares, target_symbol["price"], session.get("user_id"))
            if shares_balance == 0:
                db.execute("DELETE FROM purchases WHERE symbol = ?", target_symbol['symbol'])
            else:
                db.execute("UPDATE purchases SET shares = ? WHERE user_id = ? and symbol = ?", shares_balance, curruser, target_symbol['symbol'])
            return redirect("/")
        else:
            return apology("You do not own that many shares!")
    else:
        return render_template("sell.html", symbol=symbol)


@app.route("/repassword", methods=["GET", "POST"])
@login_required
def repassword():
    """Change user password"""
    if request.method == "POST":
        user_pass = db.execute("SELECT hash FROM users WHERE id = ?", session.get("user_id"))
        currpass = request.form.get("currpass")
        newpass = request.form.get("newpass")
        if not currpass:
            return apology("Must provide current password", 403)
        if not newpass:
            return apology("Must provide new password", 403)
        if check_password_hash(user_pass[0]['hash'], currpass) and newpass == request.form.get("confirmpass"):
            hash = generate_password_hash(newpass, method='pbkdf2:sha256', salt_length=8)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, session.get("user_id"))
            flash("Password successfully changed!")
        else:
            return apology("Wrong password!")
        return redirect("/")
    else:
        return render_template("repassword.html")

@app.route("/credit", methods=["GET", "POST"])
@login_required
def credit():
    curruser = session.get("user_id")
    amount = request.form.get("addcash")
    currcash = float(db.execute("SELECT cash FROM users WHERE id = ?", curruser)[0]['cash'])
    if request.method == "POST":
        if not amount:
            return apology("Amount required!")
        try:
            float(amount)
        except:
            return apology("Invalid amount!")
        balance = float(db.execute("SELECT cash FROM users WHERE id = ?", curruser)[0]['cash']) + float(amount)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, curruser)
        return redirect("/credit")
    else:
        return render_template("credit.html", cash=currcash)

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=8080) 