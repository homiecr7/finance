import os
import math

from cs50 import SQL
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
    # No of distinct shares
    symbol = db.execute("SELECT DISTINCT(symbol) FROM buy WHERE personID = ?", session["user_id"])

    # initiate list for list of details
    shares = []

    # initiate list for dic of cash and total cost
    other = []

    # temp dic for details which is cleard in the loop
    details = {}
    total_value1 = 0
    share_value ={}

    # loop for querying the details appending it to the dic then to list
    for i in symbol:
        for j in i.values():
            num = db.execute("SELECT SUM(noshares) AS share FROM buy WHERE symbol = ? AND personID = ?", j, session["user_id"])
            detail = lookup(j)
            details["name"] = detail["name"]
            details["price"] = detail["price"]
            details["symbol"] = detail["symbol"]
            details["noshares"] = num[0]["share"]
            details["total"] = usd(details["price"] * details["noshares"])
            temp = details.copy()
            temp["price"] = usd(temp["price"])
            shares.append(temp)
            total_value = details["price"] * details["noshares"]
            total_value1 += total_value
            details.clear()
    details["totals"] = total_value1
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    details["cash"] = cash[0]["cash"]
    details["total"] = usd(total_value1 + cash[0]["cash"])
    details["totals"] = usd(total_value1)
    details["cash"] = usd(cash[0]["cash"])
    other.append(details)

    # redering template
    return render_template("index.html", shares=shares, other=other)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    # post method
    if request.method == "POST":

        # looking up symbol quotes and number of shares
        if lookup(request.form.get("symbol")) == None:
            return apology("Please enter correct symbol")
        elif (request.form.get("shares")).isnumeric() == False:
            return apology("Please use a numeric value")
        elif int(request.form.get("shares")) < 1:
            return apology("Please enter a positive integer")

        # inserting in database if all is clear
        else:
            symbol = request.form.get("symbol")
            shares = int(request.form.get("shares"))
            detail = (lookup(symbol))["price"]
            cash = (db.execute("SELECT * FROM users WHERE id = ?", session["user_id"]))[0]["cash"]

            # check enough cash is present to afford the stock
            if cash < (detail * shares):
                return apology("You donot have enough cash")

            # run sql statemnt to purchase the stock
            # db.execute("INSERT INTO buy(personID, symbol, noshares) VALUES(?, ?, ?)", session["user_id"], symbol, shares)

            db.execute("UPDATE buy SET noshares = noshares + ? WHERE personID = ? AND symbol = ?",
                       shares, session["user_id"], symbol)

            # will check if record exist
            exist = db.execute("SELECT * FROM buy WHERE personID = ? AND symbol = ?", session["user_id"], symbol)

            # if exist has no value it will insert
            if not exist:
                db.execute("INSERT INTO buy(personID, symbol, noshares) VALUES(?, ?, ?)", session["user_id"], symbol, shares)

            # update cash
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - (detail * shares), session["user_id"])

            # update history table
            db.execute("INSERT INTO history(symbol, shares, price, datetime) VALUES(?, ?, ?, datetime('now'))",
                       symbol, shares, "${}".format(detail))

            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    history = db.execute("SELECT * FROM history")
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
    # post method
    if request.method == "POST":
        symbol = request.form.get("symbol")
        detail = lookup(symbol)

        # if wrong symbol
        if detail == None:
            return apology("Please enter a correct symbol")

        # will render template with relvant details
        else:
            detail["price"] = usd(detail["price"])
            return render_template("/quote.html", detail=detail)
    # get method
    else:
        return render_template("/quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # post method
    if request.method == "POST":

        # fetching relevant details
        name = request.form.get("username")
        password = request.form.get("password")
        re_pass = request.form.get("confirmation")

        # getting user names
        users = db.execute("SELECT username FROM users")

        # creating list of users
        user = []
        for names in users:
            for val in names.values():
                user.append(val)

        # if name dont exist in database
        if not name or not password or not re_pass:
            return apology("Please fill all the credentials.")

        # if passwords don't match
        elif password != re_pass:
            return apology("Passwords did not match.")

        # if name is already present in the database
        elif name.lower() in user:
            return apology("Username already taken :(")
        else:
            # generating password hash
            pass_hash = generate_password_hash(password)

            # inserting in the database
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name.lower(), pass_hash)

            # logging user in
            user_id = db.execute("SELECT id FROM users WHERE username = ?", name)
            session["user_id"] = user_id[0]["id"]

            # redirecting to index page
            return redirect("/")

    # get method
    return render_template("/register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    # post method
    if request.method == "POST":
        # checking if symbol and shares exist
        if not request.form.get("symbol"):
            return apology("PLEASE SELECT CORRECT SHARE SYMBOL")
        elif not request.form.get("shares"):
            return apology("PLEASE SELECT POSITIVE INTEGER FOR NUMBER OF SHARES")

        # saving the details from form
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        price = (lookup(symbol))["price"]

        # condition if shares are zero or less than zero
        if shares <= 0:
            return apology("PLEASE SELECT POSITIVE INTEGER FOR NUMBER OF SHARES")

        # condition if symbol was selected as string
        elif shares == "Symbol":
            return apology("PLEASE SELECT CORRECT SHARE SYMBOL")

        # to check if held shares are greater than selected shares
        elif shares > (db.execute("SELECT noshares FROM buy WHERE personID = ? AND symbol = ?", session["user_id"], symbol))[0]["noshares"]:
            return apology("SELLING SHARES ARE LESS THAN HELD SHARES")

        # updating shares in buy, cash in users. deletting if share count is zero and updating history table
        else:
            db.execute("UPDATE buy SET noshares = noshares - ? WHERE personID = ? AND symbol = ?",
                       shares, session["user_id"], symbol)
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", shares * price, session["user_id"])
            db.execute("DELETE FROM buy WHERE noshares = 0")
            db.execute("INSERT INTO history(symbol, shares, price, datetime) VALUES(?, ?, ?, datetime('now'))",
                       symbol, "-{}".format(shares), "${}".format(price))
            return redirect("/")

    else:
        # current stocks to sell from portfolio
        symbol = db.execute("SELECT DISTINCT(symbol) FROM buy WHERE personID = ?", session["user_id"])
        return render_template("sell.html", symbol=symbol)

@app.route("/password", methods=["GET", "POST"])
def password():

    # post request
    if request.method == "POST":
        password = request.form.get("password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # check if exist
        if not (password and new_password and confirmation) :
            return apology("Please fill all the fields")

        # current password is same
        elif not check_password_hash((db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"]))[0]["hash"], password):
            return apology("Please enter correct password")

        # new passwords are same
        elif new_password != confirmation:
            return apology("Passwords did not match")

        # generate new hash and query it to the table
        else:
            hashed = generate_password_hash(new_password)
            db.execute("UPDATE users SET hash = ? WHERE id = ?",hashed, session["user_id"])

            # log user out and redirect to the page
            logout()
            return redirect("/")

    else:
        return render_template("password.html")

