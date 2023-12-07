import os

from werkzeug.utils import secure_filename
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required
from datetime import datetime
import random
import string
from email.message import EmailMessage
import smtplib
import ssl

# Configure application
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "static/product_images"

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///HSS.db")


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
    """Show list of products"""
    # Join Products and Users database to get all products on sale
    products = db.execute(
        """
                         SELECT Products.id, Products.title, Products.description, Products.image, Products.price, Products.category, Products.status, Products.seller_id, Users.email
                         FROM Products
                         JOIN Users ON Products.seller_id = Users.id
                         WHERE status = 'On Sale'
    """
    )

    # Pass in Products variable to index.html page
    return render_template("index.html", products=products)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("login.html")

    # Ensure Harvard email as username was submitted
    email = request.form.get("email")
    if not email:
        return apology("Must provide Harvard email", 403)

    # Ensure password was submitted
    password = request.form.get("password")
    if not password:
        return apology("Must provide password", 403)

    # Query database for username (Harvard email)
    rows = db.execute("SELECT * FROM Users WHERE email = ?", email)

    # Ensure username (Harvard email) exists and password is correct
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], password):
        return apology("invalid Username and/or password", 403)

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]

    # Redirect user to home page
    return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


# Function for sending verification code
def send_verification_email(email, verification_code):
    subject = "Verify Your Email"
    body = f"Thank you for registering. Your verification code is: {verification_code}"

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = "csfinal3@gmail.com"
    msg["To"] = email
    msg["password"] = "hzxi qdaw kqup ustj"

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
        smtp.login(msg["From"], msg["password"])
        smtp.sendmail(msg["From"], msg["To"], msg.as_string())


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        # Render the registration form
        return render_template("register.html")

    password = request.form.get("password")

    # Check the length of the password
    if len(password) < 8:
        return apology("Password must be at least 8 characters long.")

    # Check for a special character in password
    if not any(char in "!@#$%^&*()_+" for char in password):
        return apology(
            "Password must contain at least one special character from !@#$%^&*()_+."
        )

    # Be able to take form submission
    email = request.form.get("email")
    session["email"] = email

    # Check that user inputs a Harvard email as their username
    if not email or not email.endswith("college.harvard.edu"):
        return apology("Must input a Harvard email as your username.")

    # Hash the password before storing it
    password = request.form.get("password")
    # Check that user inputs a password with if not
    if not password:
        return apology("Must input a password.")
    hashed_password = generate_password_hash(password)
    session["hashed_password"] = hashed_password

    confirmation = request.form.get("confirmation")
    # Check that user inputs a confirmation with if not
    if not confirmation:
        return apology("Must confirm password.")

    # Be able to take form submission forfirst name
    first_name = request.form.get("first_name")

    # Be able to take form submission for last name
    last_name = request.form.get("last_name")

    # Be able to take form submission for phone number
    phone_number = request.form.get("phone_number")

    # Check that the user inputs a phone number
    if not phone_number:
        return apology("Must input a phone number.")

    # Be able to take form submission for a birthday
    birthday = request.form.get("birthday")

    result = db.execute("SELECT * FROM Users WHERE email = ?", email)
    if result:
        return apology("Username is already taken.")

    if confirmation != password:
        return apology("Passwords do not match.")

    # Check that the user inputs a birthday
    if not birthday:
        return apology("Must input a birthday.")

    # Generate a random verification code
    verification_code = "".join(
        random.choices(string.ascii_letters + string.digits, k=20)
    )
    session["verification_code"] = verification_code

    # Send the verification email
    send_verification_email(email, verification_code)

    # Store the verification code in the database (create a new column in the users table)
    db.execute(
        "UPDATE users SET verification_code = ? WHERE email = ?",
        verification_code,
        email,
    )

    # Save user information into session
    session["first_name"] = first_name
    session["last_name"] = last_name
    session["phone_number"] = phone_number
    session["birthday"] = birthday

    # Redirect user to verify page
    return redirect(url_for(".verify_email"))


@app.route("/verify", methods=["GET", "POST"])
def verify_email():
    if request.method == "GET":
        return render_template("verify.html")
    else:
        # Get the verification code from the form submission
        verification_code_input = request.form.get("verification_code")

        # Check if the verification code is valid
        if verification_code_input == session["verification_code"]:
            # Insert user data into the Users table
            user_id = db.execute(
                "INSERT INTO Users (email, password, first_name, last_name, phone_number, birthday, verification_code) VALUES (?, ?, ?, ?, ?, ?, ?)",
                session["email"],
                session["hashed_password"],
                session["first_name"],
                session["last_name"],
                session["phone_number"],
                session["birthday"],
                session["verification_code"],
            )

            # Remember which user has logged in
            session["user_id"] = user_id

            return redirect("/")
        else:
            return apology("Invalid verification code")


# Define the allowed image extensions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell products"""
    if request.method == "POST":
        # Store title, description, image, price, and category into variables
        title = request.form.get("title")
        description = request.form.get("description")
        price = float(request.form.get("price"))
        category = request.form.get("category")

        # Handle image file upload
        if "image" not in request.files:
            return apology("No file part")

        file = request.files["image"]

        if file.filename == "":
            return apology("No selected file")

        if file and allowed_file(file.filename):
            # Secure filename to prevent possible malicious attacks
            filename = secure_filename(file.filename)

            absolute_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            # Ensure the upload folder exists
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            # Save the file to the designated upload folder
            file.save(absolute_path)

        # Ensure title was submitted
        if not title:
            return apology("Missing title")

        # Ensure description was submitted
        if not description:
            return apology("Missing description")

        # Ensure description was submitted
        if price <= 0:
            return apology("Invalid price")

        # Ensure description was submitted
        if not category:
            return apology("Missing category")

        # Store On Sale status to status variable
        status = "On Sale"

        # Get user_id from the session
        user_id = session["user_id"]

        # Update the transactions table
        db.execute(
            "INSERT INTO Products (title, description, image, price, category, status, seller_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            title,
            description,
            absolute_path,
            price,
            category,
            status,
            user_id,
        )

        # Confirm user listed a product
        flash("Listed!")

        # Redirect user to home page
        return redirect("/")
    else:
        user_id = session["user_id"]
        return render_template("sell.html")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Search for products"""
    if request.method == "POST":
        # Get the search query from the form submission
        search_query = request.form.get("search_query")

        # Validate the search query
        if not search_query:
            return apology("Please enter a search query.")

        # Perform a case-insensitive search in the Products table
        products = db.execute(
            """
                         SELECT Products.id, Products.title, Products.description, Products.image, Products.price, Products.category, Products.status, Products.seller_id, Users.email
                         FROM Products
                         JOIN Users ON Products.seller_id = Users.id
                         WHERE status = 'On Sale' AND LOWER(Products.title) LIKE LOWER(?)
    """,
            f"%{search_query}%",
        )
        # Render the search results
        return render_template(
            "search_results.html", products=products, search_query=search_query
        )

    else:
        # Render the search form
        return render_template("search.html")


@app.route("/category/<category>")
@login_required
def category(category):
    """Retrieve products based on the specified category"""
    if category == "all":
        products = db.execute(
            """
                         SELECT Products.id, Products.title, Products.description, Products.image, Products.price, Products.category, Products.status, Products.seller_id, Users.email
                         FROM Products
                         JOIN Users ON Products.seller_id = Users.id
                         WHERE status = 'On Sale'
    """
        )
    else:
        products = db.execute(
            """
                         SELECT Products.id, Products.title, Products.description, Products.image, Products.price, Products.category, Products.status, Products.seller_id, Users.email
                         FROM Products
                         JOIN Users ON Products.seller_id = Users.id
                         WHERE status = 'On Sale' AND category = ?
    """,
            category,
        )

    return render_template("index.html", products=products)


@app.route("/listing", methods=["GET", "POST"])
@login_required
def listing():
    """View your own product listings"""
    if request.method == "GET":
        # Query the database to get all items listed by the specified seller
        user_id = session["user_id"]
        try:
            seller_items = db.execute(
                "SELECT * FROM Products WHERE seller_id = ?", user_id
            )
        except Exception as e:
            print(f"Error executing SQL query: {e}")
            seller_items = []

        # Render the template with the seller's items
        return render_template("listing.html", seller_items=seller_items)


@app.route("/seller_items/<int:seller_id>")
@login_required
def seller_items(seller_id):
    """Display the listed items from the seller"""
    try:
        # Fetch the seller_id based on the provided email
        seller_id_query = db.execute("SELECT id FROM Users WHERE id = ?", seller_id)
        seller_id = seller_id_query[0]["id"] if seller_id_query else None

        seller_email_query = db.execute(
            "SELECT email FROM Users WHERE id = ?", seller_id
        )
        seller_email = seller_email_query[0]["email"] if seller_email_query else None

        # Fetch the seller's items based on the seller_id
        seller_items = db.execute(
            "SELECT * FROM Products WHERE seller_id = ? AND status = 'On Sale'",
            seller_id,
        )
    except Exception as e:
        print(f"Error executing SQL query: {e}")
        seller_items = []

    print(seller_email)
    return render_template(
        "seller_items.html",
        seller_items=seller_items,
        seller_id=seller_id,
        seller_email=seller_email,
    )


@app.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    """View your cart page"""
    if request.method == "GET":
        # Existing code to fetch and display the cart items
        user_id = session["user_id"]
        cart_items = db.execute("SELECT * FROM Carts WHERE user_id = ?", user_id)
        products = []

        for item in cart_items:
            product_id = item["product_id"]
            product = db.execute("SELECT * FROM Products WHERE id = ?", product_id)[0]

            if product:
                seller_id = product["seller_id"]
                seller_email = db.execute(
                    "SELECT email FROM Users WHERE id = ?", seller_id
                )[0]["email"]

                products.append(
                    {
                        "id": product["id"],
                        "title": product["title"],
                        "description": product["description"],
                        "image": product["image"],
                        "price": product["price"],
                        "category": product["category"],
                        "status": product["status"],
                        "seller_id": seller_id,
                        "seller_email": seller_email,
                        "product_id": product_id,
                    }
                )

        return render_template("cart.html", products=products)


@app.route("/add_to_cart/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    """Add items to your cart"""
    if request.method == "POST":
        # Retrieve product details based on the product_id
        product = db.execute("SELECT * FROM Products WHERE id = ?", product_id)[0]
        if product is None:
            return apology("Product not found", 404)

        user_id = session.get("user_id")

        if not user_id:
            return apology("user not logged in")

        # Check if the product is already in the user's cart
        existing_cart_item = db.execute(
            "SELECT * FROM Carts WHERE user_id = ? AND product_id = ?",
            user_id,
            product_id,
        )

        if existing_cart_item:
            # Product is already in the cart
            flash("Product is already in your cart!")

        else:
            db.execute(
                "INSERT INTO Carts (product_id, user_id) VALUES (?, ?)",
                product_id,
                user_id,
            )
            product = db.execute("SELECT * FROM Products WHERE id = ?", product_id)[0]

            # Flash a message indicating that the product was added to the cart
            flash(f"{product['title']} added to cart!")

        # Redirect back to index
        return redirect(url_for("index"))


# Function for sending confirmation email
def send_purchase_email(buyer_email, seller_email):
    subject = "Contact Your Buyer"
    body = f"Congratulations! Someone has bought your item. Please reach out to them as soon as possible to decide on a pickup/hand-off location for the item. Your buyer's email is: {buyer_email}"

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = "csfinal3@gmail.com"
    msg["To"] = seller_email, buyer_email
    msg["password"] = "hzxi qdaw kqup ustj"

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
        smtp.login(msg["From"], msg["password"])
        smtp.sendmail(msg["From"], msg["To"], msg.as_string())


@app.route("/buy", methods=["POST"])
def buy():
    """Buy all items in your cart"""
    if request.method == "POST":
        # Get the buyer ID
        buyer_id = request.form.get("buyer_id")

        items = db.execute("SELECT product_id FROM Carts")
        seller_id = db.execute(
            "SELECT seller_id FROM Products WHERE id IN (SELECT product_id FROM Carts)"
        )
        seller_info = seller_id[0]

        # Extract the actual seller_id value
        id_for_email = seller_info["seller_id"]

        # Update product status to "Sold"
        for x, y in zip(items, seller_id):
            item = x["product_id"]
            id = y["seller_id"]
            db.execute("UPDATE Products SET status = 'Sold' WHERE id = ?", item)
            db.execute(
                "INSERT INTO Transactions (buyer_id, seller_id, product_id) VALUES (?, ?, ?)",
                buyer_id,
                id,
                item,
            )

        # Get buyer email
        buyer_email_row = db.execute("SELECT email FROM Users WHERE id = ?", buyer_id)
        buyer_email = buyer_email_row[0]["email"]

        # Get seller email
        seller_email_row = db.execute(
            "SELECT email FROM Users WHERE id = ?", id_for_email
        )
        seller_email = seller_email_row[0]["email"]

        # Send email to buyer with information about who bought the product and their email
        send_purchase_email(buyer_email, seller_email)

        # Clear the user's cart after completing the purchase
        session["cart"] = []

        # flash a message indicating that the product was added to the cart
        flash(f"Item(s) Bought!")

        # Delete items from the Carts table where user_id matches buyer_id
        db.execute("DELETE FROM Carts WHERE user_id = ?", buyer_id)

        # redirect back to cart
        return redirect(url_for("cart"))


@app.route("/purchases")
@login_required
def purchases():
    """View all your purchases"""
    user_id = session["user_id"]
    # Query database for all purchased items using Products, Transactions, and Users tables
    purchased_items = db.execute(
        """
    SELECT Products.*, Users.email AS seller_email
    FROM Products
    JOIN Transactions ON Products.id = Transactions.product_id
    JOIN Users ON Products.seller_id = Users.id
    WHERE Transactions.buyer_id = ?
    """,
        user_id,
    )

    return render_template("purchases.html", purchased_items=purchased_items)


@app.route("/remove_from_cart/<int:product_id>", methods=["POST"])
@login_required
def remove_from_cart(product_id):
    """Remove item from cart"""
    user_id = session["user_id"]

    # Remove the item from the cart
    db.execute(
        "DELETE FROM Carts WHERE user_id = ? AND product_id = ?", user_id, product_id
    )

    # Flash message to confirm removal of product from cart
    flash("Item removed from cart!")

    # Redirect back to the cart page
    return redirect(url_for("cart"))


@app.route("/remove_product/<int:product_id>", methods=["POST"])
@login_required
def remove_listing(product_id):
    """Remove a product listed by the seller"""
    if request.method == "POST":
        user_id = session.get("user_id")

        if not user_id:
            return apology("User not logged in.")

        # Check if the product belongs to the logged-in user
        product = db.execute(
            "SELECT * FROM Products WHERE id = ? AND seller_id = ?", product_id, user_id
        )

        if not product:
            return apology("Product not found or does not belong to the user", 404)

        # Check if the product has already been sold
        if product[0]["status"] == "Sold":
            return apology("Cannot remove a product that has already been sold.")

        # Delete the product from the Products table
        db.execute("DELETE FROM Products WHERE id = ?", product_id)

        # Send user a message to show that the product has been removed
        flash("Product removed successfully!")

        # Now redirect user to the listing page
        return redirect(url_for("listing"))


@app.route("/delete_from_cart/<int:product_id>", methods=["POST"])
def delete_from_cart(product_id):
    if request.method == "POST":
        user_id = session.get("user_id")

        if not user_id:
            return apology("User not logged in")

        # Delete the item from the Carts table
        db.execute(
            "DELETE FROM Carts WHERE user_id = ? AND product_id = ?",
            user_id,
            product_id,
        )

        # Send user a message to show that the item has been removed from their cart
        flash("Item removed from cart!")

        # Redirect user back to the cart page
        return redirect(url_for("cart"))
