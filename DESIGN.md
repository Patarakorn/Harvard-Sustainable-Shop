## Overview

We configured Harvard Sustainability Shop using Flask and SQLite for the database, and we use the extension Flask-Session for session management. Among other modules, we also imported the EmailMessage, smtplib, and ssl modules to manage email verification and securely exchange contact information between the buyer and the seller.

### Frontend
The frontend of our app uses HTML, CSS, and Jinja2 templates. It has a dynamic, responsive design, making the UI accessible across different devices. We use Bootstrap and a few custom CSS styles, and JavaScript is used in the form submission for buying, the flash messages, and the cart interactions, among other uses.

### Backend
Flask powers the backend of our app. We use SQLite as a database to store user information, product details, and transaction data.

### User Authentication and Authorization
We handle user authentication using the Flask-Login extension, which manages user sessions securely. We check login throughout the application to make sure that users can only access and edit their own data.

### Email Verification
We realized that merely checking whether an email ends in “college.harvard.edu” doesn’t check whether the email is truly a valid Harvard email, so we implemented a verification code-based email verification system during user registration. The `smtplib` library is used to send verification emails to users, which are randomly generated based on 20 digits or numbers. Verification codes are securely stored in the database and associated with a user, but the data entered by the user is only stored in the database (thus verifying the user) once the verification code is entered correctly.

### File Uploads
HSS also allows sellers to upload images of their products. File uploads are handled using the werkzeug.utils module to make sure the files are handled securely. The allowed file types and secure filenames are enforced so that users can’t upload non- or invalid images.

### Transactions
When a user makes a purchase, the product status gets updated to "Sold," creates a transaction record, and notifies the seller via email with contact information for the buyer (since the buyer can reach out independently with the seller’s listed email).

### Database Schema
Relationships between tables in the HSS.db schema, such as Users, Products, and Transactions, are established using foreign keys.

### Flask Structure
The flask structure of our app is modular, with routes, templates, and static files organized into separate directories.

### Email Communication
Email communication is compartmentalized in the `send_verification_email` and `send_purchase_email` functions. We use SSL for email transmission so that emails are sent securely.

### Security
To keep information safe from external interference, we implemented security measures like password hashing using Flask's `generate_password_hash`, input validation to prevent SQL injection, and user authentication to protect sensitive user data.
