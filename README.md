# Restaurant Management System

A full-featured restaurant management web application designed to streamline both the **customer experience** and **in-house restaurant operations**. With role-based access for guests, staff, and admin users, this system supports everything from **online orders and reservations** to **staff workflow and admin reporting**.

---

## Features

### Guest Interface

![Guest Page](/images/guest.png)

Accessible without login:

* **Home** – Welcome page with restaurant highlights.
* **Menu** – Browse meals, add items to cart, and:

  * Choose **cash** or **card** payment
  * Select **pickup** or **delivery**
* **Offers** – View active discounts or bundle deals.
* **Locations** – Find restaurant branches.
* **Reservations** – Book tables online.
* **Catering** – Request large orders for events.
* **Gift Cards** – Purchase and send restaurant gift cards.
* **Authentication** – Log in or Sign up:

  * Guest
  * Staff (with access key)
  * Admin (with access key)
* **Order History** – Logged-in users can view past orders and reservations.

---

### Admin Dashboard

![Admin Page](/images/admin.png)

Admins can access the backend interface and control all aspects of the restaurant.

**Modules available:**

* Dashboard (includes live stats and quick links)
* Users & Groups
* Stores & Tables
* Categories & Products
* Orders & Online Orders
* Reports & Analytics
* Company Info & Settings
* Profile & Logout

---

### Staff Dashboard (Tablet-Friendly)

![Staff Page](/images/staff.png)

Optimized for in-restaurant use with tablets.

**Staff functionality:**

* Dashboard (table status and order overview)
* Table Management – Seat and update table status
* Orders – Take and manage dine-in orders
* Reservations & Waitlist
* Online Orders – Prepare customer pickups/deliveries
* Menu Viewer
* Profile & Logout

---

## Project Structure

```
FINAL-WORK/
├── __pycache__/
│
├── images/
│   ├── admin.png
│   ├── guest.png 
│   └── staff.png
│
├── Instance/
│   └── restaurant.db             # SQLite database
│
├── migrations/
│   ├── __pycache__/
│   └── versions/                 # Alembic migrations
│
├── env.py                        # Environment setup
├── README                        # Project readme
│
├── static/                       # Static assets
│   ├── css/
│   └── js/
│
├── templates/                    # HTML templates
│   ├── guest.html
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   └── staff.html
│
├── .gitignore
├── main.py                       # Entry point (Flask/Django/FastAPI logic)
├── package-lock.json
└── package.json
```

---

## Technologies Used

* **Frontend**: HTML, CSS, JavaScript
* **Backend**: Python (Flask)
* **Database**: SQLite
* **Templating**: Jinja2
* **Package Management**: npm (Node.js for frontend assets)
* **Migrations**: Alembic

---

## Dashboard Highlights

* Quick stats on:

  * Paid / Unpaid orders
  * Daily revenue
  * Active reservations
  * In-use vs. free tables
* Shortcuts to frequently used admin tools

---

## How to Run Locally

```bash
# Clone the repository
git clone https://github.com/your-username/restaurant-management-system.git
cd FINAL-WORK

# (Optional) Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python main.py
```

>`restaurant.db` is accessible in the `Instance/` directory.

---

## License

This project is open-source and available under the [MIT License](LICENSE).

---

## Notes

* Tablet compatibility for staff workflow is highly optimized.
* Admin access is protected via key-based registration.
* Future updates may include:

  * Real-time notifications (WebSockets)
  * Multi-language support
  * Customer loyalty program

---