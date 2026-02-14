"""
NBIL Biotech Lab Inventory - Flask Backend API
Complete REST API with JWT authentication, PostgreSQL database, real-time sync
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///inventory.db')

# Email configuration
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USERNAME = os.environ.get('EMAIL_USERNAME', '')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True') == 'True'

# Initialize extensions
CORS(app, resources={r"/api/*": {"origins": "*"}})
jwt = JWTManager(app)

# Database helper functions
def get_db():
    """Get database connection"""
    if DATABASE_URL.startswith('postgresql'):
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    else:
        # SQLite for local development
        db_path = DATABASE_URL.replace('sqlite:///', '')
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables"""
    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'user',
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Categories table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Manufacturers table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS manufacturers (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            contact_person VARCHAR(255),
            phone VARCHAR(50),
            email VARCHAR(255),
            address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Inventory items table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS inventory_items (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            category_id INTEGER REFERENCES categories(id),
            manufacturer_id INTEGER REFERENCES manufacturers(id),
            description TEXT,
            unit VARCHAR(50),
            current_stock REAL DEFAULT 0,
            min_stock_level REAL DEFAULT 0,
            max_stock_level REAL,
            location VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Purchases table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS purchases (
            id SERIAL PRIMARY KEY,
            item_id INTEGER REFERENCES inventory_items(id),
            quantity REAL NOT NULL,
            cost_per_unit REAL,
            total_cost REAL,
            supplier VARCHAR(255),
            invoice_number VARCHAR(100),
            purchase_date DATE NOT NULL,
            notes TEXT,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Consumption table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS consumption (
            id SERIAL PRIMARY KEY,
            item_id INTEGER REFERENCES inventory_items(id),
            quantity REAL NOT NULL,
            consumption_date DATE NOT NULL,
            purpose TEXT,
            consumed_by VARCHAR(255),
            notes TEXT,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id SERIAL PRIMARY KEY,
            key VARCHAR(100) UNIQUE NOT NULL,
            value TEXT,
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # Create default admin user if not exists
    cursor.execute("SELECT id FROM users WHERE email = 'admin@nbil.com'")
    if not cursor.fetchone():
        admin_password = generate_password_hash('admin123')
        cursor.execute("""
            INSERT INTO users (email, password_hash, name, role, is_active)
            VALUES ('admin@nbil.com', %s, 'System Administrator', 'admin', TRUE)
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO users (email, password_hash, name, role, is_active)
            VALUES ('admin@nbil.com', ?, 'System Administrator', 'admin', 1)
        """, (admin_password,))
        conn.commit()

    # Create default settings
    cursor.execute("SELECT id FROM settings WHERE key = 'sync_interval'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO settings (key, value, description)
            VALUES (%s, %s, %s)
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO settings (key, value, description)
            VALUES (?, ?, ?)
        """, ('sync_interval', '30', 'Sync interval in seconds'))
        conn.commit()

    cursor.execute("SELECT id FROM settings WHERE key = 'supplier_email'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO settings (key, value, description)
            VALUES (%s, %s, %s)
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO settings (key, value, description)
            VALUES (?, ?, ?)
        """, ('supplier_email', EMAIL_USERNAME, 'Default supplier email for purchase orders'))
        conn.commit()

    cursor.close()
    conn.close()

# Role-based access decorator
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = %s" if DATABASE_URL.startswith('postgresql') 
                      else "SELECT role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user or user['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403

        return fn(*args, **kwargs)
    return wrapper

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "message": "NBIL Biotech Lab Inventory API is running",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s" if DATABASE_URL.startswith('postgresql')
                  else "SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    if not user['is_active']:
        cursor.close()
        conn.close()
        return jsonify({"error": "Account is deactivated"}), 403

    if not check_password_hash(user['password_hash'], password):
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    # Update last login
    cursor.execute("""
        UPDATE users SET last_login = %s WHERE id = %s
    """ if DATABASE_URL.startswith('postgresql') else """
        UPDATE users SET last_login = ? WHERE id = ?
    """, (datetime.utcnow(), user['id']))
    conn.commit()
    cursor.close()
    conn.close()

    # Create access token
    access_token = create_access_token(identity=user['id'])

    return jsonify({
        "message": "Login successful",
        "token": access_token,
        "user": {
            "id": user['id'],
            "email": user['email'],
            "name": user['name'],
            "role": user['role']
        }
    }), 200

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, name, role FROM users WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "SELECT id, email, name, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(dict(user)), 200

# User management endpoints (Admin only)
@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, name, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([dict(user) for user in users]), 200

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    role = data.get('role', 'user')

    if not email or not password or not name:
        return jsonify({"error": "Email, password, and name required"}), 400

    password_hash = generate_password_hash(password)

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (email, password_hash, name, role)
            VALUES (%s, %s, %s, %s) RETURNING id
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO users (email, password_hash, name, role)
            VALUES (?, ?, ?, ?)
        """, (email, password_hash, name, role))

        if DATABASE_URL.startswith('postgresql'):
            user_id = cursor.fetchone()['id']
        else:
            user_id = cursor.lastrowid

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "User created successfully", "id": user_id}), 201
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 400

@app.route('/api/users/<int:user_id>/activate', methods=['PUT'])
@admin_required
def activate_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users SET is_active = %s WHERE id = %s
    """ if DATABASE_URL.startswith('postgresql') else """
        UPDATE users SET is_active = ? WHERE id = ?
    """, (True, user_id))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "User activated successfully"}), 200

@app.route('/api/users/<int:user_id>/deactivate', methods=['PUT'])
@admin_required
def deactivate_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users SET is_active = %s WHERE id = %s
    """ if DATABASE_URL.startswith('postgresql') else """
        UPDATE users SET is_active = ? WHERE id = ?
    """, (False, user_id))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "User deactivated successfully"}), 200

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "User deleted successfully"}), 200

# Category endpoints
@app.route('/api/categories', methods=['GET'])
@jwt_required()
def get_categories():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories ORDER BY name")
    categories = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([dict(cat) for cat in categories]), 200

@app.route('/api/categories', methods=['POST'])
@jwt_required()
def create_category():
    data = request.json
    name = data.get('name')
    description = data.get('description', '')

    if not name:
        return jsonify({"error": "Category name required"}), 400

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO categories (name, description)
            VALUES (%s, %s) RETURNING id
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO categories (name, description)
            VALUES (?, ?)
        """, (name, description))

        if DATABASE_URL.startswith('postgresql'):
            category_id = cursor.fetchone()['id']
        else:
            category_id = cursor.lastrowid

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Category created", "id": category_id}), 201
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 400

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM categories WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "DELETE FROM categories WHERE id = ?", (category_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Category deleted"}), 200

# Manufacturer endpoints
@app.route('/api/manufacturers', methods=['GET'])
@jwt_required()
def get_manufacturers():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM manufacturers ORDER BY name")
    manufacturers = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([dict(m) for m in manufacturers]), 200

@app.route('/api/manufacturers', methods=['POST'])
@jwt_required()
def create_manufacturer():
    data = request.json
    name = data.get('name')
    contact_person = data.get('contact_person', '')
    phone = data.get('phone', '')
    email = data.get('email', '')
    address = data.get('address', '')

    if not name:
        return jsonify({"error": "Manufacturer name required"}), 400

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO manufacturers (name, contact_person, phone, email, address)
            VALUES (%s, %s, %s, %s, %s) RETURNING id
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO manufacturers (name, contact_person, phone, email, address)
            VALUES (?, ?, ?, ?, ?)
        """, (name, contact_person, phone, email, address))

        if DATABASE_URL.startswith('postgresql'):
            manufacturer_id = cursor.fetchone()['id']
        else:
            manufacturer_id = cursor.lastrowid

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Manufacturer created", "id": manufacturer_id}), 201
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 400

@app.route('/api/manufacturers/<int:manufacturer_id>', methods=['DELETE'])
@jwt_required()
def delete_manufacturer(manufacturer_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM manufacturers WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "DELETE FROM manufacturers WHERE id = ?", (manufacturer_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Manufacturer deleted"}), 200

# Inventory endpoints
@app.route('/api/inventory', methods=['GET'])
@jwt_required()
def get_inventory():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT i.*, c.name as category_name, m.name as manufacturer_name
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN manufacturers m ON i.manufacturer_id = m.id
        ORDER BY i.name
    """)
    items = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([dict(item) for item in items]), 200

@app.route('/api/inventory', methods=['POST'])
@jwt_required()
def create_inventory_item():
    data = request.json

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO inventory_items 
            (name, category_id, manufacturer_id, description, unit, current_stock, 
             min_stock_level, max_stock_level, location)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO inventory_items 
            (name, category_id, manufacturer_id, description, unit, current_stock, 
             min_stock_level, max_stock_level, location)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('name'),
            data.get('category_id'),
            data.get('manufacturer_id'),
            data.get('description', ''),
            data.get('unit', ''),
            data.get('current_stock', 0),
            data.get('min_stock_level', 0),
            data.get('max_stock_level'),
            data.get('location', '')
        ))

        if DATABASE_URL.startswith('postgresql'):
            item_id = cursor.fetchone()['id']
        else:
            item_id = cursor.lastrowid

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Item created", "id": item_id}), 201
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 400

@app.route('/api/inventory/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_inventory_item(item_id):
    data = request.json

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE inventory_items
            SET name = %s, category_id = %s, manufacturer_id = %s, description = %s,
                unit = %s, min_stock_level = %s, max_stock_level = %s, location = %s,
                updated_at = %s
            WHERE id = %s
        """ if DATABASE_URL.startswith('postgresql') else """
            UPDATE inventory_items
            SET name = ?, category_id = ?, manufacturer_id = ?, description = ?,
                unit = ?, min_stock_level = ?, max_stock_level = ?, location = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            data.get('name'),
            data.get('category_id'),
            data.get('manufacturer_id'),
            data.get('description', ''),
            data.get('unit', ''),
            data.get('min_stock_level', 0),
            data.get('max_stock_level'),
            data.get('location', ''),
            datetime.utcnow(),
            item_id
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Item updated"}), 200
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 400

@app.route('/api/inventory/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_inventory_item(item_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inventory_items WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "DELETE FROM inventory_items WHERE id = ?", (item_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Item deleted"}), 200

@app.route('/api/inventory/<int:item_id>/details', methods=['GET'])
@jwt_required()
def get_item_details(item_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get item details
    cursor.execute("""
        SELECT i.*, c.name as category_name, m.name as manufacturer_name
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN manufacturers m ON i.manufacturer_id = m.id
        WHERE i.id = %s
    """ if DATABASE_URL.startswith('postgresql') else """
        SELECT i.*, c.name as category_name, m.name as manufacturer_name
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN manufacturers m ON i.manufacturer_id = m.id
        WHERE i.id = ?
    """, (item_id,))
    item = cursor.fetchone()

    if not item:
        cursor.close()
        conn.close()
        return jsonify({"error": "Item not found"}), 404

    # Get purchase history
    cursor.execute("""
        SELECT * FROM purchases WHERE item_id = %s ORDER BY purchase_date DESC
    """ if DATABASE_URL.startswith('postgresql') else """
        SELECT * FROM purchases WHERE item_id = ? ORDER BY purchase_date DESC
    """, (item_id,))
    purchases = cursor.fetchall()

    # Get consumption history
    cursor.execute("""
        SELECT * FROM consumption WHERE item_id = %s ORDER BY consumption_date DESC
    """ if DATABASE_URL.startswith('postgresql') else """
        SELECT * FROM consumption WHERE item_id = ? ORDER BY consumption_date DESC
    """, (item_id,))
    consumption = cursor.fetchall()

    cursor.close()
    conn.close()

    return jsonify({
        "item": dict(item),
        "purchases": [dict(p) for p in purchases],
        "consumption": [dict(c) for c in consumption]
    }), 200

# Purchase endpoints
@app.route('/api/purchases', methods=['GET'])
@jwt_required()
def get_purchases():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.*, i.name as item_name, i.unit
        FROM purchases p
        JOIN inventory_items i ON p.item_id = i.id
        ORDER BY p.purchase_date DESC
    """)
    purchases = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([dict(p) for p in purchases]), 200

@app.route('/api/purchases', methods=['POST'])
@jwt_required()
def create_purchase():
    data = request.json
    user_id = get_jwt_identity()

    item_id = data.get('item_id')
    quantity = data.get('quantity')
    cost_per_unit = data.get('cost_per_unit', 0)
    total_cost = quantity * cost_per_unit if cost_per_unit else 0

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Create purchase record
        cursor.execute("""
            INSERT INTO purchases 
            (item_id, quantity, cost_per_unit, total_cost, supplier, invoice_number, 
             purchase_date, notes, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO purchases 
            (item_id, quantity, cost_per_unit, total_cost, supplier, invoice_number, 
             purchase_date, notes, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item_id,
            quantity,
            cost_per_unit,
            total_cost,
            data.get('supplier', ''),
            data.get('invoice_number', ''),
            data.get('purchase_date', datetime.utcnow().date()),
            data.get('notes', ''),
            user_id
        ))

        if DATABASE_URL.startswith('postgresql'):
            purchase_id = cursor.fetchone()['id']
        else:
            purchase_id = cursor.lastrowid

        # Update inventory stock
        cursor.execute("""
            UPDATE inventory_items 
            SET current_stock = current_stock + %s, updated_at = %s
            WHERE id = %s
        """ if DATABASE_URL.startswith('postgresql') else """
            UPDATE inventory_items 
            SET current_stock = current_stock + ?, updated_at = ?
            WHERE id = ?
        """, (quantity, datetime.utcnow(), item_id))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Purchase recorded", "id": purchase_id}), 201
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 400

@app.route('/api/purchases/<int:purchase_id>', methods=['DELETE'])
@jwt_required()
def delete_purchase(purchase_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get purchase details to reverse stock
    cursor.execute("SELECT item_id, quantity FROM purchases WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "SELECT item_id, quantity FROM purchases WHERE id = ?", (purchase_id,))
    purchase = cursor.fetchone()

    if purchase:
        # Reverse stock update
        cursor.execute("""
            UPDATE inventory_items 
            SET current_stock = current_stock - %s, updated_at = %s
            WHERE id = %s
        """ if DATABASE_URL.startswith('postgresql') else """
            UPDATE inventory_items 
            SET current_stock = current_stock - ?, updated_at = ?
            WHERE id = ?
        """, (purchase['quantity'], datetime.utcnow(), purchase['item_id']))

    cursor.execute("DELETE FROM purchases WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "DELETE FROM purchases WHERE id = ?", (purchase_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Purchase deleted"}), 200

# Consumption endpoints
@app.route('/api/consumption', methods=['GET'])
@jwt_required()
def get_consumption():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.*, i.name as item_name, i.unit
        FROM consumption c
        JOIN inventory_items i ON c.item_id = i.id
        ORDER BY c.consumption_date DESC
    """)
    consumption = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([dict(c) for c in consumption]), 200

@app.route('/api/consumption', methods=['POST'])
@jwt_required()
def create_consumption():
    data = request.json
    user_id = get_jwt_identity()

    item_id = data.get('item_id')
    quantity = data.get('quantity')

    conn = get_db()
    cursor = conn.cursor()

    # Check stock availability
    cursor.execute("SELECT current_stock FROM inventory_items WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "SELECT current_stock FROM inventory_items WHERE id = ?", (item_id,))
    item = cursor.fetchone()

    if not item:
        cursor.close()
        conn.close()
        return jsonify({"error": "Item not found"}), 404

    if item['current_stock'] < quantity:
        cursor.close()
        conn.close()
        return jsonify({"error": "Insufficient stock"}), 400

    try:
        # Create consumption record
        cursor.execute("""
            INSERT INTO consumption 
            (item_id, quantity, consumption_date, purpose, consumed_by, notes, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
        """ if DATABASE_URL.startswith('postgresql') else """
            INSERT INTO consumption 
            (item_id, quantity, consumption_date, purpose, consumed_by, notes, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            item_id,
            quantity,
            data.get('consumption_date', datetime.utcnow().date()),
            data.get('purpose', ''),
            data.get('consumed_by', ''),
            data.get('notes', ''),
            user_id
        ))

        if DATABASE_URL.startswith('postgresql'):
            consumption_id = cursor.fetchone()['id']
        else:
            consumption_id = cursor.lastrowid

        # Update inventory stock
        cursor.execute("""
            UPDATE inventory_items 
            SET current_stock = current_stock - %s, updated_at = %s
            WHERE id = %s
        """ if DATABASE_URL.startswith('postgresql') else """
            UPDATE inventory_items 
            SET current_stock = current_stock - ?, updated_at = ?
            WHERE id = ?
        """, (quantity, datetime.utcnow(), item_id))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Consumption recorded", "id": consumption_id}), 201
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 400

@app.route('/api/consumption/<int:consumption_id>', methods=['DELETE'])
@jwt_required()
def delete_consumption(consumption_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get consumption details to reverse stock
    cursor.execute("SELECT item_id, quantity FROM consumption WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "SELECT item_id, quantity FROM consumption WHERE id = ?", (consumption_id,))
    consumption = cursor.fetchone()

    if consumption:
        # Reverse stock update
        cursor.execute("""
            UPDATE inventory_items 
            SET current_stock = current_stock + %s, updated_at = %s
            WHERE id = %s
        """ if DATABASE_URL.startswith('postgresql') else """
            UPDATE inventory_items 
            SET current_stock = current_stock + ?, updated_at = ?
            WHERE id = ?
        """, (consumption['quantity'], datetime.utcnow(), consumption['item_id']))

    cursor.execute("DELETE FROM consumption WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "DELETE FROM consumption WHERE id = ?", (consumption_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Consumption deleted"}), 200

# Low stock and purchase list
@app.route('/api/low-stock', methods=['GET'])
@jwt_required()
def get_low_stock():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT i.*, c.name as category_name, m.name as manufacturer_name
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN manufacturers m ON i.manufacturer_id = m.id
        WHERE i.current_stock < i.min_stock_level
        ORDER BY i.name
    """)
    items = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([dict(item) for item in items]), 200

@app.route('/api/send-order-email', methods=['POST'])
@jwt_required()
def send_order_email():
    data = request.json
    item_ids = data.get('item_ids', [])

    if not item_ids:
        return jsonify({"error": "No items selected"}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Get supplier email from settings
    cursor.execute("SELECT value FROM settings WHERE key = 'supplier_email'")
    setting = cursor.fetchone()
    supplier_email = setting['value'] if setting else EMAIL_USERNAME

    # Get items details
    placeholders = ','.join(['%s' if DATABASE_URL.startswith('postgresql') else '?' for _ in item_ids])
    cursor.execute(f"""
        SELECT i.*, c.name as category_name, m.name as manufacturer_name
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN manufacturers m ON i.manufacturer_id = m.id
        WHERE i.id IN ({placeholders})
    """, tuple(item_ids))
    items = cursor.fetchall()
    cursor.close()
    conn.close()

    if not items:
        return jsonify({"error": "No items found"}), 404

    # Create email content
    email_body = "<html><body>"
    email_body += "<h2>Purchase Order Request - NBIL Biotech Lab Inventory</h2>"
    email_body += f"<p>Date: {datetime.utcnow().strftime('%Y-%m-%d')}</p>"
    email_body += "<table border='1' cellpadding='5' cellspacing='0' style='border-collapse: collapse;'>"
    email_body += "<tr><th>Item Name</th><th>Category</th><th>Manufacturer</th><th>Unit</th>"
    email_body += "<th>Current Stock</th><th>Min Required</th><th>Order Quantity</th></tr>"

    for item in items:
        order_qty = item['min_stock_level'] - item['current_stock']
        if order_qty < 0:
            order_qty = item['min_stock_level']

        email_body += f"<tr>"
        email_body += f"<td>{item['name']}</td>"
        email_body += f"<td>{item['category_name'] or 'N/A'}</td>"
        email_body += f"<td>{item['manufacturer_name'] or 'N/A'}</td>"
        email_body += f"<td>{item['unit']}</td>"
        email_body += f"<td>{item['current_stock']}</td>"
        email_body += f"<td>{item['min_stock_level']}</td>"
        email_body += f"<td><strong>{order_qty}</strong></td>"
        email_body += f"</tr>"

    email_body += "</table>"
    email_body += "<br><p>Please process this order at your earliest convenience.</p>"
    email_body += "<p>Thank you,<br>NBIL Biotech Lab</p>"
    email_body += "</body></html>"

    # Send email
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Purchase Order Request - {datetime.utcnow().strftime('%Y-%m-%d')}"
        msg['From'] = EMAIL_USERNAME
        msg['To'] = supplier_email

        html_part = MIMEText(email_body, 'html')
        msg.attach(html_part)

        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        if EMAIL_USE_TLS:
            server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        return jsonify({
            "message": "Purchase order email sent successfully",
            "items_count": len(items),
            "sent_to": supplier_email
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500

# Analytics endpoints (Admin only)
@app.route('/api/analytics/overview', methods=['GET'])
@admin_required
def get_analytics_overview():
    conn = get_db()
    cursor = conn.cursor()

    # Total items
    cursor.execute("SELECT COUNT(*) as count FROM inventory_items")
    total_items = cursor.fetchone()['count']

    # Total inventory value
    cursor.execute("""
        SELECT SUM(current_stock * (
            SELECT AVG(cost_per_unit) 
            FROM purchases p 
            WHERE p.item_id = i.id
        )) as total_value
        FROM inventory_items i
    """)
    total_value_row = cursor.fetchone()
    total_value = total_value_row['total_value'] if total_value_row['total_value'] else 0

    # Low stock items
    cursor.execute("SELECT COUNT(*) as count FROM inventory_items WHERE current_stock < min_stock_level")
    low_stock_count = cursor.fetchone()['count']

    # Recent purchases (last 30 days)
    cursor.execute("""
        SELECT COUNT(*) as count, SUM(total_cost) as total_cost
        FROM purchases
        WHERE purchase_date >= DATE('now', '-30 days')
    """ if not DATABASE_URL.startswith('postgresql') else """
        SELECT COUNT(*) as count, SUM(total_cost) as total_cost
        FROM purchases
        WHERE purchase_date >= CURRENT_DATE - INTERVAL '30 days'
    """)
    recent_purchases = cursor.fetchone()

    # Recent consumption (last 30 days)
    cursor.execute("""
        SELECT COUNT(*) as count, SUM(quantity) as total_quantity
        FROM consumption
        WHERE consumption_date >= DATE('now', '-30 days')
    """ if not DATABASE_URL.startswith('postgresql') else """
        SELECT COUNT(*) as count, SUM(quantity) as total_quantity
        FROM consumption
        WHERE consumption_date >= CURRENT_DATE - INTERVAL '30 days'
    """)
    recent_consumption = cursor.fetchone()

    cursor.close()
    conn.close()

    return jsonify({
        "total_items": total_items,
        "total_inventory_value": float(total_value) if total_value else 0,
        "low_stock_items": low_stock_count,
        "recent_purchases_count": recent_purchases['count'],
        "recent_purchases_value": float(recent_purchases['total_cost']) if recent_purchases['total_cost'] else 0,
        "recent_consumption_count": recent_consumption['count'],
        "recent_consumption_quantity": float(recent_consumption['total_quantity']) if recent_consumption['total_quantity'] else 0
    }), 200

@app.route('/api/analytics/consumption-pattern', methods=['GET'])
@admin_required
def get_consumption_pattern():
    period = request.args.get('period', 'monthly')  # daily, weekly, monthly, yearly
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    conn = get_db()
    cursor = conn.cursor()

    # Build query based on period
    if period == 'daily':
        group_by = "DATE(consumption_date)"
    elif period == 'weekly':
        group_by = "strftime('%Y-W%W', consumption_date)" if not DATABASE_URL.startswith('postgresql') else "DATE_TRUNC('week', consumption_date)"
    elif period == 'yearly':
        group_by = "strftime('%Y', consumption_date)" if not DATABASE_URL.startswith('postgresql') else "DATE_TRUNC('year', consumption_date)"
    else:  # monthly
        group_by = "strftime('%Y-%m', consumption_date)" if not DATABASE_URL.startswith('postgresql') else "DATE_TRUNC('month', consumption_date)"

    query = f"""
        SELECT {group_by} as period, i.name as item_name, SUM(c.quantity) as total_quantity
        FROM consumption c
        JOIN inventory_items i ON c.item_id = i.id
    """

    params = []
    if start_date and end_date:
        query += " WHERE consumption_date BETWEEN %s AND %s" if DATABASE_URL.startswith('postgresql') else " WHERE consumption_date BETWEEN ? AND ?"
        params = [start_date, end_date]

    query += f" GROUP BY {group_by}, i.name ORDER BY period DESC"

    cursor.execute(query, params)
    results = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([dict(r) for r in results]), 200

@app.route('/api/analytics/item/<int:item_id>', methods=['GET'])
@jwt_required()
def get_item_analytics(item_id):
    conn = get_db()
    cursor = conn.cursor()

    # Item details
    cursor.execute("SELECT * FROM inventory_items WHERE id = %s" if DATABASE_URL.startswith('postgresql')
                  else "SELECT * FROM inventory_items WHERE id = ?", (item_id,))
    item = cursor.fetchone()

    if not item:
        cursor.close()
        conn.close()
        return jsonify({"error": "Item not found"}), 404

    # Total purchases
    cursor.execute("""
        SELECT COUNT(*) as count, SUM(quantity) as total_quantity, SUM(total_cost) as total_cost
        FROM purchases WHERE item_id = %s
    """ if DATABASE_URL.startswith('postgresql') else """
        SELECT COUNT(*) as count, SUM(quantity) as total_quantity, SUM(total_cost) as total_cost
        FROM purchases WHERE item_id = ?
    """, (item_id,))
    purchase_stats = cursor.fetchone()

    # Total consumption
    cursor.execute("""
        SELECT COUNT(*) as count, SUM(quantity) as total_quantity
        FROM consumption WHERE item_id = %s
    """ if DATABASE_URL.startswith('postgresql') else """
        SELECT COUNT(*) as count, SUM(quantity) as total_quantity
        FROM consumption WHERE item_id = ?
    """, (item_id,))
    consumption_stats = cursor.fetchone()

    cursor.close()
    conn.close()

    return jsonify({
        "item": dict(item),
        "purchase_count": purchase_stats['count'],
        "total_purchased": float(purchase_stats['total_quantity']) if purchase_stats['total_quantity'] else 0,
        "total_purchase_cost": float(purchase_stats['total_cost']) if purchase_stats['total_cost'] else 0,
        "consumption_count": consumption_stats['count'],
        "total_consumed": float(consumption_stats['total_quantity']) if consumption_stats['total_quantity'] else 0
    }), 200

# Settings endpoints
@app.route('/api/settings', methods=['PUT'])
@admin_required
def update_setting():
    data = request.json
    key = data.get('key')
    value = data.get('value')
    description = data.get('description', '')

    if not key:
        return jsonify({"error": "Setting key required"}), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO settings (key, value, description, updated_at)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (key) DO UPDATE SET value = %s, description = %s, updated_at = %s
    """ if DATABASE_URL.startswith('postgresql') else """
        INSERT OR REPLACE INTO settings (key, value, description, updated_at)
        VALUES (?, ?, ?, ?)
    """, (key, value, description, datetime.utcnow()) if DATABASE_URL.startswith('postgresql') 
         else (key, value, description, datetime.utcnow()))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Setting updated"}), 200

@app.route('/api/settings/<key>', methods=['GET'])
@jwt_required()
def get_setting(key):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM settings WHERE key = %s" if DATABASE_URL.startswith('postgresql')
                  else "SELECT * FROM settings WHERE key = ?", (key,))
    setting = cursor.fetchone()
    cursor.close()
    conn.close()

    if not setting:
        return jsonify({"error": "Setting not found"}), 404

    return jsonify(dict(setting)), 200

# Sync endpoint
@app.route('/api/sync', methods=['GET'])
@jwt_required()
def sync_status():
    conn = get_db()
    cursor = conn.cursor()

    # Get latest update timestamp across all tables
    cursor.execute("""
        SELECT MAX(updated_at) as last_update FROM (
            SELECT MAX(updated_at) as updated_at FROM users
            UNION ALL
            SELECT MAX(updated_at) as updated_at FROM categories
            UNION ALL
            SELECT MAX(updated_at) as updated_at FROM manufacturers
            UNION ALL
            SELECT MAX(updated_at) as updated_at FROM inventory_items
            UNION ALL
            SELECT MAX(updated_at) as updated_at FROM purchases
            UNION ALL
            SELECT MAX(updated_at) as updated_at FROM consumption
        ) as all_updates
    """)
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    return jsonify({
        "last_update": result['last_update'].isoformat() if result['last_update'] else datetime.utcnow().isoformat(),
        "server_time": datetime.utcnow().isoformat()
    }), 200

# Initialize database on startup
with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
