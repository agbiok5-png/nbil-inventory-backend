# NBIL Biotech Lab Inventory - Backend API

Flask REST API for NBIL Laboratory Inventory Management System.

## Features
- JWT Authentication with role-based access
- PostgreSQL/SQLite database support
- Real-time sync API
- Email integration for purchase orders
- 40+ REST endpoints
- Auto stock updates on purchase/consumption

## Local Development

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
copy .env.example .env
# Edit .env with your settings

# Run server
python app.py
