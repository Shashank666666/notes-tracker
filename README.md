# Notes Tracker

A Flask-based web application for managing and organizing notes with user authentication and admin functionality.

## Features

- User registration and login system
- Create, read, update, and delete notes
- Admin panel for user management
- Responsive web interface
- SQLite database for data storage

## Technologies Used

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: HTML, CSS, JavaScript
- **Authentication**: Flask-Login

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/notes-tracker.git
   cd notes-tracker
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Run the application:
   ```bash
   python app.py
   ```


## Usage

1. **Register**: Create a new account
2. **Login**: Sign in with your credentials
3. **Dashboard**: View and manage your notes
4. **Admin Panel**: Access admin features (if you have admin privileges)

## Project Structure

```
notes-tracker/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── static/            # CSS, JavaScript, and other static files
├── templates/         # HTML templates
├── instance/          # Database files (not in version control)
└── venv/             # Virtual environment (not in version control)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).
