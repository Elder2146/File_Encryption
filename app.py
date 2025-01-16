import os
import shutil
import zipfile
from flask import Flask, request, send_file, render_template, flash, redirect, url_for, session
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')  # Use environment variable for secret key

# Temporary upload folder configuration
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def cleanup_temp_folder():
    """Remove all files from the temporary folder."""
    if os.path.exists(UPLOAD_FOLDER):
        shutil.rmtree(UPLOAD_FOLDER)
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/')
def home():
    """Render the home page."""
    return render_template('index.html')


@app.route('/process', methods=['POST'])
def process():
    """Handle file encryption or decryption based on user action."""
    action = request.form.get('action')  # Get the selected action (encrypt or decrypt)

    if action == 'encrypt':
        return handle_encryption()
    elif action == 'decrypt':
        return handle_decryption()
    else:
        flash('Invalid action selected.', 'error')
        return redirect(url_for('home'))


def handle_encryption():
    """Handle file encryption."""
    if 'files[]' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('home'))

    files = request.files.getlist('files[]')
    if not files or all(file.filename == '' for file in files):
        flash('No files selected for encryption.', 'error')
        return redirect(url_for('home'))

    # Generate a unique key for this encryption session
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    # Create a ZIP file in memory containing all uploaded files
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zipf:
        for file in files:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            zipf.write(file_path, filename)
            os.remove(file_path)  # Delete the file immediately after adding to ZIP

    # Encrypt the ZIP file
    zip_buffer.seek(0)
    encrypted_data = cipher_suite.encrypt(zip_buffer.read())
    encrypted_buffer = BytesIO(encrypted_data)

    # Prepare the secret key for download
    key_buffer = BytesIO(key)
    key_buffer.seek(0)

    # Create a combined ZIP file containing the encrypted file and the secret key
    combined_zip_buffer = BytesIO()
    with zipfile.ZipFile(combined_zip_buffer, 'w') as combined_zip:
        combined_zip.writestr('encrypted_files.enc', encrypted_buffer.getvalue())
        combined_zip.writestr('secret_key.key', key_buffer.getvalue())

    combined_zip_buffer.seek(0)

    # Trigger download of the combined ZIP file
    return send_file(
        combined_zip_buffer,
        as_attachment=True,
        download_name='encrypted_files_and_key.zip',
        mimetype='application/zip'
    )


def handle_decryption():
    """Handle file decryption."""
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('home'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('home'))

    # Save the uploaded file temporarily
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
    file.save(encrypted_file_path)

    # Decrypt the file
    try:
        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()

        # Prompt the user for the secret key
        secret_key = request.form.get('secret_key')
        if not secret_key:
            flash('Secret key is required for decryption.', 'error')
            return redirect(url_for('home'))

        cipher_suite = Fernet(secret_key.encode())
        decrypted_data = cipher_suite.decrypt(encrypted_data)

        # Serve the decrypted file for download
        decrypted_buffer = BytesIO(decrypted_data)
        return send_file(
            decrypted_buffer,
            as_attachment=True,
            download_name='decrypted_files.zip',
            mimetype='application/zip'
        )
    except InvalidToken:
        flash('Decryption failed. The encryption key is incorrect.', 'error')
        return redirect(url_for('home'))
    except Exception as e:
        print(f"Error during decryption: {e}")
        flash('Decryption failed. Ensure the file is correctly encrypted.', 'error')
        return redirect(url_for('home'))


@app.after_request
def after_request(response):
    """Reset the session and clean up after each request."""
    cleanup_temp_folder()
    session.clear()
    return response


if __name__ == '__main__':
    app.run(debug=True)