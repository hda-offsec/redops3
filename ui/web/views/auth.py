from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse
from core.models import User
from core.extensions import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'error')
            return redirect(url_for('auth.login'))

        login_user(user)
        next_page = request.args.get('next')
        
        # Robust Open Redirect Protection
        def is_safe_url(target):
            ref_url = urlparse(request.host_url)
            test_url = urlparse(target)
            return test_url.scheme in ('http', 'https', '') and \
                   ref_url.netloc == test_url.netloc or not test_url.netloc

        if next_page and is_safe_url(next_page):
            return redirect(next_page)
        
        return redirect(url_for('main.index'))

    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
