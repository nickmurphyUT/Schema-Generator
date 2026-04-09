from flask import Blueprint

org_bp = Blueprint('org', __name__)

@org_bp.route('/org')
def org_home():
    return "Org Home"
