from app import db
from datetime import datetime

class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    parent_id = db.Column(db.Integer, db.ForeignKey('page.id'))
    is_category = db.Column(db.Boolean, default=False)
    
    parent = db.relationship('Page', remote_side=[id], backref='children')
    
    def __repr__(self):
        return f'<Page {self.title}>'
