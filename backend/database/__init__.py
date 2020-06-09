import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, String, Integer, Text, ForeignKey
from flask_migrate import Migrate

db = SQLAlchemy()


def setup_db(app, database_uri=None, test_env=False):
    '''
    setup_db(app)
        binds a flask application and a SQLAlchemy service
    '''
    # I have put database uri in the config file for privacy reasons
    if database_uri:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_uri

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.app = app
    db.init_app(app)

    # do not use migrations in test environment
    if test_env is True:
        db.create_all()
    else:
        migrate = Migrate(app, db)

class Question(db.Model):
    __tablename__ = 'questions'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(40), nullable=False)
    body = Column(String(), nullable=False)

    def __init__(self, user_id, body):
        self.user_id = user_id
        self.body = body

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'body': self.body
        }


class Answer(db.Model):
    __tablename__ = 'answers'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(40), nullable=False)
    body = Column(String(), nullable=False)

    def __init__(self, user_id, body):
        self.user_id = user_id
        self.body = body

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'body': self.body
        }
