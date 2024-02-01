from auth import get_jwt_sub
from sqlalchemy.orm import backref
from db import db
from flask import request
from sqlalchemy import (
    Column,
    Integer,
    ForeignKey,
    DateTime,
    VARCHAR,
    Text,
    Boolean,
    LONGBLOB,
)
from sqlalchemy.dialects.mysql import BOOLEAN
from sqlalchemy.exc import SQLAlchemyError as exc
import bcrypt


class BaseModel:
    def __init__(self):
        pass

    def update(self):
        try:
            db.session.commit()
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            raise e

    def delete(self):
        try:
            db.session.delete(self)
            db.session.commit()
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            raise e

    def insert(self):
        try:
            db.session.add(self)
            db.session.commit()
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            raise e

    def format(self):
        pass


class QuestionVote(db.Model):
    __tablename__ = "questions_votes"
    question_id = Column(Integer, ForeignKey("questions.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    vote = Column(Boolean, nullable=False)

    question = db.relationship(
        "Question",
        backref=backref("votes", cascade="all, delete-orphan", lazy="dynamic"),
    )
    user = db.relationship(
        "User",
        backref=backref(
            "questions_votes", cascade="all, delete-orphan", lazy="dynamic"
        ),
    )


class AnswerVote(db.Model):
    __tablename__ = "answers_votes"
    answer_id = Column(Integer, ForeignKey("answers.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    vote = Column(Boolean, nullable=False)

    answer = db.relationship(
        "Answer", backref=backref("votes", cascade="all, delete-orphan", lazy="dynamic")
    )
    user = db.relationship(
        "User",
        backref=backref("answers_votes", cascade="all, delete-orphan", lazy="dynamic"),
    )


class User(db.Model, BaseModel):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    first_name = Column(VARCHAR(20), nullable=False)
    last_name = Column(VARCHAR(20), nullable=False)
    email = Column(VARCHAR(60), nullable=False, unique=True)
    username = Column(VARCHAR(20), nullable=False, unique=True)
    password = Column(LONGBLOB, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    email_confirmed = Column(Boolean, default=False, nullable=False)
    job = Column(VARCHAR(50), nullable=True)
    bio = Column(Text, nullable=True)
    phone = Column(VARCHAR(50), nullable=True, unique=True)
    avatar = Column(Text, nullable=True)
    created_at = Column(DateTime(), default=datetime.utcnow, nullable=False)
    questions = db.relationship(
        "Question",
        backref="user",
        order_by="desc(Question.created_at)",
        lazy=True,
        cascade="all",
    )
    answers = db.relationship(
        "Answer",
        backref="user",
        order_by="desc(Answer.created_at)",
        lazy=True,
        cascade="all",
    )
    notifications = db.relationship(
        "Notification",
        order_by="desc(Notification.created_at)",
        lazy="dynamic",
        cascade="all",
    )

    def __init__(
        self,
        first_name: str,
        last_name: str,
        email: str,
        username: str,
        password: str,
        role_id: int,
        job: str = None,
        bio: str = None,
        phone: str = None,
        avatar: str = None,
    ):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.username = username
        self.password = bcrypt.hashpw(bytes(password, "utf-8"), bcrypt.gensalt(12))
        self.role_id = role_id
        self.job = job
        self.bio = bio
        self.phone = phone
        self.avatar = avatar

    def checkpw(self, password: str):
        return bcrypt.checkpw(bytes(password, "utf-8"), self.password)

    def set_pw(self, password: str):
        self.password = bcrypt.hashpw(bytes(password, "utf-8"), bcrypt.gensalt(12))

    def format(self):
        avatar = self.avatar
        if avatar:
            try:
                avatar = request.root_url + "uploads/" + avatar
            except RuntimeError:
                pass

        return {
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": "%s %s" % (self.first_name, self.last_name),
            "username": self.username,
            "job": self.job,
            "bio": self.bio,
            "avatar": avatar,
            "questions_count": len(self.questions),
            "answers_count": len(self.answers),
            "created_at": self.created_at,
        }
