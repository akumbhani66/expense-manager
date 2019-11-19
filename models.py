from run import db
from datetime import datetime
from passlib.hash import pbkdf2_sha256 as sha256
from sqlalchemy import text


class UserModel(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, user_id):
        return cls.query.filter_by(id=user_id).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {"username": x.username, "password": x.password}

        return {"users": list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {"message": "{} row(s) deleted".format(num_rows_deleted)}
        except:
            return {"message": "Something went wrong"}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)


class ExpenseCategoryModel(db.Model):
    __tablename__ = "expense_categories"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category_name = db.Column(db.String(120), unique=True, nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_category_name(cls, category_name):
        return cls.query.filter_by(category_name=category_name).first()

    @classmethod
    def find_by_id(cls, categoryid):
        return cls.query.filter_by(id=categoryid).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {"id": x.id, "category_name": x.category_name}

        return {
            "expense_categories": list(
                map(lambda x: to_json(x), ExpenseCategoryModel.query.all())
            )
        }

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {"message": "{} row(s) deleted".format(num_rows_deleted)}
        except:
            return {"message": "Something went wrong"}


class ExpenseModel(db.Model):
    __tablename__ = "expenses"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    total_amount = db.Column(db.Integer, unique=False, nullable=False)
    expense_category = db.Column(db.Integer, db.ForeignKey("expense_categories.id"))
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
        return self.id

    def delete_by_id(self):
        print(self)
        obj = ExpenseModel.query.filter_by(id=self).first()
        db.session.delete(obj)
        db.session.commit()

    def delete_expense(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_user(cls, user_id):
        return cls.query.filter_by(user_id=user_id).first()

    @classmethod
    def return_all(cls, user_id):
        sql = text(
            "select users.username, expenses.total_amount, expense_categories.category_name, divided_expenses.amount from users left join expenses on users.id = expenses.user_id left join divided_expenses on expenses.id = divided_expenses.expense_id left join expense_categories on expense_categories.id=expenses.expense_category"
        )
        result = db.engine.execute(sql)
        a = []
        for row in result:
            a.append(
                {
                    "username": row[0],
                    "expense": row[1],
                    "category": row[2],
                    "dividedExpense": row[3],
                }
            )
        return a

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {"message": "{} row(s) deleted".format(num_rows_deleted)}
        except:
            return {"message": "Something went wrong"}


class DividedExpenseModel(db.Model):
    __tablename__ = "divided_expenses"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    expense_id = db.Column(db.Integer, db.ForeignKey("expenses.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    amount = db.Column(db.Integer, nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


class RevokedTokenModel(db.Model):
    __tablename__ = "revoked_tokens"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)
