from flask_restful import Resource, reqparse
from models import (
    UserModel,
    RevokedTokenModel,
    ExpenseModel,
    ExpenseCategoryModel,
    DividedExpenseModel,
)
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    jwt_refresh_token_required,
    get_jwt_identity,
    get_raw_jwt,
)
import json

# Expenses
class CreateExpense(Resource):
    @jwt_required
    def post(self):
        # expenses
        parser = reqparse.RequestParser()
        parser.add_argument(
            "user_id", help="This field cannot be blank", required=True, location="json"
        )
        parser.add_argument(
            "total_amount",
            help="This field cannot be blank",
            required=True,
            location="json",
        )
        parser.add_argument(
            "expense_category",
            help="This field cannot be blank",
            required=True,
            location="json",
        )
        parser.add_argument(
            "divide_it",
            help="This field cannot be blank",
            required=False,
            location="json",
        )

        data = parser.parse_args()
        # Double check if userId is exists. Although JWT is doing this, still re-doing. unncessary
        if UserModel.find_by_id(data["user_id"]):
            # Insert to expenses
            new_expense = ExpenseModel(
                user_id=data["user_id"],
                total_amount=data["total_amount"],
                expense_category=data["expense_category"],
            )

            createdExpenseId = new_expense.save_to_db()

            # TODO: check wether expense is divide amoung other?
            if data["divide_it"] and len(data["divide_it"]) > 0:
                # If its divided, checking existance of username.
                divide_betweens = eval(data["divide_it"])
                dataToBeInsert = []

                # Divided amount must be equal to total amount
                amount_should_equal = 0

                for divide_between in divide_betweens:
                    if UserModel.find_by_id(divide_between["user_id"]):
                        a = DividedExpenseModel(
                            expense_id=createdExpenseId,
                            user_id=divide_between["user_id"],
                            amount=divide_between["amount"],
                        )
                        amount_should_equal = (
                            amount_should_equal + divide_between["amount"]
                        )
                        dataToBeInsert.append(a)
                    else:
                        # rollback created expense entry.
                        # TODO: handle error while deleting.
                        try:
                            ExpenseModel.delete_by_id(createdExpenseId)
                            return {
                                "message": "username: {} not found".format(
                                    divide_between["user_id"]
                                )
                            }
                        except:
                            return {"message": "Something went wrong"}, 500

                if int(amount_should_equal) == int(data["total_amount"]):
                    # For divident Expenses
                    for dataWillBeInsert in dataToBeInsert:
                        try:
                            dataWillBeInsert.save_to_db()
                        except:
                            return {"message": "Something went wrong"}, 500
                else:
                    # rollback created expense entry.
                    # TODO: handle error while deleting.
                    try:
                        ExpenseModel.delete_by_id(createdExpenseId)
                        return {
                            "message": "total amount is not equal to divident amount"
                        }
                    except:
                        return {"message": "Something went wrong"}, 500

            else:
                return {"message": "length doesn't exist"}
            return {
                "message": "Expense created successfully for User id: {}".format(
                    data["user_id"]
                )
            }
        else:
            return {"message": "User doesn't exists"}


# List Expanses
class ListExpenses(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("user_id", help="This field cannot be blank", required=True)
        data = parser.parse_args()
        response = ExpenseModel.return_all(data["user_id"])
        return {"expenses": response}


# Expenses categories
class CreateExpenseCategories(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument(
            "category_name", help="This field cannot be blank", required=True
        )

        data = parser.parse_args()
        new_expense_category = ExpenseCategoryModel(category_name=data["category_name"])
        try:
            new_expense_category.save_to_db()
            return {
                "message": "New expense category: {} was created".format(
                    data["category_name"]
                ),
            }
        except:
            return {"message": "Something went wrong"}, 500


class ListExpenseCategories(Resource):
    def get(self):
        return ExpenseCategoryModel.return_all()


# Users
class UserRegistration(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument(
            "username", help="This field cannot be blank", required=True
        )
        parser.add_argument(
            "password", help="This field cannot be blank", required=True
        )
        parser.add_argument("email", help="This field cannot be blank", required=True)
        data = parser.parse_args()

        if UserModel.find_by_username(data["username"]):
            return {"message": "User {} already exists".format(data["username"])}

        new_user = UserModel(
            username=data["username"],
            password=UserModel.generate_hash(data["password"]),
            email=data["email"],
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data["username"])
            refresh_token = create_refresh_token(identity=data["username"])
            return {
                "message": "User {} was created".format(data["username"]),
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        except:
            return {"message": "Something went wrong"}, 500


class UserLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument(
            "username", help="This field cannot be blank", required=True
        )
        parser.add_argument(
            "password", help="This field cannot be blank", required=True
        )
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data["username"])

        if not current_user:
            return {"message": "User {} doesn't exist".format(data["username"])}

        if UserModel.verify_hash(data["password"], current_user.password):
            access_token = create_access_token(identity=data["username"])
            refresh_token = create_refresh_token(identity=data["username"])
            return {
                "message": "Logged in as {}".format(current_user.username),
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        else:
            return {"message": "Wrong credentials"}


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()["jti"]
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {"message": "Access token has been revoked"}
        except:
            return {"message": "Something went wrong"}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()["jti"]
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {"message": "Refresh token has been revoked"}
        except:
            return {"message": "Something went wrong"}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {"access_token": access_token}


class AllUsers(Resource):
    @jwt_required
    def get(self):
        return UserModel.return_all()

    def delete(self):
        return UserModel.delete_all()
