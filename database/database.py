import pymongo
import bcrypt

from bson.objectid import ObjectId


class Database:
    def __init__(self):
        DB_URL = "mongodb://localhost:27017/transactionHistory"
        self.client = pymongo.MongoClient(DB_URL)
        self.db = self.client["transactionHistory"]
        self.transactions = self.db["transactions"]
        self.users = self.db["users"]

    def createUser(self, username: str, password: str):
        if self.users.find_one({"username": username}):
            return False
        user = {"username": username, "password": Security.hash(password)}
        self.users.insert_one(user)
        return True

    def getUserDetails(self, username: str):
        user = self.users.find_one({"username": username})
        if user:
            user["id"] = str(user["_id"])
        return user

    def getUserByID(self, id: str):
        user = self.users.find_one({"_id": ObjectId(id)})
        if user:
            user["id"] = str(user["_id"])
        return user

    def verifyUser(self, username: str, password: str):
        user = self.users.find_one({"username": username})
        if user:
            user["id"] = str(user["_id"])
            return user if Security.verify(password, user["password"]) else False
        return False

    def createTransaction(
        self,
        username: str,
        amount: float,
        description: str,
        password: str,
        tags: list = [],
    ):
        if self.verifyUser(username, password):
            transaction = {
                "username": username,
                "amount": amount,
                "description": description,
                "tags": tags,
            }
            return str(self.transactions.insert_one(transaction).inserted_id)
        return False


class Security:
    def verify(self, password: str, hashed_password: str):
        return bcrypt.checkpw(password.encode(), hashed_password.encode())

    def hash(self, password: str):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
