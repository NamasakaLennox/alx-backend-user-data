# 0x03. User authentication service
## user.py
In this task you will create a SQLAlchemy model named User for a database table named users (by using the mapping declaration of SQLAlchemy).

The model will have the following attributes:

    id, the integer primary key
    email, a non-nullable string
    hashed_password, a non-nullable string
    session_id, a nullable string
    reset_token, a nullable string

## db.py
In this task, you will complete the DB class provided below to implement the add_user method.
```
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session

from user import Base


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session
```
Note that DB._session is a private property and hence should NEVER be used from outside the DB class.

Implement the add_user method, which has two required string arguments: email and hashed_password, and returns a User object. The method should save the user to the database. No validations are required at this stage.

## db.py
In this task you will implement the DB.find_user_by method. This method takes in arbitrary keyword arguments and returns the first row found in the users table as filtered by the method’s input arguments. No validation of input arguments required at this point.

Make sure that SQLAlchemy’s NoResultFound and InvalidRequestError are raised when no results are found, or when wrong query arguments are passed, respectively.

Warning:

    NoResultFound has been moved from sqlalchemy.orm.exc to sqlalchemy.exc between the version 1.3.x and 1.4.x of SQLAchemy - please make sure you are importing it from sqlalchemy.orm.exc

## db.py
In this task, you will implement the DB.update_user method that takes as argument a required user_id integer and arbitrary keyword arguments, and returns None.

The method will use find_user_by to locate the user to update, then will update the user’s attributes as passed in the method’s arguments then commit changes to the database.

If an argument that does not correspond to a user attribute is passed, raise a ValueError.

## auth.py
In this task you will define a _hash_password method that takes in a password string arguments and returns bytes.

The returned bytes is a salted hash of the input password, hashed with bcrypt.hashpw.

## auth.py
In this task, you will implement the Auth.register_user in the Auth class provided below:
```
from db import DB


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()
```
Note that Auth._db is a private property and should NEVER be used from outside the class.

Auth.register_user should take mandatory email and password string arguments and return a User object.

If a user already exist with the passed email, raise a ValueError with the message User <user's email> already exists.

If not, hash the password with _hash_password, save the user to the database using self._db and return the User object.

## app.py
In this task, you will set up a basic Flask app.

Create a Flask app that has a single GET route ("/") and use flask.jsonify to return a JSON payload of the form:
```
{"message": "Bienvenue"}
```
Add the following code at the end of the module:
```
if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
```

## app.py
In this task, you will implement the end-point to register a user. Define a users function that implements the POST /users route.

Import the Auth object and instantiate it at the root of the module as such:

from auth import Auth


AUTH = Auth()

The end-point should expect two form data fields: "email" and "password". If the user does not exist, the end-point should register it and respond with the following JSON payload:
```
{"email": "<registered email>", "message": "user created"}
```
If the user is already registered, catch the exception and return a JSON payload of the form
```
{"message": "email already registered"}
```
and return a 400 status code

Remember that you should only use AUTH in this app. DB is a lower abstraction that is proxied by Auth.

## auth.py
In this task, you will implement the Auth.valid_login method. It should expect email and password required arguments and return a boolean.

Try locating the user by email. If it exists, check the password with bcrypt.checkpw. If it matches return True. In any other case, return False.

## auth.py
In this task you will implement a _generate_uuid function in the auth module. The function should return a string representation of a new UUID. Use the uuid module.

Note that the method is private to the auth module and should NOT be used outside of it.

## auth.py
In this task, you will implement the Auth.create_session method. It takes an email string argument and returns the session ID as a string.

The method should find the user corresponding to the email, generate a new UUID and store it in the database as the user’s session_id, then return the session ID.

Remember that only public methods of self._db can be used.

## app.py
In this task, you will implement a login function to respond to the POST /sessions route.

The request is expected to contain form data with "email" and a "password" fields.

If the login information is incorrect, use flask.abort to respond with a 401 HTTP status.

Otherwise, create a new session for the user, store it the session ID as a cookie with key "session_id" on the response and return a JSON payload of the form
```
{"email": "<user email>", "message": "logged in"}
```

## auth.py
In this task, you will implement the Auth.get_user_from_session_id method. It takes a single session_id string argument and returns the corresponding User or None.

If the session ID is None or no user is found, return None. Otherwise return the corresponding user.

Remember to only use public methods of self._db.

## auth.py
In this task, you will implement Auth.destroy_session. The method takes a single user_id integer argument and returns None.

The method updates the corresponding user’s session ID to None.

Remember to only use public methods of self._db.

## app.py
In this task, you will implement a logout function to respond to the DELETE /sessions route.

The request is expected to contain the session ID as a cookie with key "session_id".

Find the user with the requested session ID. If the user exists destroy the session and redirect the user to GET /. If the user does not exist, respond with a 403 HTTP status.

## app.py
In this task, you will implement a profile function to respond to the GET /profile route.

The request is expected to contain a session_id cookie. Use it to find the user. If the user exist, respond with a 200 HTTP status and the following JSON payload:
```
{"email": "<user email>"}
```
If the session ID is invalid or the user does not exist, respond with a 403 HTTP status.

## auth.py
In this task, you will implement the Auth.get_reset_password_token method. It take an email string argument and returns a string.

Find the user corresponding to the email. If the user does not exist, raise a ValueError exception. If it exists, generate a UUID and update the user’s reset_token database field. Return the token.

## app.py
In this task, you will implement a get_reset_password_token function to respond to the POST /reset_password route.

The request is expected to contain form data with the "email" field.

If the email is not registered, respond with a 403 status code. Otherwise, generate a token and respond with a 200 HTTP status and the following JSON payload:
```
{"email": "<user email>", "reset_token": "<reset token>"}
```

## auth.py
In this task, you will implement the Auth.update_password method. It takes reset_token string argument and a password string argument and returns None.

Use the reset_token to find the corresponding user. If it does not exist, raise a ValueError exception.

Otherwise, hash the password and update the user’s hashed_password field with the new hashed password and the reset_token field to None.

## app.py
In this task you will implement the update_password function in the app module to respond to the PUT /reset_password route.

The request is expected to contain form data with fields "email", "reset_token" and "new_password".

Update the password. If the token is invalid, catch the exception and respond with a 403 HTTP code.

If the token is valid, respond with a 200 HTTP code and the following JSON payload:
```
{"email": "<user email>", "message": "Password updated"}
```