# import libraries
import flask
from flask_cors import CORS
from models.models import db
import os
from dotenv import load_dotenv

# import routes
from liveliness.liveliness import liveliness_blueprint


# Load env variables
load_dotenv()
DB_URL = os.getenv('DB_URL')
DB_DBNAME = os.getenv('DB_DBNAME')
DB_USER = os.getenv('DB_USER')
DB_PASS = os.getenv('DB_PASS')


app = flask.Flask(__name__)
api_cors_headers = {
    "origins": [
        "localhost:3000",
        "http://localhost:3000",
    ],
    "methods": ["OPTIONS", "DELETE", "GET", "POST"],
    "allow_headers": ["Authorization", "Content-Type"]
}
cors = CORS(app, resources={"/*": api_cors_headers}, supports_credentials=True)  # nopep8


@app.before_first_request
def startup_project():
    db.create_all()


# define routes
@app.route('/', methods=['GET'])
def home():
    return {
        "data": {
            "message": "Currently supported endpoints",
            "endpoints": ["/liveliness"]
        },
        "status": 200
    }


app.register_blueprint(liveliness_blueprint, url_prefix='/liveliness')


app.config["DEBUG"] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://' + DB_USER+':'+DB_PASS+'@'+DB_URL+'/'+DB_DBNAME  # nopep8
db.init_app(app)

if __name__ == "__main__":
    # set up app variables for development
    # the production entrypoint for the project is the wsgi.py file in this dir

    print(app.url_map)
    app.run(port=8003)
    db.create_all()
