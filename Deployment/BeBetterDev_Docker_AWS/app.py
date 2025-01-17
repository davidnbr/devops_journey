# https://www.youtube.com/watch?v=1_AlV-FFxM8&t=575s

# import uvicorn
from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "<h1>Hello, Docker boiii!! </h1>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)


# to create image
# docker build -t first-time .


# to create container and run
# docker run -p 127.0.0.1:8080:8080 first-time


# to create a volume : shared folder between machine and container
# docker run -v C:\Users:/container_folder first-time

# create named volume
# docker volume
# docker volume create shared_volume
# use it
# docker run -v shared_volume:/my_path first-time


# run container with compose
# docker compose up --build
