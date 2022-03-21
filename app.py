from fastapi.responses import HTMLResponse
from fastapi.responses import FileResponse
from fastapi import FastAPI
from features import getfeatures
from fastapi.staticfiles import StaticFiles

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
def read_root():
    return FileResponse("./index.html")


@app.get("/analysis_phishing")
def read_item(url: str):
    try:
        return getfeatures(url)
    except:
        return {
            "error fatal": 1
        }
