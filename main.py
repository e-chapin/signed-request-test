import os
import hmac
from hashlib import sha256
from dotenv import load_dotenv

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

load_dotenv()

ALGORITHMS = {'sha256': sha256}
ENCODINGS = ['utf-8']

app = FastAPI()

def create_signature(body, algorithm):
    return hmac.new(
        os.getenv('SECRET').encode(),
        body.encode(),
        ALGORITHMS[algorithm]
    ).hexdigest()


@app.middleware("http")
async def validate_signature(request: Request, call_next):
    if not request.url.path.startswith('/v2/'):
        return await call_next(request)

    encoding, algorithm, signature = request.headers['x-signature'].lower().split('=')

    if algorithm not in ALGORITHMS.keys():
        raise HTTPException(status_code=400, detail="Invalid algorithm")

    if encoding not in ENCODINGS:
        raise HTTPException(status_code=400, detail="Invalid encoding")

    body = await request.body()

    expected = create_signature(body.decode(encoding), algorithm)
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    return await call_next(request)


@app.post("/v2/async/generative/uncrop")
def test():
    return JSONResponse(content={"status": "ok"})

