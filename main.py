import hmac
import json
from hashlib import sha256

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI()

def create_signature(key, body):
    return hmac.new(
        key.encode(),
        body.encode(),
        sha256
    ).hexdigest()


@app.middleware("http")
async def validate_signature(request: Request, call_next):

    secret = '' # copy from 1pass
    bad_secret = '12345'

    signature = request.headers['x-signature']
    rbody = request.headers['x-body']

    body = await request.json()
    # body is sorted on the rails side, so no need to sort here.
    json_body = json.dumps(body, separators=(',', ':'), sort_keys=True)

    good = create_signature(secret, json_body) == signature
    bad = create_signature(bad_secret, json_body) == signature

    authed_route = request.url.path.startswith('/v2/')


    if authed_route and not good:
        return Response(content="Unauthorized", status_code=401)

    response = await call_next(request)
    # set headers for validating in rails app, not needed in prod
    response.headers['x-good'] = str(good)
    response.headers['x-bad'] = str(bad)
    return response


@app.post("/v2/async/generative/uncrop")
def test():
    return JSONResponse(content={"status": "ok"})

