from datetime import timedelta

from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from security import Authenticator
import uvicorn
from schemas import ProcssedStuff, Token


ACCESS_TOKEN_EXPIRE_MINUTES = 30


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
auth = Authenticator(hash_scheme="bcrypt")
app = FastAPI()


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_id = auth.authenticate_user(form_data.username, form_data.password)

    access_token = auth.create_access_token(
        data={"sub": user_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}


async def process_stuff(token: str = Depends(oauth2_scheme)):
    return auth.verify_access_token(token)


@app.get("/process_me/", response_model=ProcssedStuff)
async def get_stuff(stuff: ProcssedStuff = Depends(process_stuff)):
    return stuff


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=5000, log_level="info", reload=True)
