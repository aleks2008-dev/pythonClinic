from typing import List, Union, Type, Sequence, Optional
from fastapi import Depends, FastAPI, HTTPException, Query, Form, Security, status
from sqlmodel import Field, Session, SQLModel, create_engine, select
from typing_extensions import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPBasic, HTTPBasicCredentials, SecurityScopes
from pydantic import BaseModel, ValidationError
import jwt
from jwt.exceptions import InvalidTokenError
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
import secrets
#from database.db import Client

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    name: Union[str, None] = None


class Client(SQLModel, BaseModel, table=True):
    id: Union[int, None] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    password: str = Field(index=True)
    age: Union[int, None] = Field(default=None, index=True)
    doctor_id: Optional[int] = Field(default=None, foreign_key="doctor.id")

class Doctor(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    doctor_name: str = Field(index=True)
    observation_room: int


class ClientInDB(Client):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

security = HTTPBasic()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

#def get_user(db, username: str):
    #if username in db:
        #user_dict = db[username]
        #return UserInDB(**user_dict)

def get_client(db, name: str):
    if name in db:
        client_dict = db[name]
        return ClientInDB(**client_dict)

def authenticate_client(db, name: str, password: str):
    client = get_client(db, name)
    if not client:
        return False
    if not verify_password(password, client.hashed_password):
        return False
    return client

def create_jwt_token(data: dict, EXPIRATION_TIME=None):
    expiration = datetime.utcnow() + EXPIRATION_TIME
    data.update({"exp": expiration})
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_jwt_token(token: str):
    try:
        decoded_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_data
    except jwt.PyJWTError:
        return None

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

SessionDep = Annotated[Session, Depends(get_session)]

async def get_current_client(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        name: str = payload.get("sub")
        if name is None:
            raise credentials_exception
        token_data = TokenData(name=name)
    except InvalidTokenError:
        raise credentials_exception
    client = get_client(db, name=token_data.name)
    if client is None:
        raise credentials_exception
    return client

async def get_current_active_client(
    current_client: Annotated[Client, Depends(get_current_client)],
):
    if current_client.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_client

def get_current_username(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
):
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = b"stanleyjobson"
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = credentials.password.encode("utf8")
    correct_password_bytes = b"swordfish"
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

#@app.post("/register")
#def register_user(username: str, password: str):
    #hashed_password = pwd_context.hash(password)
    ## Сохраните пользователя в базе данных
    #return {"username": username, "hashed_password": hashed_password}

@app.post("/clients/", summary='Запись клиента')
def create_client(session: SessionDep, client: Client = Form()) -> Client:
    hashed_password = pwd_context.hash('password')
    session.add(client)
    session.commit()
    session.refresh(client)
    #return {"hashed_password": hashed_password}
    return client

@app.post("/doctors/", summary='Запись врача')
def create_doctor(session: SessionDep, doctor: Doctor = Form()) -> Doctor:
    hashed_password = pwd_context.hash('password')
    session.add(doctor)
    session.commit()
    session.refresh(doctor)
    #return {"hashed_password": hashed_password}
    return doctor

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    client = authenticate_client(db, form_data.name, form_data.password)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect name or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": client.name}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

#@app.get("/clients/me/", response_model=Client)
#async def read_clients_me(
    #current_client: Annotated[Client, Depends(get_current_active_client())],
#):
    #return current_client

@app.get("/users/me/", response_model=Client)
async def read_client_me(
    current_user: Annotated[Client, Depends(get_current_active_client)],
):
    return current_client

@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[Client, Depends(get_current_active_client)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.get("/clients/", summary='Получение списка клиентов')
def read_clients(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
) -> Sequence[Client]:
    clients = session.exec(select(Client).offset(offset).limit(limit)).all()
    return clients


@app.get("/clients/{client_id}")
def read_client(client_id: int, session: SessionDep) -> Type[Client]:
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@app.delete("/clients/{client_id}", summary='Удаление клиента')
def delete_client(client_id: int, session: SessionDep, username: Annotated[str, Depends(get_current_username)]):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    session.delete(client)
    session.commit()
    return {"ok": True}

@app.get("/admin")
def admin_endpoint(current_user: Client = Depends(get_current_client)):
    if not get_current_client.is_admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    return {"message": "Добро пожаловать, администратор!"}