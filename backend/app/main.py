# main.py
import datetime
import enum
import logging
import csv
import io
import json # For details in audit log if needed
from typing import List, Optional, Annotated, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status, Response, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from supabase import create_client, Client # Added Client for type hinting
from fastapi.middleware.cors import CORSMiddleware


# --- Configuration ---
# Provided by user
SUPABASE_URL = "https://oksqmkbdgzofoyangpss.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9rc3Fta2JkZ3pvZm95YW5ncHNzIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0NzMzNDcyNSwiZXhwIjoyMDYyOTEwNzI1fQ.s0fa9_Hwe3ypgMVyz8C174ntQch3VNfBz4Z3g1nkQhc"
JWT_SECRET = "ohJ2RpVl1ScMXs6FETqnlY9wZnJ5kYLUHyfv7k4ZrPqGyT6ozIVDgw" # Your custom JWT Secret

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 1 day

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- OAuth2 Scheme (for custom JWT) ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Supabase Client Setup ---
# Initialize Supabase client
# Using ClientOptions to potentially manage schema if your tables are not in 'public'
# For this setup, assuming tables are in the default 'public' schema.
# supabase_options = ClientOptions() 
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
logger.info("Supabase client initialized.")


# --- Enums (remain the same, used for validation and API, DB will store as text or actual ENUMs if created) ---
class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

class TaskCategory(str, enum.Enum):
    WORK = "work"
    PERSONAL = "personal"
    STUDY = "study"
    HEALTH = "health"
    FINANCE = "finance"
    OTHER = "other"

# --- Pydantic Models (Schemas) ---
# Using model_config for Pydantic V2
class UserBase(BaseModel):
    username: str = Field(min_length=3)
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(min_length=6)

class UserCreateByAdmin(UserCreate):
    is_admin: Optional[bool] = False

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    google_id: Optional[str] = None
    created_at: datetime.datetime
    updated_at: Optional[datetime.datetime] = None
    class Config:  # This is the V1 approach
        orm_mode = True


class TaskBase(BaseModel):
    name: str = Field(min_length=1)
    description: Optional[str] = None
    category: TaskCategory = TaskCategory.OTHER
    due_date: Optional[datetime.datetime] = None # Ensure frontend sends timezone-aware or UTC datetimes
    status: TaskStatus = TaskStatus.PENDING

class TaskCreate(TaskBase):
    pass

class TaskUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1)
    description: Optional[str] = None
    category: Optional[TaskCategory] = None
    due_date: Optional[datetime.datetime] = None
    status: Optional[TaskStatus] = None

class TaskResponse(TaskBase):
    id: int
    user_id: int
    created_at: datetime.datetime
    updated_at: Optional[datetime.datetime] = None
    owner_username: Optional[str] = None
    class Config:  # This is the V1 approach
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[int] = None # Store user_id from Supabase in token
    username: Optional[str] = None 

class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime.datetime
    user_id: Optional[int] = None
    action: str
    target_user_id: Optional[int] = None
    task_id: Optional[int] = None
    details: Optional[str] = None
    username_triggered: Optional[str] = None
    class Config:  # This is the V1 approach
        orm_mode = True

class DashboardStats(BaseModel):
    tasks_due_today: int
    tasks_completed_last_7_days: int
    upcoming_tasks_count: int
    popular_categories: Dict[str, int]

# --- Audit Logging Utility ---
def create_audit_log(action: str, user_id: Optional[int] = None, target_user_id: Optional[int] = None, task_id: Optional[int] = None, details: Optional[Any] = None):
    try:
        log_entry = {
            "user_id": user_id,
            "action": action,
            "target_user_id": target_user_id,
            "task_id": task_id,
            "details": json.dumps(details) if details is not None and not isinstance(details, str) else details,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() # Ensure TZ aware
        }
        response = supabase.table("audit_logs").insert(log_entry).execute()
        if response.data:
            logger.info(f"Audit log created: {action} by user {user_id}, details: {details}")
        else:
            # Log Supabase error if available
            error_message = "Unknown error"
            if hasattr(response, 'error') and response.error:
                error_message = response.error.message
            logger.error(f"Failed to create audit log: {error_message}")
    except Exception as e:
        logger.error(f"Exception in create_audit_log: {e}", exc_info=True)

# --- Authentication Utilities ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id: Optional[int] = payload.get("user_id")
        username: Optional[str] = payload.get("sub") # 'sub' typically holds username
        if user_id is None or username is None:
            logger.warning(f"Token payload missing user_id or sub. Payload: {payload}")
            raise credentials_exception
        token_data = TokenData(user_id=user_id, username=username)
    except JWTError as e:
        logger.error(f"JWTError decoding token: {e}")
        raise credentials_exception
    
    try:
        # Fetch user from Supabase
        response = supabase.table("users").select("*").eq("id", token_data.user_id).eq("username", token_data.username).single().execute()
        if not response.data:
            logger.warning(f"User not found in Supabase with id: {token_data.user_id} and username: {token_data.username}")
            raise credentials_exception
        user_data = response.data
    except Exception as e: 
        logger.error(f"Error fetching user from Supabase during get_current_user: {e}")
        raise credentials_exception

    if not user_data.get("is_active"):
        logger.warning(f"User {user_data.get('username')} is inactive.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    
    return user_data 

async def get_current_active_admin(current_user_data: Annotated[dict, Depends(get_current_user)]):
    if not current_user_data.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions, admin required")
    return current_user_data

# --- FastAPI App Instance ---
app = FastAPI(title="Smart Task Management App (Supabase)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or ["http://localhost:5173"] for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],  # ✅ Must allow "authorization"
)

# --- Helper to fetch user by username or email from Supabase ---
def get_user_by_username_supabase(username: str) -> Optional[dict]:
    try:
        response = supabase.table("users").select("*").eq("username", username).maybe_single().execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching user by username '{username}': {e}")
        return None

def get_user_by_email_supabase(email: str) -> Optional[dict]:
    try:
        response = supabase.table("users").select("*").eq("email", email).maybe_single().execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching user by email '{email}': {e}")
        return None

# --- API Endpoints ---

@app.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_data = get_user_by_username_supabase(form_data.username)
    if not user_data or not verify_password(form_data.password, user_data["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user_data["is_active"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_data["username"], "user_id": user_data["id"]}, 
        expires_delta=access_token_expires
    )
    create_audit_log(action="USER_LOGIN", user_id=user_data["id"], details=f"User {user_data['username']} logged in.")
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["Users"])
def create_user_signup(user: UserCreate):
    if get_user_by_username_supabase(user.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    if get_user_by_email_supabase(user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user_data = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "is_admin": False, 
        "is_active": True,
    }
    try:
        response = supabase.table("users").insert(new_user_data).execute()
        if not response.data or len(response.data) == 0:
            error_msg = response.error.message if response.error else "No data returned"
            logger.error(f"Supabase user creation error: {error_msg}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Could not create user: {error_msg}")
        
        created_user = response.data[0]
        create_audit_log(action="USER_SIGNUP", user_id=created_user["id"], details=f"New user {created_user['username']} signed up.")
        return UserResponse(**created_user)
    except Exception as e:
        logger.error(f"Exception during user signup: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during signup.")


@app.post("/users/google-login", tags=["Authentication"], summary="Placeholder for Google Sign-In")
async def google_login_placeholder(token: Annotated[str, Body(embed=True)]):
    logger.info(f"Received Google token (placeholder): {token}")
    create_audit_log(action="GOOGLE_LOGIN_ATTEMPT", details=f"Google login attempt with token (first 20 chars): {token[:20] if token else 'N/A'}")
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Google Sign-In not fully implemented on backend yet. This is a placeholder.")


@app.get("/users/me", response_model=UserResponse, tags=["Users"])
async def read_users_me(current_user_data: Annotated[dict, Depends(get_current_user)]):
    return UserResponse(**current_user_data)

# Tasks
@app.post("/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED, tags=["Tasks"])
def create_task_for_user(task: TaskCreate, current_user_data: Annotated[dict, Depends(get_current_user)]):
    user_id = current_user_data["id"]
    new_task_data = task.dict()
    new_task_data["user_id"] = user_id
    if task.due_date: # Ensure ISO format for Supabase if due_date is provided
        new_task_data["due_date"] = task.due_date.isoformat()
    else:
        new_task_data["due_date"] = None


    try:
        response = supabase.table("tasks").insert(new_task_data).execute()
        if not response.data or isinstance(response.data, dict) and response.data.get("code") == "PGRST":
            logger.error(f"Unexpected response fetching tasks for user {user_id}: {response.data}")
            raise HTTPException(status_code=500, detail="Failed to fetch tasks from Supabase")

        
        created_task = response.data[0]
        create_audit_log(action="TASK_CREATE", user_id=user_id, task_id=created_task["id"], details=f"Task '{created_task['name']}' created.")
        
        task_resp_data = {**created_task, "owner_username": current_user_data["username"]}
        return TaskResponse(**task_resp_data)

    except Exception as e:
        logger.error(f"Exception during task creation: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during task creation.")

@app.get("/tasks", response_model=List[TaskResponse], tags=["Tasks"])
def read_user_tasks(
    current_user_data: Annotated[dict, Depends(get_current_user)],
    skip: int = 0, limit: int = 100,
    sort_by: Optional[str] = None, sort_order: Optional[str] = "asc",
    status_filter: Optional[TaskStatus] = None,
    category_filter: Optional[TaskCategory] = None,
    due_date_filter: Optional[datetime.date] = None
):
    user_id = current_user_data["id"]
    owner_username = current_user_data["username"]
    
    query = supabase.table("tasks").select("*").eq("user_id", user_id)

    if status_filter:
        query = query.eq("status", status_filter.value)
    if category_filter:
        query = query.eq("category", category_filter.value)
    if due_date_filter:
        start_of_day = datetime.datetime.combine(due_date_filter, datetime.time.min, tzinfo=datetime.timezone.utc)
        end_of_day = datetime.datetime.combine(due_date_filter, datetime.time.max, tzinfo=datetime.timezone.utc)
        query = query.gte("due_date", start_of_day.isoformat()).lte("due_date", end_of_day.isoformat())

    # FIXED: Check if sort_by is a valid field without using model_fields
    valid_sort_fields = ["id", "name", "description", "category", "due_date", "status", "created_at", "updated_at"]
    if sort_by and sort_by in valid_sort_fields:
        query = query.order(sort_by, desc=(sort_order.lower() == "desc"))
    else:
        query = query.order("created_at", desc=True) # Default sort

    query = query.range(skip, skip + limit - 1) 

    try:
        response = query.execute()
        
        # Only treat it as an error if response.data is a dict with a PGRST error code
        if isinstance(response.data, dict) and response.data.get("code") == "PGRST":
            logger.error(f"Unexpected API error response: {response.data}")
            raise HTTPException(status_code=500, detail="Failed to fetch tasks from Supabase")

        tasks_data = response.data or []
        return [TaskResponse(**{**task, "owner_username": owner_username}) for task in tasks_data]

    except Exception as e:
        logger.error(f"Exception in read_user_tasks for user {user_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Server error fetching tasks")

@app.get("/tasks/{task_id}", response_model=TaskResponse, tags=["Tasks"])
def read_single_task(task_id: int, current_user_data: Annotated[dict, Depends(get_current_user)]):
    user_id = current_user_data["id"]
    try:
        response = supabase.table("tasks").select("*").eq("id", task_id).eq("user_id", user_id).single().execute()
        if not response.data: # .single() raises an error if not exactly one row, or data is None
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or not owned by user")
        
        task_data = response.data
        task_resp_data = {**task_data, "owner_username": current_user_data["username"]}
        return TaskResponse(**task_resp_data)
    except Exception as e: 
        # Check if it's a PostgrestError from supabase-py and if it indicates "0 rows"
        if hasattr(e, 'message') and "JSON object requested, multiple (or no) rows returned" in e.message: # Common for .single()
             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or not owned by user")
        logger.error(f"Error fetching single task {task_id} for user {user_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error fetching task")


@app.put("/tasks/{task_id}", response_model=TaskResponse, tags=["Tasks"])
def update_user_task(task_id: int, task_update: TaskUpdate, current_user_data: Annotated[dict, Depends(get_current_user)]):
    user_id = current_user_data["id"]
    
    try:
        check_response = supabase.table("tasks").select("id, name").eq("id", task_id).eq("user_id", user_id).single().execute()
        if not check_response.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or not owned by user for update check")
        original_task_name = check_response.data['name']
    except Exception: # .single() will raise if not found
         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or not owned by user")

    update_data = task_update.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No update data provided")
    
    update_data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if "due_date" in update_data and update_data["due_date"] is not None:
        update_data["due_date"] = update_data["due_date"].isoformat()


    try:
        response = supabase.table("tasks").update(update_data).eq("id", task_id).eq("user_id", user_id).execute()
        if not response.data or len(response.data) == 0:
            error_msg = response.error.message if response.error else "No data returned or task not found for update"
            logger.error(f"Supabase task update error for task {task_id}: {error_msg}")
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or update failed")
        
        updated_task_data = response.data[0]
        create_audit_log(action="TASK_UPDATE", user_id=user_id, task_id=task_id, details=f"Task '{original_task_name}' updated to '{updated_task_data['name']}'. Changes: {json.dumps(update_data)}")
        
        task_resp_data = {**updated_task_data, "owner_username": current_user_data["username"]}
        return TaskResponse(**task_resp_data)
    except Exception as e:
        logger.error(f"Exception during task update for task {task_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during task update.")


@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Tasks"])
def delete_user_task(task_id: int, current_user_data: Annotated[dict, Depends(get_current_user)]):
    user_id = current_user_data["id"]
    
    try:
        task_to_delete_resp = supabase.table("tasks").select("name").eq("id", task_id).eq("user_id", user_id).single().execute()
        if not task_to_delete_resp.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or not owned by user for deletion")
        task_name = task_to_delete_resp.data['name']
    except Exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or not owned by user (pre-deletion check)")

    try:
        response = supabase.table("tasks").delete().eq("id", task_id).eq("user_id", user_id).execute()
        if isinstance(response.data, dict) and response.data.get("code") == "PGRST":
            logger.error(f"Supabase task delete API error for task {task_id}: {response.data}")
            raise HTTPException(status_code=500, detail="Error deleting task in Supabase")
            
        # For delete operations, empty response data could mean the task wasn't found
        if not response.data or len(response.data) == 0:
            logger.warning(f"Task {task_id} not found for deletion by user {user_id}, or already deleted.")
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found for deletion")
        
        create_audit_log(action="TASK_DELETE", user_id=user_id, task_id=task_id, details=f"Task ID {task_id} (name: '{task_name}') deleted.")
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logger.error(f"Exception during task deletion for task {task_id}: {e}", exc_info=True)
        # Avoid re-raising if it's the 404 we already handled
        if isinstance(e, HTTPException) and e.status_code == 404:
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during task deletion.")


@app.get("/tasks/export/csv", tags=["Tasks"], summary="Export user's tasks to CSV")
async def export_user_tasks_csv(
    current_user_data: Annotated[dict, Depends(get_current_user)],
    status_filter: Optional[TaskStatus] = None,
    category_filter: Optional[TaskCategory] = None,
    due_date_filter: Optional[datetime.date] = None
):
    user_id = current_user_data["id"]
    query = supabase.table("tasks").select("*").eq("user_id", user_id)

    if status_filter: query = query.eq("status", status_filter.value)
    if category_filter: query = query.eq("category", category_filter.value)
    if due_date_filter:
        start_of_day = datetime.datetime.combine(due_date_filter, datetime.time.min, tzinfo=datetime.timezone.utc)
        end_of_day = datetime.datetime.combine(due_date_filter, datetime.time.max, tzinfo=datetime.timezone.utc)
        query = query.gte("due_date", start_of_day.isoformat()).lte("due_date", end_of_day.isoformat())
    
    try:
        tasks_response = query.order("created_at", desc=True).execute()
        if isinstance(tasks_response.data, dict) and tasks_response.data.get("code") == "PGRST":
            logger.error(f"Error fetching tasks for CSV export (user {user_id}): {tasks_response.data}")
            raise HTTPException(status_code=500, detail="Error fetching tasks for export")
    
    # Handle empty array case properly (no tasks is valid)
        tasks = tasks_response.data or []
    except Exception as e:
        logger.error(f"Exception fetching tasks for CSV export (user {user_id}): {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Server error during task export preparation.")


    output = io.StringIO()
    writer = csv.writer(output)
    header = ["ID", "Name", "Description", "Category", "Due Date", "Status", "Created At", "Updated At"]
    writer.writerow(header)
    for task in tasks:
        writer.writerow([
            task.get("id"), task.get("name"), task.get("description"),
            task.get("category"), task.get("due_date"), task.get("status"),
            task.get("created_at"), task.get("updated_at")
        ])
    
    output.seek(0)
    create_audit_log(action="TASK_EXPORT_CSV", user_id=user_id, details="User exported their tasks to CSV.")
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=tasks.csv"})

# Admin Routes
@app.post("/admin/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["Admin"])
def admin_create_user(user: UserCreateByAdmin, admin_user_data: Annotated[dict, Depends(get_current_active_admin)]):
    if get_user_by_username_supabase(user.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    if get_user_by_email_supabase(user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user_data = {
        "username": user.username, "email": user.email, "full_name": user.full_name,
        "hashed_password": hashed_password,
        "is_admin": user.is_admin if user.is_admin is not None else False,
        "is_active": True
    }
    try:
        response = supabase.table("users").insert(new_user_data).execute()
        if not response.data or len(response.data) == 0:
            error_msg = response.error.message if response.error else "No data returned"
            logger.error(f"Admin: Supabase user creation error: {error_msg}")
            raise HTTPException(status_code=500, detail=f"Admin: Could not create user: {error_msg}")
        created_user = response.data[0]
        create_audit_log(action="ADMIN_USER_CREATE", user_id=admin_user_data["id"], target_user_id=created_user["id"], details=f"Admin {admin_user_data['username']} created user {created_user['username']}.")
        return UserResponse(**created_user)
    except Exception as e:
        logger.error(f"Admin create user error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Admin: Error creating user")

@app.put("/admin/users/{user_id_to_update}", response_model=UserResponse, tags=["Admin"])
def admin_update_user(user_id_to_update: int, user_update: UserUpdate, admin_user_data: Annotated[dict, Depends(get_current_active_admin)]):
    try:
        target_user_response = supabase.table("users").select("*").eq("id", user_id_to_update).single().execute()
        if not target_user_response.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except Exception: # .single() raises if not found
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found for update check")

    target_user = target_user_response.data
    update_data = user_update.dict(exclude_unset=True)

    if target_user["id"] == admin_user_data["id"]: 
        if 'is_active' in update_data and not update_data['is_active']:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admin cannot deactivate themselves via this endpoint.")
        if 'is_admin' in update_data and not update_data['is_admin']:
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admin cannot remove their own admin rights via this endpoint.")

    if not update_data:
        raise HTTPException(status_code=400, detail="No update data provided")
    
    update_data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        response = supabase.table("users").update(update_data).eq("id", user_id_to_update).execute()
        if not response.data or len(response.data) == 0:
            error_msg = response.error.message if response.error else "User not found for update or no changes made"
            logger.error(f"Admin: Supabase user update error for user {user_id_to_update}: {error_msg}")
            raise HTTPException(status_code=500, detail=f"Admin: User update failed: {error_msg}")
        updated_user = response.data[0]
        create_audit_log(action="ADMIN_USER_UPDATE", user_id=admin_user_data["id"], target_user_id=updated_user["id"], details=f"Admin {admin_user_data['username']} updated user {updated_user['username']}. Changes: {json.dumps(update_data)}")
        return UserResponse(**updated_user)
    except Exception as e:
        logger.error(f"Admin update user error for user {user_id_to_update}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Admin: Error updating user")


@app.patch("/admin/users/{user_id_to_manage}/deactivate", response_model=UserResponse, tags=["Admin"])
def admin_deactivate_user(user_id_to_manage: int, admin_user_data: Annotated[dict, Depends(get_current_active_admin)]):
    if user_id_to_manage == admin_user_data["id"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admin cannot deactivate themselves.")
    
    update_payload = {"is_active": False, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        response = supabase.table("users").update(update_payload).eq("id", user_id_to_manage).execute()
        if not response.data or len(response.data) == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found or deactivation failed")
        
        deactivated_user = response.data[0]
        create_audit_log(action="ADMIN_USER_DEACTIVATE", user_id=admin_user_data["id"], target_user_id=deactivated_user["id"], details=f"Admin {admin_user_data['username']} deactivated user {deactivated_user['username']}.")
        return UserResponse(**deactivated_user)
    except Exception as e:
        logger.error(f"Admin deactivate user error for {user_id_to_manage}: {e}", exc_info=True)
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail="Admin: Error deactivating user")


@app.patch("/admin/users/{user_id_to_manage}/activate", response_model=UserResponse, tags=["Admin"])
def admin_activate_user(user_id_to_manage: int, admin_user_data: Annotated[dict, Depends(get_current_active_admin)]):
    update_payload = {"is_active": True, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        response = supabase.table("users").update(update_payload).eq("id", user_id_to_manage).execute()
        if not response.data or len(response.data) == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found or activation failed")
        
        activated_user = response.data[0]
        create_audit_log(action="ADMIN_USER_ACTIVATE", user_id=admin_user_data["id"], target_user_id=activated_user["id"], details=f"Admin {admin_user_data['username']} activated user {activated_user['username']}.")
        return UserResponse(**activated_user)
    except Exception as e:
        logger.error(f"Admin activate user error for {user_id_to_manage}: {e}", exc_info=True)
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail="Admin: Error activating user")


@app.get("/admin/users", response_model=List[UserResponse], tags=["Admin"])
def admin_read_all_users(
    admin_user_data: Annotated[dict, Depends(get_current_active_admin)],
    skip: int = 0, limit: int = 100
):
    try:
        response = supabase.table("users").select("*").order("id").range(skip, skip + limit - 1).execute()
        if isinstance(response.data, dict) and response.data.get("code") == "PGRST":
            logger.error(f"Admin: Error fetching users: {response.data}")
            raise HTTPException(status_code=500, detail="Admin: Error fetching users from Supabase")
    
    # Empty array is valid - means no users
        return [UserResponse(**user) for user in response.data or []]
    except Exception as e:
        logger.error(f"Admin: Exception fetching all users: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Admin: Server error fetching users")


@app.get("/admin/tasks", response_model=List[TaskResponse], tags=["Admin"])
def admin_read_all_tasks(
    admin_user_data: Annotated[dict, Depends(get_current_active_admin)],
    skip: int = 0, limit: int = 100,
    user_id_filter: Optional[int] = None, 
    sort_by: Optional[str] = None, sort_order: Optional[str] = "asc",
    status_filter: Optional[TaskStatus] = None, category_filter: Optional[TaskCategory] = None
):
    query_string = "*, owner:users(id, username)" 
    
    query = supabase.table("tasks").select(query_string)

    if user_id_filter: query = query.eq("user_id", user_id_filter)
    if status_filter: query = query.eq("status", status_filter.value)
    if category_filter: query = query.eq("category", category_filter.value)
    
    # FIXED: Use the same valid_sort_fields approach as in read_user_tasks
    valid_sort_fields = ["id", "name", "description", "category", "due_date", "status", "created_at", "updated_at"]
    if sort_by and sort_by in valid_sort_fields:
        query = query.order(sort_by, desc=(sort_order.lower() == "desc"))
    else:
        query = query.order("created_at", desc=True)
        
    query = query.range(skip, skip + limit - 1)
    
    try:
        response = query.execute()
        # FIXED: Proper error checking
        if isinstance(response.data, dict) and response.data.get("code") == "PGRST":
            logger.error(f"Admin read all tasks error: {response.data}")
            raise HTTPException(status_code=500, detail="Admin: Error fetching tasks from Supabase")

        tasks_with_owner = []
        # Handle empty array case properly
        for task_data in response.data or []:
            owner_info = task_data.pop('owner', None) 
            # FIXED: Use direct instantiation instead of model_validate
            task_resp = TaskResponse(**task_data)
            if owner_info and isinstance(owner_info, dict):
                task_resp.owner_username = owner_info.get('username')
            elif task_data.get('user_id'): # Fallback if join fails or user is deleted
                task_resp.owner_username = f"User ID: {task_data.get('user_id')}"
            tasks_with_owner.append(task_resp)
        return tasks_with_owner
    except Exception as e:
        logger.error(f"Admin: Exception reading all tasks: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Admin: Server error fetching tasks")

@app.get("/admin/audit-logs", response_model=List[AuditLogResponse], tags=["Admin"])
def admin_read_audit_logs(
    admin_user_data: Annotated[dict, Depends(get_current_active_admin)],
    skip: int = 0, limit: int = 100,
    action_filter: Optional[str] = None, user_id_triggered_filter: Optional[int] = None
):
    # FIXED: Specify the relationship explicitly using the hint from the error message
    query_string = "*, user_triggered:users!audit_logs_user_id_fkey(id, username)"

    query = supabase.table("audit_logs").select(query_string) 

    if action_filter: query = query.ilike("action", f"%{action_filter}%") 
    if user_id_triggered_filter: query = query.eq("user_id", user_id_triggered_filter)

    query = query.order("timestamp", desc=True).range(skip, skip + limit -1)
    
    try:
        response = query.execute()
        # FIXED: Proper error checking
        if isinstance(response.data, dict) and response.data.get("code") == "PGRST":
            logger.error(f"Admin read audit logs error: {response.data}")
            raise HTTPException(status_code=500, detail="Admin: Error fetching audit logs from Supabase")

        results = []
        # Handle empty array case properly
        for log_item_data in response.data or []:
            user_triggered_info = log_item_data.pop('user_triggered', None)
            # FIXED: Use direct instantiation instead of model_validate
            log_resp = AuditLogResponse(**log_item_data) 
            if user_triggered_info and isinstance(user_triggered_info, dict):
                log_resp.username_triggered = user_triggered_info.get('username')
            elif log_item_data.get("user_id"):
                log_resp.username_triggered = f"User ID: {log_item_data['user_id']}" 
            else:
                log_resp.username_triggered = "System/Unknown"
            results.append(log_resp)
        return results
    except Exception as e:
        logger.error(f"Admin: Exception reading audit logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Admin: Server error fetching audit logs")

@app.get("/admin/dashboard-stats", response_model=DashboardStats, tags=["Admin"])
def get_admin_dashboard_stats(admin_user_data: Annotated[dict, Depends(get_current_active_admin)]):
    today_utc = datetime.datetime.now(datetime.timezone.utc).date()
    seven_days_ago_utc_start = datetime.datetime.combine(today_utc - datetime.timedelta(days=6), datetime.time.min, tzinfo=datetime.timezone.utc) # Inclusive of today, so 6 days back for 7 days total
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    
    start_of_today_iso = datetime.datetime.combine(today_utc, datetime.time.min, tzinfo=datetime.timezone.utc).isoformat()
    end_of_today_iso = datetime.datetime.combine(today_utc, datetime.time.max, tzinfo=datetime.timezone.utc).isoformat()

    try:
        due_today_resp = supabase.table("tasks").select("id", count="exact").gte("due_date", start_of_today_iso).lte("due_date", end_of_today_iso).execute()
        tasks_due_today = due_today_resp.count if due_today_resp.count is not None else 0

        completed_resp = supabase.table("tasks").select("id", count="exact") \
            .eq("status", TaskStatus.COMPLETED.value) \
            .gte("updated_at", seven_days_ago_utc_start.isoformat()) \
            .lte("updated_at", now_utc.isoformat()) \
            .execute()
        tasks_completed_last_7_days = completed_resp.count if completed_resp.count is not None else 0
        
        upcoming_resp = supabase.table("tasks").select("id", count="exact") \
            .gt("due_date", now_utc.isoformat()) \
            .in_("status", [TaskStatus.PENDING.value, TaskStatus.IN_PROGRESS.value]) \
            .execute()
        upcoming_tasks_count = upcoming_resp.count if upcoming_resp.count is not None else 0

        all_tasks_cat_resp = supabase.table("tasks").select("category").execute()
        popular_categories_counts = {}
        if all_tasks_cat_resp.data:
            for task in all_tasks_cat_resp.data:
                cat = task.get("category")
                if cat: # Ensure category is not None or empty
                    popular_categories_counts[cat] = popular_categories_counts.get(cat, 0) + 1
        
        sorted_popular_categories = dict(sorted(popular_categories_counts.items(), key=lambda item: item[1], reverse=True)[:5])

        return DashboardStats(
            tasks_due_today=tasks_due_today,
            tasks_completed_last_7_days=tasks_completed_last_7_days,
            upcoming_tasks_count=upcoming_tasks_count,
            popular_categories=sorted_popular_categories
        )

    except Exception as e:
        logger.error(f"Error fetching admin dashboard stats: {e}", exc_info=True)
        return DashboardStats(tasks_due_today=0, tasks_completed_last_7_days=0, upcoming_tasks_count=0, popular_categories={})


# --- Root Endpoint ---
@app.get("/", tags=["Root"])
async def root_path():
    return {"message": "Welcome to the Smart Task Management API (Supabase Edition)!"}

# --- Create a default admin user (run once manually or adapt for startup if needed) ---
def create_default_admin():
    logger.info("Attempting to create default admin user...")
    admin_username = "admin"
    admin_email = "admin@example.com"
    admin_password = "adminpassword" 

    try:
        existing_admin = get_user_by_username_supabase(admin_username)
        if existing_admin:
            logger.info(f"Admin user '{admin_username}' already exists.")
            if not existing_admin.get('is_admin'):
                logger.info(f"User '{admin_username}' exists but is not admin. Updating to admin.")
                update_resp = supabase.table("users").update({"is_admin": True, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}).eq("username", admin_username).execute()
                if update_resp.error:
                    logger.error(f"Failed to update existing user {admin_username} to admin: {update_resp.error.message}")
            return

        hashed_password = get_password_hash(admin_password)
        admin_data = {
            "username": admin_username,
            "email": admin_email,
            "full_name": "Default Admin",
            "hashed_password": hashed_password,
            "is_active": True,
            "is_admin": True,
        }
        response = supabase.table("users").insert(admin_data).execute()
        if response.data:
            logger.info(f"Default admin user '{admin_username}' created successfully.")
            # Ensure the created user's ID is available for the audit log
            created_admin_id = response.data[0].get('id')
            create_audit_log(action="SYSTEM_ADMIN_CREATE", user_id=created_admin_id, details=f"Default admin user {admin_username} created.")
        else:
            error_msg = response.error.message if response.error else "No data returned"
            logger.error(f"Failed to create default admin: {error_msg}")
    except Exception as e:
        logger.error(f"Exception creating default admin: {e}", exc_info=True)


if __name__ == "__main__":
    import uvicorn
    # create_default_admin() # Call this before starting Uvicorn if you want to ensure admin exists
    uvicorn.run(app, host="0.0.0.0", port=8000)

