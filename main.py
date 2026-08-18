# Hệ thống hiện tại đang tồn tại bốn lỗi nghiêm trọng liên quan đến logic phân quyền, thiết lập middleware và cấu hình CORS. Lỗi đầu tiên nằm ở hàm require_admin() khi sử dụng sai toán tử logic or (cụ thể là if current_user["role"] == "admin" or current_user["is_active"]). Sự nhầm lẫn này tạo ra một lỗ hổng nghiêm trọng: bất kỳ tài khoản nào đang hoạt động, dù chỉ mang quyền "user", cũng có thể dễ dàng lọt qua lớp bảo vệ. Điều này thể hiện rõ qua kịch bản kiểm thử số 1, khi một tài khoản "user" thực hiện lệnh xóa khóa học (DELETE /admin/courses/1) lại được hệ thống chấp nhận và trả về mã 200 OK thay vì bị chặn đứng bằng mã 403 Forbidden đúng chuẩn.

# Lỗi thứ hai và thứ ba đều bắt nguồn từ cách triển khai sai lầm của authentication_middleware. Middleware này đang áp dụng một quy tắc cứng nhắc: bắt buộc mọi request đi qua đều phải có header Authorization. Hậu quả đầu tiên là các endpoint công khai (Public API) như /health, vốn sinh ra để kiểm tra trạng thái hệ thống mà không cần đăng nhập, lại bị chặn lại oan uổng. Kịch bản kiểm thử số 2 cho thấy API này đang trả về lỗi 401 Unauthorized thay vì 200 OK. Hậu quả thứ hai là hệ thống phá hỏng cơ chế CORS của trình duyệt. Trước khi gửi các request thực tế khác nguồn (cross-origin), trình duyệt sẽ tự động gửi một request preflight bằng phương thức OPTIONS (hoàn toàn không chứa token). Do bị Middleware chặn lại đòi token, kịch bản kiểm thử số 3 gửi request OPTIONS /courses đã bị từ chối với mã 401 thay vì nhận được các cấu hình CORS hợp lệ.

# Cuối cùng, hệ thống đang gặp lỗi cấu hình CORS quá lỏng lẻo khi sử dụng tham số allow_origins=["*"]. Thiết lập này đồng nghĩa với việc hệ thống cho phép mọi tên miền trên internet đều có thể gọi API, vi phạm hoàn toàn quy tắc bảo mật cốt lõi là chỉ cho phép hai hệ thống Frontend được chỉ định (localhost:3000 và localhost:5173) truy cập. Kịch bản kiểm thử số 4 đã chứng minh lỗ hổng này: một website lạ như [https://unknown-website.com](https://unknown-website.com) khi gửi request đến hệ thống vẫn ngang nhiên nhận được quyền truy cập thông qua header CORS thay vì bị từ chối kết nối.
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from starlette.requests import Request

app = FastAPI()

# Chỉ định rõ 2 Frontend được phép truy cập để sửa lỗi CORS
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

TOKENS = {
    "admin-token": {
        "username": "admin01",
        "role": "admin",
        "is_active": True,
    },
    "user-token": {
        "username": "student01",
        "role": "user",
        "is_active": True,
    },
    "locked-token": {
        "username": "locked01",
        "role": "user",
        "is_active": False,
    },
}

# Cập nhật Middleware: Gỡ bỏ logic đòi Authorization, chỉ giữ lại việc gắn Header
@app.middleware("http")
async def custom_header_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-System-Name"] = "Learning Management System"
    return response

# Kiểm tra trạng thái is_active ngay tại đây để bảo vệ chung cho các API cần xác thực
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = TOKENS.get(token)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
        )
    
    if not user.get("is_active"):
        raise HTTPException(
            status_code=403,
            detail="Inactive user account",
        )

    return user

# Sửa lại logic: Bắt buộc role phải là "admin"
def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin permission required",
        )
    return current_user


@app.get("/health")
def health_check():
    return {"status": "UP"}


@app.get("/courses")
def get_courses(current_user: dict = Depends(get_current_user)):
    return {
        "items": [
            {"id": 1, "name": "FastAPI Basic"},
            {"id": 2, "name": "FastAPI Security"},
        ]
    }


@app.delete("/admin/courses/{course_id}")
def delete_course(
    course_id: int,
    current_user: dict = Depends(require_admin),
):
    return {
        "message": f"Course {course_id} has been deleted",
        "deleted_by": current_user["username"],
    }