import json
from fastapi import FastAPI, UploadFile, File, Form, Body, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import shutil
import logging
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from discord_notifier import DiscordNotifier

# Setup logging
logging.basicConfig(filename='logs/application.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Discord notifier (optional - only if webhook URL is provided)
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1080148082404114513/Ybji_FHuLTha1Z2EhwiCUy0SY8MMBjiUgT70FPtzkjkcAgoNB-BSXxvE-ax2YH3Jhf_c")
discord_notifier = DiscordNotifier(DISCORD_WEBHOOK_URL) if DISCORD_WEBHOOK_URL else None

# Instance aplikasi utama
app = FastAPI(title="mydj_server", description="Server sederhana untuk aplikasi MyDJ")

# Custom rate limit exceeded handler
@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    client_ip = request.client.host if request.client else "unknown"
    logging.warning(f'rate_limit_exceeded "ip_address": "{client_ip}"')
    
    # Send Discord notification
    print(discord_notifier)
    if discord_notifier:
        discord_notifier.send_rate_limit_alert(
            ip_address=client_ip,
            endpoint=str(request.url.path),
            attempts=10  # Based on your limit of 10/minute
        )
    
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests", "detail": "Rate limit exceeded"}
    )

# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# Izinkan semua origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Buat folder untuk unggah data jika belum ada
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.get("/")
def root():
    return {"message": "mydj_server berjalan dengan baik!"}

@app.get("/test-discord")
async def test_discord():
    """Test endpoint to verify Discord webhook integration"""
    if not discord_notifier:
        return JSONResponse(
            status_code=503,
            content={"error": "Discord webhook not configured", "hint": "Set DISCORD_WEBHOOK_URL in .env"}
        )
    
    from datetime import datetime
    
    success = discord_notifier.send_embed(
        title="🧪 Test Notification",
        description="This is a test notification from MyDJ Server to verify the Discord integration is working correctly.",
        color="info",
        fields=[
            {"name": "✅ Status", "value": "Working", "inline": True},
            {"name": "⏰ Time", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": True},
            {"name": "🔧 Endpoint", "value": "/test-discord", "inline": True}
        ],
        footer="MyDJ Server • Discord Integration Test"
    )
    
    if success:
        return {"success": True, "message": "Test notification sent! Check your Discord channel."}
    else:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to send notification. Check logs for details."}
        )

@app.post("/upload-jurnal")
@limiter.limit("10/minute")
async def upload_jurnal(
    request: Request,
    kelas: str = Form(...),
    mapel: str = Form(...),
    jam: int = Form(...),

    tujuanPembelajaran: str = Form(...),
    materiTopikPembelajaran: str = Form(...),
    kegiatanPembelajaran: str = Form(...),
    dimensiProfilPelajarPancasila: str = Form(...),
    createdAt: str = Form(...),
    image: UploadFile | None = File(None),
    video: UploadFile | None = File(None),
):
    # --------------------------
    # Simpan file foto
    # --------------------------
    image_path = None
    if image:
        image_path = os.path.join(UPLOAD_FOLDER, image.filename)
        with open(image_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
    # --------------------------
    # Simpan file video
    # --------------------------
    video_path = None
    if video:
        video_path = os.path.join(UPLOAD_FOLDER, video.filename)
        with open(video_path, "wb") as buffer:
            shutil.copyfileobj(video.file, buffer)

    # --------------------------
    # Buat objek jurnal
    # --------------------------
    jurnal_data = {
        "kelas": kelas,
        "mapel": mapel,
        "jam": jam,
        "tujuanPembelajaran": tujuanPembelajaran,
        "materiTopikPembelajaran": materiTopikPembelajaran,
        "kegiatanPembelajaran": kegiatanPembelajaran,
        "dimensiProfilPelajarPancasila": dimensiProfilPelajarPancasila,
        "createdAt": createdAt,
        "image": image_path,
        "video": video_path
    }
    # --------------------------
    # Simpan ke file JSON (APPEND)
    # --------------------------
    DATA_FILE = "uploads/data.json"
    if not os.path.exists(DATA_FILE):
        data = []
    else:
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
    data.append(jurnal_data)
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

    # --------------------------
    # Send Discord Notification
    # --------------------------
    if discord_notifier:
        discord_notifier.send_jurnal_notification(
            kelas=kelas,
            mapel=mapel,
            jam=jam,
            tujuan=tujuanPembelajaran,
            materi=materiTopikPembelajaran,
            kegiatan=kegiatanPembelajaran,
            dimensi=dimensiProfilPelajarPancasila,
            created_at=createdAt,
            has_image=image is not None,
            has_video=video is not None
        )

    # --------------------------
    # Response
    # --------------------------
    return JSONResponse({
        "message": "Jurnal berhasil di-upload!",
        "data": {
            "kelas": kelas,
            "mapel": mapel,
            "jam": jam,
            "tujuanPembelajaran": tujuanPembelajaran,
            "materiTopikPembelajaran": materiTopikPembelajaran,
            "kegiatanPembelajaran": kegiatanPembelajaran,
            "dimensiProfilPelajarPancasila": dimensiProfilPelajarPancasila,
            "createdAt": createdAt,
            # URL media di server, agar bisa ditampilkan di App
            "image_url": image_path,
            "video_url": video_path,
        }
    })