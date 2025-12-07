import json
from fastapi import FastAPI, UploadFile, File, Form, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import shutil

# Instance aplikasi utama
app = FastAPI(title="mydj_server", description="Server sederhana untuk aplikasi MyDJ")
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

@app.post("/upload-jurnal")
async def upload_jurnal(
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