from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import pandas as pd
import shutil
import sqlite3
import json
from datetime import datetime
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import hashlib

DATABASE = "parakh.db"


def init_database():
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            risk_score INTEGER,
            risk_level TEXT,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


init_database()

app = FastAPI(title="PARAKH Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)


@app.get("/")
def home():
    return {
        "message": "PARAKH backend is running"
    }


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    file_path = UPLOAD_FOLDER / file.filename

    with file_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        extension = file_path.suffix.lower()

        if extension == ".csv":
            data = pd.read_csv(file_path)
        elif extension == ".json":
            data = pd.read_json(file_path)
        elif extension in [".xlsx", ".xls"]:
            data = pd.read_excel(file_path)
        else:
            raise HTTPException(
                status_code=400,
                detail="Only CSV, JSON and XLSX files are supported"
            )

        data = data.fillna("")

        return {
            "message": "File uploaded and parsed successfully",
            "filename": file.filename,
            "columns": list(data.columns),
            "total_rows": len(data),
            "records": data.to_dict(orient="records")
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"File parsing failed: {str(error)}"
        )


@app.post("/analyze")
def analyze_file(filename: str):
    file_path = UPLOAD_FOLDER / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found. Please upload the file first."
        )

    try:
        data = pd.read_csv(file_path)
        data = data.fillna("")

        result = {
            "filename": filename,
            "total_records": len(data),
            "unique_callers": int(data["caller"].nunique()),
            "unique_receivers": int(data["receiver"].nunique()),
            "shared_imei": [],
            "shared_ip": [],
            "connections": []
        }

        imei_counts = data["imei"].value_counts()
        ip_counts = data["ip"].value_counts()

        result["shared_imei"] = [
            {
                "imei": str(imei),
                "record_count": int(count)
            }
            for imei, count in imei_counts.items()
            if count > 1
        ]

        result["shared_ip"] = [
            {
                "ip": str(ip),
                "record_count": int(count)
            }
            for ip, count in ip_counts.items()
            if count > 1
        ]

        for _, row in data.iterrows():
            result["connections"].append({
                "caller": str(row["caller"]),
                "receiver": str(row["receiver"]),
                "duration": int(row["duration"]),
                "imei": str(row["imei"]),
                "ip": str(row["ip"])
            })

        risk_score = 0

        if len(result["shared_imei"]) > 0:
            risk_score += 30

        if len(result["shared_ip"]) > 0:
            risk_score += 30

        if len(result["connections"]) >= 3:
            risk_score += 20

        result["risk_score"] = min(risk_score, 100)

        if result["risk_score"] >= 70:
            result["risk_level"] = "High"
        elif result["risk_score"] >= 40:
            result["risk_level"] = "Medium"
        else:
            result["risk_level"] = "Low"

        return result

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Analysis failed: {str(error)}"
        )
@app.post("/entities")
def extract_entities(filename: str):
    file_path = UPLOAD_FOLDER / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found. Please upload the file first."
        )

    try:
        data = pd.read_csv(file_path).fillna("")

        entities = {
            "phone_numbers": set(),
            "imeis": set(),
            "ips": set()
        }

        for _, row in data.iterrows():
            entities["phone_numbers"].add(str(row["caller"]))
            entities["phone_numbers"].add(str(row["receiver"]))
            entities["imeis"].add(str(row["imei"]))
            entities["ips"].add(str(row["ip"]))

        return {
            "filename": filename,
            "entities": {
                "phone_numbers": sorted(entities["phone_numbers"]),
                "imeis": sorted(entities["imeis"]),
                "ips": sorted(entities["ips"])
            },
            "counts": {
                "phone_numbers": len(entities["phone_numbers"]),
                "imeis": len(entities["imeis"]),
                "ips": len(entities["ips"])
            }
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Entity extraction failed: {str(error)}"
        )
@app.post("/normalize")
def normalize_file(filename: str):
    file_path = UPLOAD_FOLDER / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found. Please upload the file first."
        )

    try:
        data = pd.read_csv(file_path).fillna("")

        data["caller"] = (
            data["caller"]
            .astype(str)
            .str.replace(r"\D", "", regex=True)
        )

        data["receiver"] = (
            data["receiver"]
            .astype(str)
            .str.replace(r"\D", "", regex=True)
        )

        data["imei"] = (
            data["imei"]
            .astype(str)
            .str.strip()
            .str.upper()
        )

        data["ip"] = (
            data["ip"]
            .astype(str)
            .str.strip()
        )

        data["duration"] = pd.to_numeric(
            data["duration"],
            errors="coerce"
        ).fillna(0).astype(int)

        return {
            "message": "Data normalized successfully",
            "filename": filename,
            "total_records": len(data),
            "records": data.to_dict(orient="records")
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Normalization failed: {str(error)}"
        )
@app.post("/graph")
def create_graph(filename: str):
    file_path = UPLOAD_FOLDER / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found. Please upload the file first."
        )

    try:
        data = pd.read_csv(file_path).fillna("")

        nodes = {}
        edges = []

        for _, row in data.iterrows():
            caller = str(row["caller"])
            receiver = str(row["receiver"])
            imei = str(row["imei"])
            ip = str(row["ip"])

            nodes[caller] = {
                "id": caller,
                "type": "phone"
            }

            nodes[receiver] = {
                "id": receiver,
                "type": "phone"
            }

            nodes[imei] = {
                "id": imei,
                "type": "imei"
            }

            nodes[ip] = {
                "id": ip,
                "type": "ip"
            }

            edges.append({
                "source": caller,
                "target": receiver,
                "type": "call",
                "duration": int(row["duration"])
            })

            edges.append({
                "source": caller,
                "target": imei,
                "type": "used_device"
            })

            edges.append({
                "source": caller,
                "target": ip,
                "type": "used_ip"
            })

        return {
            "message": "Graph generated successfully",
            "filename": filename,
            "nodes": list(nodes.values()),
            "edges": edges
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Graph generation failed: {str(error)}"
        )
@app.post("/patterns")
def detect_patterns(filename: str):
    file_path = UPLOAD_FOLDER / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found. Please upload the file first."
        )

    try:
        data = pd.read_csv(file_path).fillna("")
        patterns = []

        imei_counts = data["imei"].value_counts()
        ip_counts = data["ip"].value_counts()

        for imei, count in imei_counts.items():
            if count > 1:
                patterns.append({
                    "type": "shared_device",
                    "value": str(imei),
                    "record_count": int(count),
                    "severity": "medium"
                })

        for ip, count in ip_counts.items():
            if count > 1:
                patterns.append({
                    "type": "shared_ip",
                    "value": str(ip),
                    "record_count": int(count),
                    "severity": "medium"
                })

        for _, row in data.iterrows():
            duration = int(row["duration"])

            if duration >= 120:
                patterns.append({
                    "type": "high_duration_call",
                    "caller": str(row["caller"]),
                    "receiver": str(row["receiver"]),
                    "duration": duration,
                    "severity": "low"
                })

        return {
            "message": "Suspicious patterns detected",
            "filename": filename,
            "total_patterns": len(patterns),
            "patterns": patterns
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Pattern detection failed: {str(error)}"
        )
@app.post("/save-analysis")
def save_analysis(filename: str):
    file_path = UPLOAD_FOLDER / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found. Please upload the file first."
        )

    try:
        data = pd.read_csv(file_path).fillna("")

        imei_counts = data["imei"].value_counts()
        ip_counts = data["ip"].value_counts()

        shared_imei = [
            {
                "imei": str(imei),
                "record_count": int(count)
            }
            for imei, count in imei_counts.items()
            if count > 1
        ]

        shared_ip = [
            {
                "ip": str(ip),
                "record_count": int(count)
            }
            for ip, count in ip_counts.items()
            if count > 1
        ]

        risk_score = 0

        if shared_imei:
            risk_score += 30

        if shared_ip:
            risk_score += 30

        if len(data) >= 3:
            risk_score += 20

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        result = {
            "filename": filename,
            "total_records": len(data),
            "shared_imei": shared_imei,
            "shared_ip": shared_ip,
            "risk_score": risk_score,
            "risk_level": risk_level
        }

        connection = sqlite3.connect(DATABASE)

        connection.execute(
            """
            INSERT INTO analysis_results
            (filename, risk_score, risk_level, result_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                filename,
                risk_score,
                risk_level,
                json.dumps(result),
                datetime.now().isoformat()
            )
        )

        connection.commit()
        connection.close()

        return {
            "message": "Analysis saved successfully",
            "result": result
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Saving analysis failed: {str(error)}"
        )
@app.get("/analysis-history")
def analysis_history():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        """
        SELECT id, filename, risk_score, risk_level, created_at
        FROM analysis_results
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return {
        "total_results": len(rows),
        "history": [dict(row) for row in rows]
    }
@app.get("/report/{filename}")
def generate_report(filename: str):
    file_path = UPLOAD_FOLDER / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found. Please upload the file first."
        )

    try:
        data = pd.read_csv(file_path).fillna("")

        shared_imei = data["imei"].value_counts()
        shared_ip = data["ip"].value_counts()

        risk_score = 0

        if any(shared_imei > 1):
            risk_score += 30

        if any(shared_ip > 1):
            risk_score += 30

        if len(data) >= 3:
            risk_score += 20

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        report_path = UPLOAD_FOLDER / f"{filename}_report.pdf"

        pdf = canvas.Canvas(str(report_path), pagesize=A4)

        pdf.setTitle("PARAKH Forensic Analysis Report")

        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(50, 800, "PARAKH Forensic Analysis Report")

        pdf.setFont("Helvetica", 11)
        pdf.drawString(50, 770, f"File: {filename}")
        pdf.drawString(50, 750, f"Total Records: {len(data)}")
        pdf.drawString(50, 730, f"Risk Score: {risk_score}/100")
        pdf.drawString(50, 710, f"Risk Level: {risk_level}")

        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(50, 670, "Shared IMEI")

        y = 645
        pdf.setFont("Helvetica", 11)

        for imei, count in shared_imei.items():
            if count > 1:
                pdf.drawString(
                    70,
                    y,
                    f"{imei} - {count} records"
                )
                y -= 20

        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(50, y - 15, "Shared IP")

        y -= 40
        pdf.setFont("Helvetica", 11)

        for ip, count in shared_ip.items():
            if count > 1:
                pdf.drawString(
                    70,
                    y,
                    f"{ip} - {count} records"
                )
                y -= 20

        pdf.save()

        return FileResponse(
            path=report_path,
            media_type="application/pdf",
            filename=f"{filename}_report.pdf"
        )

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Report generation failed: {str(error)}"
        )
@app.get("/hash/{filename}")
def file_hash(filename: str):
    file_path = UPLOAD_FOLDER / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found. Please upload the file first."
        )

    sha256_hash = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)

    return {
        "filename": filename,
        "algorithm": "SHA-256",
        "sha256": sha256_hash.hexdigest()
    }
