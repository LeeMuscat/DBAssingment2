import os
import io
import re
from datetime import datetime
from typing import Optional, Any, Dict

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


import motor.motor_asyncio
from bson import ObjectId



load_dotenv()

# Load mongoDb uri from .env

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError(
        "MONGO_URI not found. Make sure your .env is in the same folder as main.py "
        "and contains: MONGO_URI=..."
    )

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client.leeMuscatDB


app = FastAPI(title="Event Management API")

#patters to detect NoSQL/SQL injection attempts
BLOCK_PATTERN = re.compile(
    r"(\$|\{|\}|\[|\]|;|--|/\*|\*/|\b(OR|AND)\b\s+\d=\d)",
    re.IGNORECASE
)
#checks stringe for injection patterns
def scan_for_injection(value: str) -> None:
    if value and BLOCK_PATTERN.search(value):
        raise HTTPException(status_code=400, detail="Invalid input detected")
#checks json payload for injection patterns
def sanitize_payload(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and ("$" in k or "." in k):
                raise HTTPException(status_code=400, detail="Invalid input detected")
            sanitize_payload(v)
    elif isinstance(obj, list):
        for item in obj:
            sanitize_payload(item)
    elif isinstance(obj, str):
        scan_for_injection(obj)
#middleware automatically checks json requests before they reach endpoint
@app.middleware("http")
async def injection_protection_middleware(request: Request, call_next):
    content_type = request.headers.get("content-type", "")
    if request.method in {"POST", "PUT", "PATCH"} and "application/json" in content_type:
        body = await request.body()
        if body:
            async def receive():
                return {"type": "http.request", "body": body}
            request._receive = receive 
            try:
                import json
                payload = json.loads(body.decode("utf-8"))
                sanitize_payload(payload)
            except HTTPException:
                raise
            except Exception:
                pass
    return await call_next(request)
#returns 422 error for validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

#converts string into mongoDB ObjectId
def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id format")

#Converts mongodb document into JSON output
def to_json(doc: Dict[str, Any]) -> Dict[str, Any]:
    doc["_id"] = str(doc["_id"])
    return doc

#fetches document by id from mongo collections or returns 404 error
async def get_or_404(collection, id_str: str) -> Dict[str, Any]:
    doc = await collection.find_one({"_id": oid(id_str)})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return doc


class Event(BaseModel):
    name: str
    description: str
    date: str
    venue_id: str
    max_attendees: int


class Attendee(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None


class Venue(BaseModel):
    name: str
    address: str
    capacity: int


class Booking(BaseModel):
    event_id: str
    attendee_id: str
    ticket_type: str
    quantity: int

#creates event in events collection 
@app.post("/events")
async def create_event(event: Event):
    result = await db.events.insert_one(event.model_dump())
    return {"message": "Event created", "id": str(result.inserted_id)}

#returns list of events from events collection
@app.get("/events")
async def list_events():
    docs = await db.events.find().to_list(100)
    return [to_json(d) for d in docs]

#returns a single event from events collection by id and returns 404 if not found
@app.get("/events/{event_id}")
async def get_event(event_id: str):
    doc = await get_or_404(db.events, event_id)
    return to_json(doc)

#updates an existing event in events collection by id and returns 404 if not found
@app.put("/events/{event_id}")
async def update_event(event_id: str, event: Event):
    result = await db.events.update_one({"_id": oid(event_id)}, {"$set": event.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"message": "Event updated"}

#deletes event from events collection by id and returns 404 if not found
@app.delete("/events/{event_id}")
async def delete_event(event_id: str):
    result = await db.events.delete_one({"_id": oid(event_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"message": "Event deleted"}

#creates attendee in attendees collection
@app.post("/attendees")
async def create_attendee(attendee: Attendee):
    result = await db.attendees.insert_one(attendee.model_dump())
    return {"message": "Attendee created", "id": str(result.inserted_id)}

#returns list of attendees from attendees collection
@app.get("/attendees")
async def list_attendees():
    docs = await db.attendees.find().to_list(100)
    return [to_json(d) for d in docs]

#returns a single attendee from attendees collection by id and returns 404 if not found
@app.get("/attendees/{attendee_id}")
async def get_attendee(attendee_id: str):
    doc = await get_or_404(db.attendees, attendee_id)
    return to_json(doc)

#updates an existing attendee in attendees collection by id and returns 404 if not found
@app.put("/attendees/{attendee_id}")
async def update_attendee(attendee_id: str, attendee: Attendee):
    result = await db.attendees.update_one({"_id": oid(attendee_id)}, {"$set": attendee.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Attendee not found")
    return {"message": "Attendee updated"}

#deletes attendee from attendees collection by id and returns 404 if not found
@app.delete("/attendees/{attendee_id}")
async def delete_attendee(attendee_id: str):
    result = await db.attendees.delete_one({"_id": oid(attendee_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Attendee not found")
    return {"message": "Attendee deleted"}

#creates venue in venues collection
@app.post("/venues")
async def create_venue(venue: Venue):
    result = await db.venues.insert_one(venue.model_dump())
    return {"message": "Venue created", "id": str(result.inserted_id)}

#returns list of venues from venues collection
@app.get("/venues")
async def list_venues():
    docs = await db.venues.find().to_list(100)
    return [to_json(d) for d in docs]

#returns a single venue from venues collection by id and returns 404 if not found
@app.get("/venues/{venue_id}")
async def get_venue(venue_id: str):
    doc = await get_or_404(db.venues, venue_id)
    return to_json(doc)

#updates an existing venue in venues collection by id and returns 404 if not found
@app.put("/venues/{venue_id}")
async def update_venue(venue_id: str, venue: Venue):
    result = await db.venues.update_one({"_id": oid(venue_id)}, {"$set": venue.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Venue not found")
    return {"message": "Venue updated"}

#deletes venue from venues collection by id and returns 404 if not found
@app.delete("/venues/{venue_id}")
async def delete_venue(venue_id: str):
    result = await db.venues.delete_one({"_id": oid(venue_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Venue not found")
    return {"message": "Venue deleted"}

#creates booking in booking collection
@app.post("/booking")
async def create_booking(booking: Booking):
    result = await db.booking.insert_one(booking.model_dump())
    return {"message": "Booking created", "id": str(result.inserted_id)}

#returns list of bookings from booking collection
@app.get("/booking")
async def list_bookings():
    docs = await db.booking.find().to_list(100)
    return [to_json(d) for d in docs]

#returns a single booking from booking collection by id and returns 404 if not found
@app.get("/booking/{booking_id}")
async def get_booking(booking_id: str):
    doc = await get_or_404(db.booking, booking_id)
    return to_json(doc)

#updates an existing booking in booking collection by id and returns 404 if not found
@app.put("/booking/{booking_id}")
async def update_booking(booking_id: str, booking: Booking):
    result = await db.booking.update_one({"_id": oid(booking_id)}, {"$set": booking.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Booking not found")
    return {"message": "Booking updated"}

#deletes booking from booking collection by id and returns 404 if not found
@app.delete("/booking/{booking_id}")
async def delete_booking(booking_id: str):
    result = await db.booking.delete_one({"_id": oid(booking_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Booking not found")
    return {"message": "Booking deleted"}

#stores a file image/video in a media collection
async def upload_media(collection, link_field: str, link_id: str, media_type: str, file: UploadFile):
    content = await file.read()
    doc = {
        link_field: link_id,
        "media_type": media_type,
        "filename": file.filename,
        "content_type": file.content_type,
        "content": content,
        "uploaded_at": datetime.utcnow()
    }
    result = await collection.insert_one(doc)
    return {"message": "Uploaded", "id": str(result.inserted_id)}

#retrieves the most recent file image/video from media collection
async def stream_latest_media(collection, link_field: str, link_id: str, media_type: str):
    doc = await collection.find_one(
        {link_field: link_id, "media_type": media_type},
        sort=[("uploaded_at", -1)]
    )
    if not doc:
        raise HTTPException(status_code=404, detail="No media found")

    return StreamingResponse(
        io.BytesIO(doc["content"]),
        media_type=doc["content_type"],
        headers={"Content-Disposition": f'inline; filename="{doc["filename"]}"'}
    )

#upload and retrieve endpoints for event posters
@app.post("/upload_event_poster/{event_id}")
async def upload_event_poster(event_id: str, file: UploadFile = File(...)):
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Poster must be an image")
    return await upload_media(db.media, "event_id", event_id, "event_poster", file)

#upload and retrieve endpoints for promo videos
@app.post("/upload_promo_video/{event_id}")
async def upload_promo_video(event_id: str, file: UploadFile = File(...)):
    if not file.content_type or not file.content_type.startswith("video/"):
        raise HTTPException(status_code=400, detail="Promo must be a video")
    return await upload_media(db.media, "event_id", event_id, "promo_video", file)

#upload and retrieve endpoints for venue photos
@app.post("/upload_venue_photo/{venue_id}")
async def upload_venue_photo(venue_id: str, file: UploadFile = File(...)):
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Venue photo must be an image")
    return await upload_media(db.media, "venue_id", venue_id, "venue_photo", file)

#retrieves latest poster from media collection
@app.get("/event_poster/{event_id}")
async def get_event_poster(event_id: str):
    return await stream_latest_media(db.media, "event_id", event_id, "event_poster")

#retrieves latest promo video from media collection
@app.get("/promo_video/{event_id}")
async def get_promo_video(event_id: str):
    return await stream_latest_media(db.media, "event_id", event_id, "promo_video")

#retrieves latest venue photo from media collection
@app.get("/venue_photo/{venue_id}")
async def get_venue_photo(venue_id: str):
    return await stream_latest_media(db.media, "venue_id", venue_id, "venue_photo")
