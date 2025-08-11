from fastapi import FastAPI
from pydantic import BaseModel
from transformers import pipeline

app = FastAPI(
    title="Secure ML API",
    description="A FastAPI service for sentiment analysis with Hugging Face Transformers",
    version="1.0.0"
)

class TextInput(BaseModel):
    text: str

classifier = pipeline(
    "sentiment-analysis",
    model="distilbert-base-uncased-finetuned-sst-2-english",
    revision="714eb0f"
)

@app.get("/")
def root():
    return {"status": "API is running"}

@app.post("/predict")
def predict(input: TextInput):
    """Run sentiment analysis on the provided text."""
    result = classifier(input.text)
    return result
