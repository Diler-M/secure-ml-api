from fastapi import FastAPI
from pydantic import BaseModel
from transformers import pipeline

app = FastAPI()
classifier = pipeline(
    "sentiment-analysis",
    model="distilbert-base-uncased-finetuned-sst-2-english",
    revision="714eb0f"
)


class TextInput(BaseModel):
    text: str

@app.post("/predict")
def predict(input: TextInput):
    result = classifier(input.text)
    return result
