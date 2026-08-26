FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    google-generativeai \
    python-dotenv \
    pydantic \
    requests

COPY main.py gemini_client.py ./

ENV GEMINI_MODEL=gemini-2.5-flash
ENV HOST=0.0.0.0
ENV PORT=8002

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
