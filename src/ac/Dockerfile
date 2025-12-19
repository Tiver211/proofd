FROM python:3.13-alpine

RUN apk add --no-cache ffmpeg

RUN pip install --upgrade pip && \
    pip install uv

COPY ./pyproject.toml /
COPY ./uv.lock /

RUN uv sync --frozen

COPY . /app
WORKDIR /app

COPY ./entrypoint.sh /
ENTRYPOINT [ "ash", "/entrypoint.sh"]