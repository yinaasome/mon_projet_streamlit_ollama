FROM python:3.11-slim

# Dépendances système
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Création du dossier de l'app
WORKDIR /app

# Copie des fichiers
COPY requirements.txt requirements.txt
COPY . .

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Définir variable d'environnement pour Docker
ENV DOCKER=1

# Lancement de l'app
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
