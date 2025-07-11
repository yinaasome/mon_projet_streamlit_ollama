import os
import re
import json
import requests
import datetime
from typing import Dict, List, Optional
import pandas as pd
import streamlit as st
from langchain.prompts import PromptTemplate
from langchain_ollama import ChatOllama
from functools import reduce
import operator
from pymongo import MongoClient
from bson import ObjectId
import hashlib
import bcrypt

# 🎨 Configuration de la page
st.set_page_config(page_title="🎓 Analyse Scolaire", layout="wide")

# 🔧 Configuration pour le déploiement
# Variables d'environnement pour les services externes
OLLAMA_SERVER_URL = os.getenv("OLLAMA_SERVER_URL", "http://host.docker.internal:11434")
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
USE_EXTERNAL_SERVICES = os.getenv("USE_EXTERNAL_SERVICES", "false").lower() == "true"

# 🔐 Classe pour gérer l'authentification
class AuthManager:
    def __init__(self, db=None):
        self.db = db
        if db:
            self.users = db.users
        else:
            # Mode local si MongoDB n'est pas disponible
            if 'users_db' not in st.session_state:
                st.session_state.users_db = {
                    "admin": {
                        "username": "admin",
                        "password": bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                        "email": "admin@example.com",
                        "role": "Admin",
                        "created_at": datetime.datetime.now(),
                        "last_login": None,
                        "is_active": True
                    }
                }
    
    def hash_password(self, password: str) -> str:
        """Hache le mot de passe avec bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Vérifie le mot de passe"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_user(self, username: str, password: str, email: str = "", role: str = "Enseignant") -> bool:
        """Crée un nouvel utilisateur"""
        if self.db:
            # Vérifier si l'utilisateur existe déjà
            if self.users.find_one({"username": username}):
                return False
            
            # Créer l'utilisateur
            user_data = {
                "username": username,
                "password": self.hash_password(password),
                "email": email,
                "role": role,
                "created_at": datetime.datetime.now(),
                "last_login": None,
                "is_active": True
            }
            
            self.users.insert_one(user_data)
            return True
        else:
            # Mode local
            if username in st.session_state.users_db:
                return False
            
            st.session_state.users_db[username] = {
                "username": username,
                "password": self.hash_password(password),
                "email": email,
                "role": role,
                "created_at": datetime.datetime.now(),
                "last_login": None,
                "is_active": True
            }
            return True
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authentifie un utilisateur"""
        if self.db:
            user = self.users.find_one({"username": username, "is_active": True})
            
            if user and self.verify_password(password, user["password"]):
                # Mettre à jour la dernière connexion
                self.users.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"last_login": datetime.datetime.now()}}
                )
                
                # Retourner les données utilisateur (sans le mot de passe)
                user_data = {
                    "user_id": str(user["_id"]),
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"],
                    "created_at": user["created_at"],
                    "last_login": datetime.datetime.now()
                }
                return user_data
        else:
            # Mode local
            user = st.session_state.users_db.get(username)
            if user and user["is_active"] and self.verify_password(password, user["password"]):
                user["last_login"] = datetime.datetime.now()
                return {
                    "user_id": hashlib.sha256(username.encode()).hexdigest(),
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"],
                    "created_at": user["created_at"],
                    "last_login": user["last_login"]
                }
        
        return None

# 🗃️ Classe pour gérer la mémoire et l'historique (compatible local et MongoDB)
class ChatbotMemory:
    def __init__(self, db=None):
        self.db = db
        if db:
            self.conversations = db.conversations
            self.user_profiles = db.user_profiles
            self.user_context = db.user_context
            self.chat_sessions = db.chat_sessions
        else:
            # Initialisation des structures en mémoire si pas de DB
            if 'memory' not in st.session_state:
                st.session_state.memory = {
                    'conversations': [],
                    'user_profiles': {},
                    'user_context': {},
                    'chat_sessions': []
                }
    
    def create_new_chat_session(self, user_id: str) -> str:
        """Crée une nouvelle session de chat"""
        session_data = {
            "user_id": user_id,
            "created_at": datetime.datetime.now(),
            "is_active": True,
            "title": f"Chat du {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M')}"
        }
        
        if self.db:
            result = self.chat_sessions.insert_one(session_data)
            return str(result.inserted_id)
        else:
            session_id = f"session_{len(st.session_state.memory['chat_sessions'])}"
            session_data['_id'] = session_id
            st.session_state.memory['chat_sessions'].append(session_data)
            return session_id
    
    def get_user_chat_sessions(self, user_id: str, limit: int = 20) -> List[Dict]:
        """Récupère les sessions de chat d'un utilisateur"""
        if self.db:
            return list(self.chat_sessions.find(
                {"user_id": user_id}
            ).sort("created_at", -1).limit(limit))
        else:
            return sorted(
                [s for s in st.session_state.memory['chat_sessions'] if s['user_id'] == user_id],
                key=lambda x: x['created_at'],
                reverse=True
            )[:limit]
    
    def get_session_conversations(self, session_id: str) -> List[Dict]:
        """Récupère les conversations d'une session"""
        if self.db:
            return list(self.conversations.find(
                {"session_id": session_id}
            ).sort("timestamp", 1))
        else:
            return sorted(
                [c for c in st.session_state.memory['conversations'] if c.get('session_id') == session_id],
                key=lambda x: x['timestamp']
            )
    
    def save_conversation(self, user_id: str, session_id: str, question: str, response: str, metadata: Dict = None):
        """Sauvegarde une conversation avec la session"""
        conversation_data = {
            "user_id": user_id,
            "session_id": session_id,
            "question": question,
            "response": response,
            "timestamp": datetime.datetime.now(),
            "metadata": metadata or {}
        }
        
        if self.db:
            return self.conversations.insert_one(conversation_data)
        else:
            st.session_state.memory['conversations'].append(conversation_data)
            return True
    
    def get_conversation_history(self, user_id: str, limit: int = 50):
        """Récupère l'historique global des conversations"""
        if self.db:
            return list(self.conversations.find(
                {"user_id": user_id}
            ).sort("timestamp", -1).limit(limit))
        else:
            return sorted(
                [c for c in st.session_state.memory['conversations'] if c['user_id'] == user_id],
                key=lambda x: x['timestamp'],
                reverse=True
            )[:limit]
    
    def get_user_context(self, user_id: str):
        """Récupère le contexte utilisateur"""
        if self.db:
            return self.user_context.find_one({"user_id": user_id}) or {}
        else:
            return st.session_state.memory['user_context'].get(user_id, {})
    
    def update_user_context(self, user_id: str, context_data: Dict):
        """Met à jour le contexte utilisateur"""
        if self.db:
            self.user_context.update_one(
                {"user_id": user_id},
                {"$set": {**context_data, "last_updated": datetime.datetime.now()}},
                upsert=True
            )
        else:
            current = st.session_state.memory['user_context'].get(user_id, {})
            current.update(context_data)
            current['last_updated'] = datetime.datetime.now()
            st.session_state.memory['user_context'][user_id] = current
    
    def add_recent_entity(self, user_id: str, entity_type: str, entity_id: str, entity_name: str):
        """Ajoute une entité récemment consultée"""
        context = self.get_user_context(user_id)
        recent_key = f"recent_{entity_type}"
        
        if recent_key not in context:
            context[recent_key] = []
        
        # Supprimer l'entité si elle existe déjà
        context[recent_key] = [item for item in context[recent_key] if item['id'] != entity_id]
        
        # Ajouter en début de liste
        context[recent_key].insert(0, {
            'id': entity_id,
            'name': entity_name,
            'timestamp': datetime.datetime.now()
        })
        
        # Limiter à 20 éléments
        context[recent_key] = context[recent_key][:20]
        
        self.update_user_context(user_id, context)
    
    def update_session_title(self, session_id: str, title: str):
        """Met à jour le titre d'une session"""
        if self.db:
            self.chat_sessions.update_one(
                {"_id": ObjectId(session_id)},
                {"$set": {"title": title}}
            )
        else:
            for session in st.session_state.memory['chat_sessions']:
                if session['_id'] == session_id:
                    session['title'] = title
                    break

# 🔐 Interface de connexion
def show_login_page(auth_manager):
    """Affiche la page de connexion/inscription"""
    st.title("🎓 Chatbot Scolaire - Connexion")
    
    tab1, tab2 = st.tabs(["🔑 Connexion", "👤 Inscription"])
    
    with tab1:
        st.header("Se connecter")
        
        with st.form("login_form"):
            username = st.text_input("Nom d'utilisateur")
            password = st.text_input("Mot de passe", type="password")
            submit_login = st.form_submit_button("Se connecter")
            
            if submit_login:
                if username and password:
                    user = auth_manager.authenticate_user(username, password)
                    if user:
                        st.session_state.user = user
                        st.session_state.authenticated = True
                        st.success(f"Bienvenue {user['username']} !")
                        st.rerun()
                    else:
                        st.error("Nom d'utilisateur ou mot de passe incorrect")
                else:
                    st.error("Veuillez saisir tous les champs")
    
    with tab2:
        st.header("Créer un compte")
        
        with st.form("register_form"):
            new_username = st.text_input("Nom d'utilisateur", key="reg_username")
            new_email = st.text_input("Email (optionnel)", key="reg_email")
            new_password = st.text_input("Mot de passe", type="password", key="reg_password")
            confirm_password = st.text_input("Confirmer le mot de passe", type="password", key="reg_confirm")
            new_role = st.selectbox("Rôle", ["Enseignant", "Directeur", "Inspecteur", "Autre"], key="reg_role")
            submit_register = st.form_submit_button("Créer le compte")
            
            if submit_register:
                if new_username and new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("Les mots de passe ne correspondent pas")
                    elif len(new_password) < 6:
                        st.error("Le mot de passe doit contenir au moins 6 caractères")
                    else:
                        if auth_manager.create_user(new_username, new_password, new_email, new_role):
                            st.success("Compte créé avec succès ! Vous pouvez maintenant vous connecter.")
                        else:
                            st.error("Ce nom d'utilisateur existe déjà")
                else:
                    st.error("Veuillez saisir tous les champs obligatoires")

# 🗃️ Chargement des données
@st.cache_data(ttl=3600)
def load_data():
    try:
        # Pour Streamlit Cloud, utilisez une URL ou un chemin relatif
        df = pd.read_csv("donnees_nettoyees.csv", sep=';', encoding='ISO-8859-1', low_memory=False)
        return df
    except Exception as e:
        st.error(f"Erreur lors du chargement des données: {e}")
        # Retourne un DataFrame vide avec les colonnes attendues
        return pd.DataFrame(columns=[
            'id_eleve', 'identifiant_unique_eleve', 'id_classe', 'code_classe', 
            'nom_classe', 'nom_ecole', 'code_ecole', 'moyenne_t1', 'moyenne_t2', 
            'moyenne_t3', 'rang_t1', 'rang_t2', 'rang_t3'
        ])

# 🤖 Initialisation du modèle LLM
def init_llm():
    try:
        return ChatOllama(
            base_url=OLLAMA_SERVER_URL,
            model="gemma:2b",
            temperature=0.7,
            timeout=30
        )
    except Exception as e:
        st.warning(f"LLM non disponible: {e}")
        return None

# 📋 Template prompt amélioré avec mémoire
def get_enhanced_prompt_template():
    return PromptTemplate(
        input_variables=["question", "donnees", "historique", "contexte_utilisateur"],
        template="""
Tu es un enseignant expérimenté au Burkina Faso avec accès à l'historique des conversations. 
Tu dois répondre à une question sur les performances scolaires **en te basant uniquement sur les données fournies**. 
Ta réponse doit être claire, naturelle et structurée. ❗N'invente rien et ne fais pas de tableau.

📋 CONTEXTE UTILISATEUR :
{contexte_utilisateur}

📚 HISTORIQUE DES CONVERSATIONS RÉCENTES :
{historique}

🧠 LOGIQUE D'ANALYSE :

ÉTAPE 1 - Détecte les indicateurs temporels dans la question :
- Si mentions "premier/1er/T1" → Focus sur colonnes avec "_t1"
- Si mentions "deuxième/2ème/T2" → Focus sur colonnes avec "_t2"  
- Si mentions "troisième/3ème/T3" → Focus sur colonnes avec "_t3"
- Si pas de précision → Donne info des 3 trimestres

ÉTAPE 2 - SI LA QUESTION CONCERNE UN ÉLÈVE SPÉCIFIQUE :

### D'abord
- Présente l'école et la classe.
### Ensuite 
- Donne ses notes des matières (Calcul_T1, Conjugaison_T1, Copie_T1, Dessin_T1, Dictée_T1, 
  Ecriture_T1, Etude de Texte_T1, Exercices d'Observation_T1) en fonction du trimestre demandé
- Ses moyennes (moyenne_t1, moyenne_t2, moyenne_t3)
- Ses rangs (rang_t1, rang_t2, rang_t3)
- Analyse des points forts et des matières faibles
- Comparaison avec la moyenne de la classe
### En outre
- Conditions de vie et ressources disponibles
- Suivi pédagogique et parcours scolaire
- Assiduité et présence

📊 QUESTION SUR UNE CLASSE OU ÉCOLE :
- Fournis les statistiques générales demandées
- Compare les élèves si c'est pertinent
- Dégage des tendances

⚡ PRINCIPES CLÉS :
- Utilise l'historique pour contextualiser ta réponse
- Réponds uniquement à ce qui est demandé
- N'ajoute aucune supposition
- Sois structuré, naturel et pédagogique
- Propose des conseils adaptés
- Sois autonome dans tes commentaires et interprétations

Question actuelle :
{question}

Données :
{donnees}

➡️ Donne une réponse professionnelle, claire et adaptée au contexte scolaire.
"""
    )

# 🔍 Fonction de détection de filtre améliorée
def extraire_filtre(question, valeurs_connues):
    question_lower = question.lower()
    for val in valeurs_connues:
        if val and str(val).lower() in question_lower:
            return val
    return None

# 🔁 Fonction principale améliorée
def get_response_from_dataframe(question, df, memory, user_id, session_id):
    if df.empty:
        return "Aucune donnée disponible pour l'analyse."
    
    question_lower = question.lower()
    
    # 🧠 Détection des références contextuelles
    references_contextuelles = [
        "cet élève", "cette élève", "l'élève", "il", "elle", "lui", "son", "sa", "ses",
        "cette classe", "la classe", "cette école", "l'école", "même élève", "même classe", "même école"
    ]
    
    utilise_contexte = any(ref in question_lower for ref in references_contextuelles)
    
    # Extraction des filtres explicites
    id_eleve = extraire_filtre(question_lower, df['id_eleve'].astype(str).unique())
    identifiant_unique = extraire_filtre(question_lower, df['identifiant_unique_eleve'].astype(str).unique())
    id_classe = extraire_filtre(question_lower, df['id_classe'].astype(str).unique())
    code_classe = extraire_filtre(question_lower, df['code_classe'].astype(str).unique())
    nom_classe = extraire_filtre(question_lower, df['nom_classe'].astype(str).unique())
    nom_ecole = extraire_filtre(question_lower, df['nom_ecole'].astype(str).unique())
    code_ecole = extraire_filtre(question_lower, df['code_ecole'].astype(str).unique())
    
    # 🎯 Si aucun filtre explicite mais référence contextuelle détectée
    if not any([id_eleve, identifiant_unique, id_classe, nom_classe, nom_ecole]) and utilise_contexte:
        # Récupérer le dernier élément consulté selon le contexte
        historique = memory.get_conversation_history(user_id, 5)
        
        if historique:
            derniere_conversation = historique[0]  # Plus récente
            metadata = derniere_conversation.get('metadata', {})
            
            # Si la dernière consultation concernait un élève
            if metadata.get('type') == 'eleve' and metadata.get('eleve_id'):
                id_eleve = metadata['eleve_id']
                st.info(f"🔍 Référence contextuelle détectée : consultation de l'élève {id_eleve}")
            
            # Si la dernière consultation concernait une classe
            elif metadata.get('type') == 'classe' and metadata.get('classe'):
                nom_classe = metadata['classe']
                st.info(f"🔍 Référence contextuelle détectée : consultation de la classe {nom_classe}")
            
            # Si la dernière consultation concernait une école
            elif metadata.get('type') == 'ecole' and metadata.get('ecole'):
                nom_ecole = metadata['ecole']
                st.info(f"🔍 Référence contextuelle détectée : consultation de l'école {nom_ecole}")
    
    # Récupération du contexte utilisateur
    historique = memory.get_conversation_history(user_id, 5)
    contexte_utilisateur = memory.get_user_context(user_id)
    
    # Formatage de l'historique
    historique_text = ""
    if historique:
        historique_text = "Conversations récentes :\n"
        for conv in reversed(historique[-3:]):  # 3 dernières conversations
            historique_text += f"Q: {conv['question'][:100]}...\n"
            historique_text += f"R: {conv['response'][:150]}...\n\n"
    
    # Formatage du contexte utilisateur
    contexte_text = ""
    if contexte_utilisateur:
        recent_eleves = contexte_utilisateur.get('recent_eleves', [])
        recent_classes = contexte_utilisateur.get('recent_classes', [])
        recent_ecoles = contexte_utilisateur.get('recent_ecoles', [])
        
        if recent_eleves:
            contexte_text += f"Élèves récemment consultés: {', '.join([e['name'] for e in recent_eleves[:5]])}\n"
        if recent_classes:
            contexte_text += f"Classes récemment consultées: {', '.join([c['name'] for c in recent_classes[:5]])}\n"
        if recent_ecoles:
            contexte_text += f"Écoles récemment consultées: {', '.join([e['name'] for e in recent_ecoles[:5]])}\n"
    
    # Initialisation du template
    prompt_template = get_enhanced_prompt_template()
    
    # 🎯 Traitement par élève
    if id_eleve or identifiant_unique:
        ident = id_eleve or identifiant_unique
        ligne = df[(df['id_eleve'].astype(str) == ident) | (df['identifiant_unique_eleve'].astype(str) == ident)]
        
        if not ligne.empty:
            ligne = ligne.iloc[0]
            
            # Enregistrer l'élève dans le contexte
            memory.add_recent_entity(user_id, 'eleves', ident, f"Élève {ident}")
            
            # Préparer les données
            donnees_texte = "\n".join([f"{col}: {ligne[col]}" for col in df.columns if col in ligne])
            
            # Générer la réponse
            llm = init_llm()
            if llm is None:
                return "Le service d'analyse n'est pas disponible pour le moment."
            
            prompt = prompt_template.format(
                question=question,
                donnees=donnees_texte,
                historique=historique_text,
                contexte_utilisateur=contexte_text
            )
            
            try:
                resultat = llm.invoke(prompt)
                response = resultat.content if hasattr(resultat, 'content') else str(resultat)
                
                # Sauvegarder la conversation avec métadonnées enrichies
                metadata = {
                    'type': 'eleve',
                    'eleve_id': ident,
                    'ecole': ligne.get('nom_ecole', ''),
                    'classe': ligne.get('nom_classe', ''),
                    'sujet': 'general'
                }
                memory.save_conversation(user_id, session_id, question, response, metadata)
                
                return response
            except Exception as e:
                st.error(f"Erreur lors de la génération de la réponse: {e}")
                return "Une erreur est survenue lors de l'analyse des données."
    
    return "Aucun filtre détecté dans la question. Veuillez spécifier un élève, une classe ou une école."

# Initialisation MongoDB
def init_mongodb():
    try:
        if USE_EXTERNAL_SERVICES and MONGODB_URI:
            client = MongoClient(MONGODB_URI)
            client.admin.command('ping')  # Test de connexion
            db = client.chatbot_scolaire
            return db
    except Exception as e:
        st.warning(f"Connexion MongoDB échouée, utilisation du mode local: {e}")
    return None

# 🎨 Interface Streamlit améliorée
def main():
    # Initialisation de la session
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    
    if "user" not in st.session_state:
        st.session_state.user = None
    
    # Initialisation MongoDB
    db = init_mongodb()
    auth_manager = AuthManager(db)
    
    # Vérifier l'authentification
    if not st.session_state.authenticated:
        show_login_page(auth_manager)
        return
    
    # Interface principale pour utilisateur connecté
    st.title("🎓 Chatbot Scolaire - Analyse des Performances")
    st.subheader(f"👋 Bienvenue {st.session_state.user['username']} !")
    
    # Initialisation des services
    memory = ChatbotMemory(db)
    df_finale = load_data()
    
    if df_finale.empty:
        st.error("Aucune donnée disponible.")
        return
    
    user_id = st.session_state.user['user_id']
    
    # Initialisation des sessions
    if "current_session_id" not in st.session_state:
        st.session_state.current_session_id = memory.create_new_chat_session(user_id)
    
    if "current_chat_history" not in st.session_state:
        st.session_state.current_chat_history = []
    
    # 📋 Barre latérale améliorée
    with st.sidebar:
        st.header("🗂️ Menu")
        
        # Informations utilisateur
        st.subheader("👤 Profil")
        st.write(f"**Nom:** {st.session_state.user['username']}")
        st.write(f"**Rôle:** {st.session_state.user['role']}")
        st.write(f"**Email:** {st.session_state.user.get('email', 'Non renseigné')}")
        
        # Bouton de déconnexion
        if st.button("🚪 Se déconnecter"):
            st.session_state.authenticated = False
            st.session_state.user = None
            st.rerun()
        
        st.markdown("---")
        
        # Gestion des sessions de chat
        st.subheader("💬 Sessions de Chat")
        
        # Bouton nouveau chat
        if st.button("🆕 Nouveau Chat"):
            st.session_state.current_session_id = memory.create_new_chat_session(user_id)
            st.session_state.current_chat_history = []
            st.success("Nouveau chat créé !")
            st.rerun()
        
        # Liste des sessions précédentes
        st.subheader("📜 Historique des Sessions")
        sessions = memory.get_user_chat_sessions(user_id, 10)
        
        for session in sessions:
            session_id = str(session.get('_id', session.get('id', '')))
            session_title = session.get('title', f"Chat {session.get('created_at', datetime.datetime.now()).strftime('%d/%m')}")
            
            # Bouton pour charger la session
            if st.button(f"📄 {session_title}", key=f"session_{session_id}"):
                st.session_state.current_session_id = session_id
                # Charger l'historique de cette session
                conversations = memory.get_session_conversations(session_id)
                st.session_state.current_chat_history = []
                for conv in conversations:
                    st.session_state.current_chat_history.append({"role": "user", "content": conv['question']})
                    st.session_state.current_chat_history.append({"role": "assistant", "content": conv['response']})
                st.rerun()
        
        st.markdown("---")
        
        # Contexte utilisateur
        st.subheader("🔍 Consultés récemment")
        context = memory.get_user_context(user_id)
        
        # Élèves récents
        recent_eleves = context.get('recent_eleves', [])
        if recent_eleves:
            st.write("**Élèves:**")
            for eleve in recent_eleves[:3]:
                st.write(f"• {eleve['name']}")
        
        # Classes récentes
        recent_classes = context.get('recent_classes', [])
        if recent_classes:
            st.write("**Classes:**")
            for classe in recent_classes[:3]:
                st.write(f"• {classe['name']}")
        
        # Écoles récentes
        recent_ecoles = context.get('recent_ecoles', [])
        if recent_ecoles:
            st.write("**Écoles:**")
            for ecole in recent_ecoles[:3]:
                st.write(f"• {ecole['name']}")
    
    # 💬 Zone de chat principale
    st.subheader(f"Session actuelle: {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M')}")
    
    # Affichage de l'historique du chat actuel
    for message in st.session_state.current_chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Saisie utilisateur
    user_input = st.chat_input("Pose ta question sur les performances scolaires...")
    
    if user_input:
        # Affichage de la question
        with st.chat_message("user"):
            st.write(user_input)
        
        # Génération et affichage de la réponse
        with st.chat_message("assistant"):
            with st.spinner("Analyse en cours..."):
                response = get_response_from_dataframe(
                    user_input, 
                    df_finale, 
                    memory, 
                    user_id, 
                    st.session_state.current_session_id
                )
                st.write(response)
        
        # Ajout à l'historique de session
        st.session_state.current_chat_history.append({"role": "user", "content": user_input})
        st.session_state.current_chat_history.append({"role": "assistant", "content": response})
        
        # Mettre à jour le titre de la session si c'est la première question
        if len(st.session_state.current_chat_history) == 2:
            # Utiliser les 50 premiers caractères de la question comme titre
            title = user_input[:50] + "..." if len(user_input) > 50 else user_input
            memory.update_session_title(st.session_state.current_session_id, title)
    
    # 💡 Suggestions
    with st.expander("💡 Suggestions"):
        st.write("• Analyser les performances d'un élève spécifique")
        st.write("• Comparer les résultats entre trimestres")
        st.write("• Identifier les élèves en difficulté")
        st.write("• Analyser les tendances d'une classe")
        st.write("• Consulter les statistiques d'une école")

if __name__ == "__main__":
    main()
