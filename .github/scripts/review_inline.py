# .github/scripts/review_inline.py
import os
import re
import json
import subprocess
import sys
import fnmatch
from typing import List, Dict, Tuple
from openai import OpenAI
from openai import BadRequestError, RateLimitError

def load_patterns_from_env() -> list:
    """
    Lee patrones desde REVIEW_FILE_PATTERNS (CSV).
    Ej: "*.java,pom.xml"
    """
    raw = os.getenv("REVIEW_FILE_PATTERNS", "").strip()
    if not raw:
        return []  # sin patrones → no se filtra (o puedes poner defaults)
    return [p.strip() for p in raw.split(",") if p.strip()]

def is_allowed_by_patterns(path: str, patterns: list) -> bool:
    """
    Devuelve True si el path cumple alguno de los patrones (fnmatch).
    """
    if not patterns:
        return True  # sin patrones → permitir todo
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)

def run(cmd: List[str]) -> str:
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        print(f"Error ejecutando {' '.join(cmd)}:\n{r.stderr}", file=sys.stderr)
        return ""
    return r.stdout

def get_pr_info() -> Tuple[int, str]:
    event_path = os.getenv("GITHUB_EVENT_PATH")
    with open(event_path, "r", encoding="utf-8") as f:
        event = json.load(f)
    pr_number = int(event["pull_request"]["number"])
    head_sha = event["pull_request"]["head"]["sha"]
    return pr_number, head_sha

def parse_unified_diff(diff_text: str) -> Dict[str, List[Tuple[int, str]]]:
    """
    Devuelve {path: [(new_line_number, added_line_text), ...]}
    Solo líneas nuevas ('+') con su número en el lado RIGHT (archivo nuevo).
    """
    files: Dict[str, List[Tuple[int, str]]] = {}
    current_path = None
    new_line = None

    lines = diff_text.splitlines()
    for line in lines:
        if line.startswith("diff --git "):
            current_path = None
            new_line = None

        elif line.startswith("+++ b/"):
            current_path = line[6:]  # '+++ b/<path>'
            files.setdefault(current_path, [])
            new_line = None

        elif line.startswith("@@ "):
            # Ej: @@ -12,5 +20,7 @@
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if m:
                new_start = int(m.group(1))
                new_line = new_start
            else:
                new_line = None

        else:
            if current_path is None or new_line is None:
                continue
            if not line:
                continue

            prefix = line[0]
            content = line[1:]

            if prefix == '+':
                # línea añadida en el lado RIGHT
                files[current_path].append((new_line, content))
                new_line += 1
            elif prefix == '-':
                # eliminación: no avanza contador de new_line
                pass
            else:
                # contexto: avanza contador de línea en el archivo nuevo
                new_line += 1

    return files

def make_prompt_for_file(path: str, added_lines: List[Tuple[int, str]]) -> str:
    """
    Construye un prompt conciso con líneas añadidas y números (RIGHT side).
    """
    header = (
        "Actúa como revisor de código experto en buenas prácticas, seguridad, rendimiento, "
        "mantenibilidad y tests.\n"
        "Te paso SOLO las líneas NUEVAS del diff para este archivo (con numeración del lado derecho).\n"
        "Devuelve un JSON con una lista de observaciones. Cada item debe ser:\n"
        "{ \"path\": \"<ruta>\", \"line\": <numero_linea_right>, \"comment\": \"texto claro y accionable\", \"suggestion\": \"(opcional) snippet\" }\n"
        "Reglas:\n"
        "- Usa únicamente líneas que aparezcan abajo (line) y que existan en el diff.\n"
        "- Sé concreto y accionable; sugiere mejoras puntuales.\n"
        "- Máximo 3 observaciones por archivo.\n"
    )
    body_lines = []
    for ln, txt in added_lines[:200]:  # límite para no inflar tokens
        body_lines.append(f"{ln}: {txt}")
    body = "\n".join(body_lines)
    return f"{header}\nArchivo: {path}\nLíneas añadidas (RIGHT):\n{body}\n"

def parse_model_json(text: str) -> List[Dict]:
    """
    Intenta extraer JSON; soporta respuesta directa o envuelta en bloque ```json ...
    """
    text = text.strip()
    # Bloque ```json
    m = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
    if m:
        candidate = m.group(1)
    else:
        candidate = text

    try:
        data = json.loads(candidate)
        if isinstance(data, dict):
            # Puede venir como {"observations":[...]}
            if "observations" in data and isinstance(data["observations"], list):
                return data["observations"]
            # O lista en "items"
            if "items" in data and isinstance(data["items"], list):
                return data["items"]
            # O un solo objeto
            return [data]
        elif isinstance(data, list):
            return data
    except Exception:
        pass
    return []

def create_review_with_comments(repo: str, pr_number: int, head_sha: str, comments: List[Dict], token: str) -> None:
    """
    Envía todas las observaciones en un único review (event=COMMENT).
    Cada comentario lleva: path, line, side='RIGHT', body.
    """
    # Trunca a un máximo razonable (evitar rate limit)
    comments = comments[:30]
    payload = {
        "commit_id": head_sha,
        "event": "COMMENT",
        "comments": comments
    }
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    cmd = [
        "curl", "-sS", "-X", "POST", url,
        "-H", "Accept: application/vnd.github+json",
        "-H", f"Authorization: Bearer {token}",
        "-H", "X-GitHub-Api-Version: 2022-11-28",
        "-d", json.dumps(payload)
    ]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        print(f"Error creando review: {r.stderr}", file=sys.stderr)
    else:
        print("Review con comentarios inline enviado correctamente.")

def main():
    api_key = os.getenv("OPENAI_API_KEY")
    gh_token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    base_ref = os.getenv("GITHUB_BASE_REF")
    head_ref = os.getenv("GITHUB_HEAD_REF")

    if not all([api_key, gh_token, repo, base_ref, head_ref]):
        print("Faltan variables de entorno requeridas.", file=sys.stderr)
        sys.exit(1)

    # PR number y SHA
    pr_number, head_sha = get_pr_info()

    # Diff triple-dot contra la base (unified=0 para precisión de líneas cambiadas)
    run(["git", "fetch", "origin", base_ref, head_ref])
    diff = run(["git", "diff", "--unified=0", f"origin/{base_ref}...origin/{head_ref}"])
    if not diff.strip():
        print("No hay diff para revisar.")
        return

    # Parsear diff por archivo
    per_file_added = parse_unified_diff(diff)

    # --- NUEVO: patrones desde env ---
    patterns = load_patterns_from_env()

    # --- NUEVO: aplicar filtro por patrones ---
    per_file_added = {p: lines for p, lines in per_file_added.items() if is_allowed_by_patterns(p, patterns)}

    client = OpenAI(api_key=api_key)
    all_comments: List[Dict] = []

    for path, added_lines in per_file_added.items():
        if not added_lines:
            continue

        prompt = make_prompt_for_file(path, added_lines)

        # Intento con gpt-5-mini; si no estuviese disponible/compatible, fallback a gpt-4o-mini
        try:
            resp = client.chat.completions.create(
                model="gpt-5-mini",
                messages=[
                    {"role": "system", "content": "Eres un revisor experto en ingeniería de software y seguridad."},
                    {"role": "user", "content": prompt}
                ]
            )
        except (BadRequestError, RateLimitError):
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Eres un revisor experto en ingeniería de software y seguridad."},
                    {"role": "user", "content": prompt}
                ]
            )

        content = resp.choices[0].message.content
        items = parse_model_json(content)

        for it in items:
            try:
                c_path = it.get("path", path)
                c_line = int(it["line"])
                body = it.get("comment", "")
                suggestion = it.get("suggestion")
                if suggestion:
                    body = f"{body}\n\n**Sugerencia:**\n```diff\n{suggestion}\n```"
                # Cada comentario requiere path, line y side=RIGHT (lado nuevo del diff)
                all_comments.append({
                    "path": c_path,
                    "line": c_line,
                    "side": "RIGHT",
                    "body": body
                })
            except Exception:
                continue

    if not all_comments:
        # Si no hay nada, deja un comentario general
        general = "No se generaron observaciones automáticas en líneas específicas."
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        payload = json.dumps({"body": "## 🤖 Revisión automática\n" + general})
        cmd = [
            "curl", "-sS", "-X", "POST", url,
            "-H", "Accept: application/vnd.github+json",
            "-H", f"Authorization: Bearer {gh_token}",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
            "-d", payload
        ]
        subprocess.run(cmd, check=False)
        return

    # Enviar un único review con todos los comentarios inline
    create_review_with_comments(repo, pr_number, head_sha, all_comments, gh_token)

if __name__ == "__main__":
    main()