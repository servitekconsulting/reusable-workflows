
import os
import sys
import json
import subprocess
import zipfile
import io
import textwrap
from typing import List, Dict
from openai import OpenAI
from openai import BadRequestError, RateLimitError

# -----------------------------
# Utils de shell / HTTP (curl)
# -----------------------------
def sh(cmd: List[str]) -> subprocess.CompletedProcess:
    """Ejecuta comando que devuelve TEXTO (JSON), decodificado como UTF-8."""
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def sh_bin(cmd: List[str]) -> subprocess.CompletedProcess:
    """Ejecuta comando que devuelve BINARIO (ZIP), sin decodificar."""
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)

def gh_json(url: str, token: str) -> Dict:
    """GET JSON desde la API de GitHub (siguiendo redirects)."""
    cp = sh([
        "curl", "-sS", "-L",
        "-H", "Accept: application/vnd.github+json",
        "-H", f"Authorization: Bearer {token}",
        "-H", "X-GitHub-Api-Version: 2022-11-28",
        url
    ])
    if cp.returncode != 0:
        print(f"[ERR] curl {url} -> {cp.stderr}", file=sys.stderr)
        return {}
    try:
        return json.loads(cp.stdout)
    except Exception:
        # No JSON (p.ej., HTML de error). Devuelve vacío.
        return {}

def download_job_logs(repo: str, job_id: int, token: str) -> bytes:
    """
    Descarga logs de un job (endpoint devuelve 302 → ZIP temporal).
    Devuelve bytes (pueden ser ZIP o texto) sin fallar.
    """
    url = f"https://api.github.com/repos/{repo}/actions/jobs/{job_id}/logs"
    cp = sh_bin([
        "curl", "-sS", "-L",
        "-H", "Accept: application/vnd.github+json",
        "-H", f"Authorization: Bearer {token}",
        "-H", "X-GitHub-Api-Version: 2022-11-28",
        url
    ])
    if cp.returncode != 0:
        print(f"[ERR] logs job {job_id}: {cp.stderr}", file=sys.stderr)
        return b""
    # cp.stdout ya es bytes (text=False)
    return cp.stdout

def download_run_logs(repo: str, run_id: str, token: str) -> bytes:
    """
    Descarga logs del run completo (endpoint devuelve 302 → ZIP temporal).
    Devuelve bytes (pueden ser ZIP o texto).
    """
    url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/logs"
    cp = sh_bin([
        "curl", "-sS", "-L",
        "-H", "Accept: application/vnd.github+json",
        "-H", f"Authorization: Bearer {token}",
        "-H", "X-GitHub-Api-Version: 2022-11-28",
        url
    ])
    if cp.returncode != 0:
        print(f"[ERR] logs run {run_id}: {cp.stderr}", file=sys.stderr)
        return b""
    return cp.stdout

# -----------------------------
# Manejo de ZIP y textos
# -----------------------------
def is_zip_bytes(b: bytes) -> bool:
    """Valida si los bytes representan un ZIP."""
    try:
        return zipfile.is_zipfile(io.BytesIO(b))
    except Exception:
        return False

def extract_zip_texts(zip_bytes: bytes, max_files: int = 12) -> List[str]:
    """
    Extrae texto de los archivos del ZIP (hasta max_files).
    Si el contenido no es ZIP válido, no imprime error fuerte y devuelve lista vacía.
    """
    texts = []
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
            names = z.namelist()[:max_files]
            for name in names:
                with z.open(name) as f:
                    try:
                        data = f.read().decode("utf-8", errors="ignore")
                        texts.append(f"# {name}\n{data}")
                    except Exception:
                        # Ignora archivos binarios no-texto
                        pass
    except zipfile.BadZipFile:
        # Registramos como WARN; el caller decidirá fallback.
        print("[WARN] Contenido descargado no es un ZIP válido", file=sys.stderr)
    except Exception as e:
        print(f"[WARN] extract_zip_texts: {e}", file=sys.stderr)
    return texts

def tail(text: str, max_lines: int = 300) -> str:
    """Devuelve las últimas N líneas de un texto."""
    lines = text.splitlines()
    return "\n".join(lines[-max_lines:])

def summarize_texts(texts: List[str], max_chars: int = 22000) -> str:
    """Concatena textos truncando por tamaño total para no exceder el prompt."""
    out, size = [], 0
    for t in texts:
        chunk = tail(t, 300)
        size += len(chunk)
        if size > max_chars:
            break
        out.append(chunk)
    return "\n\n".join(out)

def build_tail_block(texts: List[str], max_lines: int = 300) -> str:
    """
    Concatena todos los textos disponibles y devuelve un tail unificado
    para mostrar como bloque en el Step Summary.
    """
    all_txt = "\n\n".join(texts) if texts else ""
    return tail(all_txt, max_lines) if all_txt else "No se encontraron logs para mostrar."

# -----------------------------
# Recomendaciones automáticas (reglas)
# -----------------------------
def recommend_rules(log_text: str) -> str:
    """
    Detecta patrones comunes en logs y devuelve recomendaciones concretas
    con snippets YAML/CLI listos para aplicar.
    """
    rules_md = []
    def add(title: str, body_md: str):
        rules_md.append(f"**{title}**\n\n{body_md}\n")

    t = log_text.lower()

    # GHCR push / permisos / login
    if any(p in t for p in [
        "requested access to the resource is denied",
        "unauthorized: authentication required",
        "permission denied",
        "denied: requested access"
    ]):
        add("GHCR: acceso denegado o permiso insuficiente",
            textwrap.dedent("""
            - Asegura permisos en el workflow:
              ```yaml
              permissions:
                contents: read
                packages: write
                actions: read
              ```
            - Inicia sesión en GHCR antes del build/push:
              ```yaml
              - name: Log into registry ghcr.io
                uses: docker/login-action@v3
                with:
                  registry: ghcr.io
                  username: ${{ github.actor }}
                  password: ${{ secrets.GITHUB_TOKEN }}
              ```
            - Verifica visibilidad del package y el namespace en `images:`/`tags:`.
            """))

    # ACR login / push
    if "azurecr.io" in t and any(p in t for p in ["unauthorized", "denied", "authentication", "login", "not found", "manifest unknown"]):
        add("ACR: login/imagen/tag inconsistentes",
            textwrap.dedent("""
            - Login a ACR con usuario/contraseña válidos:
              ```yaml
              - name: Docker login to ACR
                uses: azure/docker-login@v1
                with:
                  login-server: tesiscloud.azurecr.io
                  username: ${{ secrets.REGISTRY_USERNAME }}
                  password: ${{ secrets.REGISTRY_PASSWORD }}
              ```
            - Construye y empuja tags consistentes:
              ```bash
              IMAGE=tesiscloud.azurecr.io/myapp-java
              docker build . -t $IMAGE:${{ github.sha }} -t $IMAGE:latest
              docker push $IMAGE:${{ github.sha }}
              docker push $IMAGE:latest
              ```
            - Asegura que el manifiesto K8s use el mismo tag:
              ```yaml
              images: "tesiscloud.azurecr.io/myapp-java:${{ github.sha }}"
              ```
            """))

    # Kubernetes pull errors
    if any(p in t for p in ["imagepullbackoff", "errimagepull", "failed to pull image", "back-off pulling image"]):
        add("Kubernetes: errores al extraer la imagen (ImagePullBackOff/ErrImagePull)",
            textwrap.dedent("""
            - Si el registry es privado, añade `imagePullSecrets`:
              ```yaml
              apiVersion: v1
              kind: Secret
              metadata:
                name: acr-pull-secret
              type: kubernetes.io/dockerconfigjson
              data:
                .dockerconfigjson: <base64 de docker login>
              ---
              apiVersion: apps/v1
              kind: Deployment
              spec:
                template:
                  spec:
                    imagePullSecrets:
                      - name: acr-pull-secret
              ```
            - Confirma que el tag referenciado existe en el registry.
            - Verifica `namespace` y permisos del kubeconfig para ese namespace.
            """))

    # x509 / certificados
    if "x509: certificate signed by unknown authority" in t:
        add("Certificados: CA desconocida al extraer imagen",
            textwrap.dedent("""
            - Si hay proxy/TLS interno, agrega la CA al nodo/runner o al contenedor base.
            - Verifica que el endpoint del registry use un certificado válido para el hostname.
            """))

    # Docker build / frontend dockerfile / file not found
    if any(p in t for p in [
        "error building image",
        "failed to solve with frontend dockerfile.v0",
        "no such file or directory",
        "dockerfile"
    ]):
        add("Docker build: ruta/archivo Dockerfile o contexto incorrectos",
            textwrap.dedent("""
            - Declara `file:` y `context:` explícitos:
              ```yaml
              - name: Build and push Docker image
                uses: docker/build-push-action@v6
                with:
                  context: ${{ inputs.working-directory }}
                  file: ${{ inputs.working-directory }}/Dockerfile
                  push: true
              ```
            - Verifica que el `working-directory` apunte donde está el `Dockerfile`.
            - Añade un paso de validación:
              ```bash
              test -f "${{ inputs.working-directory }}/Dockerfile" || (echo "::error::No se encontró Dockerfile" && exit 1)
              ```
            """))

    # Manifest unknown (tags)
    if "manifest unknown" in t:
        add("Manifest unknown: el tag no existe en el registry",
            textwrap.dedent("""
            - Alinea los tags construidos y referenciados en despliegue:
              ```bash
              IMAGE=tesiscloud.azurecr.io/myapp-java
              docker build . -t $IMAGE:${{ github.sha }}
              docker push  $IMAGE:${{ github.sha }}
              ```
              ```yaml
              images: "tesiscloud.azurecr.io/myapp-java:${{ github.sha }}"
              ```
            """))

    # Cosign / OIDC firma
    if "cosign" in t or "fulcio" in t or "rekor" in t or "oidc" in t:
        add("Firma cosign/OIDC: permisos y configuración",
            textwrap.dedent("""
            - Requiere `id-token: write`:
              ```yaml
              permissions:
                id-token: write
                contents: read
                packages: write
              ```
            - Instala cosign y firma con el digest del build:
              ```yaml
              - name: Install cosign
                uses: sigstore/cosign-installer@v4
                with:
                  cosign-release: "v3.0.2"
              - name: Sign image
                env:
                  COSIGN_EXPERIMENTAL: "true"
                run: cosign sign ghcr.io/<org>/<repo>@${{ steps.build-and-push.outputs.digest }}
              ```
            """))

    # RPC Unknown (errores genéricos buildx/docker)
    if "rpc error: code = unknown" in t or "code = unknown" in t:
        add("Buildx/Docker: error genérico (rpc code = Unknown)",
            textwrap.dedent("""
            - Fija versiones de acciones:
              ```yaml
              - uses: docker/setup-buildx-action@v3
              - uses: docker/build-push-action@v6
              - uses: docker/login-action@v3
              ```
            - Limpia caché/previos e intenta de nuevo:
              ```bash
              docker builder prune -f
              ```
            """))

    # Sin patrón específico → buenas prácticas generales
    if not rules_md:
        add("Buenas prácticas generales (sin patrón específico detectado)",
            textwrap.dedent("""
            - Fija versiones de acciones para reproducibilidad.
            - Alinea tags (`${{ github.sha }}`/`latest`) entre build, push y despliegue K8s.
            - Añade `imagePullSecrets` si el registry es privado.
            - Verifica `permissions`:
              ```yaml
              permissions:
                contents: read
                packages: write
                actions: read
              ```
            """))

    return "\n".join(rules_md)

# -----------------------------
# Step summary
# -----------------------------
def write_step_summary(md: str):
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(md + "\n")
    except Exception as e:
        print(f"[WARN] No se pudo escribir Step Summary: {e}", file=sys.stderr)

# -----------------------------
# Main
# -----------------------------
def main():
    api_key     = os.getenv("OPENAI_API_KEY")
    token       = os.getenv("GITHUB_TOKEN")
    repo        = os.getenv("GITHUB_REPOSITORY")
    run_id      = os.getenv("GITHUB_RUN_ID")
    event_path  = os.getenv("GITHUB_EVENT_PATH")

    if not all([api_key, token, repo, run_id, event_path]):
        print("Faltan variables de entorno requeridas.", file=sys.stderr)
        sys.exit(1)

    # Cargar evento (para contexto; QA suele ser push sin PR)
    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event = json.load(f)
    except Exception:
        event = {}

    # 1) Listar jobs del run y filtrar fallidos
    jobs_resp = gh_json(f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs", token)
    jobs = jobs_resp.get("jobs", [])
    failed = [j for j in jobs if j.get("conclusion") == "failure"]

    if not failed:
        write_step_summary("### 🤖 AI Failure Advisor\nNo se detectaron jobs fallidos.")
        print("AI Failure Advisor escribió el resumen en $GITHUB_STEP_SUMMARY.")
        return

    # 2) Recoger logs por cada job fallido con fallback
    all_texts: List[str] = []
    for j in failed:
        job_id   = j["id"]
        job_name = j.get("name", "unknown")
        steps    = j.get("steps", [])
        failed_steps = [s for s in steps if s.get("conclusion") == "failure"]
        header = f"## Job: {job_name} (id {job_id})\nPasos fallidos: {', '.join(s.get('name','?') for s in failed_steps) or 'desconocido'}"
        all_texts.append(header)

        job_bytes = download_job_logs(repo, job_id, token)
        texts = []

        if job_bytes and is_zip_bytes(job_bytes):
            # Caso normal: ZIP válido del job
            texts = extract_zip_texts(job_bytes)
        else:
            # Fallback 1: ZIP del run completo
            run_bytes = download_run_logs(repo, run_id, token)
            if run_bytes and is_zip_bytes(run_bytes):
                texts = extract_zip_texts(run_bytes)
            else:
                # Fallback 2: usar texto crudo (HTML/JSON), sin intentar unzip
                raw = (job_bytes or run_bytes or b"").decode("utf-8", errors="ignore")
                if raw.strip():
                    texts = [f"# raw-response\n{tail(raw, 300)}"]
                # Si no hay nada, no agregamos texto.

        all_texts.extend(texts)

    # Tail real para mostrar en el Summary
    tail_block = build_tail_block(all_texts, max_lines=300)

    # Texto resumido para el prompt de la IA
    condensed_for_ai = summarize_texts(all_texts, max_chars=22000)

    # 3) Prompt especializado (Docker/GHCR/ACR/K8s/AKS/cosign)
    prompt = textwrap.dedent(f"""
    Actúa como ingeniero DevOps experto en GitHub Actions, Docker, GHCR/ACR y despliegues AKS/Kubernetes.
    Con los logs truncados de jobs fallidos, entrega:
    1) Causa raíz probable (cita fragmentos del log: p.ej. 'denied: requested access...', 'ImagePullBackOff', 'ErrImagePull', 'Failed to pull image', 'x509: certificate signed by unknown authority', 'rpc error: code = Unknown', 'no such file or directory', 'manifest unknown').
    2) Acciones inmediatas (comandos y ajustes YAML/CLI): ejemplos
       - Docker/Buildx: revisar `context`/`file`, caché Buildx, versiones de acciones.
       - GHCR: validar login con `docker/login-action`, permisos `packages: write`, visibilidad del paquete.
       - ACR: usuario/clave válidos, `azure/docker-login`, tags/repos correctos.
       - AKS/K8s: imagen referenciada en manifiestos, `imagePullPolicy`, `imagePullSecrets`, `namespace`, permisos de kubeconfig.
    3) Prevención (versiones fijas, retry/backoff, limpieza de imágenes antiguas, límites de rate).
    4) Si el fallo fue en firma (cosign), detalla OIDC/`id-token: write` y cómo reintentar.

    Logs (truncados para análisis de IA):
    {condensed_for_ai}
    """)

    client = OpenAI(api_key=api_key)

    # 4) Llamada al modelo principal: gpt-5-mini (sin parámetros no soportados)
    try:
        resp = client.chat.completions.create(
            model="gpt-5-mini",
            messages=[
                {"role": "system", "content": "Eres un analista experto en CI/CD y despliegues en contenedores."},
                {"role": "user", "content": prompt}
            ]
        )
        advice = resp.choices[0].message.content.strip()
    except (BadRequestError, RateLimitError) as e:
        # Fallback opcional por robustez (modelos con parámetros flexibles)
        try:
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Eres un analista experto en CI/CD y despliegues en contenedores."},
                    {"role": "user", "content": prompt}
                ]
            )
            advice = resp.choices[0].message.content.strip()
        except Exception as ee:
            advice = f"No se pudo obtener diagnóstico de la IA: {e} | Fallback error: {ee}"

    # 5) Armar el markdown final con diagnóstico + reglas + tail real
    md_ai    = "### 🤖 AI Failure Advisor (QA/Prod)\n\n" + advice
    md_rules = "#### 🔧 Recomendaciones automáticas (reglas)\n\n" + recommend_rules("\n".join(all_texts))
    write_step_summary(md_ai)
    write_step_summary(md_rules)

if __name__ == "__main__":
    main()
