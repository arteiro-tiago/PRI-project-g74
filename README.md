# PRI-project-g74


## configurar

**macOS / Linux:**

```bash
python3 -m venv venv

source venv/bin/activate

```

**windows:**

```bash
python -m venv venv

.\venv\Scripts\activate

```

## dependências


```bash
pip install -r "requirements.txt"

```

## correr 1º passo

Neste momento este script faz o clone do repositório, seleciona 300 cve's aleatório de cada ano entre os anos 2017-2026 e passa toda a informação para um csv

```bash
python NVD_extractor.py

```