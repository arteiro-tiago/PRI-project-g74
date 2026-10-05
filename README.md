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

## correr a pipeline

O ficheiro `selected_cves.csv` contém a amostra NVD selecionada para o projeto.
O script clona o GitHub Advisory Database, cruza os advisories com os CVEs do
NVD através do campo `aliases` e gera a coleção final `final_cves.csv`.

```bash
python NVD_extractor.py

```

O resultado contém 3.000 documentos NVD. Na execução validada, 2.791 CVEs
encontraram correspondência no GHAD e 209 não tiveram advisory associado.

Os campos acrescentados pelo GHAD são `ghsa_id`, `aliases`, `summary` e
`details`.

O merge mantém os valores do NVD quando existem e usa o GHAD como fallback para
descrição, datas, CVSS e severidade. CWE, referências e produtos afetados são
combinados e deduplicados quando possível.

O repositório GHAD é grande, por isso a primeira execução pode demorar alguns
minutos e requer ligação à internet. É necessário ter `git` instalado.